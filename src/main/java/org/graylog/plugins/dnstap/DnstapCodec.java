/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.Histogram;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.google.common.base.Splitter;
import com.google.common.net.InetAddresses;
import com.google.inject.assistedinject.Assisted;
import jakarta.inject.Inject;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageFactory;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.failure.InputProcessingException;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.annotation.Nonnull;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.stream.Collectors;

import static com.codahale.metrics.MetricRegistry.name;
import static org.graylog.plugins.dnstap.FieldNames.Field.*;

/**
 * Turns one dnstap protobuf payload (one Frame Streams data frame) into one Graylog message.
 * <p>
 * Field names come from {@link FieldNames}. The defaults line up with what a pipeline extracts from BIND's text
 * query log (dns_client_ip, dns_query_name, dns_query_type), so the two transports can be searched the same way,
 * and {@code dnstap: true} marks the message for pipeline rules.
 */
@Codec(name = "dnstap", displayName = "Dnstap")
public class DnstapCodec extends AbstractCodec {
    static final String CK_INCLUDE_ANSWERS = "include_answers";
    static final String CK_SKIP_TYPES = "skip_message_types";

    // characters; at most 3 UTF-8 bytes each, so "answers" stays below OpenSearch's 32766-byte term limit
    static final int MAX_ANSWERS_TEXT = 8192;
    static final long MAX_CLOCK_SKEW_MS = 7L * 24 * 3600 * 1000;
    private static final int MAX_CACHED_SKIP_LISTS = 32;
    private static final Splitter TYPE_LIST = Splitter.onPattern("[,\\s]+").omitEmptyStrings().trimResults();

    // Graylog creates a new codec instance for every message (DecodingProcessor: factory.create(raw.getCodecConfig())),
    // so everything computed once lives in static caches: per-input metrics and parsed skip lists.
    private static final ConcurrentMap<MetricRegistry, ConcurrentMap<String, CodecMetrics>> METRICS = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Set<String>> SKIP_TYPES = new ConcurrentHashMap<>();
    // Inputs running on this node. Graylog still decodes messages of a stopped or deleted input that wait in its
    // journal; registering metrics for those would re-create them after the input removed them, for good.
    private static final Set<String> RUNNING = ConcurrentHashMap.newKeySet();
    // counts the messages of inputs that aren't running, in a registry that nobody publishes
    private static final CodecMetrics DETACHED = new CodecMetrics(new MetricRegistry(), "detached");

    private final MessageFactory messageFactory;
    private final MetricRegistry metricRegistry;
    private final boolean includeAnswers;
    private final Set<String> skipTypes;
    private final String overrideSource;

    /**
     * Per-input codec metrics, under the same prefix as Graylog's own codec metrics for the input
     * ({@code org.graylog.plugins.dnstap.DnstapCodec.<input id>.parseTime / .failures}):
     * {@code eventLagMs} (processing time minus the DNS event's time; grows when messages wait in the relay, BIND's
     * queue or Graylog's journal), {@code skipped} (dropped by "Skip message types"), {@code nonMessage} (dnstap
     * frames without a DNS message) and {@code types.<CQ|CR|...>}.
     */
    private static final class CodecMetrics {
        // The lag histogram's reservoir is synchronised, so only 1 in N messages updates it. A power of two (mask).
        static final int LAG_SAMPLE_EVERY = 32;
        final Histogram eventLagMs;
        final Meter skipped;
        final Meter nonMessage;
        final AtomicReferenceArray<Meter> types = new AtomicReferenceArray<>(16);   // by dnstap message type, 0 = other
        final MetricRegistry registry;
        final String base;
        private final AtomicInteger sample = new AtomicInteger();

        CodecMetrics(MetricRegistry registry, String inputId) {
            this.registry = registry;
            this.base = base(inputId);
            eventLagMs = registry.histogram(name(base, "eventLagMs"));
            skipped = registry.meter(name(base, "skipped"));
            nonMessage = registry.meter(name(base, "nonMessage"));
        }

        void type(int messageType) {
            final int i = messageType > 0 && messageType < types.length() ? messageType : 0;
            Meter m = types.get(i);
            if (m == null) {
                m = registry.meter(name(base, "types", i == 0 ? "other" : DnstapFrame.typeShort(i)));
                types.set(i, m);   // harmless race: the registry returns the same meter to both threads
            }
            m.mark();
        }

        void lag(long eventMillis) {
            if ((sample.incrementAndGet() & (LAG_SAMPLE_EVERY - 1)) == 0) {
                eventLagMs.update(Math.max(0, System.currentTimeMillis() - eventMillis));
            }
        }
    }

    @Inject
    public DnstapCodec(@Assisted Configuration configuration, MessageFactory messageFactory, MetricRegistry metricRegistry) {
        super(configuration);
        this.messageFactory = messageFactory;
        this.metricRegistry = metricRegistry;
        this.includeAnswers = configuration.getBoolean(CK_INCLUDE_ANSWERS, true);
        this.skipTypes = skipTypes(configuration.getString(CK_SKIP_TYPES, ""));
        this.overrideSource = configuration.stringIsSet(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_OVERRIDE_SOURCE)
                ? configuration.getString(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_OVERRIDE_SOURCE) : null;
    }

    @Override
    public Optional<Message> decodeSafe(@Nonnull RawMessage rawMessage) {
        final CodecMetrics metrics = metrics(rawMessage);
        final DnstapFrame f;
        final DnsMessage dns;
        final boolean parsedResponse;     // dns is the response message (else the query message, or null)
        try {
            f = DnstapFrame.parse(rawMessage.getPayload());
            if (f.dnstapType != DnstapFrame.DNSTAP_TYPE_MESSAGE || !f.hasMessage) {
                metrics.nonMessage.mark();
                return Optional.empty(); // not a DNS message: dnstap reserves other types
            }
            if (!skipTypes.isEmpty() && (skipTypes.contains(DnstapFrame.typeShort(f.messageType))
                    || skipTypes.contains(DnstapFrame.typeName(f.messageType)))) {
                metrics.skipped.mark();
                return Optional.empty();
            }
            parsedResponse = f.isResponse() && f.responseMessageOffset >= 0;
            if (parsedResponse) {
                dns = DnsMessage.parse(f.buf, f.responseMessageOffset, f.responseMessageLength, includeAnswers);
            } else if (f.queryMessageOffset >= 0) {
                dns = DnsMessage.parse(f.buf, f.queryMessageOffset, f.queryMessageLength, false);
            } else {
                dns = null;
            }
        } catch (MalformedDnstapException e) {
            throw InputProcessingException.create("Couldn't decode dnstap frame: " + e.getMessage(), e, rawMessage);
        } catch (RuntimeException e) {
            // last line of defence: a parser bug fails only this frame, as an input failure, instead of
            // escaping into Graylog's processing
            throw InputProcessingException.create("Couldn't decode dnstap frame: " + e, e, rawMessage);
        }
        try {
            final Message m = toMessage(f, dns, parsedResponse, rawMessage);
            metrics.type(f.messageType);
            metrics.lag(m.getTimestamp().getMillis());
            return Optional.of(m);
        } catch (RuntimeException e) {
            throw InputProcessingException.create("Couldn't build a message from a dnstap frame: " + e, e, rawMessage);
        }
    }

    private Message toMessage(DnstapFrame f, DnsMessage dns, boolean parsedResponse, RawMessage raw) {
        final boolean response = f.isResponse();
        final String typeShort = DnstapFrame.typeShort(f.messageType);
        final String queryIp = ip(f.queryAddress);
        final String responseIp = ip(f.responseAddress);

        // event time: when the response was sent/received for *_RESPONSE, else when the query was
        DateTime ts;
        if (response && f.responseTimeSec >= 0) {
            ts = time(f.responseTimeSec, f.responseTimeNsec);
        } else if (f.queryTimeSec >= 0) {
            ts = time(f.queryTimeSec, f.queryTimeNsec);
        } else {
            ts = raw.getTimestamp();
        }
        // An event time more than MAX_CLOCK_SKEW_MS (7 days) from the receive time is not trusted: the receive
        // time becomes the timestamp and the event time goes into dnstap_event_time_suspect.
        DateTime suspect = null;
        if (raw.getTimestamp() != null && Math.abs(ts.getMillis() - raw.getTimestamp().getMillis()) > MAX_CLOCK_SKEW_MS) {
            suspect = ts;
            ts = raw.getTimestamp();
        }

        final String source = overrideSource != null ? overrideSource
                : f.identity != null && !f.identity.isEmpty() ? f.identity
                : raw.getRemoteAddress() != null ? InetAddresses.toAddrString(raw.getRemoteAddress().getAddress()) : "unknown";

        final StringBuilder text = new StringBuilder(96).append(typeShort).append(' ');
        if (queryIp != null) {
            text.append(queryIp).append('#').append(f.queryPort);
        }
        text.append(response ? " <- " : " -> ");
        if (dns != null && dns.qname != null) {
            text.append(dns.qname).append(' ').append(DnsMessage.className(dns.qclass)).append(' ').append(DnsMessage.typeName(dns.qtype));
        }
        final String answers = dns == null || dns.answers.isEmpty() ? null : cap(String.join(", ", dns.answers));
        if (parsedResponse && dns != null) {
            text.append(' ').append(DnsMessage.rcodeName(dns.rcode()));
            if (answers != null) {
                text.append(" [").append(answers).append(']');
            }
        }

        final FieldNames n = FieldNames.current();
        final Message m = messageFactory.createMessage(text.toString(), source, ts);
        m.addField(n.get(DNSTAP), true);
        m.addField(n.get(DNSTAP_TYPE), DnstapFrame.typeName(f.messageType));
        m.addField(n.get(DNSTAP_TYPE_SHORT), typeShort);
        addIfPresent(m, n.get(DNSTAP_VERSION), f.version);
        m.addField(n.get(SOCKET_FAMILY), DnstapFrame.familyName(f.socketFamily));
        m.addField(n.get(SOCKET_PROTOCOL), DnstapFrame.protocolName(f.socketProtocol));
        if (suspect != null) {
            m.addField(n.get(DNSTAP_EVENT_TIME_SUSPECT), suspect.toString());
        }
        addAddress(m, n.get(QUERY_IP), n.get(QUERY_PORT), queryIp, f.queryPort);
        addAddress(m, n.get(RESPONSE_IP), n.get(RESPONSE_PORT), responseIp, f.responsePort);
        // For client- and auth-side events the query address is the DNS client and the response address is this
        // server: name them like the fields parsed from BIND's text query log.
        if (f.isClientSide()) {
            addAddress(m, n.get(CLIENT_IP), n.get(CLIENT_PORT), queryIp, f.queryPort);
            addIfPresent(m, n.get(SERVER_IP), responseIp);
        }
        if (f.queryZone != null) {
            try {
                m.addField(n.get(QUERY_ZONE), DnsMessage.parse(zoneAsMessage(f.queryZone), 0, 12 + f.queryZone.length + 4, false).qname);
            } catch (MalformedDnstapException ignored) {
                // optional field: a bad zone name only drops query_zone
            }
        }
        if (dns != null) {
            m.addField(n.get(DNS_ID), dns.id);
            m.addField(n.get(DNS_OPCODE), DnsMessage.opcodeName(dns.opcode()));
            m.addField(n.get(DNS_FLAGS), dns.flagString());
            if (dns.qname != null) {
                m.addField(n.get(QNAME), dns.qname);
                m.addField(n.get(QTYPE), DnsMessage.typeName(dns.qtype));
                m.addField(n.get(QCLASS), DnsMessage.className(dns.qclass));
            }
            m.addField(n.get(DNS_SIZE), parsedResponse ? f.responseMessageLength : f.queryMessageLength);
            if (parsedResponse) {
                m.addField(n.get(RCODE), DnsMessage.rcodeName(dns.rcode()));
                m.addField(n.get(ANSWER_COUNT), dns.anCount);
                addIfPresent(m, n.get(ANSWERS), answers);
            }
        }
        if (response && f.queryTimeSec >= 0 && f.responseTimeSec >= 0) {
            final long us = (f.responseTimeSec - f.queryTimeSec) * 1_000_000L
                    + ((f.responseTimeNsec & 0xFFFFFFFFL) - (f.queryTimeNsec & 0xFFFFFFFFL)) / 1_000L;
            if (us >= 0) {
                m.addField(n.get(LATENCY_US), us);
            }
        }
        return m;
    }

    private static void addIfPresent(Message m, String field, Object value) {
        if (value != null) {
            m.addField(field, value);
        }
    }

    private static void addAddress(Message m, String ipField, String portField, String ip, int port) {
        if (ip != null) {
            m.addField(ipField, ip);
            if (port >= 0) {
                m.addField(portField, port);
            }
        }
    }

    private CodecMetrics metrics(RawMessage raw) {
        final Optional<String> inputId = raw.getInputIdOnCurrentNode();
        // without an input id (not from an input, e.g. in tests) the metrics go under "unknown"
        if (inputId.isPresent() && !RUNNING.contains(inputId.get())) {
            return DETACHED;
        }
        final String input = inputId.orElse("unknown");
        final ConcurrentMap<String, CodecMetrics> byInput = METRICS.computeIfAbsent(metricRegistry, r -> new ConcurrentHashMap<>());
        CodecMetrics m = byInput.get(input);
        if (m == null) {
            m = byInput.computeIfAbsent(input, id -> new CodecMetrics(metricRegistry, id));
            if (inputId.isPresent() && !RUNNING.contains(input)) {
                removeMetrics(metricRegistry, input);   // the input stopped while these were being registered
                return DETACHED;
            }
        }
        return m;
    }

    /** The input runs on this node from now on: its messages get metrics. */
    static void inputStarted(String inputId) {
        RUNNING.add(inputId);
    }

    /** The input stopped or was deleted: removes its metrics, and its messages still in Graylog's journal get none. */
    static void inputStopped(MetricRegistry registry, String inputId) {
        RUNNING.remove(inputId);
        removeMetrics(registry, inputId);
    }

    private static String base(String inputId) {
        return name(DnstapCodec.class, inputId);
    }

    /**
     * Removes this plugin's codec metrics of an input from the registry and the cache. Graylog removes an input's own
     * metrics when it stops, but not these, which the codec registers; without this, every input ever created on the
     * node would keep them until the JVM exits. Graylog's codec metrics under the same prefix ({@code parseTime},
     * {@code failures}) are left alone.
     */
    static void removeMetrics(MetricRegistry registry, String inputId) {
        final ConcurrentMap<String, CodecMetrics> byInput = METRICS.get(registry);
        if (byInput != null) {
            byInput.remove(inputId);
        }
        final String base = base(inputId);
        registry.removeMatching((metricName, metric) -> metricName.startsWith(base + ".types.")
                || metricName.equals(name(base, "eventLagMs"))
                || metricName.equals(name(base, "skipped"))
                || metricName.equals(name(base, "nonMessage")));
    }

    private static String cap(String s) {
        return s.length() > MAX_ANSWERS_TEXT ? s.substring(0, MAX_ANSWERS_TEXT) + "..." : s;
    }

    /** Wraps the wire-format query_zone name in a one-question DNS message, so DnsMessage can parse it. */
    private static byte[] zoneAsMessage(byte[] wireName) {
        final byte[] msg = new byte[12 + wireName.length + 4];
        msg[5] = 1; // qdcount = 1
        System.arraycopy(wireName, 0, msg, 12, wireName.length);
        return msg;
    }

    private static DateTime time(long sec, int nsec) {
        return new DateTime(sec * 1000L + (nsec & 0xFFFFFFFFL) / 1_000_000L, DateTimeZone.UTC);
    }

    private static String ip(byte[] a) {
        if (a == null || (a.length != 4 && a.length != 16)) {
            return null;
        }
        try {
            return InetAddresses.toAddrString(InetAddress.getByAddress(a));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static Set<String> skipTypes(String configured) {
        if (configured == null || configured.isBlank()) {
            return Set.of();
        }
        if (SKIP_TYPES.size() > MAX_CACHED_SKIP_LISTS) {
            SKIP_TYPES.clear();   // only edits of the setting add entries: keep the cache bounded
        }
        return SKIP_TYPES.computeIfAbsent(configured, DnstapCodec::parseTypes);
    }

    private static Set<String> parseTypes(String s) {
        return TYPE_LIST.splitToStream(s).map(t -> t.toUpperCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
    }

    @FactoryClass
    public interface Factory extends AbstractCodec.Factory<DnstapCodec> {
        @Override
        DnstapCodec create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            // No charset field: dnstap is binary, and a bad value would fail every message. Copied from the
            // parent's fields because ConfigurationRequest.removeField() is deprecated.
            final ConfigurationRequest cr = new ConfigurationRequest();
            super.getRequestedConfiguration().getFields().forEach((key, field) -> {
                if (!org.graylog2.plugin.inputs.codecs.Codec.Config.CK_CHARSET_NAME.equals(key)) {
                    cr.addField(field);
                }
            });
            cr.addField(new BooleanField(CK_INCLUDE_ANSWERS, "Include answers", true,
                    "For responses, add the answer records (e.g. \"A 192.0.2.1\") to the message and the 'answers' field."));
            cr.addField(new TextField(CK_SKIP_TYPES, "Skip message types", "",
                    "Comma-separated dnstap message types to drop at the input, as short codes (CQ, CR, AQ, AR, RQ, RR, FQ, FR, UQ, UR) "
                            + "or full names (CLIENT_RESPONSE). Empty = keep all.",
                    ConfigurationField.Optional.OPTIONAL));
            return cr;
        }
    }

    public static class Descriptor extends AbstractCodec.Descriptor {
        @Inject
        public Descriptor() {
            super(DnstapCodec.class.getAnnotation(Codec.class).displayName());
        }
    }
}
