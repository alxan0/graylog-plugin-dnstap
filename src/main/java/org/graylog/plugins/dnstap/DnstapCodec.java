/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.Histogram;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
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
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Turns one dnstap protobuf payload (one Frame Streams data frame) into one Graylog message.
 * <p>
 * Field names line up with what a pipeline extracts from BIND's text query log (client_ip, client_port,
 * qname, qclass, qtype, server_ip), so the two transports can be compared and searched the same way.
 */
@Codec(name = "dnstap", displayName = "Dnstap")
public class DnstapCodec extends AbstractCodec {
    static final String CK_INCLUDE_ANSWERS = "include_answers";
    static final String CK_SKIP_TYPES = "skip_message_types";

    private final MessageFactory messageFactory;
    private final MetricRegistry metricRegistry;
    static final int MAX_ANSWERS_TEXT = 8192;
    static final long MAX_CLOCK_SKEW_MS = 7L * 24 * 3600 * 1000;
    // Graylog creates a NEW codec instance for every message (DecodingProcessor: factory.create(raw.getCodecConfig())),
    // so everything that should be computed once lives in static caches: per-input metrics, parsed "skip" lists.
    private static final ConcurrentMap<MetricRegistry, ConcurrentMap<String, CodecMetrics>> METRICS = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Set<String>> SKIP_TYPES = new ConcurrentHashMap<>();
    private final boolean includeAnswers;
    private final Set<String> skipTypes;
    private final String overrideSource;

    /**
     * Per-input codec metrics, next to Graylog's own codec metrics for the input
     * ({@code org.graylog.plugins.dnstap.DnstapCodec.<input id>.parseTime / .failures}):
     * {@code eventLagMs} (processing time minus the DNS event's time: grows when the relay, BIND's queue or Graylog's
     * journal buffer), {@code skipped} (dropped by "Skip message types"), {@code nonMessage}, {@code types.<CQ|CR|...>}.
     */
    private static final class CodecMetrics {
        static final int LAG_SAMPLE_EVERY = 32;   // the lag histogram's reservoir is synchronised: sample it
        final String inputId;
        final Histogram eventLagMs;
        final Meter skipped;
        final Meter nonMessage;
        final Meter[] types = new Meter[16];      // indexed by dnstap message type (1..14)
        final MetricRegistry registry;
        final String base;
        private final java.util.concurrent.atomic.AtomicInteger sample = new java.util.concurrent.atomic.AtomicInteger();

        CodecMetrics(MetricRegistry registry, String inputId) {
            this.registry = registry;
            this.inputId = inputId;
            this.base = name(DnstapCodec.class, inputId);
            eventLagMs = registry.histogram(name(base, "eventLagMs"));
            skipped = registry.meter(name(base, "skipped"));
            nonMessage = registry.meter(name(base, "nonMessage"));
        }

        void type(int messageType) {
            final int i = messageType > 0 && messageType < types.length ? messageType : 0;
            Meter m = types[i];
            if (m == null) {
                m = registry.meter(name(base, "types", i == 0 ? "other" : DnstapFrame.typeShort(i)));
                types[i] = m;
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
        final String skip = configuration.getString(CK_SKIP_TYPES, "");
        this.skipTypes = skip == null || skip.isBlank() ? Set.of() : SKIP_TYPES.computeIfAbsent(skip, DnstapCodec::parseTypes);
        this.overrideSource = configuration.stringIsSet(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_OVERRIDE_SOURCE)
                ? configuration.getString(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_OVERRIDE_SOURCE) : null;
    }

    @Override
    public Optional<Message> decodeSafe(@Nonnull RawMessage rawMessage) {
        final DnstapFrame f;
        final DnsMessage dns;
        final boolean parsedResponse;     // the DNS message parsed is the response (else the query, or none)
        final CodecMetrics metrics = metrics(rawMessage);
        try {
            f = DnstapFrame.parse(rawMessage.getPayload());
            if (f.dnstapType != DnstapFrame.DNSTAP_TYPE_MESSAGE || !f.hasMessage) {
                metrics.nonMessage.mark();
                return Optional.empty(); // not a DNS message (dnstap reserves other types)
            }
            if (!skipTypes.isEmpty() && (skipTypes.contains(DnstapFrame.typeShort(f.messageType))
                    || skipTypes.contains(DnstapFrame.typeName(f.messageType)))) {
                metrics.skipped.mark();
                return Optional.empty();
            }
            final boolean useResponse = f.isResponse() && f.responseMessageOffset >= 0;
            parsedResponse = useResponse;
            if (useResponse) {
                dns = DnsMessage.parse(f.buf, f.responseMessageOffset, f.responseMessageLength, includeAnswers);
            } else if (f.queryMessageOffset >= 0) {
                dns = DnsMessage.parse(f.buf, f.queryMessageOffset, f.queryMessageLength, false);
            } else {
                dns = null;
            }
        } catch (MalformedDnstapException e) {
            throw InputProcessingException.create("Couldn't decode dnstap frame: " + e.getMessage(), rawMessage);
        } catch (RuntimeException e) {
            // last line of defence: a parser bug must surface as an input failure for this one frame,
            // not as an unexpected exception in Graylog's processing
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

        // Event time: when the response was sent/received for *_RESPONSE, else when the query was.
        DateTime ts;
        if (response && f.responseTimeSec >= 0) ts = time(f.responseTimeSec, f.responseTimeNsec);
        else if (f.queryTimeSec >= 0) ts = time(f.queryTimeSec, f.queryTimeNsec);
        else ts = raw.getTimestamp();
        // sanity: an event time more than 7 days away from when it was received is not trusted as the timestamp
        DateTime suspect = null;
        if (raw.getTimestamp() != null && Math.abs(ts.getMillis() - raw.getTimestamp().getMillis()) > MAX_CLOCK_SKEW_MS) {
            suspect = ts;
            ts = raw.getTimestamp();
        }

        final String source = overrideSource != null ? overrideSource
                : f.identity != null && !f.identity.isEmpty() ? f.identity
                : raw.getRemoteAddress() != null ? InetAddresses.toAddrString(raw.getRemoteAddress().getAddress()) : "unknown";

        final StringBuilder text = new StringBuilder(96).append(typeShort).append(' ');
        if (queryIp != null) text.append(queryIp).append('#').append(f.queryPort);
        text.append(response ? " <- " : " -> ");
        if (dns != null && dns.qname != null) {
            text.append(dns.qname).append(' ').append(DnsMessage.className(dns.qclass)).append(' ').append(DnsMessage.typeName(dns.qtype));
        }
        final String answers = dns == null || dns.answers.isEmpty() ? null : cap(String.join(", ", dns.answers));
        if (parsedResponse && dns != null) {
            text.append(' ').append(DnsMessage.rcodeName(dns.rcode()));
            if (answers != null) text.append(" [").append(answers).append(']');
        }

        final Message m = messageFactory.createMessage(text.toString(), source, ts);
        m.addField("dnstap_type", DnstapFrame.typeName(f.messageType));
        m.addField("dnstap_type_short", typeShort);
        if (f.version != null) m.addField("dnstap_version", f.version);
        m.addField("socket_family", DnstapFrame.familyName(f.socketFamily));
        m.addField("socket_protocol", DnstapFrame.protocolName(f.socketProtocol));
        if (suspect != null) m.addField("dnstap_event_time_suspect", suspect.toString());
        if (queryIp != null) { m.addField("query_ip", queryIp); if (f.queryPort >= 0) m.addField("query_port", f.queryPort); }
        if (responseIp != null) { m.addField("response_ip", responseIp); if (f.responsePort >= 0) m.addField("response_port", f.responsePort); }
        // For client- and auth-side events the query address is the DNS client and the response address is this
        // server: name them like the fields parsed from BIND's text query log.
        if (f.messageType == 1 || f.messageType == 2 || f.messageType == 5 || f.messageType == 6 || f.messageType == 13 || f.messageType == 14) {
            if (queryIp != null) { m.addField("client_ip", queryIp); if (f.queryPort >= 0) m.addField("client_port", f.queryPort); }
            if (responseIp != null) m.addField("server_ip", responseIp);
        }
        if (f.queryZone != null) {
            try {
                m.addField("query_zone", DnsMessage.parse(zoneAsMessage(f.queryZone), 0, 12 + f.queryZone.length + 4, false).qname);
            } catch (MalformedDnstapException ignored) {
                // optional field
            }
        }
        if (dns != null) {
            m.addField("dns_id", dns.id);
            m.addField("dns_opcode", DnsMessage.opcodeName(dns.opcode()));
            m.addField("dns_flags", dns.flagString());
            if (dns.qname != null) {
                m.addField("qname", dns.qname);
                m.addField("qtype", DnsMessage.typeName(dns.qtype));
                m.addField("qclass", DnsMessage.className(dns.qclass));
            }
            m.addField("dns_size", parsedResponse ? f.responseMessageLength : f.queryMessageLength);
            if (parsedResponse) {
                m.addField("rcode", DnsMessage.rcodeName(dns.rcode()));
                m.addField("answer_count", dns.anCount);
                if (answers != null) m.addField("answers", answers);
            }
        }
        if (response && f.queryTimeSec >= 0 && f.responseTimeSec >= 0) {
            final long us = (f.responseTimeSec - f.queryTimeSec) * 1_000_000L
                    + ((f.responseTimeNsec & 0xFFFFFFFFL) - (f.queryTimeNsec & 0xFFFFFFFFL)) / 1_000L;
            if (us >= 0) m.addField("latency_us", us);
        }
        return m;
    }

    private CodecMetrics metrics(RawMessage raw) {
        final String input = raw.getInputIdOnCurrentNode().orElse("unknown");
        final ConcurrentMap<String, CodecMetrics> byInput = METRICS.computeIfAbsent(metricRegistry, r -> new ConcurrentHashMap<>());
        final CodecMetrics m = byInput.get(input);
        return m != null ? m : byInput.computeIfAbsent(input, id -> new CodecMetrics(metricRegistry, id));
    }

    private static String cap(String s) {
        return s.length() > MAX_ANSWERS_TEXT ? s.substring(0, MAX_ANSWERS_TEXT) + "…" : s;
    }

    /** query_zone is a wire-format name; wrap it in a fake 1-question message to reuse the name parser. */
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
        if (a == null || (a.length != 4 && a.length != 16)) return null;
        try {
            return InetAddresses.toAddrString(InetAddress.getByAddress(a));
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static Set<String> parseTypes(String s) {
        final Set<String> out = new HashSet<>();
        for (String t : s.split("[,\\s]+")) {
            if (!t.isBlank()) out.add(t.trim().toUpperCase(Locale.ROOT));
        }
        return Set.copyOf(out);
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
            final ConfigurationRequest cr = super.getRequestedConfiguration();
            // dnstap is binary protobuf: a text encoding means nothing here (and a bad value would fail every message)
            cr.removeField(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_CHARSET_NAME);
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
