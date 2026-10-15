/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Names of the message fields the codec writes.
 * <p>
 * The defaults can be renamed per Graylog node with {@value #FILE_NAME} next to the plugin jar, one
 * {@code default_name = new_name} per line. The file is read when a Dnstap input starts (or when the first message is
 * decoded, if that comes first), so a change applies after restarting the input. A file with any problem (an unknown or
 * repeated field, an invalid or reserved name, two fields with the same name, not a regular file, more than
 * {@value #MAX_FILE_BYTES} bytes, not UTF-8) is ignored as a whole: its problems are logged and the default names apply.
 * <p>
 * Instances are immutable; the codec reads the current one once per message.
 */
final class FieldNames {
    static final String FILE_NAME = "dnstap-fields.conf";
    static final int MAX_FILE_BYTES = 64 * 1024;
    private static final int MAX_NAME_LENGTH = 100;
    private static final int MAX_LOGGED_PROBLEMS = 20;

    private static final Logger LOG = LoggerFactory.getLogger(FieldNames.class);
    private static final FieldNames DEFAULTS = new FieldNames(defaultNames());
    private static final Map<String, Field> BY_DEFAULT_NAME = Arrays.stream(Field.values())
            .collect(Collectors.toUnmodifiableMap(f -> f.defaultName, Function.identity()));

    private static volatile FieldNames current;

    /** Every field the codec writes besides Graylog's message, source and timestamp, with its default name. */
    enum Field {
        DNSTAP("dnstap"),
        DNSTAP_TYPE("dnstap_type"),
        DNSTAP_TYPE_SHORT("dnstap_type_short"),
        DNSTAP_VERSION("dnstap_version"),
        DNSTAP_EVENT_TIME_SUSPECT("dnstap_event_time_suspect"),
        SOCKET_FAMILY("socket_family"),
        SOCKET_PROTOCOL("socket_protocol"),
        QUERY_IP("query_ip"),
        QUERY_PORT("query_port"),
        RESPONSE_IP("response_ip"),
        RESPONSE_PORT("response_port"),
        CLIENT_IP("dns_client_ip"),
        CLIENT_PORT("client_port"),
        SERVER_IP("server_ip"),
        QUERY_ZONE("query_zone"),
        DNS_ID("dns_id"),
        DNS_OPCODE("dns_opcode"),
        DNS_FLAGS("dns_flags"),
        DNS_SIZE("dns_size"),
        QNAME("dns_query_name"),
        QTYPE("dns_query_type"),
        QCLASS("qclass"),
        EDNS("dns_edns"),
        EDNS_VERSION("dns_edns_version"),
        DO_BIT("dns_do_bit"),
        ECS("dns_ecs"),
        RCODE("rcode"),
        ANSWER_COUNT("answer_count"),
        ANSWERS("answers"),
        LATENCY_US("latency_us");

        final String defaultName;

        Field(String defaultName) {
            this.defaultName = defaultName;
        }
    }

    private final Map<Field, String> names;   // an EnumMap, never modified after construction

    private FieldNames(Map<Field, String> names) {
        this.names = names;
    }

    String get(Field field) {
        return names.get(field);
    }

    /** The names in use, loading the file on first use. */
    static FieldNames current() {
        final FieldNames n = current;
        return n != null ? n : loadOnce();
    }

    private static synchronized FieldNames loadOnce() {
        return current != null ? current : reload();
    }

    /** Re-reads {@value #FILE_NAME} from the plugin directory; called when a Dnstap input starts. */
    static FieldNames reload() {
        return reload(pluginDirectoryFile());
    }

    /** Uses the names from {@code file}, or the defaults when it is null, missing or invalid. */
    static synchronized FieldNames reload(Path file) {
        final FieldNames n = file == null ? DEFAULTS : load(file);
        current = n;
        return n;
    }

    static FieldNames defaults() {
        return DEFAULTS;
    }

    private static FieldNames load(Path file) {
        if (Files.notExists(file)) {
            LOG.info("No {}, using the default field names", file);
            return DEFAULTS;
        }
        // opening a FIFO or device could block the input's start, and the lock with it, for good
        if (!Files.isRegularFile(file)) {
            LOG.warn("{} ignored, using the default field names: not a regular file", file);
            return DEFAULTS;
        }
        final List<String> lines;
        try (InputStream in = Files.newInputStream(file)) {
            final byte[] bytes = in.readNBytes(MAX_FILE_BYTES + 1);
            if (bytes.length > MAX_FILE_BYTES) {
                LOG.warn("{} ignored, using the default field names: larger than {} bytes", file, MAX_FILE_BYTES);
                return DEFAULTS;
            }
            // strict decoding: a file that isn't UTF-8 fails instead of turning into replacement characters
            lines = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString().lines().toList();
        } catch (NoSuchFileException e) {
            LOG.info("No {}, using the default field names", file);
            return DEFAULTS;
        } catch (IOException e) {
            LOG.warn("{} ignored, using the default field names: can't read it as UTF-8 text ({})", file, e.toString());
            return DEFAULTS;
        }
        final List<String> problems = new ArrayList<>();
        final Map<Field, String> renames = new EnumMap<>(Field.class);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (i == 0 && line.startsWith("\uFEFF")) {
                line = line.substring(1);   // byte order mark written by some editors
            }
            final int comment = line.indexOf('#');
            if (comment >= 0) {
                line = line.substring(0, comment);
            }
            if (line.isBlank()) {
                continue;
            }
            final int eq = line.indexOf('=');
            final String from = eq < 0 ? "" : line.substring(0, eq).strip();
            final String to = eq < 0 ? "" : line.substring(eq + 1).strip();
            final Field field = BY_DEFAULT_NAME.get(from);
            final String problem = eq < 0 ? "expected 'default_name = new_name'"
                    : field == null ? "unknown field '" + from + "'"
                    : !validName(to) ? "invalid or reserved field name '" + to + "'"
                    : renames.containsKey(field) ? "'" + from + "' is renamed more than once"
                    : null;
            if (problem == null) {
                renames.put(field, to);
            } else {
                problems.add("line " + (i + 1) + ": " + problem);
            }
        }
        final Map<Field, String> names = defaultNames();
        names.putAll(renames);
        // each field needs a name of its own; checked on the result, so the order of the lines doesn't matter
        final Map<String, Field> owners = new HashMap<>();
        for (Map.Entry<Field, String> e : names.entrySet()) {
            final Field other = owners.putIfAbsent(e.getValue(), e.getKey());
            if (other != null) {
                problems.add("'" + e.getValue() + "' would name both " + other.defaultName + " and " + e.getKey().defaultName);
            }
        }
        if (!problems.isEmpty()) {
            // the problems quote the file: no control characters in the log
            problems.stream().limit(MAX_LOGGED_PROBLEMS).forEach(p -> LOG.warn("{} {}", file, FstrmFrameDecoder.printable(p)));
            LOG.warn("{} ignored because of {} problem(s), using the default field names", file, problems.size());
            return DEFAULTS;
        }
        LOG.info("Field names from {}: {}", file, renames.isEmpty() ? "defaults" : renames.entrySet().stream()
                .map(e -> e.getKey().defaultName + " = " + e.getValue()).collect(Collectors.joining(", ")));
        return renames.isEmpty() ? DEFAULTS : new FieldNames(names);
    }

    /**
     * A name Graylog accepts for a message field and can index, and not one it manages itself. No dots: Graylog
     * stores "a.b" as "a_b" and drops one of two fields that end up with the same name. No leading underscore:
     * OpenSearch reserves those (_routing, _version, ...), and a message carrying one fails to index.
     */
    private static boolean validName(String name) {
        return !name.isEmpty() && name.length() <= MAX_NAME_LENGTH && Message.validKey(name)
                && name.indexOf('.') < 0 && name.charAt(0) != '_'
                && !Message.RESERVED_FIELDS.contains(name) && !name.startsWith(Message.INTERNAL_FIELD_PREFIX)
                && !Message.FIELD_STREAMS.equals(name) && !Message.FIELD_FAILED_MESSAGE_STREAMS.equals(name);
    }

    private static Map<Field, String> defaultNames() {
        final Map<Field, String> names = new EnumMap<>(Field.class);
        for (Field f : Field.values()) {
            names.put(f, f.defaultName);
        }
        return names;
    }

    /** {@value #FILE_NAME} in the directory of the plugin jar, i.e. Graylog's plugin directory; null if unknown. */
    private static Path pluginDirectoryFile() {
        try {
            final CodeSource source = FieldNames.class.getProtectionDomain().getCodeSource();
            if (source != null && source.getLocation() != null) {
                return Path.of(source.getLocation().toURI()).resolveSibling(FILE_NAME);
            }
        } catch (URISyntaxException | RuntimeException e) {
            LOG.warn("Couldn't locate the plugin directory, using the default field names: {}", e.toString());
            return null;
        }
        LOG.warn("Couldn't locate the plugin directory, using the default field names");
        return null;
    }
}
