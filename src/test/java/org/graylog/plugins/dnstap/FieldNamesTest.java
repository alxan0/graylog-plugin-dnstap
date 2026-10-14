/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Message;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.graylog.plugins.dnstap.FieldNames.Field.CLIENT_IP;
import static org.graylog.plugins.dnstap.FieldNames.Field.DNSTAP;
import static org.graylog.plugins.dnstap.FieldNames.Field.DNSTAP_TYPE_SHORT;
import static org.graylog.plugins.dnstap.FieldNames.Field.QCLASS;
import static org.graylog.plugins.dnstap.FieldNames.Field.QNAME;
import static org.graylog.plugins.dnstap.FieldNames.Field.QTYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/** The field name mapping file and the dnstap marker field. */
class FieldNamesTest {
    @TempDir
    Path dir;

    @AfterEach
    void restoreDefaults() {
        FieldNames.reload(null);
    }

    private FieldNames load(String content) throws Exception {
        final Path file = dir.resolve(FieldNames.FILE_NAME);
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return FieldNames.reload(file);
    }

    private static Message firstClientQuery() throws Exception {
        final DnstapCodec c = DnstapCodecTest.codec(Map.of());
        return Fixture.frames().stream().map(f -> DnstapCodecTest.decode(c, f).orElseThrow())
                .filter(x -> "CQ".equals(x.getField("dnstap_type_short"))).findFirst().orElseThrow();
    }

    @Test
    void defaultsAreUniqueAndMatchThePipelineNames() {
        final FieldNames n = FieldNames.defaults();
        assertEquals("dns_client_ip", n.get(CLIENT_IP));
        assertEquals("dns_query_name", n.get(QNAME));
        assertEquals("dns_query_type", n.get(QTYPE));
        assertEquals("dnstap", n.get(DNSTAP));
        final Set<String> seen = new HashSet<>();
        for (FieldNames.Field f : FieldNames.Field.values()) {
            assertTrue(seen.add(n.get(f)), "duplicate default name " + n.get(f));
            assertTrue(Message.validKey(n.get(f)) && !Message.RESERVED_FIELDS.contains(n.get(f)), n.get(f));
        }
    }

    @Test
    void missingFileMeansDefaults() {
        assertSame(FieldNames.defaults(), FieldNames.reload(dir.resolve("absent.conf")));
    }

    @Test
    void messagesAreMarkedForPipelines() throws Exception {
        assertEquals(Boolean.TRUE, firstClientQuery().getField("dnstap"));
    }

    @Test
    void renamesApplyToDecodedMessages() throws Exception {
        load("""
                # comment line
                dns_client_ip = client_ip
                  dns_query_name=qname   # trailing comment

                dnstap = from_dnstap
                """);
        final Message m = firstClientQuery();
        assertEquals("127.0.0.1", m.getField("client_ip"));
        assertEquals("ns1.lab.test", m.getField("qname"));
        assertEquals(Boolean.TRUE, m.getField("from_dnstap"));
        assertEquals("A", m.getField("dns_query_type"));   // not mapped: default name
        assertFalse(m.hasField("dns_client_ip"));
        assertFalse(m.hasField("dns_query_name"));
        assertFalse(m.hasField("dnstap"));
    }

    @Test
    void anyBadLineMeansTheWholeFileIsIgnored() throws Exception {
        for (String bad : new String[] {
                "no separator here",
                "not_a_field = x",
                "dns_query_type = bad name",
                "dns_query_type = dns.query.type",
                "dns_query_type = message",
                "dns_query_type = gl2_source_input",
                "dns_query_type =",
                "= qtype",
                "dns_query_type = q\u0007type",
                "qclass = dns_query_name",                    // two fields named dns_query_name
                "dns_query_type = qtype\ndns_query_type = qt",  // renamed twice
        }) {
            assertSame(FieldNames.defaults(), load("dns_client_ip = client_ip\n" + bad + "\n"), bad);
        }
    }

    @Test
    void namesAreCheckedAfterAllLinesSoOrderDoesNotMatter() throws Exception {
        final FieldNames reused = load("qclass = dns_query_name\ndns_query_name = query\n");
        assertEquals("query", reused.get(QNAME));
        assertEquals("dns_query_name", reused.get(QCLASS));
        final FieldNames swapped = load("dns_query_name = dns_query_type\ndns_query_type = dns_query_name\n");
        assertEquals("dns_query_type", swapped.get(QNAME));
        assertEquals("dns_query_name", swapped.get(QTYPE));
    }

    @Test
    void fileWithOnlyCommentsOrNothingMeansDefaults() throws Exception {
        assertSame(FieldNames.defaults(), load("# only a comment\n\n   \n"));
        assertSame(FieldNames.defaults(), load(""));
    }

    @Test
    void byteOrderMarkAndWindowsLineEndingsAreAccepted() throws Exception {
        final FieldNames n = load("\uFEFFdns_client_ip = client_ip\r\ndns_query_name = qname\r\n");
        assertEquals("client_ip", n.get(CLIENT_IP));
        assertEquals("qname", n.get(QNAME));
    }

    @Test
    void oversizedFileIsIgnored() throws Exception {
        final String line = "# padding padding padding padding padding padding padding padding padding\n";
        final String big = "dns_client_ip = client_ip\n" + line.repeat(FieldNames.MAX_FILE_BYTES / line.length() + 1);
        assertSame(FieldNames.defaults(), load(big));
    }

    @Test
    void fileThatIsNotUtf8IsIgnored() throws Exception {
        final Path file = dir.resolve(FieldNames.FILE_NAME);
        Files.write(file, new byte[] {'d', 'n', 's', 't', 'a', 'p', ' ', '=', ' ', 'x', (byte) 0xE9, '\n'});   // Latin-1
        assertSame(FieldNames.defaults(), FieldNames.reload(file));
        Files.write(file, new byte[] {(byte) 0xFF, (byte) 0xFE, 0, 0, 1, 2, 3});                              // binary
        assertSame(FieldNames.defaults(), FieldNames.reload(file));
    }

    @Test
    void directoryInsteadOfFileIsIgnored() throws Exception {
        final Path file = Files.createDirectory(dir.resolve(FieldNames.FILE_NAME));
        assertSame(FieldNames.defaults(), FieldNames.reload(file));
    }

    @Test
    @Timeout(10)
    void fifoIsIgnoredWithoutBlocking() throws Exception {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        final Path fifo = dir.resolve(FieldNames.FILE_NAME);
        assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());
        final ExecutorService ex = Executors.newSingleThreadExecutor(r -> {
            final Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        try {
            assertSame(FieldNames.defaults(), ex.submit(() -> FieldNames.reload(fifo)).get(5, TimeUnit.SECONDS));
        } finally {
            new RandomAccessFile(fifo.toFile(), "rw").close();   // opening read-write never blocks; frees a stuck reader
            ex.shutdownNow();
        }
    }

    @Test
    void namesReservedByOpenSearchOrManagedByGraylogAreRejected() throws Exception {
        for (String name : new String[] {"_routing", "_ignored", "_version", "_seq_no", "_primary_term", "_field_names",
                "_doc_count", "_tier", "_nested_path", "streams", "failed_message_streams", "x".repeat(101)}) {
            assertSame(FieldNames.defaults(), load("dnstap_type_short = " + name + "\n"), name);
        }
        assertEquals("x".repeat(100), load("dnstap_type_short = " + "x".repeat(100) + "\n").get(DNSTAP_TYPE_SHORT));
    }
}
