/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** EDNS fields of queries: dns_edns, dns_edns_version, dns_do_bit and dns_ecs. */
class EdnsTest {
    private static final int CLIENT_QUERY = 5;
    private static final int CLIENT_RESPONSE = 6;
    private static final int QUERY_MESSAGE = 10;
    private static final int RESPONSE_MESSAGE = 14;

    // header with rd and the given an/ar counts, then "www.example.com IN A"
    private static String query(int an, int ar) {
        return "abcd0100" + "0001" + String.format("%04x", an) + "0000" + String.format("%04x", ar)
                + "03777777076578616d706c6503636f6d00" + "00010001";
    }

    private static final String ECS = "0008" + "0007" + "0001" + "18" + "00" + "c00002";   // 192.0.2.0/24
    private static final String COOKIE = "000a" + "0008" + "0102030405060708";

    // OPT record: root owner, type 41, payload size 1232, extended rcode 0, the given version and flags, options
    private static String opt(int version, int flags, String options) {
        return "00" + "0029" + "04d0" + "00" + String.format("%02x%04x", version, flags)
                + String.format("%04x", options.length() / 2) + options;
    }

    private static Message decode(int type, int field, String hex) {
        return DnstapCodecTest.codec(Map.of()).decodeSafe(new RawMessage(
                FuzzTestAccess.dnstap(type, field, HexFormat.of().parseHex(hex)), new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
    }

    @Test
    void doBitClientSubnetAndVersionAreRead() {
        final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, query(0, 1) + opt(0, 0x8000, ECS + COOKIE));
        assertEquals(Boolean.TRUE, m.getField("dns_edns"));
        assertEquals(0, ((Number) m.getField("dns_edns_version")).intValue());
        assertEquals(Boolean.TRUE, m.getField("dns_do_bit"));
        assertEquals(Boolean.TRUE, m.getField("dns_ecs"));
        assertEquals("www.example.com", m.getField("dns_query_name"));
    }

    @Test
    void ednsWithoutFlagsOrOptions() {
        final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, query(0, 1) + opt(1, 0, COOKIE));
        assertEquals(Boolean.TRUE, m.getField("dns_edns"));
        assertEquals(1, ((Number) m.getField("dns_edns_version")).intValue());
        assertEquals(Boolean.FALSE, m.getField("dns_do_bit"));
        assertEquals(Boolean.FALSE, m.getField("dns_ecs"));
    }

    @Test
    void queryWithoutEdns() {
        final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, query(0, 0));
        assertEquals(Boolean.FALSE, m.getField("dns_edns"));
        assertNull(m.getField("dns_edns_version"));
        assertEquals(Boolean.FALSE, m.getField("dns_do_bit"));
        assertEquals(Boolean.FALSE, m.getField("dns_ecs"));
    }

    @Test
    void optIsFoundBehindOtherRecords() {
        final String answer = "c00c" + "0001" + "0001" + "00000e10" + "0004" + "c0000201";   // www.example.com A
        final String tsigLike = "00" + "00fa" + "00ff" + "00000000" + "0002" + "0000";      // a record before OPT
        final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, query(1, 2) + answer + tsigLike + opt(0, 0x8000, ""));
        assertEquals(Boolean.TRUE, m.getField("dns_edns"));
        assertEquals(Boolean.TRUE, m.getField("dns_do_bit"));
    }

    @Test
    void malformedAdditionalSectionDropsOnlyTheEdnsFields() {
        for (String broken : List.of(
                query(0, 1) + "00" + "0029" + "04d0",                       // OPT cut after its class
                query(0, 1) + opt(0, 0x8000, "").substring(0, 18) + "0010",   // rdlen past the end
                query(0, 1) + "c0ff" + "0029",                               // owner name pointer, then cut
                query(0, 3) + opt(0, 0x8000, ""))) {                          // arcount 3, but the walk ends at OPT
            final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, broken);
            assertEquals("www.example.com", m.getField("dns_query_name"), broken);
            assertTrue(m.hasField("dns_edns"), broken);
        }
        final Message cut = decode(CLIENT_QUERY, QUERY_MESSAGE, query(0, 1) + "00" + "0029" + "04d0");
        assertEquals(Boolean.FALSE, cut.getField("dns_edns"));
        assertEquals(Boolean.FALSE, cut.getField("dns_do_bit"));
        // an option whose length runs past the rdata: EDNS is there, the option list just ends
        final Message badOption = decode(CLIENT_QUERY, QUERY_MESSAGE, query(0, 1) + opt(0, 0, "00080020"));
        assertEquals(Boolean.TRUE, badOption.getField("dns_edns"));
        assertEquals(Boolean.FALSE, badOption.getField("dns_ecs"));
    }

    @Test
    void responsesCarryNoEdnsFields() {
        final String response = "abcd8180" + "0001" + "0000" + "0000" + "0001"
                + "03777777076578616d706c6503636f6d00" + "00010001" + opt(0, 0x8000, "");
        final Message m = decode(CLIENT_RESPONSE, RESPONSE_MESSAGE, response);
        assertFalse(m.hasField("dns_edns"));
        assertFalse(m.hasField("dns_do_bit"));
        assertFalse(m.hasField("dns_ecs"));
    }

    @Test
    void bindCaptureQueriesCarryEdns() throws Exception {
        final DnstapCodec c = DnstapCodecTest.codec(Map.of());
        final List<Message> cqs = Fixture.frames().stream().map(f -> DnstapCodecTest.decode(c, f).orElseThrow())
                .filter(x -> "CQ".equals(x.getField("dnstap_type_short"))).toList();
        for (String f : new String[] {"dns_edns", "dns_do_bit", "dns_ecs"}) {
            assertTrue(cqs.stream().allMatch(m -> m.hasField(f)), f);
        }
        assertTrue(cqs.stream().anyMatch(m -> Boolean.TRUE.equals(m.getField("dns_edns"))), "dig sends EDNS by default");
    }

    @Test
    void manyRecordsBeforeOptStayCheap() {
        // a 65 KB query with 5000 records ahead of its OPT record: walked as wire bytes, linear in the size
        final String rr = "c00c" + "0010" + "0001" + "00000000" + "0001" + "00";
        final String hex = query(0, 5001) + rr.repeat(5000) + opt(0, 0x8000, ECS);
        for (int warm = 0; warm < 20; warm++) {
            decode(CLIENT_QUERY, QUERY_MESSAGE, hex);
        }
        final long t0 = System.nanoTime();
        final Message m = decode(CLIENT_QUERY, QUERY_MESSAGE, hex);
        final long ms = (System.nanoTime() - t0) / 1_000_000;
        assertEquals(Boolean.TRUE, m.getField("dns_ecs"));
        assertTrue(ms < 50, ms + " ms");
    }

    @Test
    void randomSectionsNeverBreakTheMessage() {
        // A valid header and question followed by random record counts and random section bytes, some with an OPT
        // record: the EDNS walk must never throw, never read past the message, and leave consistent fields.
        final Random r = new Random(Long.getLong("fuzz.seed", 20261014L));
        final byte[] question = HexFormat.of().parseHex("03777777076578616d706c6503636f6d0000010001");
        final int iterations = Integer.getInteger("fuzz.iterations", 300_000) / 3;
        for (int i = 0; i < iterations; i++) {
            final byte[] tail = new byte[r.nextInt(64)];
            r.nextBytes(tail);
            if (r.nextBoolean() && tail.length >= 11) {
                // an OPT record header at a random place in the tail
                final int at = r.nextInt(tail.length - 10);
                tail[at] = 0;
                tail[at + 1] = 0;
                tail[at + 2] = 41;
            }
            final byte[] msg = new byte[12 + question.length + tail.length];
            msg[5] = 1;                                               // qdcount 1
            msg[6] = (byte) r.nextInt(3);                             // ancount 0..515
            msg[7] = (byte) r.nextInt(4);
            msg[9] = (byte) r.nextInt(4);                             // nscount 0..3
            msg[10] = (byte) (r.nextInt(8) == 0 ? 0xFF : 0);          // arcount 0..4, or 65280..65284 (1 in 8)
            msg[11] = (byte) r.nextInt(5);
            System.arraycopy(question, 0, msg, 12, question.length);
            System.arraycopy(tail, 0, msg, 12 + question.length, tail.length);
            final DnsMessage m = DnsMessage.parse(msg, 0, msg.length, false, true);
            assertEquals("www.example.com", m.qname);
            assertTrue(m.ednsVersion >= -1 && m.ednsVersion <= 255);
            if (m.ednsVersion < 0) {
                assertFalse(m.dnssecOk || m.clientSubnet, "EDNS flags without an OPT record");
            }
        }
    }
}
