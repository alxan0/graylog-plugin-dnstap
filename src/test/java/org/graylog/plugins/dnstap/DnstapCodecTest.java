/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Decoding of the BIND capture matches dnstap-read's view of it. */
class DnstapCodecTest {
    static DnstapCodec codec(Map<String, Object> cfg) {
        return new DnstapCodec(new Configuration(cfg), TestMessages.factory(), new com.codahale.metrics.MetricRegistry());
    }

    static Optional<Message> decode(DnstapCodec c, byte[] frame) {
        return c.decodeSafe(new RawMessage(frame, new InetSocketAddress("10.251.1.53", 40000)));
    }

    @Test
    void decodesAllFramesWithTheSameTypeCountsAsDnstapRead() throws Exception {
        final DnstapCodec c = codec(Map.of());
        final Map<String, Integer> counts = new TreeMap<>();
        for (byte[] f : Fixture.frames()) {
            final Message m = decode(c, f).orElseThrow();
            counts.merge((String) m.getField("dnstap_type_short"), 1, Integer::sum);
        }
        // from: dnstap-read dnstap.fstrm.0 | awk '{print $3}' | sort | uniq -c
        assertEquals(Map.of("AQ", 57, "AR", 13, "CQ", 223, "CR", 230, "FQ", 27, "FR", 27, "UQ", 26, "UR", 26), counts);
    }

    @Test
    void firstClientQueryMatchesDnstapRead() throws Exception {
        // dnstap-read (prints local time, UTC+3):
        // 10-Oct-2026 17:17:04.145 CQ 127.0.0.1:45320 -> 127.0.0.1:53 UDP 53b ns1.lab.test/IN/A
        final DnstapCodec c = codec(Map.of());
        final Message m = Fixture.frames().stream().map(f -> decode(c, f).orElseThrow())
                .filter(x -> "CQ".equals(x.getField("dnstap_type_short"))).findFirst().orElseThrow();
        assertEquals("ns1", m.getSource());
        assertEquals("127.0.0.1", m.getField("dns_client_ip"));
        assertEquals(45320, ((Number) m.getField("dns_client_port")).intValue());
        assertEquals("127.0.0.1", m.getField("dns_server_ip"));
        assertEquals("UDP", m.getField("dns_socket_protocol"));
        assertEquals(53, ((Number) m.getField("dns_size")).intValue());
        assertEquals("ns1.lab.test", m.getField("dns_query_name"));
        assertEquals("IN", m.getField("dns_query_class"));
        assertEquals("A", m.getField("dns_query_type"));
        assertEquals("BIND 9.20.29-1~deb13u1-Debian", m.getField("dnstap_version"));
        assertEquals("CQ 127.0.0.1#45320 -> ns1.lab.test IN A", m.getMessage());
        assertEquals("2026-10-10T14:17:04.145Z", m.getTimestamp().toString());
    }

    @Test
    void responsesCarryRcodeAnswersAndLatency() throws Exception {
        final DnstapCodec c = codec(Map.of());
        final List<Message> crs = Fixture.frames().stream().map(f -> decode(c, f).orElseThrow())
                .filter(x -> "CR".equals(x.getField("dnstap_type_short"))).toList();
        assertTrue(crs.stream().anyMatch(m -> "NXDOMAIN".equals(m.getField("dns_rcode"))), "NXDOMAIN responses (nx action)");
        assertTrue(crs.stream().anyMatch(m -> "REFUSED".equals(m.getField("dns_rcode"))), "REFUSED responses (client2)");
        final Message www = crs.stream().filter(m -> "www.lab.test".equals(m.getField("dns_query_name")) && "A".equals(m.getField("dns_query_type"))
                && "NOERROR".equals(m.getField("dns_rcode"))).findFirst().orElseThrow();
        assertTrue(((String) www.getField("dns_answers")).contains("A 10.251."), www.getMessage());
        assertTrue(www.getFields().containsKey("dns_latency_us"));
    }

    @Test
    void skipTypesDropsMessagesAtTheCodec() throws Exception {
        final DnstapCodec c = codec(Map.of(DnstapCodec.CK_SKIP_TYPES, "CR, AQ,AR,FQ,FR,UQ,UR"));
        final long kept = Fixture.frames().stream().map(f -> decode(c, f)).filter(Optional::isPresent).count();
        assertEquals(223, kept);   // only the CQ frames
    }
}
