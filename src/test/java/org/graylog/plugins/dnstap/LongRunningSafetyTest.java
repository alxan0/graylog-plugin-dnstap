/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.inputs.codecs.Codec;
import org.graylog2.plugin.inputs.transports.AbstractTcpTransport;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Long-running safety: metric cleanup, TCP keepalive, codec config fields, log-line forging, label escaping. */
class LongRunningSafetyTest {
    private static final String BASE = "org.graylog.plugins.dnstap.DnstapCodec.unknown";   // no input id in unit tests

    @Test
    void codecMetricsAreRemovedWhenTheInputStops() throws Exception {
        final MetricRegistry r = new MetricRegistry();
        r.counter(BASE + ".failures");   // Graylog's own codec metric under the same prefix: must survive
        for (byte[] f : Fixture.frames()) {
            codec(r).decodeSafe(new RawMessage(f, new InetSocketAddress("10.0.0.1", 1)));
        }
        assertTrue(r.getNames().contains(BASE + ".types.CQ"));

        DnstapCodec.removeMetrics(r, "unknown");

        assertEquals(java.util.Set.of(BASE + ".failures"), r.getNames(), "only Graylog's metric is left");
        codec(r).decodeSafe(new RawMessage(Fixture.frames().get(0), new InetSocketAddress("10.0.0.1", 1)));
        assertTrue(r.getNames().contains(BASE + ".eventLagMs"), "a restarted input registers its metrics again");
    }

    @Test
    void tcpKeepaliveIsOnByDefault() {
        final ConfigurationRequest cr = new FstrmTransport.Config().getRequestedConfiguration();
        assertEquals(Boolean.TRUE, cr.getField(AbstractTcpTransport.CK_TCP_KEEPALIVE).getDefaultValue());
        assertEquals(FstrmTransport.DEFAULT_PORT, ((Number) cr.getField("port").getDefaultValue()).intValue());
    }

    @Test
    void codecConfigKeepsTheParentFieldsExceptTheEncoding() {
        final ConfigurationRequest cr = new DnstapCodec.Config().getRequestedConfiguration();
        assertTrue(cr.containsField(Codec.Config.CK_OVERRIDE_SOURCE));
        assertTrue(cr.containsField(DnstapCodec.CK_INCLUDE_ANSWERS));
        assertFalse(cr.containsField(Codec.Config.CK_CHARSET_NAME));
    }

    @Test
    void senderChosenContentTypesCannotForgeLogLines() {
        assertEquals("protobuf:x??FAKE LOG LINE", FstrmFrameDecoder.printable("protobuf:x\r\nFAKE LOG LINE"));
    }

    @Test
    void flagsAndEscapedLabels() {
        // response, flags 0x8580 (qr aa rd ra), question "a\.b.\007" IN A: a label containing a dot, one holding 0x07
        final String dns = "abcd85800001000000000000" + "03612e62" + "0107" + "00" + "00010001";
        final Message m = codec(new MetricRegistry()).decodeSafe(new RawMessage(FuzzTestAccess.dnstap(6, 14, HexFormat.of().parseHex(dns)),
                new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
        assertEquals("qr aa rd ra", m.getField("dns_flags"));
        assertEquals("a\\.b.\\007", m.getField("qname"));
    }

    private static DnstapCodec codec(MetricRegistry r) {
        return new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), r);
    }
}
