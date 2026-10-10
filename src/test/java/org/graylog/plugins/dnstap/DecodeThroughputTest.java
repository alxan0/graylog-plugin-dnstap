package org.graylog.plugins.dnstap;

import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;

/** Codec-only throughput on one core: mvn test -Dbench=true -Dtest=DecodeThroughputTest */
@EnabledIfSystemProperty(named = "bench", matches = "true")
class DecodeThroughputTest {
    @Test
    void decodeRate() throws Exception {
        final List<byte[]> frames = Fixture.frames();
        // like Graylog's DecodingProcessor: a new codec instance (and Configuration) for every message
        final com.codahale.metrics.MetricRegistry registry = new com.codahale.metrics.MetricRegistry();
        final org.graylog2.plugin.MessageFactory mf = TestMessages.factory();
        final Map<String, Object> cfg = Map.of(DnstapCodec.CK_SKIP_TYPES, "UQ,UR");
        final InetSocketAddress remote = new InetSocketAddress("10.251.1.53", 40000);
        long n = 0;
        for (int warm = 0; warm < 200; warm++) for (byte[] f : frames) new DnstapCodec(new Configuration(cfg), mf, registry).decodeSafe(new RawMessage(f, remote));
        final long t0 = System.nanoTime();
        while (System.nanoTime() - t0 < 5_000_000_000L) {
            for (byte[] f : frames) { new DnstapCodec(new Configuration(cfg), mf, registry).decodeSafe(new RawMessage(f, remote)); n++; }
        }
        final double s = (System.nanoTime() - t0) / 1e9;
        System.out.printf("DnstapCodec: %,d frames in %.1f s = %,.0f frames/s on one thread (new codec per message, as in Graylog)%n", n, s, n / s);
    }
}
