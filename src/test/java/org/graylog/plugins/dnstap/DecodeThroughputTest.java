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
        final DnstapCodec c = new DnstapCodec(new Configuration(Map.of()), TestMessages.factory());
        final InetSocketAddress remote = new InetSocketAddress("10.251.1.53", 40000);
        long n = 0;
        for (int warm = 0; warm < 200; warm++) for (byte[] f : frames) c.decodeSafe(new RawMessage(f, remote));
        final long t0 = System.nanoTime();
        while (System.nanoTime() - t0 < 5_000_000_000L) {
            for (byte[] f : frames) { c.decodeSafe(new RawMessage(f, remote)); n++; }
        }
        final double s = (System.nanoTime() - t0) / 1e9;
        System.out.printf("DnstapCodec: %,d frames in %.1f s = %,.0f frames/s on one thread%n", n, s, n / s);
    }
}
