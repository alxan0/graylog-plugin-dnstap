package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The monitoring metrics count what they claim to count. */
class MetricsTest {
    @Test
    void decoderCountsFramesHandshakesAndErrors() throws Exception {
        final MetricRegistry r = new MetricRegistry();
        final FstrmMetrics m = new FstrmMetrics(r);
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20, m));
        ch.writeInbound(Unpooled.wrappedBuffer(Fixture.bytes()));   // unidirectional file: START, 629 frames, STOP
        ch.finishAndReleaseAll();
        assertEquals(629, r.counter("fstrm.frames").getCount());
        assertEquals(1, r.counter("fstrm.control.start").getCount());
        assertEquals(1, r.counter("fstrm.control.stop").getCount());
        assertEquals(629 / 32, r.histogram("fstrm.frameSize").getCount());   // sampled 1 in 32
        assertEquals(0, r.counter("fstrm.errors.framing").getCount());

        final EmbeddedChannel bad = new EmbeddedChannel(new FstrmFrameDecoder(1024, m));
        bad.writeInbound(Unpooled.wrappedBuffer(new byte[]{0, 0, 0x10, 0}));
        assertEquals(1, r.counter("fstrm.errors.framing").getCount());
        org.junit.jupiter.api.Assertions.assertFalse(bad.isOpen());
    }

    @Test
    void codecCountsTypesSkipsAndLag() throws Exception {
        final MetricRegistry r = new MetricRegistry();
        // a new codec per message, as Graylog's DecodingProcessor does: the metrics must still add up
        for (byte[] f : Fixture.frames()) {
            new DnstapCodec(new Configuration(Map.of(DnstapCodec.CK_SKIP_TYPES, "UQ,UR")), TestMessages.factory(), r)
                    .decodeSafe(new RawMessage(f, new InetSocketAddress("10.0.0.1", 1)));
        }
        final String base = "org.graylog.plugins.dnstap.DnstapCodec.unknown";   // no input on this node in a unit test
        assertEquals(223, r.meter(base + ".types.CQ").getCount());
        assertEquals(230, r.meter(base + ".types.CR").getCount());
        assertEquals(52, r.meter(base + ".skipped").getCount());
        assertEquals((629 - 52) / 32, r.histogram(base + ".eventLagMs").getCount());   // sampled 1 in 32
        // the capture is from the past, so every lag is positive and large
        assertTrue(r.histogram(base + ".eventLagMs").getSnapshot().getMin() > 0);
    }
}
