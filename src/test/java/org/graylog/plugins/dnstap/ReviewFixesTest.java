/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Edge cases of the Frame Streams handshake, the message fields and the size limits. */
class ReviewFixesTest {
    private static DnstapCodec codec() {
        return new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), new MetricRegistry());
    }

    @Test
    void readyWithoutDnstapContentTypeIsRefused() {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        final byte[] ct = "protobuf:something.Else".getBytes(StandardCharsets.US_ASCII);
        final ByteBuf b = Unpooled.buffer().writeInt(0).writeInt(4 + 8 + ct.length).writeInt(FstrmFrameDecoder.CONTROL_READY)
                .writeInt(FstrmFrameDecoder.FIELD_CONTENT_TYPE).writeInt(ct.length).writeBytes(ct);
        ch.writeInbound(b);
        assertNull(ch.readOutbound(), "no ACCEPT for a foreign content type");
        assertFalse(ch.isOpen());
    }

    @Test
    void unidirectionalStopGetsNoFinish() throws Exception {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        ch.writeInbound(Unpooled.wrappedBuffer(Fixture.bytes()));   // a file stream: START ... STOP, no READY
        assertNull(ch.readOutbound(), "FINISH is only for bidirectional streams");
        assertFalse(ch.isOpen());
        ch.finishAndReleaseAll();
    }

    @Test
    void hugeTxtAnswersAreCapped() {
        // response, 1 question (www IN TXT), 1 answer: TXT rdata with 200 strings of 255 'a' (51200 bytes)
        final StringBuilder rdata = new StringBuilder();
        for (int i = 0; i < 200; i++) rdata.append("ff").append("61".repeat(255));
        final int rdlen = rdata.length() / 2;
        final String dns = "abcd81800001000100000000" + "0377777700" + "00100001"
                + "c00c" + "0010" + "0001" + "00000001" + String.format("%04x", rdlen) + rdata;
        final Message m = codec().decodeSafe(new RawMessage(dnstapResponse(HexFormat.of().parseHex(dns)),
                new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
        final String answers = (String) m.getField("dns_answers");
        // + 3: the "..." appended when the text is cut
        assertTrue(answers.length() <= DnstapCodec.MAX_ANSWERS_TEXT + 3, "answers capped: " + answers.length());
        assertTrue(answers.getBytes(StandardCharsets.UTF_8).length < 32766, "fits an OpenSearch keyword");
    }

    @Test
    void responseWithoutResponseBytesHasNoRcode() {
        // CLIENT_RESPONSE frame that only carries the query message
        final String dns = "abcd01000001000000000000" + "0377777700" + "00010001";
        final Message m = codec().decodeSafe(new RawMessage(FuzzTestAccess.dnstap(6, 10, HexFormat.of().parseHex(dns)),
                new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
        assertNull(m.getField("dns_rcode"), "no rcode invented from the query");
        assertEquals(dns.length() / 2, ((Number) m.getField("dns_size")).intValue());
    }

    @Test
    void missingPortsAreNotWrittenAsMinusOne() throws Exception {
        final Message m = codec().decodeSafe(new RawMessage(Fixture.frames().get(10), new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
        for (String f : new String[]{"dns_query_port", "dns_response_port", "dns_client_port"}) {
            final Object v = m.getField(f);
            assertTrue(v == null || ((Number) v).intValue() >= 0, f + "=" + v);
        }
    }

    @Test
    void absurdEventTimeFallsBackToReceiveTime() {
        // query_time_sec = 2^40 s (year ~36800): not trusted as the timestamp
        final String dns = "abcd01000001000000000000" + "0377777700" + "00010001";
        final byte[] frame = FuzzTestAccess.dnstapWithTime(5, 10, HexFormat.of().parseHex(dns), 1L << 40);
        final RawMessage raw = new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1));
        final Message m = codec().decodeSafe(raw).orElseThrow();
        assertTrue(Math.abs(m.getTimestamp().getMillis() - raw.getTimestamp().getMillis()) < 1000);
        assertTrue(m.getFields().containsKey("dnstap_event_time_suspect"));
    }

    @Test
    void maxFrameSizeIsBounded() {
        assertTrue(FstrmTransport.MIN_MAX_FRAME_SIZE > 65_535 && FstrmTransport.MAX_MAX_FRAME_SIZE >= FstrmTransport.DEFAULT_MAX_FRAME_SIZE);
    }

    @Test
    void encodingFieldIsNotOffered() {
        assertFalse(new DnstapCodec.Config().getRequestedConfiguration()
                .containsField(org.graylog2.plugin.inputs.codecs.Codec.Config.CK_CHARSET_NAME));
    }

    private static byte[] dnstapResponse(byte[] dns) {
        return FuzzTestAccess.dnstap(6, 14, dns);
    }
}
