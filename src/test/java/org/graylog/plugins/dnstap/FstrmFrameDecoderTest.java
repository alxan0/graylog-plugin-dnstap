/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Frame Streams handshake and framing. */
class FstrmFrameDecoderTest {
    @Test
    void decodesEveryFrameOfARealBindFile() throws Exception {
        // dnstap-read on the same file: 629 messages
        assertEquals(629, Fixture.frames().size());
    }

    @Test
    void bidirectionalHandshake() {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        ch.writeInbound(control(FstrmFrameDecoder.CONTROL_READY, FstrmFrameDecoder.DNSTAP_CONTENT_TYPE));
        final ByteBuf accept = ch.readOutbound();
        assertNotNull(accept, "READY must be answered with ACCEPT");
        assertEquals(0, accept.readInt());
        accept.readInt();   // control length
        assertEquals(FstrmFrameDecoder.CONTROL_ACCEPT, accept.readInt());
        assertEquals(FstrmFrameDecoder.FIELD_CONTENT_TYPE, accept.readInt());
        final int len = accept.readInt();
        assertEquals(FstrmFrameDecoder.DNSTAP_CONTENT_TYPE, accept.readCharSequence(len, StandardCharsets.US_ASCII).toString());
        accept.release();

        ch.writeInbound(control(FstrmFrameDecoder.CONTROL_START, FstrmFrameDecoder.DNSTAP_CONTENT_TYPE));
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0, 0, 0, 3, 1, 2, 3}));   // data frame: length 3, payload 1 2 3
        final ByteBuf frame = ch.readInbound();
        assertEquals(3, frame.readableBytes());
        frame.release();

        ch.writeInbound(control(FstrmFrameDecoder.CONTROL_STOP, null));
        final ByteBuf finish = ch.readOutbound();
        assertNotNull(finish, "STOP must be answered with FINISH");
        finish.skipBytes(8);   // escape (0) and control length
        assertEquals(FstrmFrameDecoder.CONTROL_FINISH, finish.readInt());
        finish.release();
        assertFalse(ch.isOpen(), "channel is closed after FINISH");
    }

    @Test
    void waitsForIncompleteFrames() {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0, 0, 0, 5, 1, 2}));   // length 5, only 2 payload bytes
        assertNull(ch.readInbound());
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{3, 4, 5}));
        final ByteBuf frame = ch.readInbound();
        assertEquals(5, frame.readableBytes());
        frame.release();
        ch.finishAndReleaseAll();
    }

    private static ByteBuf control(int type, String contentType) {
        final byte[] ct = contentType == null ? new byte[0] : contentType.getBytes(StandardCharsets.US_ASCII);
        final int clen = 4 + (contentType == null ? 0 : 8 + ct.length);
        final ByteBuf b = Unpooled.buffer();
        b.writeInt(0).writeInt(clen).writeInt(type);
        if (contentType != null) b.writeInt(FstrmFrameDecoder.FIELD_CONTENT_TYPE).writeInt(ct.length).writeBytes(ct);
        return b;
    }
}
