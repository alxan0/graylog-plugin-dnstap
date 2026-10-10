package org.graylog.plugins.dnstap;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/** The dnstap file captured from the bind-lab (BIND 9.20.29-1~deb13u1, mixed traffic profile). */
final class Fixture {
    static final String FILE = "/bind-9.20.29.fstrm";

    static byte[] bytes() throws IOException {
        try (InputStream in = Fixture.class.getResourceAsStream(FILE)) {
            return in.readAllBytes();
        }
    }

    /** All data frames of the file, decoded by FstrmFrameDecoder fed in random-sized chunks (as TCP would). */
    static List<byte[]> frames() throws IOException {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        final byte[] all = bytes();
        final Random rnd = new Random(42);
        for (int off = 0; off < all.length; ) {
            final int n = Math.min(all.length - off, 1 + rnd.nextInt(700));
            ch.writeInbound(Unpooled.wrappedBuffer(all, off, n));
            off += n;
        }
        final List<byte[]> frames = new ArrayList<>();
        ByteBuf b;
        while ((b = ch.readInbound()) != null) {
            final byte[] a = new byte[b.readableBytes()];
            b.readBytes(a);
            b.release();
            frames.add(a);
        }
        ch.finishAndReleaseAll();
        return frames;
    }
}
