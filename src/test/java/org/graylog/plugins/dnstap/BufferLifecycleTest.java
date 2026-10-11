/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import io.netty.buffer.AbstractByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reference counting of every buffer the decoder touches, on pooled direct memory as in Graylog: after a stream is
 * processed, its outputs consumed and the connection closed, every buffer (the inputs, Netty's cumulation buffers and
 * the ACCEPT/FINISH frames) must be back at refCnt 0. A leak or an extra retain fails the check; a double release or a
 * use after release throws IllegalReferenceCountException inside the pipeline, which EmbeddedChannel rethrows.
 */
class BufferLifecycleTest {
    /** Pooled direct allocator that remembers every buffer it hands out. */
    private static final class RecordingAllocator extends AbstractByteBufAllocator {
        final List<ByteBuf> allocated = new ArrayList<>();

        RecordingAllocator() {
            super(true);
        }

        @Override
        protected ByteBuf newHeapBuffer(int initialCapacity, int maxCapacity) {
            return record(PooledByteBufAllocator.DEFAULT.heapBuffer(initialCapacity, maxCapacity));
        }

        @Override
        protected ByteBuf newDirectBuffer(int initialCapacity, int maxCapacity) {
            return record(PooledByteBufAllocator.DEFAULT.directBuffer(initialCapacity, maxCapacity));
        }

        @Override
        public boolean isDirectBufferPooled() {
            return true;
        }

        private ByteBuf record(ByteBuf b) {
            allocated.add(b);
            return b;
        }

        void assertAllReleased(String scenario) {
            for (int i = 0; i < allocated.size(); i++) {
                assertEquals(0, allocated.get(i).refCnt(), scenario + ": buffer " + i + " of " + allocated.size() + " still referenced");
            }
        }
    }

    /** Runs one stream through a decoder in random chunks, consumes what comes out, closes, checks the buffers. */
    private static int run(String scenario, byte[] stream, Random rnd, boolean closeEarly) {
        final RecordingAllocator alloc = new RecordingAllocator();
        final EmbeddedChannel ch = new EmbeddedChannel();
        ch.config().setAllocator(alloc);
        ch.pipeline().addLast(new FstrmFrameDecoder(FstrmTransport.DEFAULT_MAX_FRAME_SIZE));
        int frames = 0;
        final int stop = closeEarly ? rnd.nextInt(stream.length + 1) : stream.length;
        for (int off = 0; off < stop && ch.isOpen(); ) {
            final int n = Math.min(stop - off, 1 + rnd.nextInt(900));
            ch.writeInbound(alloc.directBuffer(n).writeBytes(stream, off, n));
            off += n;
            ch.runPendingTasks();                    // the deferred close (closeLater) runs here, as on the event loop
            frames += drain(ch);
        }
        ch.checkException();
        ch.finishAndReleaseAll();                    // Graylog's side: consume the rest, then the connection ends
        alloc.assertAllReleased(scenario);
        return frames;
    }

    /** What Graylog does with decoded frames (it copies them into a RawMessage) and what the socket does with ACCEPTs. */
    private static int drain(EmbeddedChannel ch) {
        int n = 0;
        ByteBuf b;
        while ((b = ch.readInbound()) != null) {
            final byte[] copy = new byte[b.readableBytes()];
            b.readBytes(copy);
            b.release();
            n++;
        }
        while ((b = ch.readOutbound()) != null) {
            b.release();
        }
        return n;
    }

    private static byte[] control(int type, String contentType) {
        final byte[] ct = contentType == null ? new byte[0] : contentType.getBytes(StandardCharsets.US_ASCII);
        final int len = 4 + (ct.length > 0 ? 8 + ct.length : 0);
        final java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(8 + len).putInt(0).putInt(len).putInt(type);
        if (ct.length > 0) {
            b.putInt(FstrmFrameDecoder.FIELD_CONTENT_TYPE).putInt(ct.length).put(ct);
        }
        return b.array();
    }

    private static byte[] concat(byte[]... parts) {
        final java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.writeBytes(p);
        }
        return o.toByteArray();
    }

    @Test
    void everyPathReleasesItsBuffers() throws Exception {
        final Random rnd = new Random(7);
        final byte[] file = Fixture.bytes();                       // unidirectional: START, 629 frames, STOP
        final byte[] body = java.util.Arrays.copyOfRange(file, 0, file.length - 12);   // without the trailing STOP
        final byte[] ready = control(FstrmFrameDecoder.CONTROL_READY, FstrmFrameDecoder.DNSTAP_CONTENT_TYPE);

        assertEquals(629, run("file stream", file, rnd, false));
        assertEquals(629, run("bidirectional (READY/ACCEPT ... STOP/FINISH)", concat(ready, file), rnd, false));
        assertEquals(629, run("data after STOP is discarded", concat(file, body), rnd, false));
        run("refused content type", concat(control(FstrmFrameDecoder.CONTROL_READY, "protobuf:other"), file), rnd, false);
        run("framing error mid-stream", concat(body, new byte[] {0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 1, 2, 3}, body), rnd, false);
        run("unknown control type", concat(body, control(0x77, null), body), rnd, false);
        for (int i = 0; i < 300; i++) {
            run("closed mid-stream #" + i, concat(ready, body), rnd, true);   // a partial frame sits in the cumulation
        }
    }

    @Test
    void fuzzedStreamsReleaseTheirBuffers() throws Exception {
        final Random rnd = new Random(Long.getLong("fuzz.seed", 20261011L));
        final byte[] file = Fixture.bytes();
        final int iterations = Integer.getInteger("lifecycle.iterations", 20_000);
        long frames = 0;
        for (int i = 0; i < iterations; i++) {
            final byte[] stream = FuzzTest.mutate(file, rnd);
            frames += run("mutated stream #" + i, stream, rnd, rnd.nextInt(4) == 0);
        }
        System.out.println("buffer lifecycle: " + iterations + " mutated streams, " + frames + " frames, every buffer released");
        assertTrue(frames > 0);
    }
}
