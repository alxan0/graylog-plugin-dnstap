package org.graylog.plugins.dnstap;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.TooLongFrameException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.failure.InputProcessingException;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Robustness against corrupt and hostile input. Seeded, so every failure is reproducible:
 * the message names the seed, the iteration and the input bytes.
 * <ul>
 *   <li>The codec may only return a message / Optional.empty() or throw InputProcessingException
 *       (Graylog's error path), never anything else, and never slowly.</li>
 *   <li>The frame decoder may only fail with CorruptedFrameException/TooLongFrameException, must reject
 *       oversized frames from their 4-byte header (no buffering), and must close the connection.</li>
 * </ul>
 * Iterations: -Dfuzz.iterations=N (default 300000 codec mutations, 20000 decoder streams).
 */
class FuzzTest {
    private static final long SEED = Long.getLong("fuzz.seed", 20261010L);
    private static final int ITER = Integer.getInteger("fuzz.iterations", 300_000);
    private static final InetSocketAddress REMOTE = new InetSocketAddress("10.251.2.53", 40000);

    private static DnstapCodec codec() {
        return new DnstapCodec(new Configuration(Map.of()), TestMessages.factory());
    }

    /** Decode and classify: OK, EMPTY or REJECTED (InputProcessingException); anything else fails the test. */
    private static String decodeChecked(DnstapCodec c, byte[] in, String what) {
        final long t0 = System.nanoTime();
        try {
            final String r = c.decodeSafe(new RawMessage(in, REMOTE)).isPresent() ? "OK" : "EMPTY";
            check(t0, in, what);
            return r;
        } catch (InputProcessingException e) {
            check(t0, in, what);
            return "REJECTED";
        } catch (Throwable t) {
            fail(what + ": unexpected " + t + "\ninput (" + in.length + " bytes): " + HexFormat.of().formatHex(in), t);
            return "";
        }
    }

    private static void check(long t0, byte[] in, String what) {
        final long ms = (System.nanoTime() - t0) / 1_000_000;
        if (ms > 100) fail(what + ": took " + ms + " ms\ninput: " + HexFormat.of().formatHex(in));
    }

    @Test
    void codecSurvivesMutatedRealFrames() throws Exception {
        final List<byte[]> frames = Fixture.frames();
        final DnstapCodec c = codec();
        for (int w = 0; w < 50; w++) for (byte[] f : frames) c.decodeSafe(new RawMessage(f, REMOTE)); // warm up the JIT before timing
        final Random rnd = new Random(SEED);
        final Map<String, int[]> outcomes = new java.util.TreeMap<>();
        for (int i = 0; i < ITER; i++) {
            final byte[] in = mutate(frames.get(rnd.nextInt(frames.size())), rnd);
            outcomes.computeIfAbsent(decodeChecked(c, in, "seed " + SEED + " iteration " + i), k -> new int[1])[0]++;
        }
        final StringBuilder sb = new StringBuilder();
        outcomes.forEach((k, v) -> sb.append(k).append('=').append(v[0]).append(' '));
        System.out.println("codec fuzz: " + ITER + " mutated frames -> " + sb);
        assertTrue(outcomes.containsKey("OK") && outcomes.containsKey("REJECTED"), "mutations should hit both paths: " + sb);
    }

    @Test
    void codecSurvivesRandomBytes() {
        final DnstapCodec c = codec();
        final Random rnd = new Random(SEED + 1);
        for (int i = 0; i < ITER / 3; i++) {
            final byte[] in = new byte[rnd.nextInt(300)];
            rnd.nextBytes(in);
            decodeChecked(c, in, "random seed " + (SEED + 1) + " iteration " + i);
        }
    }

    @Test
    void hostileDnsMessagesAreRejected() {
        final DnstapCodec c = codec();
        // DNS header (qdcount=1) + a question name that is a compression pointer to itself (offset 12)
        assertEquals("REJECTED", decodeChecked(c, dnstapWithQuery(hex("abcd0100000100000000000" + "0" + "c00c00010001")), "self pointer"), "self pointer");
        // two pointers pointing at each other
        assertEquals("REJECTED", decodeChecked(c, dnstapWithQuery(hex("abcd01000001000000000000" + "c00e" + "c00c" + "00010001")), "pointer loop"), "pointer loop");
        // label length running past the end
        assertEquals("REJECTED", decodeChecked(c, dnstapWithQuery(hex("abcd01000001000000000000" + "3f616263")), "label overflow"), "label overflow");
        // header only, qdcount=65535
        assertEquals("REJECTED", decodeChecked(c, dnstapWithQuery(hex("abcd0100ffff000000000000")), "qdcount without questions"), "qdcount without questions");
        // response with an MX answer whose rdata is shorter than the preference field
        assertEquals("REJECTED", decodeChecked(c, dnstapWithResponse(hex(
                "abcd81800001000100000000" + "03777777" + "00" + "00010001" + "c00c000f0001000000010001" + "00")), "short MX rdata"), "short MX rdata");
        // response with ancount 1 and no answer bytes
        assertEquals("REJECTED", decodeChecked(c, dnstapWithResponse(hex("abcd818000010001000000000377777700000100 01".replace(" ", ""))), "missing answer"), "missing answer");
    }

    @Test
    void decoderRejectsOversizedFrameFromItsHeader() {
        final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
        // a header announcing 2 GiB: must fail immediately, without waiting for (or buffering) the payload
        final DecoderException e = assertThrows(DecoderException.class, () -> ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0x7f, -1, -1, -1})));
        assertTrue(e instanceof TooLongFrameException, e.toString());
        assertFalse(ch.isOpen(), "the connection is closed after a framing error");
    }

    @Test
    void decoderRejectsBadControlFrames() {
        for (byte[] bad : new byte[][]{
                hex("00000000" + "00000003" + "000000"),          // control length < 4
                hex("00000000" + "00100000"),                     // control length 1 MiB
                hex("00000000" + "00000004" + "000000ff")}) {     // unknown control type
            final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(1 << 20));
            final DecoderException e = assertThrows(DecoderException.class, () -> ch.writeInbound(Unpooled.wrappedBuffer(bad)));
            assertTrue(e instanceof CorruptedFrameException, e.toString());
            assertFalse(ch.isOpen());
        }
    }

    @Test
    void decoderSurvivesRandomStreams() {
        final Random rnd = new Random(SEED + 2);
        int frames = 0, rejected = 0;
        for (int i = 0; i < Math.max(1000, ITER / 15); i++) {
            final EmbeddedChannel ch = new EmbeddedChannel(new FstrmFrameDecoder(64 * 1024));
            try {
                for (int chunk = 0; chunk < 8 && ch.isOpen(); chunk++) {
                    final byte[] b = randomStreamChunk(rnd);
                    ch.writeInbound(Unpooled.wrappedBuffer(b));
                    ByteBuf f;
                    while ((f = ch.readInbound()) != null) { frames++; assertTrue(f.readableBytes() <= 64 * 1024); f.release(); }
                }
            } catch (DecoderException e) {
                if (!(e instanceof CorruptedFrameException || e instanceof TooLongFrameException)) {
                    fail("stream seed " + (SEED + 2) + " iteration " + i + ": unexpected " + e, e);
                }
                assertFalse(ch.isOpen(), "closed after " + e);
                rejected++;
            } catch (Throwable t) {
                fail("stream seed " + (SEED + 2) + " iteration " + i + ": unexpected " + t, t);
            } finally {
                ch.releaseInbound();
                ch.releaseOutbound();
                ch.close();
            }
        }
        System.out.println("decoder fuzz: frames=" + frames + " rejected streams=" + rejected);
    }

    // ---- helpers
    private static byte[] mutate(byte[] src, Random rnd) {
        byte[] b = src.clone();
        final int n = 1 + rnd.nextInt(8);
        for (int k = 0; k < n && b.length > 0; k++) {
            final int p = rnd.nextInt(b.length);
            switch (rnd.nextInt(7)) {
                case 0 -> b[p] ^= (byte) (1 << rnd.nextInt(8));                 // bit flip
                case 1 -> b[p] = (byte) rnd.nextInt(256);                        // random byte
                case 2 -> b[p] = (byte) (rnd.nextBoolean() ? 0xFF : 0x00);       // extreme value
                case 3 -> b = java.util.Arrays.copyOf(b, p);                      // truncate
                case 4 -> {                                                        // insert random bytes
                    final byte[] ins = new byte[1 + rnd.nextInt(16)]; rnd.nextBytes(ins);
                    final byte[] o = new byte[b.length + ins.length];
                    System.arraycopy(b, 0, o, 0, p); System.arraycopy(ins, 0, o, p, ins.length); System.arraycopy(b, p, o, p + ins.length, b.length - p);
                    b = o;
                }
                case 5 -> {                                                        // delete a range
                    final int len = Math.min(b.length - p, 1 + rnd.nextInt(16));
                    final byte[] o = new byte[b.length - len];
                    System.arraycopy(b, 0, o, 0, p); System.arraycopy(b, p + len, o, p, b.length - p - len);
                    b = o;
                }
                default -> {                                                       // duplicate a range
                    final int len = Math.min(b.length - p, 1 + rnd.nextInt(32));
                    final byte[] o = new byte[b.length + len];
                    System.arraycopy(b, 0, o, 0, p + len); System.arraycopy(b, p, o, p + len, b.length - p);
                    b = o;
                }
            }
        }
        return b;
    }

    private static byte[] randomStreamChunk(Random rnd) {
        final ByteBuf out = Unpooled.buffer();
        final int parts = 1 + rnd.nextInt(6);
        for (int i = 0; i < parts; i++) {
            switch (rnd.nextInt(5)) {
                case 0 -> { final int len = rnd.nextInt(200); out.writeInt(len); final byte[] p = new byte[len]; rnd.nextBytes(p); out.writeBytes(p); }
                case 1 -> out.writeInt(rnd.nextInt());                                         // random header
                case 2 -> { out.writeInt(0).writeInt(4 + rnd.nextInt(40)).writeInt(1 + rnd.nextInt(5)); } // control-ish
                case 3 -> { final byte[] p = new byte[rnd.nextInt(64)]; rnd.nextBytes(p); out.writeBytes(p); }
                default -> out.writeInt(0x00100000 + rnd.nextInt(1 << 20));                    // big frame header
            }
        }
        final byte[] b = new byte[out.readableBytes()];
        out.readBytes(b);
        return b;
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    /** dnstap{type=MESSAGE, message{type=CLIENT_QUERY, query_message=dns}} */
    private static byte[] dnstapWithQuery(byte[] dns) {
        return dnstap(5, 10, dns);
    }

    private static byte[] dnstapWithResponse(byte[] dns) {
        return dnstap(6, 14, dns);
    }

    private static byte[] dnstap(int messageType, int dnsField, byte[] dns) {
        final java.io.ByteArrayOutputStream msg = new java.io.ByteArrayOutputStream();
        msg.write(0x08); msg.write(messageType);                 // field 1 varint: type
        msg.write(dnsField << 3 | 2); varint(msg, dns.length); msg.writeBytes(dns);
        final byte[] m = msg.toByteArray();
        final java.io.ByteArrayOutputStream top = new java.io.ByteArrayOutputStream();
        top.write(15 << 3); top.write(1);                        // field 15 varint: MESSAGE
        top.write(14 << 3 | 2); varint(top, m.length); top.writeBytes(m);
        return top.toByteArray();
    }

    private static void varint(java.io.ByteArrayOutputStream o, int v) {
        while ((v & ~0x7F) != 0) { o.write((v & 0x7F) | 0x80); v >>>= 7; }
        o.write(v);
    }
}
