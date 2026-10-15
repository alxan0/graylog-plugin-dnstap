/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.failure.InputProcessingException;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Worst-case decode cost of hand-crafted hostile messages (CPU amplification): a sender must not be able to make one
 * frame cost much more than an ordinary frame of the same size.
 */
class AdversarialCostTest {
    // generous for a shared CI machine; an ordinary frame takes a few microseconds
    private static final long BUDGET_MS = 50;

    /** The longest name the parser accepts: labels of 63 bytes 0x01, each shown as \001 (4 characters per byte). */
    private static void longName(ByteArrayOutputStream o) {
        for (int l = 0; l < 4; l++) {
            o.write(63);
            for (int i = 0; i < 63; i++) {
                o.write(1);
            }
        }
        o.write(0);
    }

    /**
     * 65535 questions: the first carries the long name, all others point at it (6 bytes each). As a response, one
     * answer (A 192.0.2.1) follows them, so the parser has to walk all questions to reach it.
     */
    static byte[] manyQuestions(boolean response) {
        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(new byte[] {0x12, 0x34, (byte) (response ? 0x81 : 0x01), (byte) (response ? 0x80 : 0x00),
                (byte) 0xFF, (byte) 0xFF, 0, (byte) (response ? 1 : 0), 0, 0, 0, 0});
        longName(o);
        o.writeBytes(new byte[] {0, 1, 0, 1});
        for (int q = 1; q < 65535; q++) {
            o.writeBytes(new byte[] {(byte) 0xC0, 12, 0, 1, 0, 1});
        }
        if (response) {
            o.writeBytes(new byte[] {(byte) 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, (byte) 192, 0, 2, 1});
        }
        return o.toByteArray();
    }

    /** A response with the maximum 32 shown answers whose owner and CNAME target are pointer chains to the long name. */
    static byte[] pointerChainAnswers() {
        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(new byte[] {0x12, 0x34, (byte) 0x81, (byte) 0x80, 0, 1, (byte) 0xFF, (byte) 0xFF, 0, 0, 0, 0});
        longName(o);                                         // at offset 12
        o.writeBytes(new byte[] {0, 5, 0, 1});
        // a chain of 60 pointers, each pointing at the previous one, ending at the long name
        int prev = 12;
        final int chainStart = o.size();
        for (int i = 0; i < 60; i++) {
            final int here = o.size();
            o.write(0xC0 | (prev >> 8));
            o.write(prev & 0xFF);
            prev = here;
        }
        final int chainEnd = prev;
        for (int a = 0; a < 65535 && o.size() < 60_000; a++) {
            o.write(0xC0 | (chainEnd >> 8)); o.write(chainEnd & 0xFF);       // owner
            o.writeBytes(new byte[] {0, 5, 0, 1, 0, 0, 0, 60, 0, 2});         // CNAME IN ttl rdlen=2
            o.write(0xC0 | (chainEnd >> 8)); o.write(chainEnd & 0xFF);       // target
        }
        assertTrue(chainStart > 12);
        return o.toByteArray();
    }

    @Test
    void manyQuestionsAreCheap() {
        assertCheap("65535 questions", FuzzTestAccess.dnstap(5, 10, manyQuestions(false)));
    }

    @Test
    void manyQuestionsBeforeTheAnswersAreCheap() {
        final byte[] frame = FuzzTestAccess.dnstap(6, 14, manyQuestions(true));
        assertCheap("65535 questions + answer", frame);
        final String answers = (String) new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), new MetricRegistry())
                .decodeSafe(new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1))).orElseThrow().getField("dns_answers");
        assertEquals("A 192.0.2.1", answers);
    }

    @Test
    void pointerChainsInAnswersAreCheap() {
        assertCheap("pointer chains", FuzzTestAccess.dnstap(6, 14, pointerChainAnswers()));
    }

    private static void assertCheap(String what, byte[] frame) {
        final DnstapCodec codec = new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), new MetricRegistry());
        final RawMessage raw = new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1));
        for (int i = 0; i < 3; i++) {
            decode(codec, raw);   // warm-up (JIT)
        }
        final long t0 = System.nanoTime();
        final int n = 5;
        for (int i = 0; i < n; i++) {
            decode(codec, raw);
        }
        final long ms = (System.nanoTime() - t0) / n / 1_000_000;
        System.out.println("adversarial " + what + ": " + frame.length + " bytes, " + ms + " ms per frame");
        assertTrue(ms < BUDGET_MS, what + ": " + ms + " ms per frame");
    }

    private static void decode(DnstapCodec codec, RawMessage raw) {
        try {
            codec.decodeSafe(raw);
        } catch (InputProcessingException e) {
            // rejecting the frame is fine too; only the time matters
        }
    }
}
