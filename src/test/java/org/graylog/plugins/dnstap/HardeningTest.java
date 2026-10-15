/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Findings of the 1.2.0 security review: sender-controlled sizes and broken records. */
class HardeningTest {
    private static final int CLIENT_RESPONSE = 6;
    private static final int RESPONSE_MESSAGE = 14;
    // www.example.com IN A
    private static final String QUESTION = "03777777076578616d706c6503636f6d00" + "00010001";

    private static Message decode(byte[] frame) {
        return DnstapCodecTest.codec(Map.of()).decodeSafe(new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
    }

    // header qr aa rd ra, NOERROR, one question and the given answer count
    private static byte[] response(int answers, String records) {
        final String hex = "abcd8580" + "0001" + String.format("%04x", answers) + "0000" + "0000" + QUESTION + records;
        return FuzzTestAccess.dnstap(CLIENT_RESPONSE, RESPONSE_MESSAGE, HexFormat.of().parseHex(hex));
    }

    /** A frame with a dnstap identity (field 1) in front of the message fields. */
    private static byte[] withIdentity(byte[] identity, byte[] frame) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x0a);
        for (long v = identity.length; ; v >>>= 7) {
            if ((v & ~0x7FL) == 0) {
                out.write((int) v);
                break;
            }
            out.write((int) ((v & 0x7F) | 0x80));
        }
        out.writeBytes(identity);
        out.writeBytes(frame);
        return out.toByteArray();
    }

    @Test
    void longIdentityIsCapped() {
        final byte[] identity = "x".repeat(40_000).getBytes(StandardCharsets.UTF_8);
        final Message m = decode(withIdentity(identity, response(0, "")));
        assertEquals(255, m.getSource().length());
    }

    @Test
    void cappedIdentityStillEscapesControlCharacters() {
        final byte[] identity = "\n".repeat(1_000).getBytes(StandardCharsets.UTF_8);
        final Message m = decode(withIdentity(identity, response(0, "")));
        assertEquals("\\010".repeat(255), m.getSource());
    }

    @Test
    void brokenAnswerKeepsTheRestOfTheMessage() {
        final String a = "c00c" + "0001" + "0001" + "00000e10" + "0004" + "c0000201";   // www.example.com A 192.0.2.1
        final String badMx = "c00c" + "000f" + "0001" + "00000e10" + "0001" + "00";     // MX rdata of 1 byte
        final Message m = decode(response(2, a + badMx));
        assertEquals("www.example.com", m.getField("dns_query_name"));
        assertEquals("NOERROR", m.getField("dns_rcode"));
        assertEquals("A 192.0.2.1", m.getField("dns_answers"));
        assertEquals(2, ((Number) m.getField("dns_answer_count")).intValue());   // the header's ancount, not 1
    }

    @Test
    void answerCountBeyondTheRecordsKeepsTheMessage() {
        final String a = "c00c" + "0001" + "0001" + "00000e10" + "0004" + "c0000201";
        final Message m = decode(response(5, a));
        assertEquals("A 192.0.2.1", m.getField("dns_answers"));
    }

    @Test
    void txtCapNeverSplitsASurrogatePair() {
        // the rdata text is "a...a" "bXbX..." (X = U+1F600): with 250 a's, the first X's high surrogate is at
        // index 255, the last character the 256-character cap would keep
        final byte[] first = "a".repeat(250).getBytes(StandardCharsets.UTF_8);
        final byte[] second = "b\uD83D\uDE00".repeat(50).getBytes(StandardCharsets.UTF_8);
        final ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        rdata.write(first.length);
        rdata.writeBytes(first);
        rdata.write(second.length);
        rdata.writeBytes(second);
        final String txt = "c00c" + "0010" + "0001" + "00000e10" + String.format("%04x", rdata.size())
                + HexFormat.of().formatHex(rdata.toByteArray());
        final String answers = (String) decode(response(1, txt)).getField("dns_answers");
        assertTrue(answers.endsWith("..."), answers);
        assertNoLoneSurrogate(answers);
    }

    @Test
    void cutKeepsSurrogatePairsWhole() {
        assertEquals("ab", Text.cut("ab\uD83D\uDE00", 3));
        assertEquals("ab\uD83D\uDE00", Text.cut("ab\uD83D\uDE00c", 4));
        assertEquals("abc", Text.cut("abc", 5));
        assertNoLoneSurrogate(Text.cut("\uD83D\uDE00".repeat(5000), DnstapCodec.MAX_ANSWERS_TEXT));
    }

    private static void assertNoLoneSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                assertTrue(i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)), "lone high surrogate at " + i);
                i++;
            } else {
                assertFalse(Character.isLowSurrogate(c), "lone low surrogate at " + i);
            }
        }
    }
}
