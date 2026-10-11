/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** Sender-chosen text can't carry line breaks or terminal escapes into message fields. */
class FieldInjectionTest {
    @Test
    void controlCharactersAreEscapedAndUnicodeIsKept() {
        assertEquals("ns1\\010FAKE LINE", Text.escapeControls("ns1\nFAKE LINE"));
        assertEquals("a\\013b\\027[31m\\127\\133", Text.escapeControls("a\rb\u001b[31m\u007f\u0085"));
        assertEquals("x\\u2028y", Text.escapeControls("x\u2028y"));
        final String plain = "BIND 9.20.29-1~deb13u1-Debian / ns-ț-名前";
        assertEquals(plain, Text.escapeControls(plain));
    }

    @Test
    void identityAndVersionAreEscaped() {
        final String dns = "abcd01000001000000000000" + "0377777700" + "00010001";
        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        field(o, 1, "ns1\nFAKE: injected");                 // identity: becomes the message source
        field(o, 2, "BIND\r\n9.20");                        // version
        o.writeBytes(FuzzTestAccess.dnstap(5, 10, HexFormat.of().parseHex(dns)));
        final Message m = decode(o.toByteArray());
        assertEquals("ns1\\010FAKE: injected", m.getSource());
        assertEquals("BIND\\013\\0109.20", m.getField("dnstap_version"));
    }

    @Test
    void txtAnswersAreInPresentationFormat() {
        // response www IN TXT, one answer: one character-string  a<LF>b"c\
        final byte[] txt = "a\nb\"c\\".getBytes(StandardCharsets.US_ASCII);
        final String rdata = String.format("%02x", txt.length) + HexFormat.of().formatHex(txt);
        final String dns = "abcd81800001000100000000" + "0377777700" + "00100001"
                + "c00c" + "0010" + "0001" + "00000001" + String.format("%04x", rdata.length() / 2) + rdata;
        final Message m = decode(FuzzTestAccess.dnstap(6, 14, HexFormat.of().parseHex(dns)));
        assertEquals("TXT \"a\\010b\\\"c\\\\\"", m.getField("answers"));
        assertFalse(m.getMessage().contains("\n"), "no line break in the message text");
    }

    private static void field(ByteArrayOutputStream o, int number, String value) {
        final byte[] v = value.getBytes(StandardCharsets.UTF_8);
        o.write(number << 3 | 2);
        o.write(v.length);
        o.writeBytes(v);
    }

    private static Message decode(byte[] frame) {
        return new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), new MetricRegistry())
                .decodeSafe(new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1))).orElseThrow();
    }
}
