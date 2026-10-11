/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

/**
 * Sender-controlled text that becomes a message field. Control characters are written as \DDD (decimal, as in DNS
 * presentation format) so that a sender can't put line breaks or terminal escapes into fields that text-based outputs
 * (syslog, files) or terminals pass on; all other characters, including non-ASCII, are kept.
 */
final class Text {
    private Text() {
    }

    /** Escapes control characters (C0, DEL, C1) and the Unicode line/paragraph separators. */
    static String escapeControls(String s) {
        int i = 0;
        while (i < s.length() && !needsEscape(s.charAt(i))) {
            i++;
        }
        if (i == s.length()) {
            return s;    // the common case: nothing to escape, no copy
        }
        final StringBuilder sb = new StringBuilder(s.length() + 16).append(s, 0, i);
        for (; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (needsEscape(c)) {
                appendDecimal(sb, c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** One TXT character-string in presentation format: quotes and backslashes escaped too (RFC 1035 section 5.1). */
    static void appendQuoted(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (needsEscape(c)) {
                appendDecimal(sb, c);
            } else {
                sb.append(c);
            }
        }
        sb.append('"');
    }

    private static boolean needsEscape(char c) {
        return c < 0x20 || (c >= 0x7F && c <= 0x9F) || c == '\u2028' || c == '\u2029';
    }

    private static void appendDecimal(StringBuilder sb, char c) {
        if (c > 255) {
            sb.append("\\u").append(String.format("%04X", (int) c));   // only U+2028/U+2029 get here
            return;
        }
        sb.append('\\').append((char) ('0' + c / 100)).append((char) ('0' + c / 10 % 10)).append((char) ('0' + c % 10));
    }
}
