package org.graylog.plugins.dnstap;

import java.io.ByteArrayOutputStream;

/** Builds minimal dnstap protobuf payloads for tests. */
final class FuzzTestAccess {
    static byte[] dnstap(int messageType, int dnsField, byte[] dns) {
        return dnstapWithTime(messageType, dnsField, dns, -1);
    }

    static byte[] dnstapWithTime(int messageType, int dnsField, byte[] dns, long querySec) {
        final ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(0x08); varint(msg, messageType);
        if (querySec >= 0) { msg.write(8 << 3); varint(msg, querySec); }
        msg.write(dnsField << 3 | 2); varint(msg, dns.length); msg.writeBytes(dns);
        final byte[] m = msg.toByteArray();
        final ByteArrayOutputStream top = new ByteArrayOutputStream();
        top.write(15 << 3); top.write(1);
        top.write(14 << 3 | 2); varint(top, m.length); top.writeBytes(m);
        return top.toByteArray();
    }

    private static void varint(ByteArrayOutputStream o, long v) {
        while ((v & ~0x7FL) != 0) { o.write((int) ((v & 0x7F) | 0x80)); v >>>= 7; }
        o.write((int) v);
    }
}
