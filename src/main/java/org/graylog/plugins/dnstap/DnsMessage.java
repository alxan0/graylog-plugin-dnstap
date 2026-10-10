/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import com.google.common.net.InetAddresses;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal DNS wire-format parser (RFC 1035): header, first question and, optionally, the answer section.
 * Handles name compression with loop protection. Replaces dnsjava from the original plugin.
 */
final class DnsMessage {
    private static final int MAX_ANSWERS = 32;
    private static final int MAX_POINTER_JUMPS = 64;

    int id;
    int flags;
    int qdCount, anCount, nsCount, arCount;
    String qname;
    int qtype = -1, qclass = -1;
    List<String> answers = List.of();

    private final byte[] b;
    private final int base, end;
    private int pos;

    private DnsMessage(byte[] b, int offset, int length) {
        this.b = b;
        this.base = offset;
        this.end = offset + length;
        this.pos = offset;
    }

    static DnsMessage parse(byte[] buf, int offset, int length, boolean withAnswers) {
        if (length < 12) {
            throw new MalformedDnstapException("DNS message shorter than its header");
        }
        final DnsMessage m = new DnsMessage(buf, offset, length);
        m.id = m.u16();
        m.flags = m.u16();
        m.qdCount = m.u16();
        m.anCount = m.u16();
        m.nsCount = m.u16();
        m.arCount = m.u16();
        if (m.qdCount > 0) {
            m.qname = m.name();
            m.qtype = m.u16();
            m.qclass = m.u16();
            for (int i = 1; i < m.qdCount; i++) { // practically never; skip extra questions
                m.name();
                m.need(4);
                m.pos += 4;
            }
        }
        if (withAnswers && m.anCount > 0 && m.opcode() != 5) { // UPDATE uses the sections differently
            final int n = Math.min(m.anCount, MAX_ANSWERS);
            final List<String> answers = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                answers.add(m.record());
            }
            m.answers = answers;
        }
        return m;
    }

    int opcode() {
        return (flags >>> 11) & 0xF;
    }

    int rcode() {
        return flags & 0xF;
    }

    boolean isResponse() {
        return (flags & 0x8000) != 0;
    }

    String flagString() {
        final StringBuilder sb = new StringBuilder(16);
        if ((flags & 0x8000) != 0) sb.append("qr ");
        if ((flags & 0x0400) != 0) sb.append("aa ");
        if ((flags & 0x0200) != 0) sb.append("tc ");
        if ((flags & 0x0100) != 0) sb.append("rd ");
        if ((flags & 0x0080) != 0) sb.append("ra ");
        if ((flags & 0x0020) != 0) sb.append("ad ");
        if ((flags & 0x0010) != 0) sb.append("cd ");
        return sb.isEmpty() ? "" : sb.substring(0, sb.length() - 1);
    }

    // ---- wire helpers
    private void need(int n) {
        if (end - pos < n) {
            throw new MalformedDnstapException("truncated DNS message");
        }
    }

    private int u16() {
        need(2);
        final int v = (b[pos] & 0xFF) << 8 | (b[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    private long u32() {
        need(4);
        final long v = (long) (b[pos] & 0xFF) << 24 | (b[pos + 1] & 0xFF) << 16 | (b[pos + 2] & 0xFF) << 8 | (b[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    /** Reads a (possibly compressed) domain name at pos; advances pos past it. Root = ".". No trailing dot. */
    private String name() {
        final int[] p = {pos};
        final String n = nameAt(p);
        pos = p[0];
        return n;
    }

    private String nameAt(int[] posRef) {
        final StringBuilder sb = new StringBuilder(64);
        int p = posRef[0];
        int jumps = 0;
        int resume = -1;
        while (true) {
            if (p >= end) throw new MalformedDnstapException("name runs past the message");
            final int len = b[p] & 0xFF;
            if (len == 0) {
                p++;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                if (p + 1 >= end) throw new MalformedDnstapException("truncated name pointer");
                if (++jumps > MAX_POINTER_JUMPS) throw new MalformedDnstapException("name pointer loop");
                final int target = base + (((len & 0x3F) << 8) | (b[p + 1] & 0xFF));
                if (resume < 0) resume = p + 2;
                if (target >= end) throw new MalformedDnstapException("name pointer out of range");
                p = target;
                continue;
            }
            if ((len & 0xC0) != 0) throw new MalformedDnstapException("unsupported label type");
            if (p + 1 + len > end) throw new MalformedDnstapException("label runs past the message");
            if (!sb.isEmpty()) sb.append('.');
            for (int i = p + 1; i <= p + len; i++) {
                final char c = (char) (b[i] & 0xFF);
                if (c == '.' || c == '\\') sb.append('\\');
                if (c < 0x21 || c > 0x7E) sb.append(String.format("\\%03d", (int) c));
                else sb.append(c);
            }
            if (sb.length() > 1024) throw new MalformedDnstapException("name too long");
            p += 1 + len;
        }
        posRef[0] = resume >= 0 ? resume : p;
        return sb.isEmpty() ? "." : sb.toString();
    }

    /** One resource record, formatted "TYPE data" (e.g. "A 192.0.2.1", "CNAME www.example.org"). */
    private String record() {
        name(); // owner, not shown
        final int type = u16();
        u16(); // class
        u32(); // ttl
        final int rdlen = u16();
        need(rdlen);
        final int rdStart = pos;
        final String data = switch (type) {
            case 1 -> rdlen == 4 ? ip(rdStart, 4) : "?";
            case 28 -> rdlen == 16 ? ip(rdStart, 16) : "?";
            case 2, 5, 12, 39 -> { final int[] p = {rdStart}; yield nameAt(p); }               // NS, CNAME, PTR, DNAME
            case 15 -> {                                                                       // MX
                if (rdlen < 3) throw new MalformedDnstapException("MX rdata too short");
                final int pref = (b[rdStart] & 0xFF) << 8 | (b[rdStart + 1] & 0xFF);
                final int[] p = {rdStart + 2}; yield pref + " " + nameAt(p); }
            case 6 -> { final int[] p = {rdStart}; yield nameAt(p); }                          // SOA: mname
            case 16 -> txt(rdStart, rdlen);
            default -> rdlen + "b";
        };
        pos = rdStart + rdlen;
        return typeName(type) + " " + data;
    }

    private String ip(int at, int len) {
        try {
            final byte[] a = new byte[len];
            System.arraycopy(b, at, a, 0, len);
            return InetAddresses.toAddrString(InetAddress.getByAddress(a));
        } catch (UnknownHostException e) {
            return "?";
        }
    }

    private String txt(int at, int len) {
        final StringBuilder sb = new StringBuilder();
        int p = at;
        final int stop = at + len;
        while (p < stop) {
            final int l = b[p] & 0xFF;
            if (p + 1 + l > stop) break;
            if (!sb.isEmpty()) sb.append(' ');
            sb.append('"').append(new String(b, p + 1, l, java.nio.charset.StandardCharsets.UTF_8)).append('"');
            p += 1 + l;
        }
        return sb.toString();
    }

    // ---- names of numbers
    static String typeName(int t) {
        return switch (t) {
            case 1 -> "A"; case 2 -> "NS"; case 5 -> "CNAME"; case 6 -> "SOA"; case 12 -> "PTR"; case 13 -> "HINFO";
            case 15 -> "MX"; case 16 -> "TXT"; case 28 -> "AAAA"; case 33 -> "SRV"; case 35 -> "NAPTR"; case 39 -> "DNAME";
            case 41 -> "OPT"; case 43 -> "DS"; case 46 -> "RRSIG"; case 47 -> "NSEC"; case 48 -> "DNSKEY"; case 50 -> "NSEC3";
            case 51 -> "NSEC3PARAM"; case 52 -> "TLSA"; case 59 -> "CDS"; case 60 -> "CDNSKEY"; case 64 -> "SVCB";
            case 65 -> "HTTPS"; case 99 -> "SPF"; case 249 -> "TKEY"; case 250 -> "TSIG"; case 251 -> "IXFR";
            case 252 -> "AXFR"; case 255 -> "ANY"; case 256 -> "URI"; case 257 -> "CAA";
            default -> "TYPE" + t;
        };
    }

    static String className(int c) {
        return switch (c) {
            case 1 -> "IN"; case 3 -> "CH"; case 4 -> "HS"; case 254 -> "NONE"; case 255 -> "ANY";
            default -> "CLASS" + c;
        };
    }

    static String rcodeName(int r) {
        return switch (r) {
            case 0 -> "NOERROR"; case 1 -> "FORMERR"; case 2 -> "SERVFAIL"; case 3 -> "NXDOMAIN"; case 4 -> "NOTIMP";
            case 5 -> "REFUSED"; case 6 -> "YXDOMAIN"; case 7 -> "YXRRSET"; case 8 -> "NXRRSET"; case 9 -> "NOTAUTH";
            case 10 -> "NOTZONE";
            default -> "RCODE" + r;
        };
    }

    static String opcodeName(int o) {
        return switch (o) {
            case 0 -> "QUERY"; case 1 -> "IQUERY"; case 2 -> "STATUS"; case 4 -> "NOTIFY"; case 5 -> "UPDATE";
            default -> "OPCODE" + o;
        };
    }
}
