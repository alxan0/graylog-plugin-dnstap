/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import com.google.common.net.InetAddresses;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal DNS wire-format parser (RFC 1035): header, first question and, optionally, the answer section.
 * Handles name compression with loop protection. Replaces dnsjava from the original plugin.
 */
final class DnsMessage {
    private static final int MAX_ANSWERS = 32;
    private static final int MAX_POINTER_JUMPS = 64;
    private static final int MAX_RDATA_TEXT = 256;
    private static final int MAX_NAME_TEXT = 1024;

    private static final int[] FLAG_BITS = {0x8000, 0x0400, 0x0200, 0x0100, 0x0080, 0x0020, 0x0010};
    private static final String[] FLAG_NAMES = {"qr", "aa", "tc", "rd", "ra", "ad", "cd"};

    int id;
    int flags;
    int qdCount;
    int anCount;
    String qname;
    int qtype = -1;
    int qclass = -1;
    List<String> answers = List.of();

    private final byte[] b;
    private final int base;
    private final int end;
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
        m.u16(); // nscount
        m.u16(); // arcount
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

    String flagString() {
        final StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < FLAG_BITS.length; i++) {
            if ((flags & FLAG_BITS[i]) != 0) {
                if (!sb.isEmpty()) {
                    sb.append(' ');
                }
                sb.append(FLAG_NAMES[i]);
            }
        }
        return sb.toString();
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
            if (p >= end) {
                throw new MalformedDnstapException("name runs past the message");
            }
            final int len = b[p] & 0xFF;
            if (len == 0) {
                p++;
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                if (p + 1 >= end) {
                    throw new MalformedDnstapException("truncated name pointer");
                }
                jumps++;
                if (jumps > MAX_POINTER_JUMPS) {
                    throw new MalformedDnstapException("name pointer loop");
                }
                final int target = base + (((len & 0x3F) << 8) | (b[p + 1] & 0xFF));
                if (target >= end) {
                    throw new MalformedDnstapException("name pointer out of range");
                }
                if (resume < 0) {
                    resume = p + 2;
                }
                p = target;
                continue;
            }
            if ((len & 0xC0) != 0) {
                throw new MalformedDnstapException("unsupported label type");
            }
            if (p + 1 + len > end) {
                throw new MalformedDnstapException("label runs past the message");
            }
            if (!sb.isEmpty()) {
                sb.append('.');
            }
            appendLabel(sb, p + 1, len);
            if (sb.length() > MAX_NAME_TEXT) {
                throw new MalformedDnstapException("name too long");
            }
            p += 1 + len;
        }
        posRef[0] = resume >= 0 ? resume : p;
        return sb.isEmpty() ? "." : sb.toString();
    }

    /** Presentation format (RFC 4343): "." and "\\" escaped, other non-printable bytes as \\DDD. */
    private void appendLabel(StringBuilder sb, int from, int len) {
        for (int i = from; i < from + len; i++) {
            final int c = b[i] & 0xFF;
            if (c == '.' || c == '\\') {
                sb.append('\\').append((char) c);
            } else if (c < 0x21 || c > 0x7E) {
                sb.append('\\').append((char) ('0' + c / 100)).append((char) ('0' + c / 10 % 10)).append((char) ('0' + c % 10));
            } else {
                sb.append((char) c);
            }
        }
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
            case 2, 5, 6, 12, 39 -> nameAt(new int[] {rdStart});  // NS, CNAME, SOA (mname only), PTR, DNAME
            case 15 -> {                                            // MX
                if (rdlen < 3) {
                    throw new MalformedDnstapException("MX rdata too short");
                }
                final int pref = (b[rdStart] & 0xFF) << 8 | (b[rdStart + 1] & 0xFF);
                yield pref + " " + nameAt(new int[] {rdStart + 2});
            }
            case 16 -> txt(rdStart, rdlen);
            default -> rdlen + "b";
        };
        pos = rdStart + rdlen;
        // bounded: the joined answers end up in a keyword field (OpenSearch rejects terms > 32766 bytes)
        return typeName(type) + " " + (data.length() > MAX_RDATA_TEXT ? data.substring(0, MAX_RDATA_TEXT) + "…" : data);
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
            if (p + 1 + l > stop) {
                break;
            }
            if (!sb.isEmpty()) {
                sb.append(' ');
            }
            sb.append('"').append(new String(b, p + 1, l, StandardCharsets.UTF_8)).append('"');
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
