/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

/**
 * Minimal protobuf wire-format reader over a byte array.
 * <p>
 * dnstap's schema is small and stable, so it is decoded directly instead of through generated classes:
 * no protobuf-java dependency (whose runtime would have to match Graylog's own copy) and no per-message
 * object graph.
 */
final class ProtoReader {
    static final int WIRE_VARINT = 0;
    static final int WIRE_FIXED64 = 1;
    static final int WIRE_LENGTH_DELIMITED = 2;
    static final int WIRE_FIXED32 = 5;

    private final byte[] buf;
    private final int limit;
    private int pos;

    ProtoReader(byte[] buf, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > buf.length) {
            throw new MalformedDnstapException("bad protobuf bounds");
        }
        this.buf = buf;
        this.pos = offset;
        this.limit = offset + length;
    }

    boolean hasMore() {
        return pos < limit;
    }

    int position() {
        return pos;
    }

    /** Reads a field key; returns (fieldNumber << 3) | wireType. */
    int readTag() {
        final long tag = readVarint();
        if (tag <= 0 || tag > Integer.MAX_VALUE) {
            throw new MalformedDnstapException("bad protobuf tag " + tag);
        }
        return (int) tag;
    }

    long readVarint() {
        long result = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            if (pos >= limit) {
                throw new MalformedDnstapException("truncated varint");
            }
            final byte b = buf[pos++];
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
        }
        throw new MalformedDnstapException("varint too long");
    }

    int readFixed32() {
        require(4);
        final int v = (buf[pos] & 0xFF) | (buf[pos + 1] & 0xFF) << 8 | (buf[pos + 2] & 0xFF) << 16 | (buf[pos + 3] & 0xFF) << 24;
        pos += 4;
        return v;
    }

    /** Reads the length of a length-delimited field and leaves the position at its first byte. */
    int readLength() {
        final long len = readVarint();
        if (len < 0 || len > limit - pos) {
            throw new MalformedDnstapException("bad length " + len);
        }
        return (int) len;
    }

    byte[] readBytes() {
        final int len = readLength();
        final byte[] out = new byte[len];
        System.arraycopy(buf, pos, out, 0, len);
        pos += len;
        return out;
    }

    void skip(int wireType) {
        switch (wireType) {
            case WIRE_VARINT -> readVarint();
            case WIRE_FIXED64 -> advance(8);
            case WIRE_LENGTH_DELIMITED -> advance(readLength());
            case WIRE_FIXED32 -> advance(4);
            default -> throw new MalformedDnstapException("unsupported wire type " + wireType);
        }
    }

    void advance(int n) {
        require(n);
        pos += n;
    }

    private void require(int n) {
        if (limit - pos < n) {
            throw new MalformedDnstapException("truncated field");
        }
    }
}
