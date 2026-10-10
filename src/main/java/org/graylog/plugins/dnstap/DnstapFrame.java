/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

/**
 * One decoded dnstap payload (schema: https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto).
 * <pre>
 * message Dnstap  { bytes identity = 1; bytes version = 2; bytes extra = 3; Message message = 14; Type type = 15; }
 * message Message { Type type = 1; SocketFamily socket_family = 2; SocketProtocol socket_protocol = 3;
 *                   bytes query_address = 4; bytes response_address = 5; uint32 query_port = 6; uint32 response_port = 7;
 *                   uint64 query_time_sec = 8; fixed32 query_time_nsec = 9; bytes query_message = 10; bytes query_zone = 11;
 *                   uint64 response_time_sec = 12; fixed32 response_time_nsec = 13; bytes response_message = 14; ... }
 * </pre>
 */
final class DnstapFrame {
    static final int DNSTAP_TYPE_MESSAGE = 1;

    // Dnstap
    String identity;
    String version;
    int dnstapType;
    // Message
    boolean hasMessage;
    int messageType;
    int socketFamily;
    int socketProtocol;
    byte[] queryAddress;
    byte[] responseAddress;
    int queryPort = -1;
    int responsePort = -1;
    long queryTimeSec = -1;
    int queryTimeNsec;
    long responseTimeSec = -1;
    int responseTimeNsec;
    byte[] queryZone;
    // DNS messages are kept as (offset, length) into the frame buffer: no copy
    byte[] buf;
    int queryMessageOffset = -1, queryMessageLength;
    int responseMessageOffset = -1, responseMessageLength;

    static DnstapFrame parse(byte[] payload) {
        final DnstapFrame f = new DnstapFrame();
        f.buf = payload;
        final ProtoReader r = new ProtoReader(payload, 0, payload.length);
        while (r.hasMore()) {
            final int tag = r.readTag();
            final int field = tag >>> 3, wire = tag & 7;
            switch (field) {
                case 1 -> f.identity = utf8(r.readBytes());
                case 2 -> f.version = utf8(r.readBytes());
                case 15 -> f.dnstapType = (int) r.readVarint();
                case 14 -> {
                    final int len = r.readLength();
                    parseMessage(f, payload, r.position(), len);
                    r.advance(len);
                    f.hasMessage = true;
                }
                default -> r.skip(wire);
            }
        }
        return f;
    }

    private static void parseMessage(DnstapFrame f, byte[] payload, int offset, int length) {
        final ProtoReader r = new ProtoReader(payload, offset, length);
        while (r.hasMore()) {
            final int tag = r.readTag();
            final int field = tag >>> 3, wire = tag & 7;
            switch (field) {
                case 1 -> f.messageType = (int) r.readVarint();
                case 2 -> f.socketFamily = (int) r.readVarint();
                case 3 -> f.socketProtocol = (int) r.readVarint();
                case 4 -> f.queryAddress = r.readBytes();
                case 5 -> f.responseAddress = r.readBytes();
                case 6 -> f.queryPort = (int) r.readVarint();
                case 7 -> f.responsePort = (int) r.readVarint();
                case 8 -> f.queryTimeSec = r.readVarint();
                case 9 -> f.queryTimeNsec = r.readFixed32();
                case 10 -> { f.queryMessageLength = r.readLength(); f.queryMessageOffset = r.position(); r.advance(f.queryMessageLength); }
                case 11 -> f.queryZone = r.readBytes();
                case 12 -> f.responseTimeSec = r.readVarint();
                case 13 -> f.responseTimeNsec = r.readFixed32();
                case 14 -> { f.responseMessageLength = r.readLength(); f.responseMessageOffset = r.position(); r.advance(f.responseMessageLength); }
                default -> r.skip(wire);
            }
        }
    }

    boolean isResponse() {
        return messageType % 2 == 0; // *_RESPONSE types are the even ones
    }

    private static String utf8(byte[] b) {
        return new String(b, java.nio.charset.StandardCharsets.UTF_8);
    }

    // ---- names, as in dnstap.proto and dnstap-read's short codes
    private static final String[] TYPES = {null, "AUTH_QUERY", "AUTH_RESPONSE", "RESOLVER_QUERY", "RESOLVER_RESPONSE",
            "CLIENT_QUERY", "CLIENT_RESPONSE", "FORWARDER_QUERY", "FORWARDER_RESPONSE", "STUB_QUERY", "STUB_RESPONSE",
            "TOOL_QUERY", "TOOL_RESPONSE", "UPDATE_QUERY", "UPDATE_RESPONSE"};
    private static final String[] SHORT = {null, "AQ", "AR", "RQ", "RR", "CQ", "CR", "FQ", "FR", "SQ", "SR", "TQ", "TR", "UQ", "UR"};
    private static final String[] PROTOCOLS = {null, "UDP", "TCP", "DOT", "DOH", "DNSCryptUDP", "DNSCryptTCP", "DOQ"};

    static String typeName(int t) {
        return t > 0 && t < TYPES.length ? TYPES[t] : "TYPE" + t;
    }

    static String typeShort(int t) {
        return t > 0 && t < SHORT.length ? SHORT[t] : "T" + t;
    }

    static String familyName(int f) {
        return f == 1 ? "INET" : f == 2 ? "INET6" : "UNKNOWN";
    }

    static String protocolName(int p) {
        return p > 0 && p < PROTOCOLS.length ? PROTOCOLS[p] : "UNKNOWN";
    }
}
