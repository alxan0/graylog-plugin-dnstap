/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.TooLongFrameException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Frame Streams (https://github.com/farsightsec/fstrm) receiver.
 * <pre>
 * data frame:    | length (4, big endian, > 0) | payload (length bytes) |
 * control frame: | 0 (4) | control length (4) | control type (4) | fields: (type (4) | length (4) | value)* |
 * </pre>
 * Bidirectional streams (BIND, Unbound, dnstap tools via a socket): READY -> we answer ACCEPT -> START, data...,
 * STOP -> we answer FINISH and close. Unidirectional streams (a dnstap file piped in): START, data..., STOP.
 * Each data frame (one dnstap protobuf) is passed on as its own ByteBuf, which Graylog turns into one RawMessage.
 */
public class FstrmFrameDecoder extends ByteToMessageDecoder {
    private static final Logger LOG = LoggerFactory.getLogger(FstrmFrameDecoder.class);

    static final int CONTROL_ACCEPT = 0x01;
    static final int CONTROL_START = 0x02;
    static final int CONTROL_STOP = 0x03;
    static final int CONTROL_READY = 0x04;
    static final int CONTROL_FINISH = 0x05;
    static final int FIELD_CONTENT_TYPE = 0x01;
    static final String DNSTAP_CONTENT_TYPE = "protobuf:dnstap.Dnstap";
    private static final int MAX_CONTROL_LENGTH = 512;

    private final int maxFrameSize;
    private final FstrmMetrics metrics;
    private boolean failed;
    private boolean bidirectional;     // READY seen: the sender expects ACCEPT now and FINISH after STOP
    private int sizeSample;

    public FstrmFrameDecoder(int maxFrameSize) {
        this(maxFrameSize, FstrmMetrics.unregistered());
    }

    FstrmFrameDecoder(int maxFrameSize, FstrmMetrics metrics) {
        this.maxFrameSize = maxFrameSize;
        this.metrics = metrics;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (failed) {
            in.skipBytes(in.readableBytes());
            return;
        }
        try {
            decodeFrames(ctx, in, out);
        } catch (CorruptedFrameException | TooLongFrameException e) {
            // A Frame Streams connection can't resynchronise after a framing error: everything after it would be
            // misread. Count it, log it once, discard the rest and close the connection once this decode call has
            // returned (closing inside decode() would release the buffer Netty is still decoding from). Not
            // rethrown: the plugin owns this case (Graylog would log a second, generic ERROR and close again).
            // Frames decoded before the error are still delivered. The sender reconnects.
            metrics.framingErrors.inc();
            LOG.warn("Frame Streams framing error from {}, closing the connection: {}", ctx.channel().remoteAddress(), e.getMessage());
            fail(ctx, in);
        }
    }

    private void fail(ChannelHandlerContext ctx, ByteBuf in) {
        failed = true;
        in.skipBytes(in.readableBytes());
        ctx.executor().execute(ctx::close);
    }

    private void decodeFrames(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        while (in.readableBytes() >= 4) {
            final int start = in.readerIndex();
            final long length = in.getUnsignedInt(start);
            if (length == 0) {
                if (in.readableBytes() < 8) return;
                final long controlLength = in.getUnsignedInt(start + 4);
                if (controlLength < 4 || controlLength > MAX_CONTROL_LENGTH) {
                    throw new CorruptedFrameException("bad Frame Streams control frame length " + controlLength);
                }
                if (in.readableBytes() < 8 + controlLength) return;
                in.skipBytes(8);
                handleControl(ctx, in.readSlice((int) controlLength));
                if (failed) {          // STOP or refused content type: discard whatever follows
                    in.skipBytes(in.readableBytes());
                    return;
                }
            } else {
                if (length > maxFrameSize) {
                    throw new TooLongFrameException("Frame Streams data frame of " + length + " bytes exceeds the limit of " + maxFrameSize);
                }
                if (in.readableBytes() < 4 + length) return;
                in.skipBytes(4);
                out.add(in.readRetainedSlice((int) length));
                metrics.frames.inc();
                if ((++sizeSample & 31) == 0) metrics.frameSize.update(length);   // sampled: the reservoir locks
            }
        }
    }

    private void handleControl(ChannelHandlerContext ctx, ByteBuf control) {
        final int type = control.readInt();
        switch (type) {
            case CONTROL_READY -> {
                metrics.ready.inc();
                final List<String> offered = contentTypes(control);
                if (!offered.isEmpty() && !offered.contains(DNSTAP_CONTENT_TYPE)) {
                    // the spec: the receiver must not ACCEPT a stream whose content type it doesn't understand
                    metrics.framingErrors.inc();
                    LOG.warn("Frame Streams sender {} offers content types {} but not {}: closing", ctx.channel().remoteAddress(), offered, DNSTAP_CONTENT_TYPE);
                    failed = true;
                    ctx.executor().execute(ctx::close);
                    return;
                }
                bidirectional = true;
                ctx.writeAndFlush(controlFrame(ctx, CONTROL_ACCEPT));
                LOG.debug("Frame Streams READY from {}: sent ACCEPT", ctx.channel().remoteAddress());
            }
            case CONTROL_START -> {
                metrics.start.inc();
                LOG.debug("Frame Streams START from {} ({})", ctx.channel().remoteAddress(), contentTypes(control));
            }
            case CONTROL_STOP -> {
                metrics.stop.inc();
                // Nothing may follow STOP. FINISH is the receiver's answer in bidirectional mode only. Close once
                // FINISH is written, and never inside this decode call: the write can complete synchronously on the
                // event loop, and closing inside decode() releases the buffer being decoded.
                failed = true;
                if (bidirectional) {
                    LOG.debug("Frame Streams STOP from {}: sending FINISH", ctx.channel().remoteAddress());
                    ctx.writeAndFlush(controlFrame(ctx, CONTROL_FINISH)).addListener(f -> ctx.executor().execute(ctx::close));
                } else {
                    ctx.executor().execute(ctx::close);
                }
            }
            case CONTROL_ACCEPT, CONTROL_FINISH -> { /* only meaningful for the sending side */ }
            default -> throw new CorruptedFrameException("unknown Frame Streams control type " + type);
        }
    }

    private static List<String> contentTypes(ByteBuf control) {
        final List<String> types = new java.util.ArrayList<>(1);
        while (control.readableBytes() >= 8) {
            final int fieldType = control.readInt();
            final long len = control.readUnsignedInt();
            if (len > control.readableBytes()) break;
            final String value = control.readCharSequence((int) len, StandardCharsets.US_ASCII).toString();
            if (fieldType == FIELD_CONTENT_TYPE) types.add(value);
        }
        return types;
    }

    private static ByteBuf controlFrame(ChannelHandlerContext ctx, int type) {
        final byte[] ct = DNSTAP_CONTENT_TYPE.getBytes(StandardCharsets.US_ASCII);
        final boolean withContentType = type == CONTROL_ACCEPT;
        final int controlLength = 4 + (withContentType ? 8 + ct.length : 0);
        final ByteBuf buf = ctx.alloc().buffer(8 + controlLength);
        buf.writeInt(0).writeInt(controlLength).writeInt(type);
        if (withContentType) {
            buf.writeInt(FIELD_CONTENT_TYPE).writeInt(ct.length).writeBytes(ct);
        }
        return buf;
    }
}
