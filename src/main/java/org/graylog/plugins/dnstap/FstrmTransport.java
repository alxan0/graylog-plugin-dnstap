/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.google.inject.assistedinject.Assisted;
import io.netty.channel.ChannelHandler;
import io.netty.channel.EventLoopGroup;
import jakarta.inject.Inject;
import org.graylog2.configuration.TLSProtocolsConfiguration;
import org.graylog2.inputs.transports.NettyTransportConfiguration;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.MisfireException;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.transports.AbstractTcpTransport;
import org.graylog2.plugin.inputs.transports.Transport;
import org.graylog2.plugin.inputs.util.ThroughputCounter;
import org.graylog2.security.encryption.EncryptedValueService;

import java.util.LinkedHashMap;
import java.util.concurrent.Callable;

/** Graylog's TCP transport (TLS, keepalive, worker threads, receive buffer) plus the Frame Streams decoder. */
public class FstrmTransport extends AbstractTcpTransport {
    static final String CK_MAX_FRAME_SIZE = "max_frame_size";
    static final int DEFAULT_PORT = 6000;
    // A dnstap frame holds at most a 64 KiB query, a 64 KiB response and a small envelope (~130 KB). The limit is also
    // how much an incomplete frame may hold in memory per connection, so it stays near that size.
    static final int DEFAULT_MAX_FRAME_SIZE = 256 * 1024;
    static final int MIN_MAX_FRAME_SIZE = 65_535 + 1024;
    static final int MAX_MAX_FRAME_SIZE = 16 * 1024 * 1024;

    private final int maxFrameSize;
    private final FstrmMetrics metrics;

    @Inject
    public FstrmTransport(@Assisted Configuration configuration,
                          EventLoopGroup eventLoopGroup,
                          NettyTransportConfiguration nettyTransportConfiguration,
                          ThroughputCounter throughputCounter,
                          LocalMetricRegistry localRegistry,
                          TLSProtocolsConfiguration tlsConfiguration,
                          EncryptedValueService encryptedValueService) {
        // WorkerGroupFactory instead of Graylog's EventLoopGroupFactory, whose worker thread pools are never shut down
        super(configuration, throughputCounter, localRegistry, eventLoopGroup, new WorkerGroupFactory(nettyTransportConfiguration),
                nettyTransportConfiguration, tlsConfiguration, encryptedValueService);
        // clamped: a DNS message is at most 64 KiB (+ dnstap envelope); a value of 0 or less would reject every frame
        this.maxFrameSize = Math.min(MAX_MAX_FRAME_SIZE, Math.max(MIN_MAX_FRAME_SIZE, configuration.getInt(CK_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE)));
        this.metrics = new FstrmMetrics(localRegistry);   // Graylog publishes this registry under the input
    }

    @Override
    public void launch(MessageInput input) throws MisfireException {
        throughputCounter.trafficCounter().start();   // no-op unless this transport was stopped before
        super.launch(input);
    }

    @Override
    public void stop() {
        super.stop();
        // Graylog never releases it: its once-a-second task would keep running, holding this transport, forever
        throughputCounter.release();
    }

    @Override
    protected LinkedHashMap<String, Callable<? extends ChannelHandler>> getCustomChildChannelHandlers(MessageInput input) {
        final LinkedHashMap<String, Callable<? extends ChannelHandler>> handlers = new LinkedHashMap<>(super.getCustomChildChannelHandlers(input));
        handlers.put("fstrm", () -> new FstrmFrameDecoder(maxFrameSize, metrics));
        return handlers;
    }

    @FactoryClass
    public interface Factory extends Transport.Factory<FstrmTransport> {
        @Override
        FstrmTransport create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends AbstractTcpTransport.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest cr = super.getRequestedConfiguration();
            if (cr.containsField(CK_PORT)) {
                cr.getField(CK_PORT).setDefaultValue(DEFAULT_PORT);
            }
            // A relay that vanishes without FIN/RST (host down, network cut, NAT timeout) would leave a half-open
            // connection and its buffers here forever; keepalive lets the kernel detect and close it.
            if (cr.containsField(CK_TCP_KEEPALIVE)) {
                cr.getField(CK_TCP_KEEPALIVE).setDefaultValue(true);
            }
            cr.addField(new NumberField(CK_MAX_FRAME_SIZE, "Maximum frame size", DEFAULT_MAX_FRAME_SIZE,
                    "Largest accepted Frame Streams data frame in bytes (one dnstap message; DNS messages are at most 64 KiB). "
                            + "Kept between " + MIN_MAX_FRAME_SIZE + " and " + MAX_MAX_FRAME_SIZE + ".",
                    ConfigurationField.Optional.OPTIONAL, NumberField.Attribute.ONLY_POSITIVE));
            return cr;
        }
    }
}
