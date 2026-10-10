/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import com.google.inject.assistedinject.Assisted;
import io.netty.channel.ChannelHandler;
import io.netty.channel.EventLoopGroup;
import jakarta.inject.Inject;
import org.graylog2.configuration.TLSProtocolsConfiguration;
import org.graylog2.inputs.transports.NettyTransportConfiguration;
import org.graylog2.inputs.transports.netty.EventLoopGroupFactory;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.transports.AbstractTcpTransport;
import org.graylog2.plugin.inputs.transports.NettyTransport;
import org.graylog2.plugin.inputs.transports.Transport;
import org.graylog2.plugin.inputs.util.ThroughputCounter;
import org.graylog2.security.encryption.EncryptedValueService;

import java.util.LinkedHashMap;
import java.util.concurrent.Callable;

/** Graylog's TCP transport (TLS, keepalive, worker threads, receive buffer) plus the Frame Streams decoder. */
public class FstrmTransport extends AbstractTcpTransport {
    static final String CK_MAX_FRAME_SIZE = "max_frame_size";
    static final int DEFAULT_PORT = 6000;
    static final int DEFAULT_MAX_FRAME_SIZE = 1024 * 1024;

    private final int maxFrameSize;

    @Inject
    public FstrmTransport(@Assisted Configuration configuration,
                          EventLoopGroup eventLoopGroup,
                          EventLoopGroupFactory eventLoopGroupFactory,
                          NettyTransportConfiguration nettyTransportConfiguration,
                          ThroughputCounter throughputCounter,
                          LocalMetricRegistry localRegistry,
                          TLSProtocolsConfiguration tlsConfiguration,
                          EncryptedValueService encryptedValueService) {
        super(configuration, throughputCounter, localRegistry, eventLoopGroup, eventLoopGroupFactory,
                nettyTransportConfiguration, tlsConfiguration, encryptedValueService);
        this.maxFrameSize = configuration.getInt(CK_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE);
    }

    @Override
    protected LinkedHashMap<String, Callable<? extends ChannelHandler>> getCustomChildChannelHandlers(MessageInput input) {
        final LinkedHashMap<String, Callable<? extends ChannelHandler>> handlers = new LinkedHashMap<>(super.getCustomChildChannelHandlers(input));
        handlers.put("fstrm", () -> new FstrmFrameDecoder(maxFrameSize));
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
            if (cr.containsField(NettyTransport.CK_PORT)) {
                cr.getField(NettyTransport.CK_PORT).setDefaultValue(DEFAULT_PORT);
            }
            cr.addField(new NumberField(CK_MAX_FRAME_SIZE, "Maximum frame size", DEFAULT_MAX_FRAME_SIZE,
                    "Largest accepted Frame Streams data frame in bytes (one dnstap message; DNS messages are at most 64 KiB).",
                    ConfigurationField.Optional.OPTIONAL));
            return cr;
        }
    }
}
