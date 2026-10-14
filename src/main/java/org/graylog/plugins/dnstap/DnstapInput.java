/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.assistedinject.Assisted;
import jakarta.inject.Inject;
import org.graylog2.plugin.InputFailureRecorder;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.buffers.InputBuffer;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.MisfireException;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;

/**
 * The "Dnstap (Frame Streams/TCP)" input: dnstap from BIND, Unbound, Knot and others over TCP/TLS, usually through a
 * relay from the DNS server's Unix socket, or from dnstap tools.
 */
public class DnstapInput extends MessageInput {
    private static final String NAME = "Dnstap (Frame Streams/TCP)";

    private final MetricRegistry metricRegistry;

    @Inject
    public DnstapInput(@Assisted Configuration configuration,
                       FstrmTransport.Factory transportFactory,
                       DnstapCodec.Factory codecFactory,
                       Config config,
                       Descriptor descriptor,
                       MetricRegistry metricRegistry,
                       LocalMetricRegistry localRegistry,
                       ServerStatus serverStatus) {
        super(metricRegistry, configuration, transportFactory.create(configuration),
                localRegistry, codecFactory.create(configuration), config, descriptor, serverStatus);
        this.metricRegistry = metricRegistry;
    }

    @Override
    public void launch(InputBuffer buffer, InputFailureRecorder failureRecorder) throws MisfireException {
        FieldNames.reload();
        DnstapCodec.inputStarted(getId());
        super.launch(buffer, failureRecorder);
    }

    @Override
    public void stop() {
        super.stop();
        DnstapCodec.inputStopped(metricRegistry, getId());
    }

    @Override
    public void terminate() {
        super.terminate();
        DnstapCodec.inputStopped(metricRegistry, getId());
    }

    @FactoryClass
    public interface Factory extends MessageInput.Factory<DnstapInput> {
        @Override
        DnstapInput create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    public static class Descriptor extends MessageInput.Descriptor {
        public Descriptor() {
            super(NAME, false, "https://dnstap.info/");
        }

        @Override
        public String getDescription() {
            return "dnstap from BIND, Unbound, Knot, PowerDNS or CoreDNS, as Frame Streams over TCP/TLS (e.g. via a socat relay from the server's Unix socket)";
        }

        @Override
        public boolean isForwarderCompatible() {
            return false;
        }
    }

    @ConfigClass
    public static class Config extends MessageInput.Config {
        @Inject
        public Config(FstrmTransport.Factory transport, DnstapCodec.Factory codec) {
            super(transport.getConfig(), codec.getConfig());
        }
    }
}
