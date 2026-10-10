/*
 * Dnstap input for Graylog 7.1. MIT License.
 * Rewrite of sega-yarkin/graylog-plugin-dnstap (Copyright (c) 2016 Sergey I. Yarkin, MIT).
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.assistedinject.Assisted;
import jakarta.inject.Inject;
import org.graylog2.plugin.LocalMetricRegistry;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.MessageInput;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;

/** "Dnstap (Frame Streams/TCP)": accepts dnstap from BIND/Unbound/Knot via a Unix-socket-to-TCP relay, or from dnstap tools. */
public class DnstapInput extends MessageInput {
    private static final String NAME = "Dnstap (Frame Streams/TCP)";

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
    }

    @ConfigClass
    public static class Config extends MessageInput.Config {
        @Inject
        public Config(FstrmTransport.Factory transport, DnstapCodec.Factory codec) {
            super(transport.getConfig(), codec.getConfig());
        }
    }
}
