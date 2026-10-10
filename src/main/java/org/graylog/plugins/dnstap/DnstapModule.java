/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.PluginModule;

/** Registers the Frame Streams transport, the dnstap codec and the Dnstap input with Graylog. */
public class DnstapModule extends PluginModule {
    @Override
    protected void configure() {
        addTransport("dnstap-fstrm", FstrmTransport.class);
        addCodec("dnstap", DnstapCodec.class);
        addMessageInput(DnstapInput.class);
    }
}
