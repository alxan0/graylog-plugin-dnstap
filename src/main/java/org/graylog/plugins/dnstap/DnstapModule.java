/*
 * Dnstap input for Graylog 7.1. MIT License.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.PluginModule;

public class DnstapModule extends PluginModule {
    @Override
    protected void configure() {
        addTransport("dnstap-fstrm", FstrmTransport.class);
        addCodec("dnstap", DnstapCodec.class);
        addMessageInput(DnstapInput.class);
    }
}
