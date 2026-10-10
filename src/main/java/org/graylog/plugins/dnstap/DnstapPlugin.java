/*
 * Dnstap input for Graylog 7.1. MIT License.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.List;

public class DnstapPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new DnstapPluginMetaData();
    }

    @Override
    public Collection<PluginModule> modules() {
        return List.of(new DnstapModule());
    }
}
