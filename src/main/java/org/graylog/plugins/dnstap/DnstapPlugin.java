/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.List;

/** Plugin entry point, listed in META-INF/services/org.graylog2.plugin.Plugin. */
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
