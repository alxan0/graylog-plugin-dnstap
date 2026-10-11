/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Set;

/** Plugin metadata; the versions come from graylog-plugin.properties, which Maven fills in from the pom. */
public class DnstapPluginMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.plugins.dnstap.graylog-plugin-dnstap/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.dnstap.DnstapPlugin";
    }

    @Override
    public String getName() {
        return "Dnstap Input";
    }

    @Override
    public String getAuthor() {
        return "alxan0 (rewrite of Sergey I. Yarkin's graylog-plugin-dnstap)";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/alxan0/graylog-plugin-dnstap");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(1, 0, 0, "unknown"));
    }

    @Override
    public String getDescription() {
        return "Dnstap (Frame Streams over TCP) input for Graylog 7.1";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(7, 1, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Set.of();
    }
}
