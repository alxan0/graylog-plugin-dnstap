/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import org.graylog2.plugin.MessageFactory;

/** Graylog's DefaultMessageFactory for tests. */
final class TestMessages {
    static MessageFactory factory() {
        try {
            final var ctor = Class.forName("org.graylog2.plugin.DefaultMessageFactory").getDeclaredConstructor();
            ctor.setAccessible(true); // package-private: Graylog injects it
            return (MessageFactory) ctor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
