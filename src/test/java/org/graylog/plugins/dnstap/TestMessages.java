package org.graylog.plugins.dnstap;

import org.graylog2.plugin.MessageFactory;

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
