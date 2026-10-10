/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

/** A dnstap frame or the DNS message inside it could not be decoded. */
public class MalformedDnstapException extends RuntimeException {
    public MalformedDnstapException(String message) {
        super(message, null, false, false); // no stack trace: it reports bad data, not a bug, and stays cheap
    }
}
