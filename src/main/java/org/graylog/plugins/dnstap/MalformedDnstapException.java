/*
 * Dnstap input for Graylog 7.1. MIT License.
 */
package org.graylog.plugins.dnstap;

/** A dnstap frame or the DNS message inside it could not be decoded. */
public class MalformedDnstapException extends RuntimeException {
    public MalformedDnstapException(String message) {
        super(message, null, false, false); // no stack trace: this is a data error, and it is cheap this way
    }
}
