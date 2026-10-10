/*
 * Dnstap input for Graylog 7.1. MIT License.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.Counter;
import com.codahale.metrics.Histogram;
import com.codahale.metrics.MetricRegistry;

/**
 * Frame Streams level metrics of one input. They live in the transport's registry, which Graylog publishes under
 * the input: {@code org.graylog.plugins.dnstap.DnstapInput.<input id>.fstrm.*}.
 */
final class FstrmMetrics {
    final Counter frames;          // data frames handed to Graylog (one dnstap message each)
    final Counter ready;           // READY control frames (bidirectional handshakes)
    final Counter start;           // START control frames (streams started)
    final Counter stop;            // STOP control frames (orderly stream ends, e.g. BIND reload/shutdown)
    final Counter framingErrors;   // corrupt/oversized frames: the connection was closed
    final Histogram frameSize;     // bytes per data frame

    FstrmMetrics(MetricRegistry registry) {
        frames = registry.counter("fstrm.frames");
        ready = registry.counter("fstrm.control.ready");
        start = registry.counter("fstrm.control.start");
        stop = registry.counter("fstrm.control.stop");
        framingErrors = registry.counter("fstrm.errors.framing");
        frameSize = registry.histogram("fstrm.frameSize");
    }

    /** For tests and tools that don't need metrics. */
    static FstrmMetrics unregistered() {
        return new FstrmMetrics(new MetricRegistry());
    }
}
