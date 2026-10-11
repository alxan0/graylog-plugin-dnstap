/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import io.netty.channel.EventLoopGroup;
import io.netty.util.concurrent.Future;
import org.graylog2.inputs.transports.NettyTransportConfiguration;
import org.graylog2.inputs.transports.netty.EventLoopGroupFactory;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.graylog2.plugin.system.SimpleNodeId;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Nothing of an input outlives its stop: codec metrics, and the worker threads of its event loop group. */
class InputLifecycleLeakTest {
    private static final SimpleNodeId NODE = new SimpleNodeId("test-node");
    private static final String ID = "5f0c0ffee0000000000000a1";

    private static void decode(MetricRegistry registry, byte[] frame) {
        final RawMessage raw = new RawMessage(frame, new InetSocketAddress("10.0.0.1", 1));
        raw.addSourceNode(ID, NODE);
        new DnstapCodec(new Configuration(Map.of()), TestMessages.factory(), registry).decodeSafe(raw);
    }

    private static boolean hasInputMetrics(MetricRegistry registry) {
        return registry.getNames().stream().anyMatch(n -> n.contains(ID));
    }

    @Test
    void lateMessagesOfAStoppedInputRegisterNoMetrics() throws Exception {
        final MetricRegistry registry = new MetricRegistry();
        final List<byte[]> frames = Fixture.frames();

        DnstapCodec.inputStarted(ID);
        for (int i = 0; i < 10; i++) {
            decode(registry, frames.get(i));
        }
        assertTrue(hasInputMetrics(registry), "a running input has its codec metrics");

        DnstapCodec.inputStopped(registry, ID);
        assertFalse(hasInputMetrics(registry), "removed on stop");
        // messages of the input still waiting in Graylog's journal are decoded after the stop (or delete)
        for (int i = 10; i < 20; i++) {
            decode(registry, frames.get(i));
        }
        assertFalse(hasInputMetrics(registry), "late messages must not re-create the metrics of a stopped input");

        DnstapCodec.inputStarted(ID);   // the input is started again
        decode(registry, frames.get(20));
        assertTrue(hasInputMetrics(registry), "a restarted input gets its metrics back");
        DnstapCodec.inputStopped(registry, ID);
        assertFalse(hasInputMetrics(registry));
    }

    /** Starts every worker thread of a group, shuts the group down, returns how many of its threads still run. */
    private static long runningAfterShutdown(EventLoopGroupFactory factory, MetricRegistry registry) throws Exception {
        final EventLoopGroup group = factory.create(4, registry, "workers");
        final List<Future<?>> started = new ArrayList<>();
        group.forEach(loop -> started.add(loop.submit(() -> { })));
        for (Future<?> f : started) {
            f.get(10, TimeUnit.SECONDS);
        }
        assertEquals(4, registry.meter("workers.thread-factory.created").getCount());
        assertTrue(group.shutdownGracefully(0, 1, TimeUnit.SECONDS).await(10, TimeUnit.SECONDS));
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (registry.counter("workers.thread-factory.running").getCount() > 0 && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        return registry.counter("workers.thread-factory.running").getCount();
    }

    @Test
    void workerThreadsEndWithTheirGroup() throws Exception {
        final NettyTransportConfiguration config = new NettyTransportConfiguration();
        final MetricRegistry ours = new MetricRegistry();
        assertEquals(0, runningAfterShutdown(new WorkerGroupFactory(config), ours), "worker threads left after the group terminated");
        assertEquals(4, ours.meter("workers.thread-factory.terminated").getCount());
        assertTrue(ours.getNames().contains("workers.executor-service.submitted"), "same executor metrics as Graylog's factory");

        // Graylog 7.1's own factory, for comparison: its pool is never shut down, so its threads stay (the leak)
        final long graylogs = runningAfterShutdown(new EventLoopGroupFactory(config), new MetricRegistry());
        System.out.println("worker threads still running after the group terminated: plugin's factory 0, Graylog's " + graylogs);
    }
}
