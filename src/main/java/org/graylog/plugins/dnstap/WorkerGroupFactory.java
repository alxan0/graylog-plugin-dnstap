/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.InstrumentedExecutorService;
import com.codahale.metrics.InstrumentedThreadFactory;
import com.codahale.metrics.MetricRegistry;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.IoHandlerFactory;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.epoll.EpollIoHandler;
import io.netty.channel.kqueue.KQueueIoHandler;
import io.netty.channel.nio.NioIoHandler;
import org.graylog2.inputs.transports.NettyTransportConfiguration;
import org.graylog2.inputs.transports.netty.EventLoopGroupFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The input's worker event loop group, built like Graylog 7.1's EventLoopGroupFactory (same thread names, metric
 * names and transport type), except that its thread pool is shut down when the group terminates.
 * <p>
 * Graylog's factory gives each group a fixed thread pool that nothing ever shuts down. AbstractTcpTransport.stop()
 * only shuts down the group, so every start of a TCP input leaves its worker threads idle forever. They keep the old
 * transport and its metric registry reachable: about 12 threads and 0.7 MB of heap per restart, in a lab test.
 */
final class WorkerGroupFactory extends EventLoopGroupFactory {
    private final NettyTransportConfiguration configuration;

    WorkerGroupFactory(NettyTransportConfiguration configuration) {
        super(configuration);
        this.configuration = configuration;
    }

    @Override
    public EventLoopGroup create(int threads, MetricRegistry registry, String name) {
        final InstrumentedThreadFactory threadFactory = new InstrumentedThreadFactory(
                new ThreadFactoryBuilder().setNameFormat("netty-transport-%d").build(), registry, MetricRegistry.name(name, "thread-factory"));
        final ExecutorService pool = Executors.newFixedThreadPool(threads, threadFactory);
        final EventLoopGroup group = new MultiThreadIoEventLoopGroup(threads,
                new InstrumentedExecutorService(pool, registry, MetricRegistry.name(name, "executor-service")), ioHandlerFactory());
        group.terminationFuture().addListener(f -> pool.shutdown());
        return group;
    }

    private IoHandlerFactory ioHandlerFactory() {
        return switch (configuration.getType()) {
            case EPOLL -> EpollIoHandler.newFactory();
            case KQUEUE -> KQueueIoHandler.newFactory();
            case NIO -> NioIoHandler.newFactory();
        };
    }
}
