/*
 * graylog-plugin-dnstap: Dnstap input for Graylog 7.1. MIT License, see LICENSE.
 * Based on sega-yarkin/graylog-plugin-dnstap, Copyright (c) 2016 Sergey I. Yarkin.
 */
package org.graylog.plugins.dnstap;

import com.codahale.metrics.MetricRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufAllocatorMetricProvider;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ResourceLeakDetector;
import io.netty.util.ResourceLeakDetectorFactory;
import io.netty.util.internal.PlatformDependent;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.journal.RawMessage;
import org.graylog2.plugin.system.SimpleNodeId;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Long-running leak test (opt-in: -Dleak.soak=true; run alone with -Dtest=LeakSoakTest so that the leak detector
 * factory below is installed before any ByteBuf class is initialised).
 * <p>
 * Simulates what Graylog does with many inputs over a long uptime: per input a transport registry with FstrmMetrics,
 * connections (an FstrmFrameDecoder per connection, on Netty's default allocator with direct buffers), a NEW
 * DnstapCodec per message (as DecodingProcessor does), messages carrying the input id, then the input's stop
 * (DnstapCodec.inputStopped, as DnstapInput.stop() calls it). After every round: forced GC, heap/old gen used, static cache sizes (reflection),
 * registry size, Netty direct memory, leak reports.
 */
@EnabledIfSystemProperty(named = "leak.soak", matches = "true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LeakSoakTest {
    static final AtomicLong LEAKS = new AtomicLong();
    static final List<String> LEAK_TEXT = new ArrayList<>();

    static {
        // counting reporter, installed before AbstractByteBuf creates its detector
        ResourceLeakDetectorFactory.setResourceLeakDetectorFactory(new ResourceLeakDetectorFactory() {
            @Override
            @SuppressWarnings("deprecation")
            public <T> ResourceLeakDetector<T> newResourceLeakDetector(Class<T> resource, int samplingInterval, long maxActive) {
                return new ResourceLeakDetector<T>(resource, samplingInterval) {
                    @Override
                    protected void reportTracedLeak(String resourceType, String records) {
                        LEAKS.incrementAndGet();
                        synchronized (LEAK_TEXT) {
                            if (LEAK_TEXT.size() < 5) {
                                LEAK_TEXT.add(resourceType + records);
                            }
                        }
                        super.reportTracedLeak(resourceType, records);
                    }

                    @Override
                    protected void reportUntracedLeak(String resourceType) {
                        LEAKS.incrementAndGet();
                        super.reportUntracedLeak(resourceType);
                    }
                };
            }
        });
    }

    private static final SimpleNodeId NODE = new SimpleNodeId("leak-test-node");

    private static byte[] control(int type, String contentType) {
        final byte[] ct = contentType == null ? new byte[0] : contentType.getBytes(StandardCharsets.US_ASCII);
        final int len = 4 + (ct.length > 0 ? 8 + ct.length : 0);
        final java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(8 + len).putInt(0).putInt(len).putInt(type);
        if (ct.length > 0) {
            b.putInt(FstrmFrameDecoder.FIELD_CONTENT_TYPE).putInt(ct.length).put(ct);
        }
        return b.array();
    }

    @SuppressWarnings("unchecked")
    private static ConcurrentMap<MetricRegistry, ConcurrentMap<String, ?>> metricsCache() throws Exception {
        final Field f = DnstapCodec.class.getDeclaredField("METRICS");
        f.setAccessible(true);
        return (ConcurrentMap<MetricRegistry, ConcurrentMap<String, ?>>) f.get(null);
    }

    @SuppressWarnings("unchecked")
    private static int skipCacheSize() throws Exception {
        final Field f = DnstapCodec.class.getDeclaredField("SKIP_TYPES");
        f.setAccessible(true);
        return ((Map<String, ?>) f.get(null)).size();
    }

    private static long[] heapAfterGc() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            System.gc();
            Thread.sleep(100);
        }
        long old = -1;
        for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
            if (p.getName().contains("Old Gen") || p.getName().contains("Tenured")) {
                old = p.getUsage().getUsed();
            }
        }
        return new long[] {ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed(), old};
    }

    private static long allocatorUsedDirect(ByteBufAllocator a) {
        return a instanceof ByteBufAllocatorMetricProvider p ? p.metric().usedDirectMemory() : -1;
    }

    /** One connection of input ID: the stream in random chunks of direct buffers, each frame decoded by a new codec. */
    private static int connection(ByteBufAllocator alloc, byte[] stream, Random rnd, String inputId, FstrmMetrics fm,
                                  MetricRegistry registry, Configuration config, boolean closeEarly) {
        final EmbeddedChannel ch = new EmbeddedChannel();
        ch.config().setAllocator(alloc);
        ch.pipeline().addLast(new FstrmFrameDecoder(FstrmTransport.DEFAULT_MAX_FRAME_SIZE, fm));
        int msgs = 0;
        final int stop = closeEarly ? rnd.nextInt(stream.length + 1) : stream.length;
        for (int off = 0; off < stop && ch.isOpen(); ) {
            final int n = Math.min(stop - off, 1 + rnd.nextInt(4096));
            ch.writeInbound(alloc.directBuffer(n).writeBytes(stream, off, n));
            off += n;
            ch.runPendingTasks();
            ByteBuf b;
            while ((b = ch.readInbound()) != null) {
                final byte[] payload = new byte[b.readableBytes()];   // Graylog's RawMessageHandler copies, then releases
                b.readBytes(payload);
                b.release();
                final RawMessage raw = new RawMessage(payload, new InetSocketAddress("10.251.2.53", 40000));
                raw.addSourceNode(inputId, NODE);
                try {
                    if (new DnstapCodec(config, TestMessages.factory(), registry).decodeSafe(raw).isPresent()) {
                        msgs++;
                    }
                } catch (RuntimeException e) {
                    // InputProcessingException only for broken frames; the capture has none
                    throw new AssertionError("unexpected decode failure", e);
                }
            }
            while ((b = ch.readOutbound()) != null) {
                b.release();
            }
        }
        ch.finishAndReleaseAll();
        return msgs;
    }

    private static String randomId(Random rnd) {
        final StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++) {
            sb.append(Character.forDigit(rnd.nextInt(16), 16));
        }
        return sb.toString();
    }

    @Test
    @Order(1)
    void manyInputsManyFramesStayBounded() throws Exception {
        final int rounds = Integer.getInteger("leak.rounds", 40);
        final int inputsPerRound = Integer.getInteger("leak.inputs", 100);
        final int connsPerInput = Integer.getInteger("leak.conns", 3);
        final MetricRegistry registry = new MetricRegistry();       // Graylog's global registry
        final Random rnd = new Random(20261011L);
        final byte[] file = Fixture.bytes();
        final byte[] ready = control(FstrmFrameDecoder.CONTROL_READY, FstrmFrameDecoder.DNSTAP_CONTENT_TYPE);
        final byte[] bidi = new byte[ready.length + file.length];
        System.arraycopy(ready, 0, bidi, 0, ready.length);
        System.arraycopy(file, 0, bidi, ready.length, file.length);
        final ByteBufAllocator[] allocs = {ByteBufAllocator.DEFAULT, PooledByteBufAllocator.DEFAULT};

        // a long-lived input that never stops (its metrics must stay, and its cache entry stays at one)
        final String permanent = "000000000000000000000000";
        final MetricRegistry permanentLocal = new MetricRegistry();
        final FstrmMetrics permanentFm = new FstrmMetrics(permanentLocal);
        DnstapCodec.inputStarted(permanent);

        System.out.println("leak.level=" + ResourceLeakDetector.getLevel() + " allocator.default=" + ByteBufAllocator.DEFAULT.getClass().getSimpleName()
                + " maxDirect=" + PlatformDependent.maxDirectMemory() + " noCleaner=" + PlatformDependent.useDirectBufferNoCleaner());
        System.out.println("round,frames_total,messages_total,heap_after_gc_kb,old_gen_kb,registry_names,metrics_cache_inputs,skip_cache,netty_used_direct,alloc_default_direct,alloc_pooled_direct,leaks,ms");
        long frames = 0;
        long messages = 0;
        final long[] firstHeap = new long[2];
        long lastHeap = 0;
        final List<Long> heaps = new ArrayList<>();
        final long t0 = System.currentTimeMillis();
        for (int r = 1; r <= rounds; r++) {
            final long tr = System.currentTimeMillis();
            for (int i = 0; i < inputsPerRound; i++) {
                final String id = randomId(rnd);
                DnstapCodec.inputStarted(id);                        // DnstapInput.launch()
                final MetricRegistry local = new MetricRegistry();   // the transport's LocalMetricRegistry
                final FstrmMetrics fm = new FstrmMetrics(local);
                final Map<String, Object> cfg = new HashMap<>();
                // every input has its own "Skip message types" text: the static cache must stay bounded
                cfg.put(DnstapCodec.CK_SKIP_TYPES, (i % 3 == 0) ? "" : "AQ, FR, X" + rnd.nextInt(1_000_000));
                cfg.put(DnstapCodec.CK_INCLUDE_ANSWERS, i % 2 == 0);
                final Configuration config = new Configuration(cfg);
                for (int c = 0; c < connsPerInput; c++) {
                    messages += connection(allocs[(i + c) & 1], (c & 1) == 0 ? bidi : file, rnd, id, fm, registry, config, c == connsPerInput - 1 && rnd.nextBoolean());
                }
                frames += fm.frames.getCount();
                DnstapCodec.inputStopped(registry, id);              // DnstapInput.stop()/terminate()
                // the permanent input receives one connection per simulated input
                messages += connection(ByteBufAllocator.DEFAULT, bidi, rnd, permanent, permanentFm, registry, new Configuration(Map.of()), false);
                frames += 629;
            }
            final long[] h = heapAfterGc();
            if (r == 1) {
                firstHeap[0] = h[0];
                firstHeap[1] = h[1];
            }
            lastHeap = h[0];
            heaps.add(h[0]);
            final ConcurrentMap<String, ?> byInput = metricsCache().get(registry);
            System.out.printf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d%n", r, frames, messages, h[0] / 1024, h[1] / 1024, registry.getNames().size(),
                    byInput == null ? 0 : byInput.size(), skipCacheSize(), PlatformDependent.usedDirectMemory(),
                    allocatorUsedDirect(ByteBufAllocator.DEFAULT), allocatorUsedDirect(PooledByteBufAllocator.DEFAULT), LEAKS.get(),
                    System.currentTimeMillis() - tr);
        }
        System.out.println("total " + frames + " frames, " + messages + " messages, " + (rounds * inputsPerRound) + " inputs created and stopped, "
                + (System.currentTimeMillis() - t0) / 1000 + " s");
        synchronized (LEAK_TEXT) {
            LEAK_TEXT.forEach(System.out::println);
        }
        final ConcurrentMap<String, ?> byInput = metricsCache().get(registry);
        assertEquals(1, byInput.size(), "only the permanent input stays in the codec metrics cache");
        assertTrue(byInput.containsKey(permanent));
        // what is left in the global registry: only the permanent input's codec metrics
        registry.getNames().forEach(n -> assertTrue(n.contains(permanent), "left over: " + n));
        assertTrue(skipCacheSize() <= 33, "skip cache bounded");
        assertEquals(0, LEAKS.get(), "Netty leak reports");
        // heap after GC: the second half of the run must not sit above the first half by more than 16 MB
        final long firstHalf = heaps.subList(1, heaps.size() / 2).stream().mapToLong(Long::longValue).max().orElse(0);
        final long secondHalfMin = heaps.subList(heaps.size() / 2, heaps.size()).stream().mapToLong(Long::longValue).min().orElse(0);
        System.out.println("heap after GC: first round " + firstHeap[0] / 1024 + " KB, max of rounds 2.." + heaps.size() / 2 + " " + firstHalf / 1024
                + " KB, min of the second half " + secondHalfMin / 1024 + " KB, last " + lastHeap / 1024 + " KB");
        assertTrue(secondHalfMin <= firstHalf + 16L * 1024 * 1024, "heap floor rising");
    }
}
