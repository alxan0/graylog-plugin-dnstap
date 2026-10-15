# graylog-plugin-dnstap 1.2.0: production readiness

This report collects the lab tests behind each release, newest first. Settings, fields and metrics are described in
[docs/reference.md](docs/reference.md).

## Test setup

The lab is built like a production deployment:

| Component | Version |
|---|---|
| Graylog | 7.1.10 with one Data Node and a MongoDB cluster, 2 GB heap (512 MB for the 1.1.0 tests); 7.2.0 with Data Node 7.2.0 for 1.2.0 |
| BIND | 9.20.29-1~deb13u1 (Debian 13) |
| Host | 12 CPUs, 9 GB (15 GB for the Graylog 7.2.0 tests) |

Unless a test says otherwise, it used the recommended setup from the README:
- dnstap over TLS with required client certificates
- `fstrm-set-input-queue-size 16384`
- a socat relay with `retry=120,interval=1`

The load came from `dnsperf` with uniquely named queries. Each query was counted exactly at every hop: dnsperf,
BIND's counters, the input's counters, and an exact OpenSearch count by query name. The 1.0.x tests ran on
2026-10-10/11.

## Verdict

Ready for production, under the operating conditions below.

| Area | Result |
|---|---|
| Delivery | lossless at every tested rate up to Graylog's capacity; 54,000,000 of 54,000,000 in a 3 h soak at 5,000 q/s (1.0.6) |
| Restarts (2,000 q/s) | a Graylog restart loses 31 events, a stopped input 56, a killed relay 23, a named restart 0 (1.0.3) |
| Faults | every injected fault is detected and reported (1.0.3) |
| Leaks | none in the data path; the input restart leaks found on 1.0.6 are fixed; threads stay flat over 60 restarts (1.0.7), heap and plugin instances over 22 (1.1.0) and 30 (1.2.0) |
| Security | no code execution, out-of-bounds read, input crash or super-linear CPU found; four problems fixed (1.2.0) |
| Graylog 7.2.0 | the 1.2.0 jar works unchanged |

Operating conditions:
1. **Size Graylog and OpenSearch for the peak rate.** The plugin isn't the bottleneck: it decodes ~240k frames/s per
   core, and BIND + relay export losslessly up to 30k q/s. On the lab's size, Graylog keeps up to ~10k q/s; beyond
   that its journal grows, losslessly but with delay. A large resolver (e.g. ~10-20k q/s at peak) needs a bigger
   Graylog than the lab, and ~200 bytes of storage per event.
2. **Use the queue and retry settings.** Without them, a Graylog restart loses ~29k events at 2k q/s, as UDP syslog
   does, and silently.
3. **Monitor with `monitor/dnstap-health`** (cron, Nagios, Icinga, Zabbix), and add the Graylog alert from
   `monitor/create-graylog-alerts` as a second check. The alert only works on a cluster that also receives other
   logs (see finding 1 below).
4. **Keep exactly one plugin jar** in the plugin directory.

## Findings

These are Graylog behaviours, not plugin bugs, found during the 1.0.3 tests:

1. **The Graylog "no messages" alert doesn't fire on an otherwise idle Graylog.** In Graylog 7.1.10 an aggregation
   window runs only after a message received after the window start has been indexed somewhere:
   `EventProcessorDependencyCheck` needs `SOME_UP_TO_DATE`, and `ALL_IDLE` waits. On a Graylog that only received
   dnstap, the alert never fired in 330 s. With other syslog traffic flowing, as in production, it fired after 136 s.
   That is why `dnstap-health`, which has no such dependency, is the primary check.
2. **Webhook notifications are blocked by Graylog's URL allowlist**, which 7.x enables by default ("URL ... is not
   allowlisted"). `create-graylog-alerts` adds the webhook to the allowlist.
3. **Counters reset.** An input restart recreates its metrics at 0, and a named restart resets `DNSTAPdropped`.
   `dnstap-health` treats a lower value as a reset, so errors after it aren't missed.

Expected behaviour worth knowing:
- **Event lag p95 is ~1 s at low rates.** named sends a partly filled buffer once per
  `fstrm-set-output-flush-timeout` (1 s).
- **After an outage, events arrive late with their original timestamps.** BIND's queue replays them, so a few
  messages appear inside an outage window afterwards.
- **`dnstap-health`'s 1-minute rate is an EWMA.** It needs about a minute after a start or a recovery to reach the
  real rate, so keep `--min-rate` well below normal traffic.

## 1.2.0

1.2.0 adds the EDNS fields `dns_edns`, `dns_edns_version`, `dns_do_bit` and `dns_ecs` for queries, read from the OPT
record, and fixes the problems found by a security review.

### EDNS fields compared with BIND's query log

BIND 9.20.29 wrote its query log (to syslog) and dnstap for the same queries at once, with two views and DoT and DoH
listeners. 28 kinds of query were sent from two clients: RD off, DO, CD, no EDNS, ECS over IPv4, IPv6 and DoH, TCP,
DoT, DoH, TSIG-signed, EDNS version 1, no cookie, CH class, and ANY, MX, TXT, CAA, HTTPS, PTR, deep and mixed-case
names.

- The fields a pipeline derives from each query log line were compared with the plugin's fields (`dns_rd`,
  `dns_cd_bit` and `dns_tcp` derived from `dns_flags` and `socket_protocol`). 54 of 56 queries were identical on all
  22 fields; the other 2 are CH-class queries, for which BIND has no view. `dns_ecs` matched BIND's `[ECS ...]`
  marker.
- A query with EDNS version 1 is answered BADVERS before both query logging and dnstap (as BIND's source says), so
  neither shows it. dig then retries with version 0, and that retry is one of the 54 identical queries.
- The comparison gave the same result on Graylog 7.1.10 and 7.2.0, and again on 7.2.0 after the security fixes.

### Load

| Run | Result |
|---|---|
| 5,000 q/s for 2 min, default 512-frame BIND queue | every query BIND exported (600,000 minus the 25 counted in `DNSTAPdropped`) stored with its EDNS fields, 0 codec failures |
| 5,000 q/s for 2 min on Graylog 7.2.0 | 600,000 of 600,000 queries stored with their EDNS fields, 0 codec failures |
| 30,000 q/s for 5 min on Graylog 7.2.0, queue 16384 and relay retry, Netty leak detector on | every query BIND exported stored (8,950,713; dnsperf's other 49,287 never reached BIND), 0 dropped by BIND. Each query carried EDNS, DO and ECS and a name starting with its type: 0 stored messages disagree with their own name or settings. Graylog processed about 8,300 messages/s, so its journal peaked at 7.3 million and drained 12.5 min after the load. Heap after a full GC 120.9 MB before and 122.5 MB after; 0 codec failures, framing errors, Netty leak reports or ERROR lines |

### Restarts and leaks on Graylog 7.2.0

30 input restarts under 500 q/s, with `dnstap-fields.conf` cycling through a valid file, an invalid file, no file and
a FIFO:

| Check | Result |
|---|---|
| Heap after a full GC | 125.2 MB before, 128.5 MB after |
| Plugin class instances | one of each |
| File descriptors | 240, then 242 |
| Threads | settle at the same count after each restart |
| Netty leak reports, ERROR lines | 0, 0 |

### Graylog 7.2.0 compatibility

The 1.2.0 jar, built against 7.1.10 as released, was tested on Graylog 7.2.0 with Data Node 7.2.0. The code was also
compiled and unit-tested against the 7.2.0 `graylog.jar`. Against 7.2.0, these pass: the unit tests, static analysis
(no deprecated or removed Graylog API in use), 3,000,000 fuzz iterations and the leak soak test (heap after GC 46.1 MB
in the first round, 46.3 MB in the last). The query log comparison, the 5,000 q/s run and the restart test above also
ran on 7.2.0.

The final 1.2.0 jar was also run on Graylog 7.1.10: the query log comparison (54 of 56 identical, as on 7.2.0), the
READY flood (1 ACCEPT, connection closed), 5,000 q/s for 1 minute (300,000 of 300,000 stored and enriched) and 24
input restarts under load with the same `dnstap-fields.conf` cycle. Live heap objects after a full GC were 136.1 MB
before the last 12 restarts and 139.0 MB after, with the same number of instances of every plugin class; threads
stayed at 296 and the `netty-transport` group at 37 across further restarts; 0 Netty leak reports, ERROR lines or
codec failures.

Graylog 7.2.0 itself needs the MongoDB role `dbAdmin` on its database besides `readWrite`: it runs `collMod` on
`cluster_events` at startup and does not start without it.

### Security review

A code review plus live attacks on the input in the Graylog 7.2.0 lab: hostile framing, 2,000 undecodable frames,
300 parallel connections, 100 connections each holding an incomplete 256 KiB frame, a READY flood, and hostile DNS
and EDNS content.

It found no code execution, out-of-bounds read, input crash or super-linear CPU. It found four problems, all fixed in
1.2.0 with tests (`HardeningTest`, `FstrmFrameDecoderTest`):

| Problem | Fix |
|---|---|
| Every Frame Streams READY was answered with ACCEPT, so a sender that never read the replies could make the input queue ACCEPT frames without limit | a second READY closes the connection; 200,000 READY frames on one connection get one ACCEPT |
| dnstap identity and version had no length cap; a 40,000-byte value made the message fail to index | capped at 255 bytes |
| A broken answer record dropped the whole message | it only ends the answer list |
| The text caps could cut a surrogate pair in half; an emoji in a TXT answer made Graylog's search API return invalid JSON | a surrogate pair is never split |

After the fixes, the query log comparison and the READY flood were re-run on Graylog 7.2.0 with the same results.

Two issues remain. They are documented in [docs/reference.md](docs/reference.md#security) and can't be fixed in the
plugin without a design change:
- Graylog sets no connection limit and no timeout for incomplete frames, so many connections can each hold up to
  *Maximum frame size* of memory.
- Undecodable frames produce Graylog ERROR log lines.

Both are reachable without authentication when TLS client authentication is off, which is Graylog's default. Use TLS
client authentication and a firewall.

## 1.1.0

1.1.0 renames three fields, adds `dnstap: true` and reads `dnstap-fields.conf` (see the README). It was tested on
Graylog 7.1.10 with a 512 MB heap, the "DNS dnstap" pipeline attached to the stream, and Netty's paranoid leak
detector on.

### 1-hour soak

300 q/s of uniquely named queries (queries and responses, 600 messages/s) plus 30 syslog query lines/s through the
syslog pipeline. The input was restarted every 10 minutes with a changing `dnstap-fields.conf`: a valid mapping, an
invalid file, no file and a FIFO.

| Check | Result |
|---|---|
| Queries delivered | 1,079,974 of 1,080,000; responses 1,079,950 of 1,080,000. The missing ones fall in the 7 input restarts |
| Syslog lines delivered and enriched | 108,000 of 108,000 |
| Codec failures, framing errors, processing errors | 0, 0, 0 |
| Netty leak reports, Graylog ERROR lines | 0, 0 |
| Input restarts | 7 of 7 RUNNING; each file case logged as intended, defaults used for the invalid file and the FIFO |
| File descriptors | 260 to 265 |
| RSS | 962 MB down to 889 MB |
| Threads | grow by 6 over the first restarts as the worker loops start, then flat over 10 more restarts |
| Heap after a full GC (`jcmd GC.run`) | 141.8 MB after the soak; 139.3 MB after another 10 minutes at 300 q/s with 5 more restarts |
| Plugin class instances | one of each (input, transport, frame decoder, metrics) after 22 restarts, so no old input survives |

### Review and stress test of the new code

Done before the soak:
- About 90 malformed `dnstap-fields.conf` variants (binary, 100 MB, wrong encodings, device and FIFO symlinks, loops,
  no permission, log-forging attempts): each one ignored and reported, the input always RUNNING.
- 10.2M messages decoded while the names were reloaded 676,000 times, and 12 input restarts under 3,000 q/s (75,241
  messages): no message with mixed names.
- Two problems found and fixed before release: a FIFO as the file blocked the input's start, and names reserved by
  OpenSearch (`_routing`, ...) or managed by Graylog (`streams`) were accepted.
- The unit tests, the analysis profile, 3,000,000 fuzz iterations and the opt-in `LeakSoakTest` (8.8M messages, heap
  flat) pass.

## 1.0.7

A leak test on 1.0.6 stopped and started the input 120 times under 2,000 q/s, created and deleted a second input 100
times, killed the relay 40 times and restarted BIND 8 times. It took class histograms and a heap dump from the live
Graylog, with Netty's paranoid leak detector on. It found no leak in the plugin's data path, and two leaks around
input restarts, both fixed in 1.0.7:

| Finding | 1.0.6 | 1.0.7 (same test) |
|---|---|---|
| Graylog 7.1.10 never shuts down an input's worker thread pool; every TCP input leaks its worker threads and old transport on each start | +12 threads and +0.7 MB heap per restart | flat over 60 restarts (211 -> 255 threads as the worker loops start once, then no growth); Graylog's own GELF input, as a control, still +12 per restart |
| Deleting an input while its messages wait in the journal re-creates its codec metrics | 11 metrics per input, forever | 0 |
| Netty leak reports, Graylog ERRORs | 0, 0 | 0, 0 |

In-process, 1,000 inputs created and stopped with 2.3M frames:
- Heap after GC: 48,720 -> 48,742 KB.
- Registry and cache: only the permanent input's metrics, 1 cache entry.
- Direct memory: constant, 0 leak reports.

Still open in Graylog, not in the plugin: Graylog keeps its own two per-input decoding metrics (`parseTime`,
`processedMessages`) after an input is deleted.

## 1.0.4 to 1.0.6

- 1.0.4: fixes from static analysis and a review for long uptime (metric cleanup, keepalive, close handling, log
  sanitising).
- 1.0.5: fixes a CPU amplification. A crafted 400 KB frame took 146 ms to decode; it now takes under 1 ms.
- 1.0.6: escapes sender-chosen text in fields and lowers the default frame limit to 256 KiB.

None of them changes the data path's design. Re-verified on 1.0.6:

| Test | Result |
|---|---|
| Unit tests | 37 pass, including CPU worst cases, buffer lifecycle and field injection |
| Unit tests under Netty's paranoid leak detector, 3,000,000 fuzz iterations | 0 leak reports, 0 reference-count errors |
| Buffer lifecycle on pooled direct memory: every decoder path, 20,000 mutated streams (3.5M frames) | every buffer released exactly once |
| Static analysis: Error Prone, SpotBugs + FindSecBugs, PMD | no new findings; the remaining ones are reviewed in [docs/reference.md](docs/reference.md#static-analysis) |
| Live, against Graylog 7.1.10 with Netty's paranoid leak detector | TLS 6/6; events lost on an input stop 1, Graylog restart 32, relay kill 24, named restart 0, all recovered by themselves; monitoring 9/9; quick throughput 1k/4k/8k q/s at 100.000 %; 0 leak reports, and every ERROR line came from a fault the tests injected |
| 3 h soak at 5,000 q/s over TLS, queue + retry, paranoid leak detector | 54,000,000 answered, 54,000,000 delivered, 0 lost; 36/36 windows OK; 0 BIND drops, 0 decode failures |
| Graylog log during the soak | 238 lines: 0 ERROR, 0 WARN, 0 leak reports |
| Resources over 3 h (first vs last hour) | old gen after GC 203 -> 186 MB, heap 885 -> 737 MB, Graylog RSS 2.24 -> 2.02 GB, threads 428 -> 428, FDs 342 -> 341: no growth |
| Journal during the soak | median 1 uncommitted message; peaks up to 13,648 (< 3 s of traffic) during index rotations, always drained |

A CPU profile under 8,000 messages/s puts the plugin at 1.3 % of Graylog's CPU, so faster plugin code wouldn't
change capacity.

## 1.0.3

The baseline run. Every functional, fault, restart and monitoring test passes.

| Test | Result |
|---|---|
| Build against Graylog 7.1.10's jar; 24 unit tests including 300k-case fuzzing | pass |
| API compatibility review against the Graylog 7.1.10 sources | no incompatibilities; 7 robustness fixes, released as 1.0.3 |
| Long fuzzing (see below) | pass |
| Production export setup end to end: a query found in Graylog with parsed fields | pass |
| TLS: the 629-frame capture under 5 client configurations, counted with the input's own counter | valid client 629/629; plain TCP, no client cert, untrusted CA: 0; wrong server CA: refused by the client |
| Restarts at 2,000 q/s, lost events counted exactly | input stopped 5 s: 56; Graylog restart: 31; relay killed: 23; named restart: 0; syslog/UDP on a Graylog restart, for comparison: 26,773. Every case recovered by itself |
| Monitoring: injected faults | 9/9 pass: OK under load; WARNING for a corrupt frame header and for an undecodable frame; CRITICAL with the input stopped; OK after recovery; Graylog alert fired 136 s after dnstap stopped; webhook delivered |
| Throughput, production setup, 1k / 4k / 8k q/s | 100.000 % delivered, 0 BIND drops |
| Throughput, production setup, stepped to 30k q/s | 10k q/s with no loss and no backlog; 15-25k lossless, but Graylog's journal backs up; the export itself lossless to 30k |
| Web UI | input form complete with defaults, input wizard, saved values, search; an input created with 1.0.2 kept working after the jar swap |
| 1 h soak at 3,000 q/s over TLS (see below) | 10,800,000 of 10,800,000 delivered, resources stable |

### 1-hour soak

1 h at 3,000 q/s of uniquely named queries, dnstap over TLS with queue + retry. Each 5-minute window was counted
exactly in OpenSearch.

Delivery: 12 of 12 windows OK; 10,800,000 sent = answered = delivered (0.0000 % lost); `DNSTAPdropped` 0; decode
failures 0.

Resources, sampled every 30 s, leaving out the first 10 min as warm-up:

| Indicator | Behaviour | Verdict |
|---|---|---|
| Graylog old gen after GC | one step 126 -> 220 MB in the first 7 min (the first G1 cycle), then flat at 220 MB for 55 min | stable |
| Threads | 450 | stable |
| File descriptors | 341 | stable |
| Graylog RSS | 2.5 -> 2.1 GB | stable |
| Data Node RSS | ~2.2 GB | stable |
| named RSS | 35 -> 20 MB | stable |
| Journal | 0 uncommitted | stable |

An hour can't rule out a very slow leak, but there is no sign of one: no rising floor, and no thread or FD growth.

### Long fuzzing

`FUZZ_ITERATIONS=3000000 ./build.sh`:
- Codec: 3,000,000 mutated real BIND frames gave 211,012 messages, 100,112 empty results and 2,688,876 per-frame
  rejections. Nothing else happened: no other exception, nothing slow.
- Frame decoder: of the random byte streams, 188,226 were rejected and their connection closed; the rest yielded
  52,341 frames.
