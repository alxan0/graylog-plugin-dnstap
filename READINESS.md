# graylog-plugin-dnstap 1.0.7: production readiness

Tested on 2026-10-10/11 in a lab built like a production deployment:
- Graylog 7.1.10 with one Data Node and a MongoDB cluster (Graylog heap 2 GB)
- BIND 9.20.29-1~deb13u1 (Debian 13)
- a host with 12 CPUs / 9 GB

Every test used the **recommended setup** (see the README):
- dnstap over TLS with required client certificates
- `fstrm-set-input-queue-size 16384`
- a socat relay with `retry=120,interval=1`

The load came from `dnsperf` with uniquely named queries. Each query was counted exactly at every hop: dnsperf, BIND's
counters, the input's counters, and an exact OpenSearch count by query name.

## 1.0.7: leak test and fixes

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
- **Heap after GC:** 48,720 -> 48,742 KB.
- **Registry and cache:** only the permanent input's metrics, 1 cache entry.
- **Direct memory and leaks:** constant, 0 leak reports.

Still open in Graylog, not in the plugin: Graylog keeps its own two per-input decoding metrics (`parseTime`,
`processedMessages`) after an input is deleted.

## 1.0.4 to 1.0.6

- **1.0.4:** fixes from static analysis and a review for long uptime (metric cleanup, keepalive, close handling, log
  sanitising).
- **1.0.5:** fixes a CPU amplification. A crafted 400 KB frame took 146 ms to decode; it now takes under 1 ms.
- **1.0.6:** escapes sender-chosen text in fields and lowers the default frame limit to 256 KiB.

None of them changes the data path's design.

**Re-verified on 1.0.6:**

| Test | Result |
|---|---|
| Unit tests | 37 pass, including CPU worst cases, buffer lifecycle and field injection |
| Unit tests under Netty's paranoid leak detector, 3,000,000 fuzz iterations | 0 leak reports, 0 reference-count errors |
| Buffer lifecycle on pooled direct memory: every decoder path, 20,000 mutated streams (3.5M frames) | every buffer released exactly once |
| Static analysis: Error Prone, SpotBugs + FindSecBugs, PMD | no new findings; the remaining ones are reviewed in docs/reference.md |
| Live, against Graylog 7.1.10 with Netty's paranoid leak detector | TLS 6/6; restarts lost input stop 1, Graylog restart 32, relay kill 24, named restart 0, all recovered by themselves; monitoring 9/9; quick throughput 1k/4k/8k q/s at 100.000 %; 0 leak reports, and every ERROR line came from a fault the tests injected |
| **3 h soak at 5,000 q/s over TLS**, queue + retry, paranoid leak detector | **54,000,000 answered, 54,000,000 delivered, 0 lost**; 36/36 windows OK; 0 BIND drops, 0 decode failures |
| Graylog log during the soak | 238 lines: 0 ERROR, 0 WARN, 0 leak reports |
| Resources over 3 h (first vs last hour) | old gen after GC 203 -> 186 MB, heap 885 -> 737 MB, Graylog RSS 2.24 -> 2.02 GB, threads 428 -> 428, FDs 342 -> 341: no growth |
| Journal during the soak | median 1 uncommitted message; peaks up to 13,648 (< 3 s of traffic) during index rotations, always drained |

A CPU profile under 8,000 messages/s puts the plugin at 1.3 % of Graylog's CPU, so faster plugin code wouldn't
change capacity.

The full-profile throughput run and the 1 h soak below are from 1.0.3.

## Verdict

**Ready for production**, under the operating conditions below. Every functional, fault, restart and monitoring test
passes on 1.0.3:

| | |
|---|---|
| Delivery | lossless at every tested rate up to Graylog's capacity |
| Restarts | a Graylog restart loses 31 events; a stopped input 56; a killed relay 23; a named restart 0 |
| Faults | every injected fault is detected and reported |
| Soak (1 h, 3,000 q/s, TLS) | 10,800,000 of 10,800,000 delivered, resources stable |

Operating conditions:
1. **Size Graylog/OpenSearch for the peak rate.** The plugin isn't the bottleneck: it decodes ~240k frames/s per core,
   and BIND + relay export losslessly up to 30k q/s. On the lab's size, Graylog keeps up to ~10k q/s; beyond that its
   journal grows, losslessly but with delay. A large resolver (e.g. ~10-20k q/s at peak) needs a bigger Graylog than
   the lab, and ~200 bytes of storage per event.
2. **Use the queue + retry settings.** Without them, a Graylog restart loses ~29k events at 2k q/s, as UDP syslog
   does, and silently.
3. **Monitor with `monitor/dnstap-health`** (cron/Nagios/Icinga/Zabbix), and add the Graylog alert from
   `monitor/create-graylog-alerts` as a second check. The alert only works on a cluster that also receives other
   logs (finding 1).
4. **Keep exactly one plugin jar** in the plugin directory.

## Results

| Test | Result |
|---|---|
| Build against Graylog 7.1.10's jar; 24 unit tests incl. 300k-case fuzzing | PASS |
| API compatibility review against the Graylog 7.1.10 sources | no incompatibilities; 7 robustness fixes, released as 1.0.3 |
| Long fuzzing: 3M mutated real frames into the codec, random byte streams into the frame decoder | PASS |
| Production export setup end to end: a query found in Graylog with parsed fields | PASS |
| TLS: the 629-frame capture under 5 client configurations, counted with the input's own counter | valid client 629/629; plain TCP, no client cert, untrusted CA: 0; wrong server CA: refused by the client |
| Restarts at 2,000 q/s, lost events counted exactly | input stopped 5 s: **56**; Graylog restart: **31**; relay killed: **23**; named restart: **0**; syslog/UDP on a Graylog restart, for comparison: **26,773**. Every case recovered by itself |
| Monitoring: injected faults | 9/9 PASS: OK under load; WARNING for a corrupt frame header and for an undecodable frame; CRITICAL with the input stopped; OK after recovery; Graylog alert fired 136 s after dnstap stopped; webhook delivered |
| Throughput, production setup, 1k / 4k / 8k q/s | 100.000 % delivered, 0 BIND drops |
| Throughput, production setup, stepped to 30k q/s | 10k q/s with no loss and no backlog; 15-25k lossless, but Graylog's journal backs up; the export itself lossless to 30k |
| Web UI | input form complete with defaults, input wizard, saved values, search; an input created with 1.0.2 kept working after the jar swap |
| Soak, 1 h at 3,000 q/s over TLS | **10,800,000 answered, 10,800,000 delivered, 0 lost**, 0 BIND drops, 0 decode failures, 12/12 five-minute windows OK; resources stable |

## Findings

1. **The Graylog "no messages" alert doesn't fire on an otherwise idle Graylog.** This is Graylog 7.1.10 behaviour,
   not the plugin's. An aggregation window runs only after a message received after the window start has been
   indexed somewhere: `EventProcessorDependencyCheck` needs `SOME_UP_TO_DATE`, and `ALL_IDLE` waits.
   - On a Graylog that only received dnstap, the alert never fired in 330 s.
   - With other syslog traffic flowing, as in production, it fired after 136 s.

   Hence `dnstap-health`, which has no such dependency, is the primary check.
2. **Webhook notifications are blocked by Graylog's URL allowlist**, which 7.x enables by default ("URL ... is not
   allowlisted"). `create-graylog-alerts` adds the webhook to the allowlist.
3. **Counters reset.** An input restart recreates its metrics at 0, and a named restart resets `DNSTAPdropped`.
   `dnstap-health` treats a lower value as a reset, so errors after it aren't missed.

## Expected behaviour worth knowing

- **Event lag p95 ~ 1 s at low rates.** named sends a partly filled buffer once per
  `fstrm-set-output-flush-timeout` (1 s).
- **After an outage, events arrive late with their original timestamps.** BIND's queue replays them, so a few
  messages "appear" inside an outage window afterwards.
- **`dnstap-health`'s 1-minute rate is an EWMA.** It needs about a minute after a start or a recovery to reach the
  real rate, so keep `--min-rate` well below normal traffic.

## Soak (1 h)

The soak ran 1 h at 3,000 q/s of uniquely named queries, dnstap over TLS with queue + retry. Each 5-minute window was
counted exactly in OpenSearch.

**Delivery:** 12 windows, 10,800,000 sent = answered = delivered (0.0000 % lost), `DNSTAPdropped` 0, decode failures 0.

**Resources** (sampled every 30 s; the first 10 min are left out as warm-up):

| Indicator | Behaviour | Verdict |
|---|---|---|
| Graylog old gen after GC | one step 126 -> 220 MB in the first 7 min (the first G1 cycle), then **flat at 220 MB for 55 min** | stable |
| Threads | 450 | stable |
| File descriptors | 341 | stable |
| Graylog RSS | 2.5 -> 2.1 GB | stable |
| Data Node RSS | ~2.2 GB | stable |
| named RSS | 35 -> 20 MB | stable |
| Journal | 0 uncommitted | stable |

An hour can't rule out a very slow leak, but there is no sign of one: no rising floor, and no thread or FD growth.

## Long fuzzing

`FUZZ_ITERATIONS=3000000 ./build.sh` on 1.0.3:
- **Codec:** 3,000,000 mutated real BIND frames gave 211,012 messages, 100,112 empty results and 2,688,876 per-frame
  rejections. Nothing else happened: no other exception, nothing slow.
- **Frame decoder:** of the random byte streams, 188,226 were rejected and their connection closed; the rest yielded
  52,341 frames.
