# graylog-plugin-dnstap 1.0.3: production readiness

Tested on 2026-10-10 in the bench labs, which mirror production:
- Graylog 7.1.10 with one Data Node and a MongoDB cluster
- BIND 9.20.29-1~deb13u1
- 12 CPU / 9 GB, Graylog heap 2 GB

Every test used the **recommended production setup**:
- dnstap over TLS with required client certificates
- `fstrm-set-input-queue-size 16384`
- a socat relay with `retry=120,interval=1`

The labs are offline: recursion only goes to the lab's fake internet, so no DNS left the host.

## Verdict

**Ready for production**, with the operating conditions below.

Every functional, fault, restart and monitoring test passes on 1.0.3, and delivery is counted exactly per query:

| | |
|---|---|
| Lossless delivery | at the tested rates |
| Restart losses | Graylog restart 31, input stopped 56, relay kill 23, named restart 0 |
| Faults | every fault is detected and reported |
| Soak (1 h, 3,000 q/s, TLS) | 10,800,000 / 10,800,000 delivered, no leak indicator growing |

Operating conditions:
1. **Size Graylog for the peak rate, not the plugin.** The plugin decodes ~240k frames/s per core, and BIND + relay export without loss up to 30k q/s. The limit is Graylog/OpenSearch: on the lab's size it keeps up to ~10k q/s, and beyond that the journal grows (BACKLOG), lossless but delayed. A city-resolver peak (Timișoara: ~10–20k q/s) needs a bigger Graylog than this lab, e.g. 2 nodes or more cores/heap, and ~90–180 GB/day of storage.
2. **Use the queue + retry settings.** Without them, a Graylog restart loses ~29k events (14 s at 2k q/s), as UDP syslog does, and silently.
3. **Monitor with `monitor/dnstap-health`** (cron/Nagios/Icinga/Zabbix) **and** the Graylog alert from `monitor/create-graylog-alerts`. The Graylog alert only works on a cluster that receives other logs as well (see Findings 2).
4. **Keep exactly one plugin jar** in the plugin directory.

## Results

| Test | Result | Evidence |
|---|---|---|
| Build against Graylog 7.1.10's jar; 24 unit tests incl. 300k-case fuzzing | PASS (the throughput micro-benchmark is opt-in) | `itest/results/readiness-20261010-225207/build-unit-fuzz.log` |
| API compatibility review against the 7.1.10 sources | no incompatibilities; 7 robustness fixes → 1.0.3 | README, "1.0.3" |
| Long fuzzing: 3M mutated real frames into the codec, random byte streams into the frame decoder | PASS | `itest/results/fuzz-3M-20261011.log` |
| Production export setup end to end (a query searched in Graylog with parsed fields) | PASS | `export-prod*.log` |
| TLS: valid client 629/629; plain TCP, no client cert, untrusted CA, wrong server CA → 0 | PASS | `itest/results/tls-20261010-225236.txt` |
| Restarts at 2,000 q/s (lost events, exact) | input stopped 5 s: **56** · Graylog restart: **31** · relay killed: **23** · named restart: **0** · syslog/UDP for comparison: **26,773**. All recovered by themselves | `itest/results/restarts-20261010-225303/table.txt` |
| Monitoring faults (`dnstap-health` + Graylog alert) | all 9 checks PASS: OK under load, WARNING on a corrupt frame header and on an undecodable frame, CRITICAL with the input stopped, OK after recovery, alert fired after 136 s, webhook delivered | `itest/results/monitoring-20261010-232816/report.txt` |
| Throughput, quick profile, production setup | 1k / 4k / 8k q/s: 100.000 % delivered, 0 BIND drops, all PASS | `itest/results/readiness-20261010-225207/bench-quick/summary.md` |
| Throughput, full profile, production setup (1.0.2, same data path) | 10k q/s PASS; 15–25k lossless, but Graylog's journal backs up; export lossless to 30k | `../bench/results/20261010-220714-default/` |
| Web UI: input form | 1.0.3 form complete with defaults (Encoding gone); the 1.0.2 input kept working after the jar swap | API `inputs/types` |
| Soak, 1 h at 3,000 q/s over TLS | **10,800,000 answered, 10,800,000 delivered, 0 lost**, 0 BIND drops, 0 plugin failures, 12/12 windows OK; all leak indicators stable | `../bench/results/soak-20261010-233356/summary.md` |

## Findings fixed during this round

1. **Hung fault injector (test harness).** When the plugin rightly keeps a valid connection open, socat blocks in the TLS shutdown and ignores SIGTERM, so `timeout` never ended it. It is now killed with SIGKILL.
2. **The Graylog "no messages" alert doesn't fire on an otherwise idle Graylog.** This is Graylog 7.1.10 behaviour, not the plugin's. An aggregation window runs only after a message received after the window start has been indexed somewhere (`EventProcessorDependencyCheck` needs `SOME_UP_TO_DATE`; `ALL_IDLE` waits). On the bench Graylog, which only receives dnstap, the alert never fired in 330 s. With other syslog traffic flowing, as in production, it fired after 136 s. Consequences:
   - `dnstap-health` is the primary check: it has no such dependency.
   - The itest now sends background syslog traffic during the alert test.
3. **The webhook was blocked by Graylog's URL allowlist**, which is on by default in 7.x ("URL … is not allowlisted"). `create-graylog-alerts` now adds the webhook to the allowlist. The itest also checks that the webhook call belongs to *this* event, not an older one.
4. **Counter resets were not handled.** An input restart recreates its metrics at 0, and a named restart resets `DNSTAPdropped`. `dnstap-health` only warned when a counter grew, so errors after a reset could be missed until the counter passed its old value. A lower value is now treated as a reset.
5. **`bench-soak` read a metric that doesn't exist** (`DnstapInput.<id>.invalidMessages`). It now uses the codec's `failures` counter.

## Expected behaviour worth knowing

- **Event lag p95 ≈ 1 s at low rates.** named sends a partly filled buffer once per `fstrm-set-output-flush-timeout` (1 s).
- **After an outage, events arrive late with their original timestamps.** BIND's queue replays them, which is why a few messages "appear" inside an outage window afterwards.
- The 1-minute rate in `dnstap-health` is an EWMA: it needs about a minute after start or recovery to reach the real rate, so keep `--min-rate` well below normal traffic.

## Soak (1 h)

The soak ran 1 h at 3,000 q/s of uniquely named queries, dnstap over TLS with queue + retry. Each 5-minute window was counted
exactly in OpenSearch.

**Delivery:** 12 windows, 10,800,000 sent = answered = delivered (0.0000 % lost), `DNSTAPdropped` 0, codec failures 0.

**Resources** (sampled every 30 s; the first 10 min are left out as warm-up):

| Indicator | Behaviour | Verdict |
|---|---|---|
| Graylog old gen after GC | one step 126 → 220 MB in the first 7 min (the first G1 cycle), then **flat at 220 MB for 55 min** | stable |
| Threads | 450 | stable |
| File descriptors | 341 | stable |
| Graylog RSS | 2.5 → 2.1 GB | stable |
| Data Node RSS | ~2.2 GB | stable |
| named RSS | 35 → 20 MB | stable |
| Journal | 0 uncommitted | stable |

An hour cannot rule out a very slow leak, but there is no sign of one: no rising floor, and no thread or FD growth.

Bench harness fix: the report's trend used to include the warm-up step, which labelled this run "growing". The
first 10 min are now left out, and a "growing" verdict from a run under 2 h is marked inconclusive.

## Long fuzzing

`FUZZ_ITERATIONS=3000000 ./build.sh` on 1.0.3: 3,000,000 mutated real BIND frames into the codec. The results were 211,012 messages,
100,112 empty results and 2,688,876 per-frame rejections, with no other exception and nothing slow. Random byte streams into the frame
decoder: 188,226 streams rejected with the connection closed, and 52,341 frames decoded from the rest. 24/24 unit tests pass.
