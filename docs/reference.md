# Reference

Details behind the [README](../README.md): settings, fields, monitoring, behaviour during outages, performance, security and how the plugin is tested.

- [Input settings](#input-settings)
- [Fields](#fields)
- [Monitoring](#monitoring)
- [Restarts and outages](#restarts-and-outages)
- [Performance and sizing](#performance-and-sizing)
- [Security](#security)
- [Tests](#tests)
- [Static analysis](#static-analysis)
- [Code layout](#code-layout)

## Input settings
Besides Graylog's usual bind address, port, TLS, receive buffer, worker threads and *Override source*:

| Setting | Default | Notes |
|---|---|---|
| Maximum frame size | 256 KiB | clamped to 65,535 + 1,024 B to 16 MiB; a bigger frame is a framing error and closes the connection. A complete dnstap frame is at most ~130 KB; the limit also bounds the memory an incomplete frame can hold per connection |
| Include answers | on | the `dns_answers` field of responses (capped at 8 KiB of text, each rdata at 256 characters) |
| Skip message types | empty | e.g. `CR,AR`: dropped at the input, counted in the `skipped` metric |
| TCP keepalive (Graylog's setting) | **on** for new inputs | lets the kernel close connections whose relay vanished without closing them (host down, network cut). Inputs created with 1.0.3 or older keep their stored value: enable it there |

## Fields

| Field | Example | Notes |
|---|---|---|
| `message` | `CQ 10.0.0.101#54344 -> www.example.org IN A` / `CR 10.0.0.101#54344 <- www.example.org IN A NOERROR [A 192.0.2.80]` | |
| `source` | `ns1` | dnstap identity; else the sender address; or *Override source* |
| `timestamp` | query (or response) time from dnstap, ms precision, UTC | |
| `dnstap` | `true` | on every message, for pipeline rules |
| `dnstap_type`, `dnstap_type_short` | `CLIENT_QUERY`, `CQ` | AQ AR CQ CR RQ RR FQ FR SQ SR TQ TR UQ UR |
| `dnstap_version` | `BIND 9.20.29-1~deb13u1-Debian` | |
| `dns_socket_family`, `dns_socket_protocol` | `INET`, `UDP` | |
| `dns_query_ip`, `dns_query_port`, `dns_response_ip`, `dns_response_port` | | raw dnstap addresses |
| `dns_client_ip`, `dns_client_port`, `dns_server_ip` | | for AUTH_\*, CLIENT_\*, UPDATE_\* messages (the client side) |
| `dns_query_name`, `dns_query_type`, `dns_query_class` | `www.example.org`, `A`, `IN` | first question, no trailing dot |
| `dns_id`, `dns_opcode`, `dns_flags`, `dns_size` | `QUERY`, `qr aa rd` | |
| `dns_edns`, `dns_edns_version`, `dns_do_bit`, `dns_ecs` | `true`, `0` | queries only: the query has an EDNS OPT record (RFC 6891), its version (only with EDNS), the DO bit, an EDNS Client Subnet option (RFC 7871) |
| `dns_rcode`, `dns_answer_count`, `dns_answers`, `dns_latency_us` | `NOERROR`, `1`, `A 192.0.2.80` | responses only |
| `dns_query_zone` | | when BIND sets it |
| `dnstap_event_time_suspect` | `2019-03-01T10:00:00.000Z` | the dnstap time, only when the dnstap time is more than 7 days from the receive time; `timestamp` is then the receive time |

Every field except `message`, `source` and `timestamp` can be renamed with `dnstap-fields.conf` (see the
[README](../README.md#usage)). The file is read when an input starts (in Docker: when the container starts, since the
image copies the plugin directory then). The whole file is ignored, with a warning in Graylog's log for each
problem, and the default names apply when:
- a field is unknown or renamed twice
- a new name isn't a valid Graylog field name, contains a dot, starts with `_`, is longer than 100 characters or is
  reserved (`message`, `streams`, `gl2_*`, ...)
- two fields would end up with the same name
- the file isn't a regular file, is larger than 64 KiB, isn't UTF-8 or can't be read

The names apply to every Dnstap input on the node, and to messages still waiting in Graylog's journal. A new name that
the current index already holds with another type (for example a number field renamed onto a text field) makes
messages fail to index until the index set rotates, so prefer names that aren't in use yet.

An undecodable frame raises an `InputProcessingException`. Graylog counts it as a processing failure in the input's
`failures` codec metric. Non-message dnstap payloads are skipped and counted (`nonMessage`).

## Monitoring
All metrics are under *System > Nodes > Metrics* and `GET /api/system/metrics/<name>`, with `I` = the input id.

| Metric | Type | Meaning |
|---|---|---|
| `org.graylog.plugins.dnstap.DnstapInput.I.incomingMessages` | meter | frames received (Graylog's own); `m1_rate` = msg/s |
| `....DnstapInput.I.open_connections` | gauge | connected relays; 0 = nothing is sending |
| `....DnstapInput.I.fstrm.frames` | counter | data frames decoded |
| `....DnstapInput.I.fstrm.control.ready` / `start` / `stop` | counter | handshakes: a growing `start` means senders reconnect |
| `....DnstapInput.I.fstrm.errors.framing` | counter | corrupt streams; each one closes a connection |
| `....DnstapInput.I.fstrm.frameSize` | histogram | bytes per frame (1 in 32 sampled) |
| `org.graylog.plugins.dnstap.DnstapCodec.I.failures` | counter | undecodable frames (Graylog's own) |
| `....DnstapCodec.I.eventLagMs` | histogram | Graylog processing time - DNS event time, ms (1 in 32 sampled); a rising p95 = backlog |
| `....DnstapCodec.I.types.CQ` (`AQ`, `CR`, ...) | meter | messages per dnstap type |
| `....DnstapCodec.I.skipped`, `nonMessage` | meter | dropped by *Skip message types* / not a DNS message |

Notes on these metrics:
- A lag p95 of about **1 s at low rates is normal**: named sends a partly filled buffer once per
  `fstrm-set-output-flush-timeout` (default 1 s).
- Counters restart at 0 when the input restarts. When an input is stopped or deleted, the plugin removes its metrics.
  Graylog keeps two of its own (`parseTime`, `processedMessages`) after an input is deleted.
- Watch Graylog's `jvm.threads.count` too. Graylog 7.1.10 leaks the worker threads of its own TCP inputs on every
  input restart (the Dnstap input works around this since 1.0.7), so a count that keeps rising points to inputs being
  restarted often.
- Also watch BIND's `DNSTAPdropped` counter (statistics channel, `/xml/v3/server`): frames named dropped because its
  queue was full.

**[`monitor/dnstap-health`](../monitor/dnstap-health)** is a read-only check with Nagios/Icinga conventions (exit
0/1/2/3, perfdata), for cron, Nagios, Icinga or Zabbix. It needs `curl` and `jq` and a Graylog API token:
```bash
monitor/dnstap-health --url https://graylog.example.org:9000 --token TOKEN --bind-stats http://ns1:8053 --min-rate 50
```
It prints a line such as `DNSTAP OK - rate=1032/s conns=1 lag_p95=1054ms frames=... framing_errors=0 failures=0 bind_dropped=0 | ...`.
- **CRITICAL:** the input is missing or not running, no sender is connected, the 1-min rate is below `--min-rate`, or
  the lag p95 is above `--lag-crit`.
- **WARNING:** the lag is above `--lag-warn`, or there are new framing errors, undecodable frames or BIND drops since
  the last run (kept in the `--state` file; a counter that went down counts as a reset).

**[`monitor/create-graylog-alerts`](../monitor/create-graylog-alerts)** sets up Graylog-native alerting and is idempotent:
```bash
monitor/create-graylog-alerts --url https://graylog.example.org:9000 --token TOKEN --minutes 5 --webhook https://alerts.example.org/hook
```
- It creates the event definition *"dnstap: no messages for 5 min"* on the stream, checked every minute.
- It adds an optional HTTP notification and puts the webhook on Graylog's URL allowlist, which 7.x enables by default.

**The Graylog alert needs other traffic on the cluster.** Graylog 7.1 evaluates an aggregation window only after
a message received after the window start has been indexed somewhere. While every node is idle, it waits.
- A Graylog that also receives other logs fires the alert 2-3 min after dnstap stops.
- On a Graylog that receives **only** dnstap, it never fires.

`dnstap-health` has no such dependency: use it as the primary check.

## Restarts and outages
Measured at 2,000 q/s over TLS, counting every query exactly. *Lost* = queries BIND answered whose event never
reached Graylog.

| Event | Default relay (BIND queue 512/thread) | Queue 16384 + relay retry (recommended) |
|---|---|---|
| Graylog input stopped 5 s | 9,593 lost | **56** |
| Graylog restart (~15 s) | 28,767 lost | **31** |
| (comparison) Graylog restart with syslog/UDP | 26,773 lost | - |
| Relay process killed | 64 | **23** |
| named restart | 0 | 0 |

Every case recovered without intervention.

- **With the default setup, dnstap loses a Graylog outage just like UDP, and silently.** socat accepts named's frames
  and drops them, so BIND's `DNSTAPdropped` doesn't count them.
- Neither change helps alone:
  - a bigger queue only: 30,068 lost
  - relay retry only: 26,657 lost, but *counted* by BIND
- **Together they ride out a Graylog restart.**
  - socat's `retry=120,interval=1` keeps named's connection waiting.
  - `fstrm-set-input-queue-size 16384` holds the frames meanwhile: per worker thread, so 12 threads ~ 98 s at 2,000 q/s.
  - Beyond the queue, named drops frames and counts them; it never slows DNS.

## Performance and sizing
Measured on a lab with 12 CPUs / 9 GB, Graylog 7.1.10 with a 2 GB heap, one Data Node and BIND 9.20:

| | syslog -> rsyslog -> UDP | dnstap |
|---|---|---|
| Sustained end to end (no loss, no backlog) | 10k q/s | 15k q/s plain TCP; 10k with TLS |
| named CPU at 15k q/s | 1.38 cores + rsyslog 0.47 | 0.96 cores + socat ~0.01 |
| DNS answers start failing | 15-20k q/s | 25-30k q/s |

The plugin itself decodes ~240k frames/s per core, and BIND + relay export losslessly up to 30k q/s. **The limit is
Graylog/OpenSearch**: size them for your peak query rate. Beyond their capacity the journal grows: no loss, but
delay. Storage is about 200 bytes per event in OpenSearch.

A CPU profile of the bench Graylog under 8,000 dnstap messages/s (JFR, all threads) puts the plugin at **1.3 %** of
Graylog's CPU. Most of the rest is Graylog's output stage, which serialises messages to JSON for OpenSearch. Making
the plugin faster wouldn't change the system's capacity. For more throughput, give Graylog/OpenSearch more cores, or
add nodes.

## Security
**What a sender controls:** the bytes on the TCP connection and, through the queries it logs, DNS names and record
data. With Graylog's defaults (no TLS, no client authentication) anyone who reaches the port can send. Use *TLS
client authentication: required* so that only holders of a certificate from your CA get past Graylog's TLS layer to
the plugin, and firewall the port anyway.

**What the plugin does with them:** it parses them into strings and numbers and nothing else. It has no process,
reflection, deserialisation or outbound network access. Its only file access is reading `dnstap-fields.conf` from the
plugin directory when an input starts. `InetAddress.getByAddress` only formats addresses, without DNS lookups. So no
input can make the plugin execute anything or reach beyond its message fields.
The static analysers (see [Static analysis](#static-analysis)) and a manual review checked for such APIs.

**Limits on what one connection can cost:**

| Resource | Limit |
|---|---|
| Memory for an incomplete frame | *Maximum frame size* (default 256 KiB), per connection |
| Control frame | 512 bytes |
| DNS name | 1,024 characters |
| Pointer jumps per name | 64 |
| Answers shown | 32, each rdata cut at 256 characters, all answers at 8 KiB of text; a broken record ends the list |
| Identity, version | 255 bytes each |
| CPU per frame | linear in the frame size, including crafted worst cases (see [Tests](#tests)) |

A framing error, a READY with a foreign content type or a second READY closes the connection. Text is never cut
between the two halves of a surrogate pair.

**Text injection:** control characters in sender-chosen text become `\DDD`: identity (the message `source`), version
and TXT answers, which are in RFC 1035 presentation format. DNS names are in presentation format anyway. Content types
that end up in Graylog's log are reduced to printable ASCII. Line breaks and terminal escapes therefore can't reach
text-based outputs or log files.

**Out of the plugin's hands:**
- TLS itself and the input's worker threads: Graylog configures and runs them. Graylog sets no limit on the number of
  connections and no timeout for idle connections or incomplete frames, so a sender that opens many connections and
  leaves a frame unfinished on each can hold *Maximum frame size* of memory per connection. TLS client
  authentication or a firewall keeps such senders out.
- Graylog writes two ERROR lines, with the frame's ID, for every undecodable frame, so any sender that reaches the
  port can make the server log noisy. Watch the `failures` metric; `dnstap-health` warns on it.

## Tests
**In this repository** (`./build.sh`): 70 unit tests on the BIND capture (two of them opt-in: a throughput benchmark and a
leak soak), covering:
- frame decoding fed in random chunks
- the full handshake
- message-type counts equal to `dnstap-read`
- field values and metrics
- the review fixes
- seeded fuzzing:
  - mutated real frames and random inputs into the codec: only a message, an empty result or
    `InputProcessingException`, each in under 100 ms
  - random byte streams into the frame decoder: only framing exceptions, and the connection closed
  - hostile DNS messages: compression loops, overlong labels, short records
- crafted worst cases for CPU cost (`AdversarialCostTest`), e.g. 65,535 questions pointing at one long name: each
  decodes in under 50 ms (in practice under 1 ms)
- buffer reference counting (`BufferLifecycleTest`), on pooled direct memory as in Graylog: on every decoder path,
  and for 20,000 mutated streams, every buffer is released exactly once. That covers the inputs, Netty's cumulation
  buffers and the handshake frames. A leak, a double release or a use after release fails the test.
- escaping of sender-chosen text (`FieldInjectionTest`)
- the field name file: renames, ignored lines, defaults and the `dnstap` field (`FieldNamesTest`)
- the EDNS fields, including malformed and random record sections (`EdnsTest`)
- the security review fixes: identity and version caps, broken answer records, surrogate pairs (`HardeningTest`)

The full suite also runs clean with Netty's leak detector at paranoid level and 3,000,000 fuzz iterations.

**In a production-like lab** (Graylog 7.1.10 and 7.2.0 + Data Node + MongoDB cluster, BIND 9.20.29; the lab harness
isn't part of this repository):
- TLS client-certificate cases
- restarts of every component
- fault injection checked against the monitoring
- the web UI
- stepped throughput benchmarks with exact per-query counting
- a 1 h soak at 3,000 q/s over TLS: 10,800,000 of 10,800,000 delivered, resources stable
- a 3 h soak at 5,000 q/s over TLS with Netty's paranoid leak detector, on 1.0.6: 54,000,000 of 54,000,000 delivered,
  0 leak reports, no resource growth
- input restart and leak tests with heap dumps and class histograms
- the EDNS fields compared with BIND's own query log
- a security review with live attacks on the input

Results and findings are in [READINESS.md](../READINESS.md). The procedure for testing a change or a release is in
[testing.md](testing.md).

## Static analysis
`./build.sh analyze` runs three tools on top of the normal build and tests. They report findings without failing the
build:
- **Error Prone** checks bug patterns at compile time, together with `javac -Xlint:all`.
- **SpotBugs** with **FindSecBugs** analyses the bytecode for bugs and security issues.
- **PMD** checks the source, including copy-paste detection.

Their reports are in `target/spotbugsXml.xml` and `target/pmd.xml`.

The first run on 1.0.3 reported 10 SpotBugs, 11 Error Prone/javac and 61 PMD findings. Version 1.0.4 fixes every real
one: an ignored write future, sender data in log lines, unread fields, a duplicate branch, a lost exception cause, a
deprecated API and style issues. That left 7 SpotBugs, 3 Error Prone and 5 PMD findings, each reviewed and kept on
purpose. 1.1.0 added findings in `FieldNames` of the same kinds (the two `FieldNames` rows and `GuardLogStatement` in
the table below). The remaining findings:

| Finding | Why it stays |
|---|---|
| SpotBugs `EI_EXPOSE_REP2`: storing the injected `MetricRegistry` | it's Graylog's shared registry; holding the reference is the point |
| FindSecBugs `CRLF_INJECTION_LOGS` in `FstrmFrameDecoder` | the remaining logged values are the peer address, the plugin's own numeric messages, and content types already stripped of control characters (`printable()`), which the tool can't see |
| FindSecBugs `CRLF_INJECTION_LOGS` in `FieldNames` | the logged values are the plugin's own file path, validated field names and file text passed through `printable()` |
| PMD `AvoidUsingVolatile` in `FieldNames` | the current field names are replaced on input start and read once per message; a volatile reference is the cheapest safe publication |
| PMD `GuardLogStatement` | SLF4J parameterized calls with cheap arguments; the one costly argument on the frame path is guarded, and `FieldNames` logs only while it loads its file |
| Error Prone `NonApiType` / PMD `LooseCoupling` (`LinkedHashMap`) | the type is fixed by the Graylog method being overridden |
| Error Prone `NonCanonicalType` (`AbstractCodec.Factory`) | the form Graylog's own codecs use |
| Error Prone `FutureReturnValueIgnored` in `FuzzTest` | closing a test channel during teardown; nothing to check |
| PMD `CloseResource` in `WorkerGroupFactory` | the pool is shut down by the event loop group's termination listener, which PMD can't follow |

On top of the tools, a review looked for problems that only show up after long uptime or many configuration changes
(fixed in 1.0.4, covered by `LongRunningSafetyTest`):
- codec metrics and a static cache entry that outlived every deleted input
- half-open connections without keepalive
- an unbounded cache keyed by configuration text
- a data race in the per-type meters

The metric cleanup was also checked in a real Graylog 7.1.10. While the input runs, the plugin's metrics exist. After a
stop only Graylog's own remain, and after a restart the plugin's come back, with 200 of 200 test queries delivered.

The 1 h and 3 h soaks (see [READINESS.md](../READINESS.md)) showed no growth in heap, threads, file descriptors or
RSS.

## Code layout
Classes in `src/main/java/org/graylog/plugins/dnstap/`:

| Class | What it does |
|---|---|
| `DnstapInput`, `DnstapModule`, `DnstapPlugin`, `DnstapPluginMetaData` | Graylog wiring |
| `FstrmTransport` | Graylog TCP transport, with TLS from Graylog |
| `FstrmFrameDecoder` | Frame Streams framing and handshake |
| `FstrmMetrics` | the input's metrics |
| `DnstapCodec` | dnstap -> Graylog message fields |
| `FieldNames` | field names, and `dnstap-fields.conf` |
| `DnstapFrame`, `ProtoReader` | protobuf |
| `DnsMessage` | DNS wire format |
| `Text` | escaping of sender-chosen text in fields |

Unit tests and a real BIND 9.20.29 dnstap capture (629 frames) are in `src/test/`.
