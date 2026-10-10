# graylog-plugin-dnstap for Graylog 7.1 (1.0.3)

A **Dnstap input** for Graylog **7.1.10**: it receives [dnstap](https://dnstap.info/) over Frame Streams/TCP and
turns each DNS message into a Graylog message with parsed fields.

It is a rewrite of [sega-yarkin/graylog-plugin-dnstap](https://github.com/sega-yarkin/graylog-plugin-dnstap)
(v0.0.2, MIT, written for Graylog 2.x; see the [community thread](https://community.graylog.org/t/dnstap-input-plugin/22770)).
The original can't load on 7.x: it uses Netty 3, `javax.inject`, Graylog 2.x codec/input APIs, the old `Message`
constructors and protobuf 3.0.

| | Original 0.0.2 | This plugin 1.0.3 |
|---|---|---|
| Graylog API | 2.x (Netty 3, `javax.inject`, `new Message(...)`) | 7.1 (Netty 4 `AbstractTcpTransport`, `jakarta.inject`, `MessageFactory`, `decodeSafe` + `InputProcessingException`) |
| Frame Streams | READY → ACCEPT; ignored STOP | READY → ACCEPT (with content type), START, **STOP → FINISH + close**, unidirectional files; frame size limit |
| Decoding | protobuf-java 3.0 generated classes + dnsjava 2.1 | small hand-written protobuf + DNS wire parsers: **no dependencies**, no clash with Graylog's own protobuf, ~240k frames/s per core (codec micro-benchmark, a new codec per message as Graylog does) |
| Fields | `dnstap_*` | dnstap metadata **and** the names a BIND query-log pipeline produces (`client_ip`, `client_port`, `qname`, `qclass`, `qtype`, `server_ip`), plus `rcode`, `answers`, `latency_us`, `dns_flags`, … |
| Config | full message on/off | include answers; skip message types (e.g. drop responses at the input) |
| Monitoring | — | input/codec metrics (frames, handshakes, framing errors, undecodable frames, event lag, per-type rates), a Nagios-style health check and Graylog alert setup (`monitor/`) |
| Tests | — | 24 unit tests incl. fuzzing (see below), integration tests for TLS, restarts and monitoring (`itest/`), a UI check, a soak test |

## Build
```bash
./build.sh            # compiles against graylog.jar of graylog/graylog:7.1.10 (extracted from the image), runs the tests
./build.sh bench      # + codec throughput micro-benchmark
# -> dist/graylog-plugin-dnstap-1.0.3.jar
```
Needs only Docker: it runs Maven + JDK 21 in `maven:3.9.9-eclipse-temurin-21`.
`GRAYLOG_VERSION=7.1.x ./build.sh` builds against another 7.1 image.

## Install
- **Package install:** copy the jar to `/usr/share/graylog-server/plugin/` and restart `graylog-server`.
- **Docker:** mount the jar's directory at `/usr/share/graylog/plugin/`.
- **These labs:** `../graylog-lab/deploy-graylog-lab --name X --plugin-dir ../graylog-plugin-dnstap/dist`

The server log shows `Loaded plugin: Dnstap Input 1.0.3`. The new input type is **Dnstap (Frame Streams/TCP)**,
default port 6000. Built and verified against Graylog 7.1.10 (every API it uses was checked against that version's jar).

**Upgrading / migrating:**
- Keep **exactly one** jar of this plugin in the plugin directory; two versions of the same plugin conflict at startup.
- From this plugin 1.0.x: replace the jar and restart. Inputs, streams and settings are kept.
- From the original 0.0.2 plugin: it cannot load on 7.x anyway. Remove its jar and create the input anew, because the
  input type and settings are different.

**Input settings** (besides Graylog's usual bind address, port, TLS, receive buffer and *Override source*):

| Setting | Default | |
|---|---|---|
| Maximum frame size | 1 MiB | clamped to 65,535 + 1,024 B … 16 MiB; a bigger frame is a framing error |
| Include answers | on | the `answers` field of responses (capped at 8 KiB of text, each rdata at 256 chars) |
| Skip message types | empty | e.g. `CR,AR`: dropped at the input, counted in the `skipped` metric |

## Feeding it from BIND 9.20
BIND writes dnstap only to a file or a **Unix socket**, so a relay carries the socket to Graylog's TCP port.
The bidirectional handshake passes through it unchanged.
```
# named.conf, options { }
dnstap { auth query; client query; };          # one message per incoming query (like the query log)
dnstap-output unix "/run/named/dnstap.sock";
dnstap-identity hostname;                       # becomes the message source
```
```bash
socat -b 262144 UNIX-LISTEN:/run/named/dnstap.sock,fork,unlink-early,user=bind,group=bind,mode=0660 \
      TCP:graylog.example:6000,nodelay
```
⚠️ **Use `auth` *and* `client`.** BIND tags a query `CLIENT_QUERY` only when it is recursive (RD set and recursion
allowed for that client), and `AUTH_QUERY` otherwise. With `client query` alone, every non-recursive query is silently
missing. The lab benchmark's self-test caught exactly this: 1000 queries sent, 1 message received.

`auth`/`client` without `query`/`response` logs both directions, i.e. two messages per query. Responses add
`rcode`, `answers` and `latency_us`.

## Fields

| Field | Example | Notes |
|---|---|---|
| `message` | `CQ 10.251.2.101#54344 -> www.lab.test IN A` / `CR 10.251.2.101#54344 <- www.lab.test IN A NOERROR [A 10.251.2.80]` | |
| `source` | `ns1` | dnstap identity; else the sender address; or *Override source* |
| `timestamp` | query (or response) time from dnstap, ms precision, UTC | |
| `dnstap_type`, `dnstap_type_short` | `CLIENT_QUERY`, `CQ` | AQ AR CQ CR RQ RR FQ FR SQ SR TQ TR UQ UR |
| `dnstap_version` | `BIND 9.20.29-1~deb13u1-Debian` | |
| `socket_family`, `socket_protocol` | `INET`, `UDP` | |
| `query_ip`, `query_port`, `response_ip`, `response_port` | | raw dnstap addresses |
| `client_ip`, `client_port`, `server_ip` | | for AUTH_\*, CLIENT_\*, UPDATE_\* messages (the client side) |
| `qname`, `qtype`, `qclass` | `www.lab.test`, `A`, `IN` | first question, no trailing dot |
| `dns_id`, `dns_opcode`, `dns_flags`, `dns_size` | `QUERY`, `qr aa rd` | |
| `rcode`, `answer_count`, `answers`, `latency_us` | `NOERROR`, `1`, `A 10.251.2.80` | responses only |
| `query_zone` | | when BIND sets it |
| `dnstap_event_time_suspect` | `true` | only when the dnstap time is more than 7 days from the receive time; `timestamp` is then the receive time |

An undecodable frame raises an `InputProcessingException`. Graylog counts it as a processing failure, and the plugin
counts it in its `failures` metric (see Monitoring). Non-message dnstap payloads are skipped and counted (`nonMessage`).

## Hardening and test status (1.0.3)

The production-readiness verdict, conditions and findings are in **[READINESS.md](READINESS.md)**.

| Test | How | Result |
|---|---|---|
| Unit tests | 24 tests (handshake, metrics, review fixes, fuzzing, throughput) on a real BIND 9.20.29 capture (629 frames): frame decoding fed in random chunks, the READY/ACCEPT/START/STOP/FINISH handshake, message-type counts equal to `dnstap-read`, field values | pass |
| **Fuzzing** (`FuzzTest`, seeded, `FUZZ_ITERATIONS=3000000 ./build.sh`) | 3,000,000 mutated real frames + 1,000,000 random inputs into the codec: only a message, an empty result or `InputProcessingException` is allowed, each in < 100 ms. 200,000 random byte streams into the frame decoder: only `CorruptedFrameException`/`TooLongFrameException` are allowed, and the connection must be closed. Hand-written hostile DNS messages: compression-pointer loops, overlong labels, missing records, short MX | pass after the fixes below |
| **TLS** (`itest/itest-tls`) | Input with a server certificate and *required* client certificates (lab CA); the 629-frame capture sent under 5 client configurations, counted exactly with the input's own counter | valid client: 629/629. Plain TCP, no client cert, cert from an untrusted CA: 0. A client verifying the server against the wrong CA refuses to connect |
| **Restarts** (`itest/itest-restarts`) | 2,000 q/s of uniquely named queries for 60 s; one event at +15 s; loss counted exactly, gap from per-second counts | see the next section |
| **Monitoring** (`itest/itest-monitoring`) | At 1,000 q/s over TLS, it injects faults: a corrupt frame header, an undecodable frame, a stopped input, and no messages for > 2 min. It checks `dnstap-health` and the Graylog alert + webhook | all pass: OK under load; WARNING for the framing error and the undecodable frame; CRITICAL for the stopped input; OK after recovery; the alert fired 136 s after dnstap stopped, and its webhook arrived |
| **Web UI** | Created, started and edited a Dnstap input in the browser (7.1 input setup wizard); sent the capture; searched it | the form shows all settings including the plugin's own; values are saved and reloaded correctly; "skip CR" → 629 received, 399 indexed, 0 CR; messages searchable |
| **Soak** (`../bench/bench-soak`) | 3,000 q/s over TLS for hours; exact loss per 5-minute window; Graylog old-gen live set after GC, heap, threads, FDs, RSS sampled every 30 s | 1.0.3, 1 h at 3,000 q/s over TLS: 10,800,000/10,800,000 delivered, 0 lost; old gen, threads, FDs and RSS stable (`../bench/results/soak-20261010-233356/`) |

**Bugs found and fixed by these tests (1.0.0 → 1.0.1):**
1. **A framing error didn't close the connection** (fuzzing). The stream can't resynchronise, so later bytes would have been misread as frames. The decoder now discards the rest and closes, and the sender reconnects.
2. **Closing inside `decode()` used a buffer Netty had already released** (`IllegalReferenceCountException`, found by fuzzing). This happened after a framing error and **on every normal STOP/FINISH**, i.e. every time BIND stops its stream (reload, shutdown). The connection is now closed after the decode call returns.
3. **Short MX rdata wasn't bounds-checked** (fuzzing). It is now, and the codec additionally turns *any* unexpected exception into a per-frame `InputProcessingException` instead of an error inside Graylog's processing.
4. Build: `target/` wasn't cleaned, so `dist/` received two plugin jars (two versions of the same plugin conflict in Graylog). The build now runs `clean package` and copies only the current jar.

**1.0.2 — monitoring:** the metrics and `monitor/` scripts below. Graylog creates a **new codec instance for every
message** (`DecodingProcessor`), so per-instance state is useless there: the metrics, the parsed skip list and the
sampling counters live in static per-input caches.

**1.0.3 — fixes from a review against the Graylog 7.1.10 sources:**
1. A framing error was rethrown after closing, so Graylog logged a second generic ERROR. It is now counted, logged once (WARN) and closed by the plugin.
2. READY with a content type other than `protobuf:dnstap.Dnstap` was accepted. It now gets no ACCEPT and the connection is closed.
3. FINISH was sent after STOP on unidirectional streams too, where the sender reads nothing. Now it is sent only after a READY, and the connection is closed once the write completes.
4. `answers` had no total cap (a response with ~51 KiB of TXT produced a ~51 KiB field). It is now capped at 8 KiB.
5. An absurd dnstap time (e.g. the year 36800) became the message timestamp. Beyond 7 days of skew, the receive time is used and `dnstap_event_time_suspect` is set.
6. `client_port`/`server_port` were written as `-1` when absent; they are now omitted. IPv6 addresses use the canonical form, and the meaningless *Encoding* setting was removed.
7. *Maximum frame size* is bounded (see Install).

## Restarts and outages: losses, and how to avoid them
dnstap over TLS at 2,000 q/s. *lost* = queries BIND answered whose event never reached Graylog. Re-run on 1.0.3 with queue + retry: input stopped 56, Graylog restart 31, relay kill 23, named restart 0; syslog on a Graylog restart lost 26,773 (`itest/results/restarts-20261010-225303/`).

| Event | Default relay (socat, BIND queue 512/thread) | `--dnstap-queue 16384 --relay-retry` |
|---|---|---|
| Graylog input stopped 5 s | **9,593 lost** (4.8 s), BIND counted 0 | **55** lost |
| Graylog restart (~15 s) | **28,767 lost** (14.4 s), BIND counted 14 | **32** lost |
| (for comparison) Graylog restart with syslog/UDP | 26,710 lost (13.4 s) | – |
| Relay connection killed | 64 (in flight) | **23** (1.0.3 run) |
| named restart | 0 of the answered queries | – |

Every case recovered on its own.

- **With the default setup, dnstap loses a Graylog outage just like UDP, and silently.** socat accepts named's frames and drops them, so BIND's `DNSTAPdropped` doesn't count them. Only Graylog-side counting reveals the loss.
- Each change alone doesn't help:
  - a bigger queue only: 30,068 lost
  - relay retry only: 26,657 lost, but now *counted* by BIND
- **Together they ride out a Graylog restart almost completely.**
  - `socat … TCP/OPENSSL:…,retry=120,interval=1` keeps named's connection waiting instead of being dropped.
  - `fstrm-set-input-queue-size 16384` (per worker thread) holds the frames until Graylog is back: 12 threads × 16,384 ≈ 98 s at 2,000 q/s.

  Beyond the queue, named drops frames and counts them; it never slows DNS.

**Recommended BIND + relay settings:**
```
options {
    dnstap { auth query; client query; };
    dnstap-output unix "/run/named/dnstap.sock";
    dnstap-identity hostname;
    fstrm-set-input-queue-size 16384;      // per worker thread; size it for the longest Graylog outage to ride out
};
```
```bash
socat -b 262144 UNIX-LISTEN:/run/named/dnstap.sock,fork,unlink-early,user=bind,group=bind,mode=0660 \
  OPENSSL:graylog.example:6000,cafile=/etc/bind/tls/ca.crt,cert=/etc/bind/tls/client.crt,key=/etc/bind/tls/client.key,verify=1,nodelay,retry=120,interval=1
```
Run socat as a systemd service with `Restart=always`, and monitor the flow as described in the next section.

## Monitoring
All metrics are under *System > Nodes > Metrics* and `GET /api/system/metrics/<name>`, with `I` = the input id.

| Metric | Type | Meaning |
|---|---|---|
| `org.graylog.plugins.dnstap.DnstapInput.I.incomingMessages` | meter | frames received (Graylog's own); `m1_rate` = msg/s |
| `….DnstapInput.I.open_connections` | gauge | connected relays (BIND); 0 = nothing is sending |
| `….DnstapInput.I.fstrm.frames` | counter | data frames decoded |
| `….DnstapInput.I.fstrm.control.ready` / `start` / `stop` | counter | handshakes: a growing `start` means senders reconnect |
| `….DnstapInput.I.fstrm.errors.framing` | counter | corrupt streams; each one closes a connection |
| `….DnstapInput.I.fstrm.frameSize` | histogram | bytes per frame (1 in 32 sampled) |
| `org.graylog.plugins.dnstap.DnstapCodec.I.failures` | counter | undecodable frames (Graylog's codec failure counter) |
| `….DnstapCodec.I.eventLagMs` | histogram | Graylog processing time − DNS event time, ms (1 in 32 sampled); a rising p95 = backlog |
| `….DnstapCodec.I.types.CQ` (`AQ`, `CR`, …) | meter | messages per dnstap type |
| `….DnstapCodec.I.skipped`, `nonMessage` | meter | dropped by *Skip message types* / not a DNS message |

A lag p95 of about **1 s at low rates is normal**: named sends a partly filled output buffer only once per
`fstrm-set-output-flush-timeout` (default 1 s). Counters restart at 0 when the input restarts; `dnstap-health` treats
a lower value as such a reset.

Also watch BIND's `DNSTAPdropped` (statistics channel, `/xml/v3/server`). It counts frames named had to drop
because its queue was full.

**`monitor/dnstap-health`** is a read-only check following Nagios/Icinga conventions (exit 0/1/2/3, perfdata), for cron, Nagios, Icinga or Zabbix:
```bash
monitor/dnstap-health --url https://graylog.example:9000 --token TOKEN --bind-stats http://ns1:8053 --min-rate 50
# DNSTAP OK - rate=1032/s conns=1 lag_p95=1054ms frames=... framing_errors=0 failures=0 bind_dropped=0 | ...
```
- **CRITICAL:** input missing or not running, no sender connected, rate below `--min-rate`, lag p95 above `--lag-crit`.
- **WARNING:** lag above `--lag-warn`, or new framing errors, undecodable frames or BIND drops since the last run (`--state` file).

**`monitor/create-graylog-alerts`** sets up Graylog-native alerting. It is idempotent, so re-running it updates the existing definitions:
```bash
monitor/create-graylog-alerts --url https://graylog.example:9000 --token TOKEN --minutes 5 --webhook https://alerts.example/hook
```
It creates the event definition *"dnstap: no messages for 5 min"* on the stream, checked every minute, plus an HTTP
notification, and adds the webhook to Graylog's URL allowlist. That allowlist is on by default in 7.x, and without the
entry every notification fails with "is not allowlisted".

⚠️ **The Graylog alert needs other traffic on the cluster.** Graylog 7.1.10 runs an aggregation window only after a
message received after the window start has been indexed on some node: `EventProcessorDependencyCheck` waits while
every node is idle. A production Graylog always receives other logs, so the alert fires 2–3 min after dnstap stops
(window + 1 min schedule). On a Graylog that receives **only** dnstap, it never fires. The lab test shows both:
nothing at all in 330 s without other traffic, and the alert firing once some other syslog traffic flows. `dnstap-health` has no such
dependency, so use it as the primary check and the Graylog alert as the second one.

`itest/itest-monitoring` injects each fault and checks that it is reported (see the test table).

## Layout
`src/main/java/org/graylog/plugins/dnstap/`:
- `FstrmTransport` (Graylog TCP transport + decoder)
- `FstrmFrameDecoder` (Frame Streams)
- `DnstapCodec` (fields)
- `DnstapFrame` / `ProtoReader` (protobuf)
- `DnsMessage` (DNS wire format)
- `DnstapInput`, `DnstapModule`, `DnstapPlugin`, `DnstapPluginMetaData`

Tests and the BIND capture are in `src/test/`. Integration tests are in `itest/`; their outputs go to `itest/results/`.

License: MIT. Credit to Sergey I. Yarkin for the original plugin.
