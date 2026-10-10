# graylog-plugin-dnstap

A **Dnstap input for Graylog 7.1**. It receives [dnstap](https://dnstap.info/) over Frame Streams (TCP, optionally
TLS) and turns every DNS message into a Graylog message with parsed fields: client, query name/type, response code,
answers, latency and more.

Use it to get DNS server query logs into Graylog without the text query log. Compared with BIND's query log over
syslog/UDP, measured on the same lab:
- BIND needs **about half the CPU** (named + rsyslog versus named + socat)
- **~1.5× the end-to-end throughput** over plain TCP; about equal with TLS, where Graylog is the limit
- a Graylog restart costs **~31 events instead of ~27,000**, with the recommended relay settings

Version **1.0.4**, built and tested against **Graylog 7.1.10** and **BIND 9.20** (Debian 13). See
[READINESS.md](READINESS.md) for the full test results.

This is a rewrite of [sega-yarkin/graylog-plugin-dnstap](https://github.com/sega-yarkin/graylog-plugin-dnstap)
(v0.0.2, MIT, for Graylog 2.x; see the [community thread](https://community.graylog.org/t/dnstap-input-plugin/22770)).
The original can't load on Graylog 7.x. It uses Netty 3, `javax.inject`, the Graylog 2.x codec and input APIs and
protobuf 3.0.

| | Original 0.0.2 | This plugin 1.0.4 |
|---|---|---|
| Graylog API | 2.x (Netty 3, `javax.inject`, `new Message(...)`) | 7.1 (Netty 4 `AbstractTcpTransport`, `jakarta.inject`, `MessageFactory`, `decodeSafe` + `InputProcessingException`) |
| Frame Streams | READY → ACCEPT; STOP ignored | full handshake (READY/ACCEPT/START/STOP/FINISH), unidirectional streams, content-type check, frame size limit |
| Decoding | protobuf-java 3.0 + dnsjava 2.1 | small hand-written protobuf and DNS parsers: **no runtime dependencies**, no clash with Graylog's own protobuf, ~240k frames/s per core |
| Fields | `dnstap_*` | dnstap metadata **and** the field names a BIND query-log pipeline produces (`client_ip`, `qname`, `qtype`, …), plus `rcode`, `answers`, `latency_us`, `dns_flags`, … |
| Settings | full message on/off | include answers; skip message types; maximum frame size |
| Monitoring | — | input and codec metrics, a Nagios-style health check, Graylog alert setup (`monitor/`) |
| Tests | — | 24 unit tests incl. fuzzing with millions of cases; TLS, restart, fault/monitoring, throughput and 1 h soak tests in a production-like lab |

## Contents
- [How it fits together](#how-it-fits-together)
- [Install on Graylog](#install-on-graylog)
- [Set up BIND 9](#set-up-bind-9)
- [Verify](#verify)
- [Input settings](#input-settings)
- [Fields](#fields)
- [Monitoring](#monitoring)
- [Restarts and outages](#restarts-and-outages)
- [Performance and sizing](#performance-and-sizing)
- [Build from source](#build-from-source)
- [Tests](#tests)
- [Static analysis](#static-analysis)
- [Changelog](#changelog)
- [License](#license)

## How it fits together

```
named --dnstap--> /run/named/dnstap.sock --socat (TLS, client cert)--> Graylog Dnstap input :6000 --> stream
```

BIND writes dnstap only to a file or a **Unix socket**, so a small relay (`socat`) carries the socket to Graylog. The
Frame Streams handshake passes through it unchanged. The relay runs on the DNS server, as a systemd service.

## Install on Graylog

Download `graylog-plugin-dnstap-1.0.4.jar` from the releases, or [build it](#build-from-source).

1. Copy the jar to the plugin directory on **every Graylog node**: `plugin_dir` in `server.conf`, normally
   `/usr/share/graylog-server/plugin/` for package installs and `/usr/share/graylog/plugin/` in the Docker image.
   Keep **only one** jar of this plugin there; two versions of the same plugin conflict at startup.
2. Restart Graylog. The log shows `Loaded plugin: Dnstap Input 1.0.4`.
3. For TLS (recommended), put the server certificate, its key (PKCS#8 PEM) and the CA certificate somewhere the
   `graylog` user can read, e.g. `/etc/graylog/server/dnstap-tls/`. No internal CA? Use
   [`contrib/make-dnstap-pki.sh`](contrib/make-dnstap-pki.sh) `graylog.example.org`. It creates the CA, the server
   certificate (SAN = the Graylog host name) and a client certificate for the relay.
4. **System → Inputs → "Dnstap (Frame Streams/TCP)" → Launch new input** (Global on a multi-node cluster):
   - port 6000
   - *Enable TLS*, with *TLS cert file* and *TLS private key file* set to the server files
   - *TLS client authentication*: required; *TLS Client Auth Trusted Certs*: the CA certificate

   Graylog 7.1's setup wizard then offers to route the input into a new stream, e.g. "BIND dnstap". Start the input.
5. Allow port 6000/tcp from the DNS servers only.

**Upgrading:** from 1.0.x, replace the jar and restart: inputs and settings are kept. From the original 0.0.2
plugin (which can't load on 7.x anyway), remove its jar and create the input anew: the input type is different.

## Set up BIND 9

Tested with Debian 13's `bind9` 9.20 (built with `--enable-dnstap`; check with `named -V`).

**1. The relay.** Install `socat`. Put `ca.crt`, `client.crt` and `client.key` in `/etc/bind/dnstap-tls/`
(root:bind, key 0640). Install [`contrib/dnstap-relay.service`](contrib/dnstap-relay.service) as
`/etc/systemd/system/dnstap-relay.service`, set your Graylog host in it, then enable it:
```bash
sudo systemctl daemon-reload
```
```bash
sudo systemctl enable --now dnstap-relay
```
`retry=120,interval=1` in the unit matters: see [Restarts and outages](#restarts-and-outages).

**2. AppArmor (Debian/Ubuntu).** named's AppArmor profile doesn't allow the socket, so named can't connect without
this line. Add it to `/etc/apparmor.d/local/usr.sbin.named`:
```
/{,var/}run/named/dnstap.sock rw,
```
Then reload the profile:
```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.named
```

**3. named.conf**, inside `options { }`:
```
dnstap { auth query; client query; };       // one message per incoming query, like the query log
dnstap-output unix "/run/named/dnstap.sock";
dnstap-identity hostname;                   // becomes the message source in Graylog
fstrm-set-input-queue-size 16384;           // per worker thread: rides out a Graylog restart
```
Then `named-checkconf` and `systemctl restart named`.

⚠️ **Use `auth` *and* `client`.** BIND tags a query `CLIENT_QUERY` only when it is recursive (RD set and recursion
allowed for that client), and `AUTH_QUERY` otherwise. With `client query` alone, every non-recursive query is
silently missing. `auth`/`client` without `query`/`response` logs both directions: two messages per query, and the
responses add `rcode`, `answers` and `latency_us`.

**4. Switch off the text query log** once dnstap works (`rndc querylog off`, and `querylog no;` or remove the
`queries` category in the config). Otherwise every query is logged twice and the CPU saving is lost. Other
categories can stay on syslog.

## Verify
- The Dnstap input shows **1 active connection** per DNS server.
- Run `dig @your-dns-server www.example.com`, then search the stream for `qname:www.example.com`.
- If nothing arrives:
  - check `journalctl -u dnstap-relay`
  - check `journalctl -k | grep -i apparmor` for denials of named
  - check the Graylog server log for TLS handshake errors

## Input settings
Besides Graylog's usual bind address, port, TLS, receive buffer, worker threads and *Override source*:

| Setting | Default | |
|---|---|---|
| Maximum frame size | 1 MiB | clamped to 65,535 + 1,024 B … 16 MiB; a bigger frame is a framing error and closes the connection |
| Include answers | on | the `answers` field of responses (capped at 8 KiB of text, each rdata at 256 characters) |
| Skip message types | empty | e.g. `CR,AR`: dropped at the input, counted in the `skipped` metric |
| TCP keepalive (Graylog's setting) | **on** for new inputs | lets the kernel close connections whose relay vanished without closing them (host down, network cut). Inputs created with 1.0.3 or older keep their stored value: enable it there |

## Fields

| Field | Example | Notes |
|---|---|---|
| `message` | `CQ 10.0.0.101#54344 -> www.example.org IN A` / `CR 10.0.0.101#54344 <- www.example.org IN A NOERROR [A 192.0.2.80]` | |
| `source` | `ns1` | dnstap identity; else the sender address; or *Override source* |
| `timestamp` | query (or response) time from dnstap, ms precision, UTC | |
| `dnstap_type`, `dnstap_type_short` | `CLIENT_QUERY`, `CQ` | AQ AR CQ CR RQ RR FQ FR SQ SR TQ TR UQ UR |
| `dnstap_version` | `BIND 9.20.29-1~deb13u1-Debian` | |
| `socket_family`, `socket_protocol` | `INET`, `UDP` | |
| `query_ip`, `query_port`, `response_ip`, `response_port` | | raw dnstap addresses |
| `client_ip`, `client_port`, `server_ip` | | for AUTH_\*, CLIENT_\*, UPDATE_\* messages (the client side) |
| `qname`, `qtype`, `qclass` | `www.example.org`, `A`, `IN` | first question, no trailing dot |
| `dns_id`, `dns_opcode`, `dns_flags`, `dns_size` | `QUERY`, `qr aa rd` | |
| `rcode`, `answer_count`, `answers`, `latency_us` | `NOERROR`, `1`, `A 192.0.2.80` | responses only |
| `query_zone` | | when BIND sets it |
| `dnstap_event_time_suspect` | `true` | only when the dnstap time is more than 7 days from the receive time; `timestamp` is then the receive time |

An undecodable frame raises an `InputProcessingException`. Graylog counts it as a processing failure, and the plugin
counts it in its `failures` metric. Non-message dnstap payloads are skipped and counted (`nonMessage`).

## Monitoring
All metrics are under *System → Nodes → Metrics* and `GET /api/system/metrics/<name>`, with `I` = the input id.

| Metric | Type | Meaning |
|---|---|---|
| `org.graylog.plugins.dnstap.DnstapInput.I.incomingMessages` | meter | frames received (Graylog's own); `m1_rate` = msg/s |
| `….DnstapInput.I.open_connections` | gauge | connected relays; 0 = nothing is sending |
| `….DnstapInput.I.fstrm.frames` | counter | data frames decoded |
| `….DnstapInput.I.fstrm.control.ready` / `start` / `stop` | counter | handshakes: a growing `start` means senders reconnect |
| `….DnstapInput.I.fstrm.errors.framing` | counter | corrupt streams; each one closes a connection |
| `….DnstapInput.I.fstrm.frameSize` | histogram | bytes per frame (1 in 32 sampled) |
| `org.graylog.plugins.dnstap.DnstapCodec.I.failures` | counter | undecodable frames |
| `….DnstapCodec.I.eventLagMs` | histogram | Graylog processing time − DNS event time, ms (1 in 32 sampled); a rising p95 = backlog |
| `….DnstapCodec.I.types.CQ` (`AQ`, `CR`, …) | meter | messages per dnstap type |
| `….DnstapCodec.I.skipped`, `nonMessage` | meter | dropped by *Skip message types* / not a DNS message |

Notes on these metrics:
- A lag p95 of about **1 s at low rates is normal**: named sends a partly filled buffer once per
  `fstrm-set-output-flush-timeout` (default 1 s).
- Counters restart at 0 when the input restarts. When an input is stopped or deleted, its metrics are removed.
- Also watch BIND's `DNSTAPdropped` counter (statistics channel, `/xml/v3/server`): frames named dropped because its
  queue was full.

**[`monitor/dnstap-health`](monitor/dnstap-health)** is a read-only check with Nagios/Icinga conventions (exit
0/1/2/3, perfdata), for cron, Nagios, Icinga or Zabbix. It needs `curl` and `jq` and a Graylog API token:
```bash
monitor/dnstap-health --url https://graylog.example.org:9000 --token TOKEN --bind-stats http://ns1:8053 --min-rate 50
```
It prints a line such as `DNSTAP OK - rate=1032/s conns=1 lag_p95=1054ms frames=... framing_errors=0 failures=0 bind_dropped=0 | ...`.
- **CRITICAL:** the input is missing or not running, no sender is connected, the 1-min rate is below `--min-rate`, or
  the lag p95 is above `--lag-crit`.
- **WARNING:** the lag is above `--lag-warn`, or there are new framing errors, undecodable frames or BIND drops since
  the last run (kept in the `--state` file; a counter that went down counts as a reset).

**[`monitor/create-graylog-alerts`](monitor/create-graylog-alerts)** sets up Graylog-native alerting and is idempotent:
```bash
monitor/create-graylog-alerts --url https://graylog.example.org:9000 --token TOKEN --minutes 5 --webhook https://alerts.example.org/hook
```
- It creates the event definition *"dnstap: no messages for 5 min"* on the stream, checked every minute.
- It adds an optional HTTP notification and puts the webhook on Graylog's URL allowlist, which 7.x enables by default.

⚠️ **The Graylog alert needs other traffic on the cluster.** Graylog 7.1 evaluates an aggregation window only after
a message received after the window start has been indexed somewhere. While every node is idle, it waits.
- A Graylog that also receives other logs fires the alert 2–3 min after dnstap stops.
- On a Graylog that receives **only** dnstap, it never fires.

`dnstap-health` has no such dependency: use it as the primary check.

## Restarts and outages
Measured at 2,000 q/s over TLS, counting every query exactly. *Lost* = queries BIND answered whose event never
reached Graylog.

| Event | Default relay (BIND queue 512/thread) | Queue 16384 + relay retry (recommended) |
|---|---|---|
| Graylog input stopped 5 s | 9,593 lost | **56** |
| Graylog restart (~15 s) | 28,767 lost | **31** |
| (comparison) Graylog restart with syslog/UDP | 26,773 lost | – |
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
  - `fstrm-set-input-queue-size 16384` holds the frames meanwhile: per worker thread, so 12 threads ≈ 98 s at 2,000 q/s.
  - Beyond the queue, named drops frames and counts them; it never slows DNS.

## Performance and sizing
Measured on a lab with 12 CPUs / 9 GB, Graylog 7.1.10 with a 2 GB heap, one Data Node and BIND 9.20:

| | syslog → rsyslog → UDP | dnstap |
|---|---|---|
| Sustained end to end (no loss, no backlog) | 10k q/s | 15k q/s plain TCP; 10k with TLS |
| named CPU at 15k q/s | 1.38 cores + rsyslog 0.47 | 0.96 cores + socat ~0.01 |
| DNS answers start failing | 15–20k q/s | 25–30k q/s |

The plugin itself decodes ~240k frames/s per core, and BIND + relay export losslessly up to 30k q/s. **The limit is
Graylog/OpenSearch**: size them for your peak query rate. Beyond their capacity the journal grows: no loss, but
delay. Storage is about 200 bytes per event in OpenSearch.

## Build from source
```bash
./build.sh
```
- Needs only Docker: the build runs Maven + JDK 21 in `maven:3.9.9-eclipse-temurin-21`.
- It extracts `graylog.jar` from the `graylog/graylog:7.1.10` image, compiles against it and runs the unit tests.
- Output: `dist/graylog-plugin-dnstap-1.0.4.jar`.

Variants:
- `./build.sh bench` adds the codec throughput micro-benchmark.
- `FUZZ_ITERATIONS=3000000 ./build.sh` fuzzes longer (default 300,000).
- `GRAYLOG_VERSION=7.1.x ./build.sh` builds against another 7.1 image.
- `./build.sh analyze` also runs the static analysers (see [Static analysis](#static-analysis)).

Layout (`src/main/java/org/graylog/plugins/dnstap/`):

| Class | What it does |
|---|---|
| `DnstapInput`, `DnstapModule`, `DnstapPlugin`, `DnstapPluginMetaData` | Graylog wiring |
| `FstrmTransport` | Graylog TCP transport, with TLS from Graylog |
| `FstrmFrameDecoder` | Frame Streams framing and handshake |
| `FstrmMetrics` | the input's metrics |
| `DnstapCodec` | dnstap → Graylog message fields |
| `DnstapFrame`, `ProtoReader` | protobuf |
| `DnsMessage` | DNS wire format |

Unit tests and a real BIND 9.20.29 dnstap capture (629 frames) are in `src/test/`.

## Tests
**In this repository** (`./build.sh`): 24 unit tests on the BIND capture, covering:
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

**In a production-like lab** (Graylog 7.1.10 + Data Node + MongoDB cluster, BIND 9.20.29; the lab harness isn't part
of this repository):
- TLS client-certificate cases
- restarts of every component
- fault injection checked against the monitoring
- the web UI
- stepped throughput benchmarks with exact per-query counting
- a 1 h soak at 3,000 q/s over TLS: 10,800,000 of 10,800,000 delivered, resources stable

Results and findings are in [READINESS.md](READINESS.md).

## Static analysis
`./build.sh analyze` runs three tools on top of the normal build and tests. They report findings without failing the build:
- **Error Prone** checks bug patterns at compile time, together with `javac -Xlint:all`.
- **SpotBugs** with **FindSecBugs** analyses the bytecode for bugs and security issues.
- **PMD** checks the source, including copy-paste detection.

Their reports are in `target/spotbugsXml.xml` and `target/pmd.xml`.

The first run on 1.0.3 reported 10 SpotBugs, 11 Error Prone/javac and 61 PMD findings. Version 1.0.4 fixes every real one: an
ignored write future, sender data in log lines, unread fields, a duplicate branch, a lost exception cause, a deprecated
API and style issues. That leaves 7 SpotBugs, 3 Error Prone and 5 PMD findings, each reviewed and kept on purpose:

| Finding | Why it stays |
|---|---|
| SpotBugs `EI_EXPOSE_REP2`: storing the injected `MetricRegistry` | it's Graylog's shared registry; holding the reference is the point |
| FindSecBugs `CRLF_INJECTION_LOGS` in `FstrmFrameDecoder` | the remaining logged values are the peer address, the plugin's own numeric messages, and content types already stripped of control characters (`printable()`), which the tool can't see |
| PMD `GuardLogStatement` | SLF4J parameterized calls with cheap arguments; the one costly argument is guarded |
| Error Prone `NonApiType` / PMD `LooseCoupling` (`LinkedHashMap`) | the type is fixed by the Graylog method being overridden |
| Error Prone `NonCanonicalType` (`AbstractCodec.Factory`) | the form Graylog's own codecs use |
| Error Prone `FutureReturnValueIgnored` in `FuzzTest` | closing a test channel during teardown; nothing to check |

On top of the tools, a review looked for problems that only show up after long uptime or many configuration changes
(fixed in 1.0.4, covered by `LongRunningSafetyTest`):
- codec metrics and a static cache entry that outlived every deleted input
- half-open connections without keepalive
- an unbounded cache keyed by configuration text
- a data race in the per-type meters

The metric cleanup was also checked in a real Graylog 7.1.10. While the input runs, the plugin's metrics exist. After a
stop only Graylog's own remain, and after a restart the plugin's come back, with 200 of 200 test queries delivered.

The 1 h soak (see READINESS.md) showed no growth in heap, threads, file descriptors or RSS.

## Changelog
**1.0.4** brings fixes from static analysis and a review for long uptime:
- When an input is stopped or deleted, its codec metrics are removed. Before, they stayed in Graylog's registry until
  restart, with a cache entry for every input ever created.
- New inputs have TCP keepalive on, so half-open connections get closed.
- A failed ACCEPT write closes the connection.
- Sender-supplied content types are sanitised before logging.
- The skip-types cache is bounded, and the per-type meters are free of data races.
- Undecodable frames keep their cause, and the plugin no longer uses the deprecated `ConfigurationRequest.removeField()`.
- Code cleanup. 29 unit tests.

**1.0.3** fixes from a review against the Graylog 7.1.10 sources:
- A framing error is counted, logged once and closed by the plugin. Before, it was rethrown, so Graylog logged a
  second ERROR.
- READY with a content type other than `protobuf:dnstap.Dnstap` gets no ACCEPT, and the connection is closed.
- FINISH is sent only after a READY, which bidirectional senders send first, and the connection closes once it is
  written.
- `answers` is capped at 8 KiB in total.
- A dnstap time more than 7 days off falls back to the receive time, and `dnstap_event_time_suspect` is set.
- Missing ports are omitted instead of being written as `-1`, IPv6 addresses use the canonical form, the meaningless
  *Encoding* setting is gone, and *Maximum frame size* is bounded.

**1.0.2** added monitoring: the metrics and the `monitor/` scripts. Graylog creates a new codec instance for every
message, so the metrics, the parsed skip list and the sampling counters live in static per-input caches.

**1.0.1** brought hardening found by fuzzing:
- A framing error now closes the connection, because the stream can't resynchronise.
- The connection is no longer closed inside `decode()`, which used an already released buffer on every STOP/FINISH.
- MX rdata is bounds-checked.
- Any unexpected exception becomes a per-frame `InputProcessingException`.

**1.0.0** was the rewrite for the Graylog 7.1 plugin API.

## License
MIT, see [LICENSE](LICENSE).

Based on the original plugin, Copyright (c) 2016 Sergey I. Yarkin, MIT. This is an independent community plugin, not
affiliated with or endorsed by Graylog, Inc. or ISC.
