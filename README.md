# graylog-plugin-dnstap for Graylog 7.1

A **Dnstap input** for Graylog **7.1.10**: it receives [dnstap](https://dnstap.info/) over Frame Streams/TCP and
turns each DNS message into a Graylog message with parsed fields.

It is a rewrite of [sega-yarkin/graylog-plugin-dnstap](https://github.com/sega-yarkin/graylog-plugin-dnstap)
(v0.0.2, MIT, written for Graylog 2.x; see the [community thread](https://community.graylog.org/t/dnstap-input-plugin/22770)).
The original can't load on 7.x: it uses Netty 3, `javax.inject`, Graylog 2.x codec/input APIs, the old `Message`
constructors and protobuf 3.0.

| | Original 0.0.2 | This plugin 1.0.0 |
|---|---|---|
| Graylog API | 2.x (Netty 3, `javax.inject`, `new Message(...)`) | 7.1 (Netty 4 `AbstractTcpTransport`, `jakarta.inject`, `MessageFactory`, `decodeSafe` + `InputProcessingException`) |
| Frame Streams | READY → ACCEPT; ignored STOP | READY → ACCEPT (with content type), START, **STOP → FINISH + close**, unidirectional files; frame size limit |
| Decoding | protobuf-java 3.0 generated classes + dnsjava 2.1 | small hand-written protobuf + DNS wire parsers: **no dependencies**, no clash with Graylog's own protobuf, ~630k frames/s per core (codec micro-benchmark) |
| Fields | `dnstap_*` | dnstap metadata **and** the names a BIND query-log pipeline produces (`client_ip`, `client_port`, `qname`, `qclass`, `qtype`, `server_ip`), plus `rcode`, `answers`, `latency_us`, `dns_flags`, … |
| Config | full message on/off | include answers; skip message types (e.g. drop responses at the input) |
| Tests | — | 8 unit tests against a real BIND 9.20.29 dnstap capture (frame decoding in random chunks, handshake, type counts equal to `dnstap-read`, field values) |

## Build
```bash
./build.sh            # compiles against graylog.jar of graylog/graylog:7.1.10 (extracted from the image), runs the tests
./build.sh bench      # + codec throughput micro-benchmark
# -> dist/graylog-plugin-dnstap-1.0.0.jar (33 KB)
```
Needs only Docker: it runs Maven + JDK 21 in `maven:3.9.9-eclipse-temurin-21`.
`GRAYLOG_VERSION=7.1.x ./build.sh` builds against another 7.1 image.

## Install
- **Package install:** copy the jar to `/usr/share/graylog-server/plugin/` and restart `graylog-server`.
- **Docker:** mount the jar's directory at `/usr/share/graylog/plugin/`.
- **These labs:** `../graylog-lab/deploy-graylog-lab --name X --plugin-dir ../graylog-plugin-dnstap/dist`

The server log shows `Loaded plugin: Dnstap Input 1.0.0`. The new input type is **Dnstap (Frame Streams/TCP)**,
default port 6000.

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

Malformed frames raise an `InputProcessingException`, so they show up in Graylog's input/processing failure handling.
Non-message dnstap payloads are skipped.

## Layout
`src/main/java/org/graylog/plugins/dnstap/`:
- `FstrmTransport` (Graylog TCP transport + decoder)
- `FstrmFrameDecoder` (Frame Streams)
- `DnstapCodec` (fields)
- `DnstapFrame` / `ProtoReader` (protobuf)
- `DnsMessage` (DNS wire format)
- `DnstapInput`, `DnstapModule`, `DnstapPlugin`, `DnstapPluginMetaData`

Tests and the BIND capture are in `src/test/`.

License: MIT. Credit to Sergey I. Yarkin for the original plugin.
