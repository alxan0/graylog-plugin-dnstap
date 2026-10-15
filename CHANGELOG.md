# Changelog

## 1.3.0

Every field the plugin extracts now starts with `dns_`, apart from `dnstap` and the `dnstap_*` fields.

- Renamed: `socket_family`, `socket_protocol`, `query_ip`, `query_port`, `response_ip`, `response_port`,
  `client_port`, `server_ip`, `query_zone`, `rcode`, `answer_count`, `answers` and `latency_us` get the `dns_`
  prefix; `qclass` becomes `dns_query_class`, like `dns_query_name` and `dns_query_type`.
- An existing `dnstap-fields.conf` must name fields by their 1.3.0 names on the left (`dns_query_class = ...`, not
  `qclass = ...`). An old name is an unknown field, and a file with any problem is ignored as a whole.
- To keep the 1.2.0 names, put these lines in `dnstap-fields.conf`:
  ```
  dns_socket_family = socket_family
  dns_socket_protocol = socket_protocol
  dns_query_ip = query_ip
  dns_query_port = query_port
  dns_response_ip = response_ip
  dns_response_port = response_port
  dns_client_port = client_port
  dns_server_ip = server_ip
  dns_query_zone = query_zone
  dns_query_class = qclass
  dns_rcode = rcode
  dns_answer_count = answer_count
  dns_answers = answers
  dns_latency_us = latency_us
  ```

## 1.2.0

Adds the EDNS data of queries and fixes the problems found by a security review.
- New fields for queries, from the OPT record: `dns_edns`, `dns_edns_version`, `dns_do_bit` and `dns_ecs` (EDNS
  Client Subnet). No pipeline rule can get them from the other fields. If the record sections can't be parsed,
  `dns_edns`, `dns_do_bit` and `dns_ecs` are false and `dns_edns_version` is left out; the rest of the message is
  kept.
- A second READY on a connection is a framing error and closes it. Before, every READY was answered with ACCEPT, so a
  sender that never read the replies could make the input queue ACCEPT frames without limit.
- dnstap identity and version are capped at 255 bytes. A longer one made the message fail to index.
- A broken answer record ends the answer list instead of dropping the whole message.
- The text caps no longer cut an emoji or another surrogate pair in half, which made Graylog's search API return
  invalid JSON.
- Tested on Graylog 7.2.0.

## 1.1.0

Aligns field names with a BIND query log pipeline and makes them configurable.
- `client_ip`, `qname` and `qtype` are now `dns_client_ip`, `dns_query_name` and `dns_query_type`.
- Every message has `dnstap: true`, so pipeline rules can select dnstap messages.
- Any field can be renamed with `dnstap-fields.conf` in the plugin directory, read when the input starts (in Docker,
  when the container starts). A file with any error is ignored and reported in Graylog's log. To keep the 1.0.x
  names:
  ```
  dns_client_ip = client_ip
  dns_query_name = qname
  dns_query_type = qtype
  ```

## 1.0.7

Fixes leaks found by a leak test with input stop/start cycles.
- Graylog 7.1.10 never shuts down an input's worker thread pool, so every start of a TCP input leaves its worker
  threads (12 by default) and the old transport behind: about 0.7 MB of heap per restart, for every TCP input. The
  Dnstap input now builds its worker group like Graylog does, but shuts the pool down when the group stops. It also
  releases the input's throughput counter on stop, which Graylog leaves running.
- Deleting an input while some of its messages still waited in Graylog's journal re-created 11 of its metrics for
  good. Metrics are now only created for inputs that are running.
- New tests: input lifecycle (metrics and worker threads), and an opt-in long leak soak (`LeakSoakTest`).

## 1.0.6

Hardens the plugin against sender input.
- Sender-chosen text is escaped: control characters in identity, version and TXT become `\DDD`.
- The default *Maximum frame size* drops from 1 MiB to 256 KiB, because it bounds the memory an incomplete frame can
  hold per connection. Existing inputs keep their stored value.
- New tests: buffer lifecycle and field injection. 37 tests.

## 1.0.5

Fixes a CPU amplification.
- A crafted 400 KB message with 65,535 questions pointing at one long name took ~146 ms to decode, about 7 frames/s
  per core. It now takes under 1 ms: extra questions and owner names are skipped as wire bytes, without being
  decoded.

## 1.0.4

Fixes from static analysis and a review for long uptime.
- When an input is stopped or deleted, its codec metrics are removed. Before, they stayed in Graylog's registry until
  restart, with a cache entry for every input ever created.
- New inputs have TCP keepalive on, so half-open connections get closed.
- A failed ACCEPT write closes the connection.
- Sender-supplied content types are sanitised before logging.
- The skip-types cache is bounded, and the per-type meters are free of data races.
- Undecodable frames keep their cause, and the plugin no longer uses the deprecated
  `ConfigurationRequest.removeField()`.
- Code cleanup. 29 unit tests.

## 1.0.3

Fixes from a review against the Graylog 7.1.10 sources.
- A framing error is counted, logged once and closed by the plugin. Before, it was rethrown, so Graylog logged a
  second ERROR.
- READY with a content type other than `protobuf:dnstap.Dnstap` gets no ACCEPT, and the connection is closed.
- FINISH is sent only after a READY, which bidirectional senders send first, and the connection closes once it is
  written.
- `answers` is capped at 8 KiB in total.
- A dnstap time more than 7 days off falls back to the receive time, and `dnstap_event_time_suspect` is set.
- Missing ports are omitted instead of being written as `-1`, and IPv6 addresses use the canonical form.
- The meaningless *Encoding* setting is gone, and *Maximum frame size* is bounded.

## 1.0.2

Adds monitoring.
- New metrics and the `monitor/` scripts.
- Graylog creates a new codec instance for every message, so the metrics, the parsed skip list and the sampling
  counters live in static per-input caches.

## 1.0.1

Hardening found by fuzzing.
- A framing error now closes the connection, because the stream can't resynchronise.
- The connection is no longer closed inside `decode()`, which used an already released buffer on every STOP/FINISH.
- MX rdata is bounds-checked.
- Any unexpected exception becomes a per-frame `InputProcessingException`.

## 1.0.0

Rewrite for the Graylog 7.1 plugin API, done with the help of Claude (Anthropic).
