# Changelog

**1.1.0** aligns field names with a BIND query log pipeline and makes them configurable:
- `client_ip`, `qname` and `qtype` are now `dns_client_ip`, `dns_query_name` and `dns_query_type`.
- Every message has `dnstap: true`, so pipeline rules can select dnstap messages.
- Any field can be renamed with `dnstap-fields.conf` in the plugin directory, read when the input starts (in
  Docker, when the container starts). A file with any error is ignored and reported in Graylog's log. To keep
  the 1.0.x names:
  ```
  dns_client_ip = client_ip
  dns_query_name = qname
  dns_query_type = qtype
  ```

**1.0.7** fixes leaks found by a leak test with input stop/start cycles:
- Graylog 7.1.10 never shuts down an input's worker thread pool, so every start of a TCP input leaves its worker
  threads (12 by default) and the old transport behind: about 0.7 MB of heap per restart, for every TCP input. The
  Dnstap input now builds its worker group like Graylog does, but shuts the pool down when the group stops. It also
  releases the input's throughput counter on stop, which Graylog leaves running.
- Deleting an input while some of its messages still waited in Graylog's journal re-created 11 of its metrics for
  good. Metrics are now only created for inputs that are running.
- New tests: input lifecycle (metrics and worker threads), and an opt-in long leak soak (`LeakSoakTest`).

**1.0.6** hardens the plugin against sender input:
- Sender-chosen text is escaped: control characters in identity, version and TXT become `\DDD`.
- The default *Maximum frame size* drops from 1 MiB to 256 KiB, because it bounds the memory an incomplete frame
  can hold per connection. Existing inputs keep their stored value.
- New tests: buffer lifecycle and field injection. 37 tests.

**1.0.5** fixes CPU amplification. A crafted 400 KB message with 65,535 questions pointing at one long name took
~146 ms to decode, about 7 frames/s per core; it now takes under 1 ms. Extra questions and owner names are skipped
as wire bytes, without being decoded.

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

**1.0.0** was the rewrite for the Graylog 7.1 plugin API, done with the help of Claude (Anthropic).
