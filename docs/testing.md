# Testing

How to test a change and a release of the plugin. Most checks need only Docker; the live checks need a Graylog with
the plugin and a DNS server sending dnstap to it, ideally a lab built like production (see
[READINESS.md](../READINESS.md) for the one used so far). What the unit tests cover is listed in
[reference.md](reference.md#tests).

- [Per change](#per-change)
- [Release smoke test](#release-smoke-test)
- [Deeper release tests](#deeper-release-tests)
- [Worth adding later](#worth-adding-later)

## Per change

Run these for every change, in this order:

| Check | Command | Pass |
|---|---|---|
| Build and unit tests | `./build.sh` | `BUILD SUCCESS`, `Failures: 0, Errors: 0`; only the two opt-in tests (benchmark, leak soak) skipped |
| Static analysis | `./build.sh analyze` | no finding beyond those reviewed in [reference.md](reference.md#static-analysis) |
| Other Graylog versions | `GRAYLOG_VERSION=7.2.0 ./build.sh`, and so on for each version you support | as `./build.sh` |

Error Prone findings are in the build output (`[WARNING] /src/src/main/...`), SpotBugs and PMD findings in
`target/spotbugsXml.xml` and `target/pmd.xml`. Compare the counts per rule with the previous release; a new rule or a
new class in the list needs a fix or a reason in the table.

Each run replaces `dist/*.jar`, so finish with a plain `./build.sh` (or with the version the release targets) before
copying the jar anywhere.

To run Maven with other options, use the command `build.sh` runs (after one `./build.sh`, which fills `.build/m2`):

```bash
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src maven:3.9.9-eclipse-temurin-21 \
  mvn -B -ntp -Dmaven.repo.local=/src/.build/m2 -Dgraylog.version=7.1.10 OPTIONS clean test
```

## Release smoke test

On a test Graylog, with the jar that will be released. Stop at the first failure.

| # | Step | Pass |
|---|---|---|
| 1 | The per-change checks above, on the release jar's Graylog version | all pass |
| 2 | Put the jar in the plugin directory (only that one plugin jar), restart Graylog | the log shows `Loaded plugin: Dnstap Input <version>` and the field names line (`Field names from ...` or `No ... dnstap-fields.conf, using the default field names`); the input is RUNNING |
| 3 | Send test queries; look at a stored query message | the fields and names match [reference.md](reference.md#fields); a search for a field name of the previous release finds nothing new |
| 4 | Replay the test capture, which has responses: `socat -u FILE:src/test/resources/bind-9.20.29.fstrm TCP:graylog.example.org:6000` (for a TLS input, `OPENSSL:` with a client certificate instead of `TCP:`) | with *Skip message types* empty, 629 messages: AQ 57, AR 13, CQ 223, CR 230, FQ 27, FR 27, UQ 26, UR 26; the 296 responses have `dns_rcode` and `dns_latency_us` |
| 5 | If BIND also writes its query log to Graylog: send queries with different flags and transports and compare each query's fields in both flows | every query in both flows; differences only where they are known (e.g. CH class queries, which have no view) |
| 6 | Your pipeline rules, if any: run their test cases through Graylog's pipeline simulator | all pass |
| 7 | One minute of load at your normal rate, with unique query names | stored = sent (minus BIND's `DNSTAPdropped`), 0 codec failures, 0 processing errors, the journal drains |
| 8 | Stop and start the input about 6 times under load, with `dnstap-fields.conf` valid, invalid, missing and a FIFO | RUNNING after each start; the log reports each file case; afterwards one instance of each plugin class (class histogram) |
| 9 | READY flood (many Frame Streams READY frames on one connection) and a data frame header above *Maximum frame size* | one ACCEPT, then the connection is closed; the oversized frame closes its connection with one WARN line |
| 10 | Graylog's log and indexer failures since step 2 | 0 `LEAK:` lines, 0 indexer failures, ERROR lines only from faults you injected (each undecodable frame logs one) |

Step 3 is what catches a field rename gone wrong, step 4 the response fields when the DNS server exports only queries
(`dnstap { client query; }`), step 8 the input restart leaks fixed in 1.0.7.

## Deeper release tests

For a release that changes decoding, framing, buffer handling or the supported Graylog versions. Each takes from a
minute to a few hours.

**In the repository**
- Long fuzzing: `FUZZ_ITERATIONS=3000000 ./build.sh`. Pass: `FuzzTest` passes. Its summary lines (`codec fuzz: ...`,
  `decoder fuzz: ...`) count the outcomes; only messages, empty results and rejections may occur.
- Unit tests under Netty's paranoid leak detector: `OPTIONS` = `-Dio.netty.leakDetection.level=paranoid` in the Maven
  command above. Pass: all tests pass and the output has no `LEAK:` line. It runs about ten times slower.
- Leak soak: `OPTIONS` = `-Dleak.soak=true -Dtest=LeakSoakTest` (run it alone, so its leak detector is installed
  first). Pass: the test passes; it checks 0 leak reports, the caches and registry back to one input, and heap after GC
  in the second half within 16 MB of the first half.
- Benchmark: `./build.sh bench`, only when decoding speed matters; compare with the previous release on the same
  machine.

**Live**
- Query log comparison with the full matrix: RD, DO, CD, no EDNS, ECS (IPv4, IPv6, over DoH), TCP, DoT, DoH, TSIG,
  EDNS version 1, no cookie, CH class, several query types, deep and mixed-case names, from clients in each view.
- Load at the production peak rate with exact counting at every hop: the load generator, BIND's counters, the input's
  `fstrm.frames`, and a count of stored messages by query name.
- Soak: 1 to 3 hours at a steady rate. Sample every 30 s and compare the first and last hour: heap after GC, threads,
  file descriptors, RSS, journal. A rising floor is a leak; one step at the start is the first GC cycle.
- Input restart leak check: 20 to 30 restarts under load as in smoke step 8. Before and after, force a full GC and
  take a class histogram:
  ```bash
  jcmd PID GC.run
  jcmd PID GC.class_histogram | awk '/^Total/{print $3/1048576 " MB live"} /org\.graylog\.plugins\.dnstap\./'
  ```
  Without `-all` the histogram counts live objects only. `GC.heap_info` counts occupied regions, which can stay
  high after a GC. The Graylog image has only a JRE: copy `jcmd` from a JDK image of the same Java version and run
  it as the Graylog user or with `docker exec --privileged`. Pass: live heap within a few MB, one instance of each
  plugin class, the `netty-transport` thread count unchanged after the first round (worker loops start once, on first
  use), file descriptors not rising, 0 `LEAK:` lines. Count threads by name (`/proc/PID/task/*/comm`): Graylog's own
  pools, such as its REST workers, grow on demand and can make the total rise. Run Graylog with
  `-Dio.netty.leakDetection.level=paranoid` for this test only; it slows Netty down.
- Outages: stop the input, restart Graylog, kill the relay, restart named, each under load; count the lost events and
  check that delivery recovers by itself. Inject faults (corrupt frame, stopped input) and check that
  `monitor/dnstap-health` reports each one.
- Hostile input, as in the 1.2.0 security review: random byte streams, undecodable frames, many parallel connections,
  connections holding an incomplete frame, hostile DNS content (compression loops, overlong labels, broken records,
  emoji in TXT). Pass: the input stays RUNNING, CPU and heap return to normal, each bad connection is closed and
  counted.
- Upgrade: on a Graylog running the previous release with an input and a `dnstap-fields.conf`, swap the jar and
  restart. Pass: the input keeps its settings and runs; the log shows the expected field names.
- TLS: a valid client certificate, no certificate, an untrusted CA, plain TCP against a TLS input.

Write the results into [READINESS.md](../READINESS.md).

## Worth adding later

| Addition | Why |
|---|---|
| Mutation testing with [PIT](https://pitest.org/) (`pitest-maven` with `pitest-junit5-plugin`) on `DnsMessage`, `ProtoReader`, `FstrmFrameDecoder`, `FieldNames` | shows which code changes the tests would not notice, which line coverage can't |
| Coverage-guided fuzzing with [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) `@FuzzTest` on the codec and the frame decoder, seeded with the BIND capture | it steers inputs towards new branches; the seeded fuzzer only mutates at random. Crashing inputs are kept as regression tests that run in every build |
| Property-based tests (e.g. [jqwik](https://jqwik.net/)) for `Text` and the text caps: output never has control characters, never splits a surrogate pair, stays under the cap | shrinking reports the smallest failing input instead of a random one |
| A coverage report (JaCoCo) | cheap way to find branches no test reaches, e.g. rare DNS record types |
| The paranoid leak detector in every build (surefire `argLine`), failing on `LEAK:` | today it's a manual step, so a leak can slip in between releases |
| An automated container test (e.g. [Testcontainers](https://java.testcontainers.org/)) that starts the Graylog image with the jar and sends the capture | catches plugin loading and field problems on each Graylog version without the lab; needs a few GB of RAM for Graylog, MongoDB and OpenSearch |
| An upgrade test that loads the previous release's `dnstap-fields.conf` examples | a rename can make an old file invalid, and then the whole file is ignored |
| [JMH](https://github.com/openjdk/jmh) instead of `DecodeThroughputTest` | JMH handles warm-up and dead-code elimination; only worth it if decoding speed starts to matter |

Concurrency is covered by the restart tests and the 1.1.0 stress test (names reloaded during decoding).
[jcstress](https://github.com/openjdk/jcstress) would only be worth it if the plugin got more shared mutable state
than the one volatile reference in `FieldNames`.

## References

- Test pyramid: https://martinfowler.com/articles/practical-test-pyramid.html
- Netty reference counting and leak detection levels: https://netty.io/wiki/reference-counted-objects.html
- jcmd (GC.run, GC.class_histogram, GC.heap_dump): https://docs.oracle.com/en/java/javase/21/docs/specs/man/jcmd.html
- JUnit user guide: https://docs.junit.org/current/user-guide/
- PIT mutation testing: https://pitest.org/quickstart/maven/
- Jazzer: https://github.com/CodeIntelligenceTesting/jazzer, OSS-Fuzz for JVM projects:
  https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/
- jqwik: https://jqwik.net/docs/current/user-guide.html
- Testcontainers JUnit 5: https://java.testcontainers.org/test_framework_integration/junit_5/
- Error Prone: https://errorprone.info/, SpotBugs: https://spotbugs.github.io/, FindSecBugs:
  https://find-sec-bugs.github.io/, PMD: https://pmd.github.io/
- JMH: https://github.com/openjdk/jmh, jcstress: https://github.com/openjdk/jcstress
