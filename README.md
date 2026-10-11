# graylog-plugin-dnstap

A Graylog 7.1 input that receives [dnstap](https://dnstap.info/) from DNS servers (BIND, Unbound, Knot and others)
and stores each query as a Graylog message with parsed fields: client IP, query name and type, response code,
answers and latency.

Compared with sending BIND's query log over syslog, dnstap uses about half the CPU on the DNS server. With the relay
settings below, it also survives a Graylog restart almost without losing events.

Tested with Graylog 7.1.10 and BIND 9.20 on Debian 13.

## How it works

BIND only writes dnstap to a file or a Unix socket, so `socat` on the DNS server forwards the socket to the Graylog
input over TCP (TLS recommended):

```
named -> /run/named/dnstap.sock -> socat (TLS) -> Graylog Dnstap input :6000
```

## Install

**Graylog**

1. Get `graylog-plugin-dnstap-<version>.jar` from the [releases](../../releases), or build it (see below).
2. Copy it into the plugin directory of every Graylog node (`/usr/share/graylog-server/plugin/` for package
   installs, `/usr/share/graylog/plugin/` in Docker) and restart Graylog. Keep only one version of the jar there.
3. Create the input under System > Inputs > *Dnstap (Frame Streams/TCP)*, port 6000. For TLS, set the server
   certificate and key, and set *TLS client authentication* to *required* with your CA as trusted certs.
   No CA at hand? [`contrib/make-dnstap-pki.sh`](contrib/make-dnstap-pki.sh) creates one, plus the server and client
   certificates.

**BIND**

Add this inside `options { }` and restart named:

```
dnstap { auth query; client query; };
dnstap-output unix "/run/named/dnstap.sock";
dnstap-identity hostname;
fstrm-set-input-queue-size 16384;
```

Use both `auth` and `client`. BIND tags non-recursive queries as `AUTH_QUERY`, so `client` alone misses them.

Run the relay with [`contrib/dnstap-relay.service`](contrib/dnstap-relay.service) after setting your Graylog host and
certificate paths in it. On Debian and Ubuntu, AppArmor also has to allow named to use the socket. Add this line to
`/etc/apparmor.d/local/usr.sbin.named`, then run `apparmor_parser -r /etc/apparmor.d/usr.sbin.named`:

```
/{,var/}run/named/dnstap.sock rw,
```

Once messages arrive, turn off BIND's text query log (`rndc querylog off`), or every query is logged twice.

[`monitor/`](monitor) has a Nagios-style health check and a script that sets up a Graylog alert for when no dnstap
arrives. Fields, settings, metrics and outage behaviour are covered in [docs/reference.md](docs/reference.md).

## Build

```bash
./build.sh
```

It needs only Docker. The script builds against the `graylog.jar` from the `graylog/graylog:7.1.10` image, runs the
tests, and writes the jar to `dist/`. Use `GRAYLOG_VERSION=7.1.x ./build.sh` to build against another 7.1 release,
and `./build.sh analyze` to also run Error Prone, SpotBugs and PMD.

Test results, including a 3-hour soak test, are in [READINESS.md](READINESS.md). Version history is in
[CHANGELOG.md](CHANGELOG.md).

## Credits

This plugin is a rewrite of [graylog-plugin-dnstap](https://github.com/sega-yarkin/graylog-plugin-dnstap) by
Sergey I. Yarkin, which was written for Graylog 2.x and no longer loads on current versions (see the
[Graylog community thread](https://community.graylog.org/t/dnstap-input-plugin/22770)). Thanks also to the
[dnstap](https://dnstap.info/) project for the format and the Frame Streams protocol.

The port to the Graylog 7.1 plugin API, and the testing behind it, was done with the help of Claude, Anthropic's AI
assistant.

It isn't affiliated with Graylog, Inc. or ISC.

## License

MIT, see [LICENSE](LICENSE).
