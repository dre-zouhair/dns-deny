# Concurrent DNS load tester

Measure a DNS server over UDP or TCP with concurrent workers. Build with Go 1.27.3;
the Make targets select that toolchain and download pinned dependencies as needed.
From the repository root:

```bash
make build-loadtest
./target/dns-loadtest -server 127.0.0.1:1053 -name nas.home.arpa \
  -duration 10s -concurrency 16 -qps 500
```

Choose a name your resolver can answer; this example assumes a local
`nas.home.arpa` record. The default workload is `example.com A` and may use upstream
DNS. Use `-help` for all options. The compiled binary can run on a separate load
machine without the source or Go toolchain. Correctness checks belong to the
[integration suite](../integration/README.md).

## Workloads

### Fixed request count and JSON report

```bash
./target/dns-loadtest -server 127.0.0.1:1053 -name nas.home.arpa \
  -queries 10000 -duration 0 -concurrency 32 -qps 500 -json > result.json
```

`-queries` limits total attempts across all workers, including failures. When both
count and duration are nonzero, the first limit reached stops new attempts.
`-duration 0` requires a nonzero count. Names are scheduled round-robin; completion
order varies with concurrency. There are no automatic retries: a failed attempt
is counted once and the worker moves on.

### Mixed names and record types

Create a query file with one `name [type]` per line. Blank lines and `#` comments
are ignored. A missing type uses `-type` (default `A`). Repeating a row gives it
more weight. For example, using names you have configured or included in lists:

```text
# Repeated cached name, IPv6, blocked name, and a negative lookup
nas.home.arpa A
nas.home.arpa A
nas.home.arpa AAAA
blocked.example.test A
missing.example.test A
```

```bash
./target/dns-loadtest -server 127.0.0.1:1053 -file queries.txt \
  -duration 30s -concurrency 32 -qps 500
```

The file is loaded and validated before timing starts. Memory for the corpus grows
with the number of rows. Standard named DNS types and numeric `TYPE<number>` are
accepted; `TYPE0` is rejected. Names are normalized to lowercase absolute names.

### TCP and maximum-throughput runs

```bash
./target/dns-loadtest -server 127.0.0.1:1053 -name nas.home.arpa \
  -network tcp -duration 10s -concurrency 32 -qps 500

./target/dns-loadtest -server 127.0.0.1:1053 -name nas.home.arpa \
  -duration 10s -concurrency 64 -qps 0
```

`-qps` is a **global target**, not a per-worker target. Zero removes pacing.
Each worker has one outstanding query and reuses its own connected UDP socket or
TCP connection. Maximum in-flight work is bounded by concurrency (1–1024).
A failed attempt closes the connection before the next query. Connection setup
is included in first/reconnect attempt latency; successful queries reuse the connection.

This is a closed-loop generator: workers wait for responses before starting their
next query. If concurrency, server latency, or client CPU prevents the requested
rate, achieved QPS will be lower. There is no unbounded pending-request queue or
accumulating pacing debt. Timer scheduling can bunch already-reserved slots; the
QPS setting is not a strict packet-by-packet traffic shaper.

UDP does not automatically retry truncated answers over TCP. Truncation is counted
and reported; run TCP explicitly to measure full TCP responses. EDNS defaults to
1232 bytes; use `-edns-size 0` to disable it. `-dnssec` sets the DNSSEC OK bit and
requires EDNS; it does not validate signatures. `-rd=false` clears recursion desired.
The target must be a literal IP and nonzero port, including bracketed IPv6 such
as `[::1]:1053`, so resolving the target cannot add hidden DNS traffic.

## Reports and exit status

The default output is a text summary. `-json` writes only the final JSON report to
stdout; the startup message and configuration errors go to stderr. The report
contains:

- Attempts, valid replies, timeouts, I/O errors, invalid replies, and cancelled
  attempts. Each attempted query belongs to exactly one reply/error category.
- Counts for every DNS RCODE received, unexpected RCODEs, and truncated replies.
- Attempt and reply rates over measured elapsed time, including connection setup
  and draining of outstanding queries.
- Min/mean/max latency and p50/p95/p99 upper bounds in milliseconds for valid
  replies, including replies with unexpected RCODEs. Timeouts and invalid replies
  are excluded from latency; inspect error counts alongside the percentiles.
- Target, transport, concurrency, rate/count/duration/timeout settings, question
  count, and whether a user interrupt stopped the run.

Latency runs from immediately before an attempt's connection setup/write until
its reply is decoded; pacing time is excluded. Histograms use 32 KiB per worker,
independent of run length, with percentile upper-bound overestimation below
1.563%. Min, mean, and max use actual measured values. A run with no valid replies
has zero latency samples and zero-valued latency fields; those zeros do not mean
a fast server.

`NOERROR` and `NXDOMAIN` are acceptable by default because a filter can legitimately
return negative answers. `SERVFAIL` and `REFUSED` still count as DNS replies but
make the run fail unless included in `-expect-rcode`. For a workload intentionally
exercising admission limits:

```bash
./target/dns-loadtest -server 127.0.0.1:1053 -name nas.home.arpa \
  -duration 5s -qps 2000 -expect-rcode NOERROR,NXDOMAIN,REFUSED
```

- Exit **0**: at least one attempt, all attempts received valid replies with
  acceptable RCODEs. This is not a throughput or latency threshold assertion.
- Exit **1**: no attempts, a transport/validation error, or an unexpected RCODE.
- Exit **2**: invalid configuration/input or inability to write the report.
- Exit **130**: SIGINT/SIGTERM; a partial report is emitted and active sockets
  are closed promptly.

The duration stops issuing new attempts; existing attempts may finish for up to
`-timeout` (default 1s). Interrupts cancel them instead. A finite-count run against
an unavailable target can take roughly `queries / concurrency * timeout`, depending
on how quickly connection failures are detected. Use a duration cap to bound that
workload.

## Interpreting DNS Deny results

DNS Deny's default `ratelimit_qps_per_worker = 1000` is a global **per-client-IP**
limit across listener workers, despite its name. Multiple Go workers/UDP source
ports do not bypass it. A high-rate run can measure refusals instead of resolver
capacity. Configure the server's allowed-client networks and rate budget for the
intended experiment before the initial seed, or use the supported provisioning
process for an existing state database. Do not delete saved state to run a benchmark.
See [configuration](../../CONFIGURATION.md).

Use a small repeated corpus for a warm-cache test. Use a controlled, diverse
corpus and deterministic upstream for misses; many different names under a
blocked parent can all hit the filter instead of reaching upstream. Run separate
experiments for local answers, filtering, forwarding, and a blocklist refresh under
load. This tool does not disable caches, change server settings, report server
cache-hit ratios, or trigger reloads.

For capacity measurements, generate load from a separate machine and monitor both
machines' CPU and resource use. Increasing client concurrency or using unlimited
mode does not prove the load generator can saturate the server. Functional fixture
runs are verification of this tool, not published DNS Deny performance numbers.

## Development checks

```bash
make test-loadtest
```

The target runs `go test -race ./...` and `go vet ./...` against localhost fixtures.
From `tests/dns-loadtest`, format edits with `GOTOOLCHAIN=go1.27.3 go fmt ./...`.
