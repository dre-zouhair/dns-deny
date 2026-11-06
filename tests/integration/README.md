# Docker correctness tests

Go 1.27.3 black-box tests exercise the real DNS Deny image using a deterministic
Go DNS resolver and local blocklist fixtures.

## Run

Use a local Docker daemon and a Go installation supporting toolchain selection.
From the repository root:

```bash
make test-integration
```

The target selects Go 1.27.3, disables test-result caching, and sets a 15-minute
timeout. First builds download pinned dependencies and base images; later builds
reuse Docker layers. Bind mounts and loopback port mappings require the daemon
on the test machine. Rootless/user-namespace setups must allow access to the
bind-mounted test data directories.

From `tests/integration`, filter a group or case, or run the race detector:

```bash
GOTOOLCHAIN=go1.27.3 go test -count=1 -v -timeout 15m -run 'TestIntegration/FilterTiers'
GOTOOLCHAIN=go1.27.3 go test -count=1 -v -timeout 15m -run 'TestIntegration/StatePersistence/test_config_persistence_across_restarts_and_toml_independence'
GOTOOLCHAIN=go1.27.3 go test -count=1 -race -timeout 15m ./...
GOTOOLCHAIN=go1.27.3 go vet ./...
```

`go test -list .` lists entry points without starting Docker. Use `-count=1` for
fresh correctness runs and `-json` for machine-readable results.

## Image reuse

Ordinary runs build `dns-deny:go-integration` from `deploy/Dockerfile` and
`dns-deny-mock:go-integration` from the mock Dockerfile. To reuse images already
built from the source revision being tested:

```bash
DNS_DENY_TEST_IMAGE=dns-deny:go-integration \
DNS_DENY_MOCK_IMAGE=dns-deny-mock:go-integration \
  make test-integration
```

Each override skips that image's build; the caller must ensure it matches current
source. The mock uses a Go builder and a `scratch` runtime containing a stripped
static binary. Images and build caches are retained between runs.

## Isolation and cleanup

- Each run creates a unique Docker network. Host UDP/TCP/API ports are ephemeral
  and published only on `127.0.0.1`; readiness is checked by actual requests.
- Most cases share one server and run serially. `t.Cleanup` unwinds settings and
  rules in reverse order. Do not add `t.Parallel` to shared-state cases.
- Rate-limit cases use a dedicated 100-query-window server. The ordinary server
  uses a 10,000-query window so unrelated tests do not trigger throttling.
- Restart/persistence cases use separate bind-mounted data directories and run
  their containers under the test process's UID/GID for Go SQLite access. The
  shared server uses the image's normal service user. Containers use UTC.
- Failed scopes dump container logs before cleanup. Commands, requests, polls,
  and the overall suite have timeouts. A hard kill cannot run `t.Cleanup`;
  test-created containers/networks carry `dns-deny.test=integration` labels.

## Suites

| Group | Coverage | Source |
| --- | --- | --- |
| Smoke | Startup, forwarding, and seeded filtering | `test_pipeline_test.go` |
| EndpointCoverage | API round trips, credentials, diagnostics, logs, SSE | `test_endpoints_test.go` |
| StatePersistence | Seed, restart/reseed, failed writes, unsupported state, independent logs | `test_state_test.go` |
| DNSResolution | UDP/TCP, custom ports, truncation, SOA, coalescing, DoH fallback, sinkholes | `test_resolution_test.go` |
| AllowDenyLists / FilterTiers | Visibility, mutual exclusion, regex validation, cross-tier precedence | `test_pipeline_test.go` |
| DevicePolicy | Static/scheduled policies and pause expiry/resume | `test_pipeline_test.go` |
| LocalDNS | A/AAAA/CNAME, validation, NODATA, chains, delete behavior | `test_pipeline_test.go` |
| ProtectionPause | Global/category/service pause, resume, expiry, countdown | `test_resolution_test.go` |
| RateLimit | Normal/burst traffic and bypass boundaries | `test_pipeline_test.go` |
| SafeSearch / Services | Rewrite targets, precedence, built-in/custom blocks | `test_pipeline_test.go` |

`internal/mockdns` checks the fixture's deterministic answers and truncation
behavior. For throughput and latency experiments, use the separate
[DNS load tester](../dns-loadtest/README.md).
