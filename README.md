# DNS Deny

Self-hosted DNS filtering in Rust. Block unwanted domains, manage device policies,
and inspect local query logs through a dashboard or JSON API.
Free to deploy, use, and extend under [AGPL-3.0](LICENSE).

## Start here

- [Installation guides](https://dns-deny.larandj.com/install/) — choose an architecture and installation format.
- [Deployment](deploy/DEPLOYMENT.md) — service setup, HTTPS, verification, backups, and upgrades.
- [Configuration reference](https://dns-deny.larandj.com/configuration.html) — every setting, persistence, and update/restart behavior.
- [Documentation index](docs/README.md) — development tools and architecture decisions.

## Features

- UDP/TCP DNS with UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS upstreams.
- Domain, subdomain, and regex filtering; hosts, Adblock, and Gravity imports.
- Blocklist categories, allow/deny rules, SafeSearch, and local DNS records.
- Device policies, schedules, service blocking, and temporary protection pauses.
- Server-rendered dashboard, live query updates, and optional JSON API.
- In-memory answer caches and asynchronous SQLite query logging.

DNS filtering applies to clients using this resolver. Devices using another
resolver or their own encrypted DNS can bypass these policies.

## Build

Requires Rust **1.90+**, Cargo, a C compiler, and platform build tools. On Debian
or Ubuntu, install `build-essential` and `pkg-config`. Run from the repository root:

```bash
git clone https://github.com/dre-zouhair/dns-deny.git
cd dns-deny
make build-release
```

The native executable is `target/release/dns-deny`. Dashboard builds also need
the matching `static/` directory at deployment time.

| Variant | Command | Includes |
| --- | --- | --- |
| Full (default) | `make build-release` | Dashboard and JSON API |
| Dashboard only | `make build-release-no-api` | Dashboard with its HTTP admin server |
| JSON API only | `make build-release-api-only` | JSON endpoints without dashboard |
| Resolver only | `cargo build --release --no-default-features` | DNS; set `api_enabled = false` |
| Optional scoring | `cargo build --release --features feat-scoring` | Full build plus domain scoring |

For compiler/target prerequisites, use the [architecture guides](https://dns-deny.larandj.com/install/).
[Debian packaging](deploy/DEBIAN_PACKAGING.md) covers package targets and filenames;
[Cargo flag examples](https://dns-deny.larandj.com/install/binary.html#build-flags)
and [Docker build flags](https://dns-deny.larandj.com/install/docker.html#build-flags)
cover custom feature combinations. Scoring also needs `ml_scoring_enabled = true`
in saved configuration.

## Local development

Copy `config/default.toml` to `/tmp/dns-deny-dev.toml`, replace the sample `api_key`,
and set `api_bind_address = "127.0.0.1"` in that private copy before starting.
HTTP is enabled by default; [HTTPS deployment](deploy/DEPLOYMENT.md#https-administration)
covers remote administration.

```bash
DNS_CONFIG=/tmp/dns-deny-dev.toml DNS_STATE_DB=/tmp/dns-deny-dev.db DNS_PORT=1053 cargo run --release
```

TOML seeds the first run; an existing `state.db` keeps its saved settings.
See [applying changes](CONFIGURATION.md#applying-changes) before editing an existing installation.

## Development checks

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace -- -D warnings
make test-variants
```

| Check | Command | Prerequisites and details |
| --- | --- | --- |
| Docker correctness suite | `make test-integration` | [Go 1.27.3 and local Docker](tests/integration/README.md) |
| DNS load testing | `make build-loadtest` / `make test-loadtest` | [Go 1.27.3; workloads and reports](tests/dns-loadtest/README.md) |
| Component performance probes | `cargo run -p core_dns --release --example performance_probe` | [Method and recorded samples](docs/PERFORMANCE.md) |

Browser regression checks require Node and Chrome/Chromium:

```bash
cargo build -p api --example web_fixture
node tests/ui/test_server_ui.mjs
```

Use `CHROME_BIN` for a custom browser path and `UI_SCREENSHOT` for a PNG capture.

## Workspace

`src/` wires the service together; workspace crates implement DNS, filtering,
ingestion, logging, administration, scoring, and shared rule types. Browser assets
are in `static/`, the product site in `landing/`, and packaging in `deploy/`.
See [architecture decisions](docs/ARCHITECTURE.md) for ownership and update boundaries.

## License

[GNU Affero General Public License v3.0](LICENSE). You provide the hardware and
hosting. Modifications and distribution remain subject to the license, including
its network source availability terms.
