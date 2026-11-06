# Deployment

Choose [Debian packaging](DEBIAN_PACKAGING.md), a manual binary installation,
or Docker Compose. Commands below run from the repository root on Linux.
Before starting, choose a unique admin password, restrict DNS to trusted clients,
and configure HTTPS administration.

## Debian package

Build for your [architecture](DEBIAN_PACKAGING.md), then install the matching file:

```bash
sudo apt install ./target/dns-deny_0.1.0_amd64.deb
sudoedit /etc/dns-deny/config.toml
```

Replace the sample `api_key` before the first start. For a host-local proxy, set
`api_bind_address = "127.0.0.1"`. Complete [HTTPS setup](#https-administration),
then start the service:

```bash
sudo systemctl enable --now dns-deny
sudo systemctl status dns-deny
journalctl -u dns-deny -f
```

The package creates directories and the service account; it does not start the
service automatically. DNS listens on port 53 by default.

## Manual binary installation

Build with `make build-release`, or copy a matching Linux executable from a
cross-build. GNU targets may depend on the target system's glibc; inspect with
`file` and `ldd`. A single executable is not a promise of static linking.

For a fresh installation:

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dns-deny
sudo mkdir -p /etc/dns-deny /var/lib/dns-deny
sudo chown dns-deny:dns-deny /var/lib/dns-deny
sudo chmod 750 /var/lib/dns-deny
sudo install -m 755 target/release/dns-deny /usr/local/bin/dns-deny
sudo install -m 640 -o root -g dns-deny config/default.toml /etc/dns-deny/config.toml
sudo cp -r static /var/lib/dns-deny/
sudo chown -R dns-deny:dns-deny /var/lib/dns-deny/static
sudo install -m 644 deploy/dns-deny.service /etc/systemd/system/
sudoedit /etc/dns-deny/config.toml
```

Skip account creation if the account already exists. Substitute the target binary
path for cross-builds and `config/pi-zero.toml` for the original Pi Zero.
Dashboard builds require the complete matching `static/` tree; API-only and
resolver-only builds do not. Set `api_enabled = false` for resolver-only builds.

After configuring credentials and HTTPS:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dns-deny
```

The service runs without root and receives the capability to bind port 53.
Its working directory is `/var/lib/dns-deny`, with a 512 MiB process memory limit.
The seed file is read-only; runtime settings are written to SQLite.

## HTTPS administration

DNS Deny allows direct HTTP administration by default. To require an HTTPS
reverse proxy, seed these settings before creating the state database:

```toml
api_bind_address = "127.0.0.1"
api_allow_insecure_http = false
api_trusted_proxy_cidrs = ["127.0.0.1/32", "::1/128"]
```

Configure your proxy to terminate TLS, preserve the public `Host`, overwrite
`X-Forwarded-Proto` with `https`, and overwrite `X-Forwarded-For` or append the
verified client address. Keep the backend accessible only to that proxy.
For example, a Caddyfile for a hostname you control:

```caddyfile
dns.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto https
    }
}
```

Open `https://dns.example.com` and sign in with your configured admin password.
For integrations, generate a dedicated JSON API token; see [authentication](../CONFIGURATION.md#authentication).
A proxy on another machine requires a protected connection to the HTTP backend.

## Docker Compose

Edit `deploy/config.toml` before the first start, replacing the sample password.
Keep `api_bind_address = "0.0.0.0"` inside the container. The current Compose file
publishes the admin backend on **127.0.0.1:8083**, forwarding to container port
8080. Open `http://127.0.0.1:8083` to use the dashboard. HTTP is enabled in
`deploy/config.toml` by default. To require HTTPS, set
`api_allow_insecure_http = false` and point the host HTTPS proxy at
`127.0.0.1:8083`. Existing state volumes retain their saved configuration.
Changing `api_allow_insecure_http` in an existing installation requires the
saved-state procedure in the
[configuration reference](https://dns-deny.larandj.com/configuration.html#state);
the seed cannot override it.

The proxy peer seen inside Docker is often a bridge gateway. Trust its actual
IP with a /32 or /128 prefix, through `api_trusted_proxy_cidrs` or the startup
environment variable `DNS_API_TRUSTED_PROXY_CIDRS`. Do not trust an entire LAN
just to make forwarding headers work. The environment override also applies to
existing state databases; invalid CIDRs prevent API startup.

```bash
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml logs -f
```

DNS is published on **1053/UDP and 1053/TCP** for development. For normal DNS,
change both mappings to `53:53` and set `DNS_PORT: "53"`; enable the supplied
`NET_BIND_SERVICE` capability if required by the container runtime.
Allow DNS traffic only from trusted networks.

The image is built locally; this repository does not establish a published
multi-architecture image. Original Pi Zero deployments should use the ARMv6
binary/package guide.

The current Compose healthcheck references `curl` (absent from the runtime image)
and an `API_KEY` variable, and uses direct HTTP. Replace it with a probe suitable
for your build, credentials, and HTTPS path before relying on container health.
A failing probe alone does not establish whether DNS is answering.

### Docker build flags

The [Docker build guide](https://dns-deny.larandj.com/install/docker.html#build-flags)
owns the `CARGO_BUILD_FLAGS` recipes and persistent Compose build-argument setup.
Save the chosen arguments under `services.dns-deny.build.args` before routine
rebuilds; otherwise a later plain build returns to default features.

## Verify operation

Query the selected DNS port from an allowed client:

```bash
dig @127.0.0.1 -p 53 example.com
```

Use `-p 1053` for the default development container. Confirm dashboard login over
HTTPS. With a JSON API build, check `/api/v1/stats` using a Bearer token; a
successful API response alone does not test DNS forwarding.

## State, backups, and upgrades

The seed TOML is read only when `state.db` has no stored configuration. Editing
it later does not update a running or restarted installation. Use the dashboard
or supported API endpoints; some changes require restart as described in
[configuration](../CONFIGURATION.md#applying-changes).

Back up the data directory and seed securely. Stop the service/container for a
consistent filesystem backup, or use SQLite-aware backups that include WAL
state. Protect backups: runtime state includes authentication material and logs
can contain clients' browsing domains.

For package upgrades, stop the service, back up data, install the matching new
package, then start the service. For manual upgrades, replace the binary and
matching dashboard assets while stopped. Check release notes for state-format
compatibility before upgrading or rolling back.

For Docker updates, preserve the named data volume:

```bash
docker compose -f deploy/docker-compose.yml build
docker compose -f deploy/docker-compose.yml up -d
```

**`make docker-rebuild` runs `down -v` and deletes persisted state.** It is a
reset command, not a production upgrade path. Do not delete `state.db` to apply
routine settings or rotate a password.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| HTTP 426 | HTTPS proxy, forwarded protocol, and exact trusted proxy peer |
| HTTP 429 | Login/API limits; use a dedicated token for integrations |
| DNS REFUSED | `allowed_client_cidrs` and the client's source IP |
| DNS cannot bind | Port 53 conflict and service capability |
| Startup validation error | Error text, valid upstreams, memory budget, incompatible resolver options |
| Missing styles | Deploy matching `static/` files or set `DNS_STATIC_DIR` |
| Seed edits ignored | Existing SQLite state is authoritative |

Use `journalctl -u dns-deny` or container logs. Set `RUST_LOG` temporarily for
diagnosis; avoid verbose per-rule debug logging during normal operation.
