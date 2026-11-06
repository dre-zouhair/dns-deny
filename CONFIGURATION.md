# Configuration

The maintained, field-by-field manual is the
[HTML configuration reference](https://dns-deny.larandj.com/configuration.html).
Its source is [landing/configuration.html](landing/configuration.html); open that
file locally to read it offline. Update setting descriptions there.

Start a new installation with the complete [general seed](config/default.toml)
or [Pi Zero seed](config/pi-zero.toml). Replace its sample administrator password
before the first start. Service paths, HTTPS, and backups are covered in
[deployment](deploy/DEPLOYMENT.md).

## Applying changes

TOML seeds configuration only when the selected SQLite state database has no
saved configuration. After that, **`state.db` is authoritative**, including
credentials. Editing the seed and restarting does not replace saved settings.

Use the dashboard or supported settings endpoints. Successful changes are
validated and persisted before a new live snapshot is published. Primary upstream
and resolver-mode endpoints report a restart requirement. Startup settings without
an editor require a planned state migration or re-provisioning; deleting the
database is not a routine update or password-rotation procedure.

See [state and restarts](https://dns-deny.larandj.com/configuration.html#state)
and [updates and backups](https://dns-deny.larandj.com/configuration.html#operations)
for the complete lifecycle and per-setting guidance.

## Reference sections

| Topic | Reference |
| --- | --- |
| Environment variables and paths | [Environment](https://dns-deny.larandj.com/configuration.html#environment) |
| DNS client admission | [Network access](https://dns-deny.larandj.com/configuration.html#network) |
| Upstreams, DoH, iterative resolution, DNSSEC | [Resolution](https://dns-deny.larandj.com/configuration.html#resolution) |
| Sources, imports, and refreshes | [Blocklists](https://dns-deny.larandj.com/configuration.html#lists) |
| Sinkhole discovery, malicious IPs, scoring | [Detection](https://dns-deny.larandj.com/configuration.html#detection) |
| Device identities, policies, and schedules | [Devices](https://dns-deny.larandj.com/configuration.html#devices) |
| Service blocks, SafeSearch, local records | [Services and local DNS](https://dns-deny.larandj.com/configuration.html#services) |
| Global, category, service, and device pauses | [Protection pauses](https://dns-deny.larandj.com/configuration.html#pauses) |
| Response caching and DNS rate limits | [Caches and rates](https://dns-deny.larandj.com/configuration.html#cache) |
| Query logging and retention | [Logs](https://dns-deny.larandj.com/configuration.html#logging) |

## Authentication

See [administration and credentials](https://dns-deny.larandj.com/configuration.html#admin)
for passwords, browser sessions, dedicated API tokens, HTTPS, and trusted proxies.
The reference distinguishes credentials that survive restart from process-local
sessions. Existing installations retain the saved authentication settings.
