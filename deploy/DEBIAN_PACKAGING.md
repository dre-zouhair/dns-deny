# Debian package builds

Build from the repository root with Rust 1.90+, Cargo, and Debian/Ubuntu tools:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config dpkg-dev
```

## Architecture

Follow the linked architecture guide for native/cross compiler and linker setup.
A package must match the target OS userspace and libc as well as its processor.

| Target system | Prerequisites | Build command | Package (version 0.1.0) |
| --- | --- | --- | --- |
| AMD64 / x86-64 Linux | [Native AMD64 host](https://dns-deny.larandj.com/install/amd64.html#toolchain) | `make release-deb` | `target/dns-deny_0.1.0_amd64.deb` |
| ARM64 / AArch64 Linux | [Native or cross-build toolchain](https://dns-deny.larandj.com/install/arm64.html#toolchain) | `make release-deb-arm64` | `target/dns-deny_0.1.0_arm64.deb` |
| Original Pi Zero / Zero W | [ARMv6 toolchain](https://dns-deny.larandj.com/install/pi-zero.html#toolchain) | `make release-deb-pi-zero` | `target/dns-deny_0.1.0_pi-zero_armhf.deb` |

The AMD64 script builds for the host; ARM64 and Pi Zero use explicit Rust targets.

## Variants

Append `-no-api` (dashboard only, with its HTTP admin server) or `-api-only`
(JSON endpoints without dashboard assets) to any package target. For example,
`make release-deb-arm64-api-only` creates the ARM64 JSON-only package.

| Variant | AMD64 filename | Pi Zero filename |
| --- | --- | --- |
| Full | `dns-deny_0.1.0_amd64.deb` | `dns-deny_0.1.0_pi-zero_armhf.deb` |
| Dashboard only | `dns-deny_0.1.0_no-api_amd64.deb` | `dns-deny_0.1.0_pi-zero_no-api_armhf.deb` |
| JSON API only | `dns-deny_0.1.0_api-only_amd64.deb` | `dns-deny_0.1.0_pi-zero_api-only_armhf.deb` |

For ARM64, replace `_amd64.deb` with `_arm64.deb`. All packages appear in `target/`.

### Script flag examples

Direct scripts accept an architecture argument and these environment variables:

| Variable | Values and effect |
| --- | --- |
| `VARIANT` | `full` (default), `no-api`, or `api-only` |
| `BUILD_PACKAGE` | `false` stops after compiling the binary |
| `CARGO_BUILD_FLAGS` | Extra Cargo flags; quote multiword values |

```bash
# ARM64 JSON-only package with scoring; requires the ARM64 toolchain.
VARIANT=api-only CARGO_BUILD_FLAGS="--features feat-scoring" \
  ./deploy/build_deb.sh arm64

# Pi Zero dashboard executable without packaging; requires the ARMv6 toolchain.
VARIANT=no-api BUILD_PACKAGE=false ./deploy/build_pi_zero.sh
```

Scoring also needs `ml_scoring_enabled = true` in saved configuration. Extra flags
do not add a filename suffix, so a new build can overwrite the same variant's
previous artifact. [Cargo feature examples](https://dns-deny.larandj.com/install/binary.html#build-flags)
explain `--features`, `--no-default-features`, and target selection.

## Installed files

| Component | Path |
| --- | --- |
| Executable | `/usr/bin/dns-deny` |
| Seed configuration, root:dns-deny, mode 0640 | `/etc/dns-deny/config.toml` |
| Dashboard assets (except API-only) | `/var/lib/dns-deny/static/` |
| Runtime configuration and query logs | `/var/lib/dns-deny/` |
| systemd unit | `/lib/systemd/system/dns-deny.service` |

Installation creates the service account and directories but does **not** start
the service. Follow [deployment](DEPLOYMENT.md#debian-package) for installation,
credentials, HTTPS, and startup. The seed is a Debian conffile; existing settings
remain in `state.db`. Follow the [upgrade procedure](DEPLOYMENT.md#state-backups-and-upgrades)
to preserve that data.
