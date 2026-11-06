# Documentation

## Installation and operation

| Guide | Owns |
| --- | --- |
| [Installation guides](https://dns-deny.larandj.com/install/) | Architecture/toolchain prerequisites and installation-format walkthroughs |
| [Configuration reference](https://dns-deny.larandj.com/configuration.html) | Every setting, defaults, persistence, and update/restart behavior |
| [Repository configuration entry point](../CONFIGURATION.md) | Seed files, essential state rules, and links into the full reference |
| [Deployment](../deploy/DEPLOYMENT.md) | Service setup, HTTPS, verification, backups, and upgrades |
| [Debian packaging](../deploy/DEBIAN_PACKAGING.md) | Package targets, build options, artifact names, and installed paths |

The static site is in `landing/`. [Site maintenance](../landing/README.md)
covers publishing, URLs, and metadata.

## Development

| Guide | Owns |
| --- | --- |
| [Architecture decisions](ARCHITECTURE.md) | State ownership, publication, resolver work, and administration boundaries |
| [Docker correctness suite](../tests/integration/README.md) | Running and extending HTTP/DNS and SQLite lifecycle tests |
| [DNS load tester](../tests/dns-loadtest/README.md) | Concurrent workloads, report semantics, and measurement limits |
| [Component performance probes](PERFORMANCE.md) | Reproducing and interpreting local component measurements |

Keep detailed instructions in the owning guide and link to them from other entry
points. Retain short state/password/data-loss reminders beside commands that need
them. Completed plans and implementation-era specifications remain in
[Git history](ARCHITECTURE.md#historical-records).
