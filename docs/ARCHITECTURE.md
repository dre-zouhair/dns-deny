# Architecture decisions

These decisions explain current implementation boundaries. Operator-facing
settings belong in the [configuration reference](https://dns-deny.larandj.com/configuration.html);
installation and backup procedures belong in [deployment](../deploy/DEPLOYMENT.md).

## Configuration ownership and publication

TOML is an initial seed; `state.db` owns persisted configuration afterward.
Requests read immutable `RuntimeConfigSnapshot` values through `ConfigHandle`,
so they can retain a consistent view across asynchronous work without copying
configuration collections or reading SQLite on the DNS path.

Configuration edits are serialized, validated, and persisted before publication.
A revision check rejects writes based on stale state. Failed persistence leaves
the live snapshot unchanged. Components created at startup, such as the primary
upstream pool, need an explicit restart even when a new value has been saved.

Settings endpoints are scoped by feature. A read-only full-config endpoint
redacts credentials; a generic full-config writer would bypass feature-specific
validation and side effects.

Sources: [ConfigHandle](../core/src/config.rs),
[configuration store](../core/src/config_store.rs), and [startup](../src/main.rs).

## DNS policy and bounded resolution

Client admission and rate limits run before content-policy bypasses. Policy is
checked before cache use and against returned aliases/addresses, so a cached
answer cannot bypass a newly applicable rule. The complete precedence rules are
in the configuration reference.

Identical concurrent cache misses share an upstream result. The leader owns a
cleanup guard so cancellation cannot leave followers waiting forever. Admission
budgets bound active requests and upstream/discovery work instead of building an
unbounded pending queue.

Responses retain their upstream response code and authoritative negative TTL.
DNSSEC validation is local; an upstream AD flag is insufficient. Resolver
fallback rules keep validation failures from silently becoming unchecked answers.

Sources: [request handling](../core/src/handler.rs),
[shared policy](../core/src/policy.rs), [caches](../core/src/cache/mod.rs), and
[DNSSEC handling](../core/src/dnssec.rs).

## Filter updates and durable rules

Local domain/regex rules and learned denies use separate rule files. Remote
source copies and validators survive restart so startup can restore filtering
without a successful download. A failed import or rebuild retains the last
working filter.

Compilation and SQLite work run off the asynchronous DNS runtime. Rules and their
verdict cache are published together; a reader using an old filter can populate
only that filter's cache. Allows take precedence across filter tiers, and opposing
local allow/deny entries are reconciled when edited.

Sources: [blocklist updater](../core/src/updater.rs),
[filter snapshots](../filter/src/lib.rs), and [query logger](../logger/src/lib.rs).

## Administration boundaries

The dashboard is server-rendered and uses process-local browser sessions. The
JSON API independently authenticates Bearer credentials; a browser session is not
an API key. Password changes revoke sessions after a successful commit, while a
dedicated API token has its own rotation lifecycle.

Dashboard assets and the JSON API are separate build features. Query history is
stored independently from configuration so retention cannot remove settings.

Sources: [API and authentication](../api/src/lib.rs),
[dashboard](../api/src/web/mod.rs), and [build features](../Cargo.toml).

## Historical records

Completed resolver/SQLite migration plans and implementation-era endpoint/UI
specifications are preserved in
[Git history before consolidation](https://github.com/dre-zouhair/dns-deny/tree/b33de6fe83cf6ba67cfd7ee0075bb78c5f157bac/docs).
Their code snippets, API names, and checklist states describe that revision;
use the current guides for setup and development instructions.
