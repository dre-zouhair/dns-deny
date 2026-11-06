# Performance probes

Run `cargo run -p core_dns --release --example performance_probe` to measure
L1 retrieval plus TTL adjustment, eight local blocklist endpoints delayed by
100 ms each, and a 100,000-rule edit on a single Tokio runtime thread. The
probe counts allocations on its calling thread. It uses temporary files and
localhost listeners and does not contact public DNS or blocklist providers.

[Recorded samples](performance-review.csv) compare correctness commit
`4ec6053` with the subsequent performance changes on an Intel Xeon E3-1241 v3
host. Five runs alternated baseline and optimized executables; each cache
sample is itself the median of seven 25,000-operation loops. Median results:

| Probe | Baseline | Optimized |
| --- | ---: | ---: |
| Cache hit, one TXT record | 418 ns; 6 allocations | 331 ns; 3 allocations |
| Cache hit, eight TXT records | 1,935 ns; 34 allocations | 955 ns; 17 allocations |
| Cache hit, 32 TXT records | 7,092 ns; 130 allocations | 3,736 ns; 65 allocations |
| Eight delayed source downloads | 815 ms | 204 ms |
| Edit with 100,000 existing rules | 275 ms | 34 ms |
| Worst timer delay during that edit | 275.006 ms | 1.091 ms |

These are local component measurements, not end-to-end DNS throughput or Pi
Zero results. Filesystem and scheduling noise affect the edit and timer
measurements. The cache probe excludes network I/O and response serialization.
The source probe uses concurrency four; the Pi Zero preset deliberately uses
one to limit peak memory. Rule files are buffered and written on the blocking
pool; DNS address checks read an immutable IP snapshot instead of waiting on
the file writer's lock.

[Back to documentation](README.md).
