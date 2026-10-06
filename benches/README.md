# Reproducing scanner measurements

Use release builds and record hardware/CPU/OS/Rust/Git, binary size, corpus bytes,
active policy, worker count and cache state. Decimal MB means 1,000,000 bytes.
Warm-cache results do not establish cold-cache or production guarantees.

`cargo bench --bench engine` precompiles all ten built-ins plus one entropy-gated
custom rule and scans preloaded synthetic records. Each block exercises provider,
JOSE, generic entropy, weak-password and custom acceptance plus directive,
reference and checksum suppression. Forty passes report median/p95/p99 and
one-worker throughput; independent finding/byte assertions protect scanned scope.
Compilation, process startup, filesystem, Git and rendering are excluded.

`cargo bench --bench scope` exercises complete rules against real files, one
supported finding per file, at 8/32/128/256/4096 files, 256/16384-byte content and
1/2/8 workers. `RAYLOC_BENCH_THRESHOLD` defaults to the production 256-file gate;
set it to `1` to measure the former always-parallel behavior. Five samples include each scan's worker pool/discovery startup;
p95/p99 equal the slowest sample and should not be interpreted as stable tails.
Environment overrides remain `RAYLOC_BENCH_FILES`, `RAYLOC_BENCH_BYTES`,
`RAYLOC_BENCH_WORKERS`, `RAYLOC_BENCH_THRESHOLD`, `RAYLOC_BENCH_POLICY` (256 custom rules/ignore patterns)
and `RAYLOC_BENCH_DENSE` (finding-overflow workload).

For startup-inclusive file, directory and staged latency plus peak RSS:

```sh
cargo build --locked --release
PYTHONDONTWRITEBYTECODE=1 python3 scripts/e2e_measure.py --samples 21 --hardware YOUR_MACHINE
PYTHONDONTWRITEBYTECODE=1 python3 scripts/e2e_measure.py --samples 3 --large-mb 1024 --output target/e2e-extended.json --hardware YOUR_MACHINE
```

The stdlib Python harness compiles a tiny benchmark-only native C launcher with
`cc`, then executes the real scanner. This separates scanner RSS from Python's
fixture-generation heap; a 96-MiB launcher-ballast regression test proves that
boundary. `wait4` peak RSS includes waited Git children, in KiB (Darwin bytes are
converted). Wall time includes the small native launcher overhead. Fixture
creation/compilation is outside timing. The cache is warm from creation plus one
untimed scan; no caches are flushed. All ten built-ins/default policy are active.
File/staged work is serial; directory selection auto-admits up to eight workers.

Fixtures cover >10-MB files, a 1-MiB-overlimit giant line (mandatory exit 2),
16-MB directories, 2,000 tiny files, and empty/10/100/1,000 added-line index diffs
across 1/10/100 files where possible. Git baseline/index setup is untimed;
scanner Git acquisition/rendering is timed. Finding counts, output leaks and
reported scanned bytes are asserted for every sample. Diff byte counts exclude
patch framing and removed LF delimiters; giant-line throughput is not a complete
scan throughput result. The extended run uses a 1.024-GB decimal file with bounded
records and a mandatory finding at the end. JSON records the exact executable
SHA-256 and size. Percentiles use nearest ranks, with conventional median.

[Recorded baseline](../docs/research/release-baseline.md) contains measured results
and regression policy. Under 5 ms startup-inclusive staged latency and
500 MB/s/core remain unmet stretch goals on this workload. Compare only identical
scope, rules, threads, hardware/cache and compiler conditions. Cold cache and
real-world labeled clean repositories remain future evidence.
