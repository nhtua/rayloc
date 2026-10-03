# Directory and glob scope implementation and measurements

Measured 2026-10-02 on Linux x86_64, AMD Ryzen 9 9950X (32 logical CPUs),
Rust 1.88.0, Git 2.55.0. Locked tests also pass on Rust 1.85.0 and Git 2.30.0.
The original performance tables describe `9a7012b`; the fix-round measurements
at the end supersede them for the additional administration discovery pass.

## Scope and policy

`rayloc scan` selects the current directory. An explicit directory selects its
subtree; `scan --glob '**/*.{rs,toml}'` and a quoted positional pattern select
repository-relative paths (current-directory-relative outside Git). An existing
literal path wins over positional glob interpretation. Regular matches are counted
before policy: no matches is exit 2; all excluded is exit 0 with EXCLUDED output.

Hidden files, lockfiles and dependency/generated directories have no automatic
exclusion. Nested `.gitignore` applies to discovered untracked paths; tracked
paths and explicit files bypass this layer. Outside Git, discovery applies local
`.gitignore`, while explicit files still bypass it. Only root `.raylocignore`
supplies scanner exclusions, in every mode, at higher priority than Git policy.
Ignored parents require effective parent re-inclusion before a descendant
whitelist can apply. Tracked paths bypass Git-excluded parents but retain scanner
parent exclusions. Nested `.gitignore` loads only under an effectively included
parent. Unrelated `.ignore`, global Git excludes, `.git/info/exclude`, and
outside-root parent policy are disabled.

Traversal continues structurally through policy-excluded directories to count
regular matches and find force-tracked children. Read/traversal failures there
still produce incomplete exit 2. Real nested repository working directories are
traversed under the selected root's policy. `.git` entries and resolved Git/common
administration directories are excluded before descent. An explicitly selected
file inside independently located Git administration may return safe discovery
error 2 because Git cannot identify its working tree there.

Selected symlink leaves and recursively encountered symlinks are not followed;
recursive nonregular entries are counted as exclusions. Explicit real files
through symlink ancestor aliases preserve canonical-parent policy, as established
by earlier file-mode tests. This is a non-atomic working-tree scan. No snapshot or
protection against every concurrent filesystem mutation is claimed; observed
missing/replaced sources produce fixed errors when detected.

## Bounded ordering and execution

Directory entry names are sorted by native encoded bytes, with a trailing `/`
in directory sort keys. Iterative depth-first traversal produces the same raw
leaf order as Git's cached index path stream. A monotonic validated NUL cursor
labels tracked membership without a repository-wide path map; adjacent duplicate
index stages are consumed internally. `ls-files` deliberately omits
`--deduplicate`, which Git 2.30 does not support. Removed tracked leaves are not
selected working-tree files. Decreasing/malformed metadata and child failures
fail closed, including during final drain.

Source numbers count matching regular leaves before policy. They can have gaps
and are stable for an unchanged selected path set, rather than being persistent
content identities. A shared ordered collector retains the globally lowest
10,000 source/line/column/rule findings, including lower-column custom matches
emitted after provider matches. Counts include overflow findings; overflow exits
2. Final error categories and findings have deterministic order.

One private Rayon pool handles bounded metadata chunks and scan lanes. At most
eight reusable workers own read/line buffers and histograms. Results from at most
eight lanes are reduced with checked file/byte/line/finding and all five
suppression counters. There are no per-file finding heaps or unrestricted jobs
holding reader state. Matcher programs are shared and compiled on policy entry,
not on every file or line.

| Resource | Admission bound |
| --- | --- |
| Worker threads / stack | min(available parallelism, 8); 2 MiB per thread |
| Serial-to-pool threshold | 256 directory entries or admitted batch files |
| Scan batch | 256 paths and 1 MiB path payload |
| Metadata parallel chunk | 256 entries |
| Live frontier / each directory | 65,536 allocated entries, including batch capacity |
| Live path/name payload | 16 MiB; boxed exact payload plus charged entry capacities |
| Each absolute/relative path | 16 KiB |
| Directory depth | 128 frames, including selected-root ancestors |
| Active scanner plus Git policy | 32 present files, 256 KiB input capacity, 1,024 lines, 256 patterns, 4,096 wildcard/escape/alternative markers |
| Cumulative policy work | 4,096 present files and 64 MiB input capacity |
| Each policy input / line | 1 MiB bounded reader / 16 KiB |
| Inclusion glob | 16 KiB, 16 brace levels, 1,024 commas |
| Git cursor | 256 KiB reader; 16 KiB record; 1,000,000 records and 64 MiB payload |
| Git diagnostic drain | 8 KiB discard buffer; no retained stderr |
| Per-worker reader / physical record | 256 KiB / 1 MiB |
| Candidate / per-line emitted ranges | 64 KiB / 10,000 |
| Glob matching regular source numbers | checked u32 |
| Global retained findings | 10,000 fully masked values |

All budget errors are incomplete exit 2, never silent truncation. Entry Vec
capacities are charged, not just lengths; names/paths are boxed to avoid spare
capacity. Allocator overhead, temporary metadata path construction, matcher
program/cache internals and pool stacks are additional. Active pattern/complexity
limits bound admission but are not a proof of an exact compiled-matcher RSS
ceiling. Git's internal index allocation is separate from rayloc bookkeeping.

## Dependency decisions

Direct `globset = 0.4.19` exposes the already-locked ignore dependency's complete
separator/escaping/brace grammar; duplicating this parser in stdlib would be
larger and less reliable. `rayon = 1.12.0` is required for one bounded pool and
parallel lanes. Its `rayon-core = 1.13.0` and `either = 1.18.0` are the only new
locked packages; crossbeam packages were already present through `ignore`.
Rayon and rayon-core normalized upstream manifests declare Rust 1.80; actual
locked Rust 1.85 tests pass. No separate traversal/parser/concurrency library
was added. Cursor framing, ordering, limits, traversal and reporting use stdlib.

References: [Rayon manifest](https://raw.githubusercontent.com/rayon-rs/rayon/v1.12.0/Cargo.toml),
[Rayon pool](https://docs.rs/rayon/1.12.0/rayon/struct.ThreadPoolBuilder.html),
[globset](https://docs.rs/globset/0.4.19/globset/),
[Git index ordering](https://git-scm.com/docs/gitformat-index),
[Git ls-files](https://git-scm.com/docs/git-ls-files).

## Crossover and throughput

Reproduce with `cargo bench --bench scope`. The benchmark reports medians of
five warm-filesystem scope executions, including a fresh pool per execution,
real file IO, discovery, policy and scan work. Fixture generation is outside
the timed interval. Clean fixture records are 19 bytes, so requested 256-byte
and 16-KiB sizes become exactly 266 and 16,397 bytes per file. Results are
synthetic warm-cache measurements, not end-to-end CLI cold-start percentiles.

| Files x bytes | Serial median ms / MB/s | 8-worker median ms / MB/s |
| --- | --- | --- |
| 8 x 266 | 0.030 / 70.32 | 0.328 / 6.48 |
| 32 x 266 | 0.119 / 71.67 | 0.278 / 30.66 |
| 128 x 266 | 0.322 / 105.79 | 0.369 / 92.24 |
| 256 x 266 | 0.660 / 103.12 | 0.500 / 136.09 |
| 4,096 x 266 | 10.391 / 104.85 | 5.099 / 213.66 |
| 8 x 16,397 | 0.477 / 275.20 | 0.349 / 375.38 |
| 32 x 16,397 | 1.952 / 268.75 | 0.614 / 855.04 |
| 128 x 16,397 | 7.853 / 267.26 | 1.565 / 1,340.98 |
| 256 x 16,397 | 15.754 / 266.44 | 3.350 / 1,252.85 |
| 4,096 x 16,397 | 256.467 / 261.87 | 45.673 / 1,470.51 |

The eight-worker crossover for tiny files occurs between 128 and 256 files.
The default threshold is consequently 256, rather than the initial provisional
32. Metadata entry count can start the pool even when many entries are later
excluded. File size is not used to start an earlier pool: that would require
additional metadata/admission heuristics. Larger files benefit earlier, so this
choice favors predictable small-scope startup over maximizing every workload.
Two-worker results also appear in the benchmark output; no automatic tuning is
claimed. An earlier run measured 259.50 versus 1,075.44 MB/s for the 4,096 large
files, showing real timing variation rather than a guaranteed rate.

## Peak RSS and adversarial workload measurements

Reproduce with `python3 scripts/scope_measure.py
target/release/deps/scope-<hash>` after building the scope benchmark. The stdlib
driver uses `wait4` per fresh child, converting Darwin bytes to KiB. RSS includes
fixture construction, matcher compilation and five scans. It excludes a separate
Git child. Linux child high-water RSS can include the parent's inherited
pre-exec footprint: the repeated 16,152-KiB value is a measurement floor, not
proof that all these workloads have identical scanner-only memory. There was
no cache eviction or maximum-RSS guarantee.

| Workload | 1-worker MB/s / peak KiB | 8-worker MB/s / peak KiB |
| --- | --- | --- |
| 20,000 x 266-byte files | 80.65 / 16,152 | 221.31 / 16,152 |
| 4,096 x 16,397-byte files | 261.54 / 16,152 | 1,558.76 / 16,152 |
| 256 x 16,397, 256 complex ignores + 256 custom rules | 115.04 / 18,964 | 414.86 / 21,012 |
| 256 x 2,100-byte files, 25,600 findings | 185.02 / 16,152 | 70.96 / 16,152 |

Dense findings make the shared deterministic collector a contention point;
eight workers are slower than serial here. This is a measured limitation of
the bounded single-collector design, not a universal speedup claim. The dense
case checks exact overflow counts and incomplete exit 2. The complex policy
case exercises the full active pattern count and full custom-rule count, but
not worst-case regex program/cache allocations or every admitted ignore form.
The separate 20,000-entry Git metadata process reported 16,152 KiB with the same
pre-exec floor; this does not establish an exact index-only peak or a worst-case
Git child bound. Linux measurements do not establish macOS memory/performance.

Tests additionally enforce exact/over physical-line and candidate bounds,
>10-MiB streaming through the final finding, injected small frontier/path/depth/
policy caps, malformed/truncated/decreasing Git records, duplicate stages,
checked-counter overflow, child/drainer failures, permissions and disappearing
sources. Serial/2/8-worker runs of 300 dense files compare identical findings,
all counters and errors, retaining the lowest 10,000 of 12,000 detections.

## Fix round 1: nested administration and selected symlink leaves

Directory scope now performs a bounded metadata-only pass before admitting any
scan work. Encountered regular `.git` pointer files resolve both their Git and
common directories with the existing bounded Git path helper. Inherited
`GIT_DIR`, `GIT_WORK_TREE` and `GIT_COMMON_DIR` are cleared only for these local
queries; selected-root policy and tracked membership remain unchanged. This
excludes separate administration that sorts before its nested working directory,
as well as linked-worktree common administration. Ordinary nested `.git`
directories remain excluded without scanning their contents.

The pass uses the same private pool, depth/frontier/path budgets and iterative
frames. It admits no files, counts no duplicate exclusions, loads no additional
ignore policy, and retains only deduplicated administration boundaries. At most
4,096 pointer resolutions and two paths per pointer are admitted; path payload
is capped at 16 KiB each, charged against the existing 16-MiB live path budget,
and vector capacities are charged against the existing 65,536-entry frontier.
No repository-wide discovered-file list is retained. Invalid pointers/common
queries and resource exhaustion fail closed before scanning. Directory metadata
errors are incomplete even if the later pass can read other sources. The scan
remains non-atomic; changed pointers or paths between passes are not a snapshot.

CLI selection reconstructs path components before `symlink_metadata`, removing
trailing separators without resolving ancestors. Thus `linked/` and `linked///`
reject a selected directory symlink, while `linked/sub/` and `linked/sub/key`
retain the supported ancestor-alias behavior.

Fresh final-code `cargo bench` retains the tiny-file crossover at 256: 128 x
266 bytes takes 0.382 ms serial versus 0.483 ms with eight workers; 256 files
takes 0.759 versus 0.669 ms. 4,096 x 16,397 bytes takes 259.473 ms / 258.84 MB/s
serial versus 49.073 ms / 1,368.63 MB/s with eight workers. The metadata pass's
cost is included. The existing engine driver measures 271.42 MB/s here.

Fresh `scope_measure.py` results with the same methodology and inherited-RSS
floor caveat:

| Workload | 1-worker MB/s / peak KiB | 8-worker MB/s / peak KiB |
| --- | --- | --- |
| 20,000 x 266-byte files | 77.29 / 16,128 | 196.87 / 16,384 |
| 4,096 x 16,397-byte files | 256.91 / 16,384 | 1,440.41 / 16,384 |
| 256 x 16,397, 256 complex ignores + 256 custom rules | 113.45 / 19,244 | 421.17 / 22,908 |
| 256 x 2,100-byte files, 25,600 findings | 168.68 / 16,640 | 63.65 / 16,640 |

Separate 20,000-entry Git metadata measurement: 16,640 KiB with the same floor.
These workloads do not measure maximum nested-repository query latency or
worst-case administrative-path storage; caps and malformed/query/counter error
paths are separately exercised by real repositories and injected small budgets.
