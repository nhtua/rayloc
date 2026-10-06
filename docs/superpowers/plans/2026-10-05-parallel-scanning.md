# Parallel Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task, or superpowers:subagent-driven-development when delegation is explicitly selected. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve directory and glob scan throughput by exposing bounded thread control, admitting useful work sooner, balancing files dynamically, and reducing traversal overhead.

**Architecture:** Keep policy evaluation and source-ID assignment in a deterministic producer. Use one private Rayon pool with bounded reusable scanner state; start with dynamically scheduled batches, then overlap discovery and scanning through a bounded queue. Preserve the administrative discovery pass and existing scan scope before considering broader traversal changes.

**Tech Stack:** Rust 1.85+, existing Rayon 1.12.0, standard-library synchronization and buffered I/O; no new production dependencies.

**Spec:** `technical-design.md` sections 1, 2, 4, 5 and 7; `AGENTS.md`; the proposed decisions and evidence below, approved by the user for implementation.

## Global Constraints

- No raw secrets in diagnostics, reports, queue messages, or timing instrumentation. Findings retain `RedactedString`.
- Preserve exit 0 for clean scans, 1 for findings, and 2 for execution/configuration errors.
- Preserve tracked-file exceptions to Git ignores, scanner exclusion precedence, root-relative glob semantics, nested Git administration exclusions, hidden files, and no symlink following.
- Preserve deterministic retained findings, source IDs, statistics, and error ordering across worker counts. Sort errors explicitly if concurrent reduction changes their arrival order.
- Do not load files larger than 10 MB into memory; retain bounded buffered reading. Do not introduce mappings of mutable files.
- Compile rules once. Keep per-worker read buffers at 256 KiB, physical lines capped at 1 MiB, candidates capped at 64 KiB, and retained findings capped at 10,000.
- Keep existing frontier, depth, policy and metadata budgets. Count pending and running work against queue/path budgets.
- Production coverage: at least 97% lines and regions, 100% functions; no production exclusions.
- This proposal initially changes directory/glob execution. File, staged and diff scanning retain their existing execution model.

## Evidence and Diagnosis

Inspected source: commit `431a3fc`, version `2026.10.6`. Hardware: AMD Ryzen 9 9950X, 16 physical cores / 32 logical CPUs; Rust 1.88.0. Measurements use optimized release code, warm filesystem cache, one untimed pass, and medians of three samples unless indicated. Output was redirected to temporary files; terminal rendering cost is not established by these measurements. Benchmark timing runs were isolated from compilation for the confirmed results.

### Observations from the code

1. `ScopeOptions::default()` limits file lanes to `min(available_parallelism, 8)`; scope entry rejects more than eight. `RAYON_NUM_THREADS` controls the global pool, not these lanes.
2. `Runner::pool()` only allocates `Worker` objects. It does not build a thread pool, despite the module description. `par_iter_mut()` uses Rayon's global pool.
3. Scanning requires batches of at least 256 files. A directory containing 32 multi-megabyte files is scanned serially. Even after workers exist, the final smaller batch uses only worker zero.
4. `flush()` splits paths into contiguous equal-count chunks and executes a serial loop inside each lane. Rayon cannot steal the individual files within that loop. Filename order can concentrate expensive files in one lane.
5. Discovery and scanning alternate: `regular()` calls synchronous `flush()`, and discovery resumes only after the slowest lane finishes.
6. `entries()` performs `symlink_metadata` for each entry and invokes a parallel iterator for every directory chunk, including tiny chunks, without checking the scan threshold or requested lane count.
7. The selected tree is walked twice: administration discovery, then policy-aware file discovery. Excluded directory descendants are still enumerated. Here, 108 scanned files / 868,038 bytes required considering 16,644 regular files, 16,538 of them excluded.
8. The CLI uses `SharedEmitter<TerminalEmitter>` directly. Each finding takes the collector lock, takes it again for a label, and acquires the emitter lock while writing. `channel_emitter()` has no production caller and uses an unbounded channel.
9. `benches/scope.rs` sets `parallel_threshold: 1`, so existing scope benchmarks bypass the CLI's 256-file gate. It also has uniform file sizes and does not time CLI streaming.

### Measured effects

| Warm release workload | Rayon pool 1 | Pool 8 | Pool 32 | Interpretation |
| --- | ---: | ---: | ---: | --- |
| 32 files, about 128 MiB total | 1,186 ms | 1,205 ms | 1,188 ms | Approximately one CPU used; batch gate prevents parallel file scans |
| 256 equal files, about 128 MiB total | 1,186 ms | 189 ms | 191 ms | Eight file lanes work; 32 pool threads add no file lanes |
| One 64 MiB file + 255 tiny files | 597 ms | 626 ms | 629 ms | Large-file work remains a single sequential job |
| Rayloc checkout, 108 scanned files (five samples) | 86.7 ms | 76.0 ms | 109.6 ms | Extra threads spend CPU on discovery scheduling |
| 8,192 excluded files + 257 scanned files | 17.7 ms | 12.3 ms | 23.5 ms | Excluded metadata traversal still incurs work; 32 threads are slower |

Confirmed isolated probes, five samples each:

- Existing library API, same 32-file / 128 MiB fixture and eight workers: threshold 256 = **1,143 ms**; threshold 1 = **177 ms**, approximately **6.5x faster**. No scanner source was changed.
- Same 256 files / about 64 MiB, eight workers: placing all 32 large files in the first static lane = **625 ms**, **1.01 average CPUs**; spreading them across lanes = **99 ms**, **7.67 average CPUs**. Only file-size placement by filename changed, approximately **6.3x** elapsed difference.
- `perf record -e cycles:u -F 999` on the checkout with symbols: at 32 pool threads approximately **66%** of samples landed in `crossbeam_epoch::default::with_handle` and **14%** in `Global::try_advance`. At eight, roughly **42%** landed in `with_handle` and **16%** in Rayon wakeup code. These are short exploratory profiles, not stable production percentages or evidence of a dependency bug.

The user's exact 5.15-second directory workload has not been identified. The above demonstrates mechanisms that explain poor scaling, but does not establish its dominant bottleneck or promise a particular speedup there.

Diagnostic artifacts are temporary, not production changes: `/tmp/rayloc_parallel_review.py`, `/tmp/rayloc_scope_probe.rs`, `/tmp/rayloc-parallel-review-yx0i_ekv/matrix.json`, `/tmp/rayloc-parallel-review-4m7gvuaj/checkout.json`, `/tmp/rayloc-parallel-review-0hhq1vlh/confirmation.json`, and `/tmp/rayloc-profile-{1,8,32}.data`.

## Proposed Decisions

- Expose `scan --threads N` for directory/glob scopes. Resolve CLI flag, then `RAYON_NUM_THREADS`, then automatic default; reject supplied invalid values with fixed errors and exit 2. The CLI flag overrides the environment, including an invalid environment value.
- Proposed maximum: **64 scan threads**, replacing the existing hard limit of eight. Keep the automatic default at `min(available_parallelism, 8)` initially, then evaluate a higher automatic default with the expanded benchmark matrix. Explicit 32 becomes 32 available file workers, rather than eight workers in a 32-thread pool. Permit explicit oversubscription within the limit; it is not a throughput guarantee.
- At 64 lanes, read and maximum line buffers alone can occupy **80 MiB** (64 times 256 KiB plus 1 MiB). Regex caches, retained findings, paths, queues and thread stacks add to this; record total RSS rather than presenting 80 MiB as a total memory ceiling.
- Use a private pool with the resolved size, created lazily and reused throughout one scan. Tiny serial scopes should not create it. Map construction errors to `ScanError::Pool`; never print raw builder errors.
- Initially enable parallel batches when there are at least **two eligible files** and either **256 files** or **256 KiB estimated selected-file bytes**. These are initial benchmarkable thresholds, not tuned universal values.
- Dynamically claim individual files from the current bounded batch using an atomic index. Preassign source IDs before scheduling; each lane owns one reusable `Worker`. Do not allocate a new scanner for every file or assume `map_init` initializes exactly once per operating-system thread.
- Prefer `DirEntry::file_type()` for classification; inspect full metadata only where needed. Evaluate sequential classification first, avoiding Rayon jobs for cheap per-entry operations.
- Retain both traversal passes initially. Pruning ignored trees or eliminating the administration prepass requires a separately specified compatibility change, not a casual optimization.
- Treat one huge file as a separate later work unit problem. Better file scheduling cannot parallelize its internal records.

## Review Focus

1. Force-added tracked files under ignored directories remain scanned; a generic ignore walker does not satisfy this.
2. A nested repository can point at an administration directory that sorts before its `.git` pointer; nothing is scanned before administration discovery completes.
3. A slow printer, full work queue, or failure during discovery must terminate without deadlock, loss of admitted findings, or unbounded buffering.
4. Multiple workers competing around the 10,000-finding limit must retain the same ordered findings and errors as serial execution.
5. Cached directory entry types can become stale or expose different permission errors; opening a file still verifies regular-file status and failures still produce exit 2.

## Task 1: Establish Representative Regression Measurements

**Files:** modify `benches/scope.rs`, `benches/README.md`, `scripts/scope_measure.py`; add `scripts/parallel_measure.py`; test harness behavior in `tests/measurement_tools.py`.

**Interfaces:** the new script invokes the actual release CLI, accepts `--binary`, `--samples`, and `--output`, and writes JSON containing case, thread request, cache description, median wall/user/system time, peak RSS, reported bytes/files/findings, exit code, and binary SHA-256. It never stores source contents or full report output.

- [x] Add cases for 32 large files, 255/256/257 files, uniform files, clustered large files, one large file, many tiny directories, excluded trees, Git tracked exceptions, and dense findings. Test fixture and summary accounting against independently calculated byte/file/finding counts.
- [x] Run the harness tests before adding their implementation; require failure due to the missing harness or incorrect accounting, not flaky speed assertions.
- [x] Add CLI runs for pool requests 1/2/8/16/32, default scheduling, redirected output, and a drained slow output pipe. Add library runs for the production default threshold as well as threshold 1. Warm and measure one process at a time; do not overlap timing with builds.
- [x] Record a baseline and CPU/RSS profiles. Treat any change in scanned scope or exit code as a failed comparison.
- [x] Run `python3 -m unittest discover -s tests -p measurement_tools.py` and release benchmark cases; commit the harness independently.

## Task 2: Use One Explicitly Sized Pool and Expose Thread Selection

**Files:** create `src/scanner/execution.rs`; modify `src/scanner/mod.rs`, `src/scanner/scope.rs`, `src/cli.rs`, `README.md`; tests in `tests/unit/scope.rs`, `tests/unit/cli.rs`, `tests/scope_cli.rs`, plus `tests/unit/execution.rs`.

**Interfaces:** execution module exports internally `MAX_SCAN_THREADS: usize = 64` and `resolve_threads(requested: Option<usize>, environment: Option<&std::ffi::OsStr>, available: usize) -> Result<usize, ScanError>`. `BatchExecutor` owns the optional private pool and reusable lanes. Retain `ScopeOptions.workers` as the resolved numeric size for library/benchmark callers; its default remains automatic without consulting process environment. Add `scan_directory_with_options_and_emitter(root: &ScopeRoot, selected: &Path, pattern: Option<&str>, registry: &Registry, options: ScopeOptions, emitter: SharedEmitter) -> ScanOutcome` so the CLI actually propagates its selection.

- [x] Write failing tests for precedence, 1/8/32/64, zero, values above 64, nonnumeric/non-UTF-8 environment input, duplicate/missing CLI values, and invalid scopes. `--threads` on explicit-file, staged, or diff scopes returns a fixed unsupported-scope error, exit 2. Tests must not echo argument values.
- [x] Verify the actual private pool size using `current_num_threads()` inside it; ensure a competing global pool does not override it. Empty/small serial scope must not initialize the private pool. Exercise the pool construction error boundary with a deterministic injected failure.
- [x] Implement resolution, lazy private pool creation, CLI propagation, and fixed errors. Route both existing parallel call sites through the private pool, with a serial metadata fallback for small chunks, until Task 4 removes unnecessary parallel classification. Update all eight-worker ceiling assertions and documentation; retain one-worker serial execution.
- [x] Run `cargo test --all` and representative startup/throughput cases. Check that requested 32 appears in executor instrumentation and no production operation inadvertently uses the global pool.
- [x] Commit this independently from scheduling changes.

## Task 3: Admit Byte-Heavy Batches and Schedule Files Dynamically

**Files:** modify `src/scanner/execution.rs`, `src/scanner/scope.rs`; tests in `tests/unit/execution.rs`, `tests/unit/scope.rs`, `tests/scope_cli.rs`; benchmark fixtures in `benches/scope.rs`.

**Interfaces:** keep `ScopeOptions.parallel_threshold` as the file-count threshold and add `parallel_bytes_threshold: u64`, default 256 KiB. Add an estimated-byte hint to `Work`, computed only for eligible regular files. A failed size lookup supplies a conservative parallel-admission hint and still sends the file through the existing verified-open path. Hints must not determine scope, completion, or reported scanned bytes. `BatchExecutor` receives the immutable job slice; each lane repeatedly claims the next index with `AtomicUsize::fetch_add(Ordering::Relaxed)`.

- [x] Write failing structural tests that 32 large files and a byte-heavy final partial batch enter parallel execution, while one file and a small batch of tiny files remain serial. Assert correct byte totals and source locations; do not use elapsed-time assertions.
- [x] Write a controlled scheduler test where an expensive first job is held behind a synchronization gate and another lane completes later eligible jobs. Prove files are independently claimable rather than tied to contiguous lane chunks. Use bounded waits and always release the gate on failure.
- [x] Implement the admission predicate and dynamic claiming with at most `min(requested_threads, job_count)` active lanes. Reuse buffers and preserve preassigned IDs. Keep existing bounded batch/path storage and checked production counters; estimated-byte totals may saturate for scheduling only.
- [x] Extend serial/parallel equality tests to 1/2/8/32 workers, boundary-crossing lines, dense findings, caps, custom rules, accepted values and partial failures. Verify errors have a stable canonical order.
- [x] Run `cargo test --all`; compare the 32-large and clustered/distributed fixtures. Require identical findings/stats, and materially reduce the filename-order sensitivity. Record actual speedup; do not assume 32 beats eight on SMT hardware.
- [x] Commit after validating the change independently.

## Task 4: Make Discovery Cheaper Without Changing Scope

**Files:** modify `src/scanner/scope.rs`; tests in `tests/unit/scope.rs`, `tests/scope_cli.rs`; benchmark cases in `scripts/parallel_measure.py`.

**Interfaces:** `Runner::entries()` retains bounded `Vec<Entry>` storage and its deterministic sort for scan discovery. Obtain `Kind` from `DirEntry::file_type()` before dropping the entry; avoid retaining `DirEntry` objects across recursion. Preserve explicit classification failures as `Kind::Error` and verified-open checks for admitted files.

- [x] Write tests for regular/directory/symlink classification, stale types followed by verified-open failure, enumeration errors, resource limits, and readable directories whose children cannot be opened. Tests should pin exit 2 and scope preservation; avoid requiring an unnecessary metadata syscall to fail during classification.
- [x] Replace unconditional per-entry `symlink_metadata` plus `par_iter_mut()` with cheap entry-type classification. Benchmark before adding parallel metadata fallback; a cached type normally needs no additional syscall on supported filesystems.
- [x] Keep `discover_administration()` and traversal of excluded trees. Verify force-added tracked files, nested administrative pointers sorting before/after their destination, linked worktrees, malformed pointers, glob matches that are all excluded, and ignored-tree errors.
- [x] Measure the checkout and excluded-tree cases at 1/8/32. Require lower scheduling CPU cost and unchanged completed-file/finding sets; record exclusion counts as well.
- [x] Investigate remaining path/policy cost only if profiling still shows it dominant. Avoid compiling root `.raylocignore` twice by passing/reusing the loaded matcher if that cost is material.
- [x] Run scope tests and the complete suite; commit the discovery optimization independently.

## Task 5: Overlap Discovery and Scanning with Bounded Admission

**Execution decision (2026-10-06): deferred.** The measured cases after dynamic
batch scheduling complete in 1.7–2.4 ms for 256 tiny files in 32 directories;
the larger excluded-tree case completes in 7.4–10.0 ms. These runs do not show
that producer/consumer overlap is the limiting stage. A queue would add another
resource-accounting and shutdown protocol; revisit it against a matching deep
mixed-content repository with stage-level profiles.

The exact five-second user corpus was not provided, so this decision does not
rule out queueing benefits for that unidentified workload.

**Files:** extend `src/scanner/execution.rs`; modify `src/scanner/scope.rs`; tests in `tests/unit/execution.rs`, `tests/unit/scope.rs`, `tests/scope_cli.rs`.

**Interfaces:** introduce an owned `WorkQueue` with `push(Work)`, `pop() -> Option<Work>`, and `close()`. Use standard-library `Mutex`/`Condvar` and an admission guard. Proposed total limits are **512 queued plus running jobs** and **2 MiB queued plus running path bytes**, charged alongside existing traversal budgets and released only when a job finishes. The deterministic producer owns policy state; workers consume only already-admitted paths and preassigned IDs.

- [ ] Write failing tests proving discovery can admit later files while an earlier file is scanning, admission blocks at count/byte caps, and shutdown wakes producers and consumers.
- [ ] Complete administration discovery before starting consumers. Accumulate enough initial work to choose serial versus parallel execution, then start persistent lanes on the same private Rayon pool. Run the pool coordinator in a scoped helper thread so the producer is outside the pool; do not block a Rayon worker trying to produce into its own full queue. The serial path uses no helper thread.
- [ ] Retain exactly one `Worker` per admitted lane. Workers claim individual files, release queue locks before opening/scanning, and return local outcomes for canonical reduction. On producer error, close the queue and drain already-admitted work before returning the partial outcome.
- [ ] Preserve the discovery-time source IDs; do not derive IDs from completion order. Test that late nested pointer failures still occur before any scanning, and that consumer/read failure cannot strand a producer.
- [ ] Run mixed-directory tests with gated readers, queue saturation and injected discovery failure. Benchmark deep tiny directories mixed with medium files against Task 4; retain the pipeline only if it improves that measured case without startup/RSS regression.
- [ ] Commit after full verification of termination and resource accounting.

## Task 6: Move Report I/O Away from Scanning Workers

**Execution decision (2026-10-06): deferred.** The 800-finding fixture takes
2.5–2.7 ms with a fast sink. A deliberately throttled reader raises elapsed
time to 133 ms, which is output-drain time; a printer thread cannot reduce the
required drain. Revisit when the actual target workload has enough findings to
show scanner/report contention and when earlier output visibility is required.

**Files:** modify `src/report/emitter.rs`, `src/scanner/engine.rs`, `src/scanner/execution.rs`, `src/scanner/scope.rs`, `src/cli.rs`; tests in `tests/unit/emitter.rs`, `tests/unit/engine_collector.rs`, `tests/cli.rs`.

**Interfaces:** add a bounded reporter handle using `std::sync::mpsc::sync_channel`, with proposed capacity **256 messages** and an additional **1 MiB message-byte budget** including sanitized labels. The handle owns printer lifecycle and joins before CLI return. Messages contain only redacted findings/safe labels and completion state. A collector offer returns the emission metadata in the same lock acquisition, removing the second label lookup lock.

- [ ] First measure dense findings with fast and slow sinks. If output dominates total runtime, report output time separately; moving I/O cannot eliminate the time required to drain it.
- [ ] Write failing tests for slow output, full queues, printer termination, partial scan failures, bounded message admission and redaction. A bounded channel intentionally applies backpressure when the sink falls behind; do not claim workers can never block.
- [ ] Replace the unused unbounded printer helper with an owned bounded lifecycle and connect it to the CLI. Keep final retained output deterministic: publish sorted completed-batch findings initially. With overlapping execution, assign bounded batch-completion watermarks and release ready batches in source order; account for completed-but-unpublished findings in the existing retention budget.
- [ ] Do not enqueue while holding the collector or work-queue lock. Finish only after all producers close, print the summary after all accepted report messages, and join. Streaming becomes visible at completed-batch boundaries rather than immediately in nondeterministic arrival order; document this behavior.
- [ ] Keep the collector's global cap initially. Only replace it with local bounded collectors plus a deterministic merge if post-change profiles establish meaningful contention and the memory bound is explicitly preserved.
- [ ] Run dense-finding, cap, leak and deadlock regressions; commit separately. Schedule this task earlier than Task 5 if the user's actual workload is finding/output-heavy.

## Task 7: Validate, Tune, and Publish Measured Results

**Files:** update `benches/README.md`, `README.md`, `technical-design.md`, and `docs/research/parallel-scanning-results.md` with the selected thresholds, pool behavior and matching-workload measurements.

- [x] Run the benchmark matrix sequentially with 1/2/8/16/32 threads, default and threshold-control cases, and fast/slow sinks. Include the checked-out project; the user's reported five-second corpus remains unidentified.
- [x] Compare exact completed-file sets, bytes, findings, suppressions, errors and exit codes before interpreting throughput. Do not accept speed gained by scanning less content.
- [x] Record median/p95 wall time, user/system CPU, configured pool size and active-lane upper bound, peak RSS and binary identity. Use at least 15 timed samples for performance decisions; document warm-cache scope and separate startup from sustained scanning.
- [x] Acceptance targets on the inspected machine: 32-large should beat its serial median by at least 3x at eight threads; clustered-heavy should approach distributed-heavy within 1.5x; tiny-scope median should remain within 10% or 1 ms of baseline, whichever allowance is larger. These are local review gates, not timing-sensitive unit tests or universal guarantees. Investigate misses before changing the targets.
- [x] Tune byte/count admission before increasing the automatic default above eight. Prove memory grows with bounded worker/queue resources rather than repository size. Allow 32 to be slower than 16 if the hardware/workload measurements support that.
- [x] Run all mandatory checks: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`, `cargo bench`, and `cargo coverage`. Required outcome: all commands succeed, coverage lines/regions >=97%, functions 100%.
- [x] Commit the verified documentation and measurements. Do not claim the user's 5-second case is fixed until that exact scan has been measured.

**Coverage tool note:** this environment's `cargo coverage` alias reports an
unrecognized `llvm-cov` subcommand. The equivalent `cargo llvm-cov` invocation
with the alias's locked/workspace/features/exclusion/threshold arguments passed:
100% functions, 97.68% lines, and 98.69% regions.

## Deferred Work and Alternatives

- **Large-file record parallelism:** if profiles still show one or a few huge text files dominating, prepare a separate plan for bounded batches of complete physical records, preserving original line/column positions, CRLF, final unterminated lines, binary sampling, inline directives, per-file statistics, partial-read failures and finding caps. Keep streaming input; do not split arbitrary byte offsets or mmap mutable files. This is required to speed up the one-64-MiB fixture beyond a single core, but is not required for the first scheduling improvements.
- **Ignore-tree pruning:** a separate compatibility decision is needed. Current behavior counts excluded descendant files, checks traversal errors in ignored trees, and discovers Git pointers there before scanning their possible destinations. Pruning changes these observables and can invalidate glob no-match behavior or administrative exclusions. Do not simply return early when `combined == false`; tracked files can remain eligible.
- **Single traversal:** retaining all paths to avoid a second walk conflicts with bounded storage. Removing the first walk is unsafe when administrative destinations sort before pointers. Keep it until a bounded replacement has a demonstrated exclusion protocol.
- **Regex state isolation:** shared regexes can contend on short inputs; clone compiled search handles per worker only if a custom-rule workload profile shows it. Never recompile policy in a file/line loop.

## Reference APIs

- [Rayon pool sizing](https://docs.rs/rayon/1.12.0/rayon/struct.ThreadPoolBuilder.html#method.num_threads) and [private pool installation](https://docs.rs/rayon/1.12.0/rayon/struct.ThreadPool.html#method.install).
- [Rayon `map_init`](https://docs.rs/rayon/1.12.0/rayon/iter/trait.ParallelIterator.html#method.map_init): initialization is per job, not a guaranteed once-per-thread cache.
- [Standard-library `DirEntry::file_type`](https://doc.rust-lang.org/std/fs/struct.DirEntry.html#method.file_type): no symlink following, often no additional syscall on Unix.
- [Regex sharing and cloning](https://docs.rs/regex/latest/regex/#sharing-a-regex-across-threads-can-result-in-contention).
