# Bounded Parallel Line Batches Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve scans of a few large, many-line files by lending complete-line batches to the existing Rayon pool without changing detection or error semantics.

**Architecture:** File owners retain their existing 256 KiB read buffers and serial streaming sessions. They expose bounded LF-terminated batches to globally leased helper scratch slots in the same private pool, scan the first batch themselves, and publish helper outcomes in source order. Dense or accounting-sensitive batches replay serially before any speculative publication.

**Tech Stack:** Rust 2024, existing Rayon 1.12.0 and byte-regex registry, standard-library synchronization, existing stdlib Python/native measurement tooling. No new production dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-parallel-line-batches-design.md` (approved in chat 2026-10-06). Read both documents before execution. Baseline production commit: `8662919`; the subsequent spec commit is `287f229`.

## Global Constraints

- Scope: CLI file, directory, and glob scans; staged/diff acquisition and individual giant-line streaming remain unchanged.
- One private Rayon pool per scan; configured width 1–64, automatic maximum eight; never create a per-file pool or use the unrestricted global pool.
- Existing read window 256 KiB; file eligibility hint at least 256 KiB; target batch 32 KiB; hard batch 64 KiB including LF; at most eight descriptors per wave.
- A useful wave needs at least two eligible batches and one helper slot; at most `workers - 1` helper slots across the scan.
- At most 128 provisional redacted findings per helper slot, at most 8,064 across a 64-worker scan; the existing global retained cap stays 10,000.
- Borrow raw input, retain CR, remove only LF for detection, do not require UTF-8, and never log/debug raw payloads. Recorded values use `RedactedString` immediately.
- Preserve source IDs, byte columns, line numbers, acceptance IDs, disabled rules, duplicate priority, inline ignores, terminal-error boundaries, and exact counters.
- No channels, extra reader threads, memory mapping, whole-file loads, detector rewrites, or new dependencies. Preserve Rust 2024/MSRV 1.85 declarations and existing public serial APIs.
- No capacity waits within Rayon jobs; scarce helpers fall back serially. Join every scoped task before reusing input. Pool creation failure remains `ScanError::Pool`.
- Benchmarks: at least 15 timed samples after warm-up; target >=1.5x baseline CLI median for representative one-file clean/sparse input at four workers on >=4 logical CPUs; <=10% regression on comparison workloads.
- Run all five AGENTS.md commands. Also enforce 100% production function coverage explicitly; the current alias only enforces 98%, and AGENTS.md's workflow requests >=97% lines/regions. Do not weaken configuration or exclude production code to pass.

## Review Focus

1. A short read ending mid-CRLF or mid-secret must not manufacture EOF, a token terminator, or a clean result (Task 4).
2. An earlier owner/helper failure must suppress already-finished later helpers, while preserving findings emitted before the failure (Tasks 3–4).
3. Nested work stealing with every file lane busy must never alias mutable scratch, deadlock waiting for capacity, or exceed the scan-wide slot cap (Tasks 3, 5).
4. The 129th provisional finding must trigger lossless replay, not a new finding-limit error; accepted/ignored findings must not consume staging capacity (Tasks 3–4).
5. A legacy baseline binary rejects file `--threads`; measurements must omit that flag for baseline file scans and must not infer active helpers from thread counts (Task 7).

---

## File Structure and Dependency Map

| File | Responsibility |
| --- | --- |
| Create `src/scanner/record.rs` | Small shared accepted-ID/redaction/publication seam, extracted from `engine::detect_record`; not a detector rewrite |
| Create `src/scanner/batch.rs` | Descriptor planning, bounded leased scratch, helper preparation, ordered wave resolution and diagnostics |
| Modify `src/scanner/mod.rs` | Register modules; re-export diagnostics types; attach unit-test support |
| Modify `src/scanner/engine.rs` | Preserve serial wrappers; integrate file-only acquisition; add options-bearing file entry point |
| Modify `src/scanner/scope.rs` | Share one helper arena with the existing private file pool and preserve discovery |
| Modify `src/cli.rs` | Accept file `--threads`, reuse thread resolution, route to the new file entry point |
| Create `tests/unit/record.rs`, `batch.rs`, `parallel_support.rs`; modify `engine.rs`, `scope.rs`, `cli.rs` unit tests | Test seams, scheduling/resource invariants, and exact equivalence |
| Modify `tests/scope_cli.rs`; retain staged/worktree integration suites | Executable thread-option, policy, redaction, and compatibility contracts |
| Create `scripts/line_batch_measure.py`, `tests/line_batch_measurement.py`, `benches/line_batches.rs` | Baseline/candidate CLI comparison and separate release-library diagnostic measurements |
| Modify `scripts/rss_launcher.c`, `Cargo.toml`, `benches/README.md`, `README.md`, `docs/technical-design.md` | Backward-compatible measurement resource mode, benchmark registration, current execution documentation |
| Create `docs/research/parallel-line-batches-results.md` | Measured gates, workload/caching/hardware limitations and final constants |

Tasks 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7. Execute sequentially: they share scanner interfaces. Do not run concurrent writers against these files.

Attach new Rust unit files using the repository's `#[cfg(test)] #[path = "../../tests/unit/..."] mod tests;` pattern. `parallel_support.rs` is a test-only module under `scanner`, not production code. Allow a narrowly documented temporary `#[allow(dead_code)]` on the unwired batch module in Tasks 2–3; remove it in Task 4. This is not a coverage exclusion.

## Task 1: Establish a shared safe record seam and freeze serial behavior

**Files:** Create `src/scanner/record.rs`, `tests/unit/record.rs`, `tests/unit/parallel_support.rs`; modify `src/scanner/mod.rs` and `src/scanner/engine.rs:299-357`.

**Interfaces:**
- Consumes existing `Registry::detect_line_with_suppressions`, `FindingId::new`, `RedactedString::new`, `engine::{Limits, Collector, add, merge_suppressions}`, and `LineSession::push` unchanged.
- Produces these `pub(super)` record interfaces:

```rust
#[derive(Clone, Copy)]
pub(super) struct RecordContext<'a> {
    pub source_id: u32,
    pub path: &'a [u8],
    pub registry: &'a Registry,
}
pub(super) fn prepare_finding(
    bytes: &[u8], line_number: u64, context: RecordContext<'_>,
    rule: RuleId, span: Range<usize>,
) -> Option<Finding>;
pub(super) fn evaluate_record(
    bytes: &[u8], line_number: u64, context: RecordContext<'_>,
    histogram: &mut Histogram, suppressions: &mut Suppressions,
    emit: impl FnMut(Finding),
) -> Result<(), ScanError>;
pub(super) fn publish_finding(
    finding: Finding, path: &[u8], outcome: &mut ScanOutcome, limits: Limits,
    collector: &Mutex<Collector>, emitter: Option<&SharedEmitter>,
);
```

- `prepare_finding` returns `None` only for an accepted ID; spans are validated registry output. `evaluate_record` counts accepted findings, including before a registry error, and preserves callback order. `publish_finding` preserves the current nonterminal counter/finding-limit handling and releases the collector lock before output.
- Test support produces `token_line() -> Vec<u8>` using `[b"ghp_".as_slice(), b"abcdefgh", b"ijklmnop", b"\n"].concat()`, and `semantic_key(&ScanOutcome) -> String` comparing findings, sources, errors, stats and exit code, excluding only elapsed time. Use safe `Debug` values; no raw fixture contents in assertion messages.

- [ ] **Step 1: Prepare isolated execution before production edits.** Use `using-git-worktrees` at execution time, respect existing changes, and verify the checkout has the approved spec and plan.
- [ ] **Step 2: Build the unmodified release binary.** Run `cargo build --locked --release`; expect success before changing production files.
- [ ] **Step 3: Freeze the baseline artifact.** Copy the binary to `/tmp/opencode/rayloc-line-batch-baseline` using Python `shutil.copy2`, then record `sha256sum`, `rustc --version`, `git --version`, CPU/OS and `git rev-parse HEAD` in `/tmp/opencode/rayloc-line-batch-baseline.json`. If those paths already exist, verify their identity instead of overwriting unfamiliar artifacts; use a documented unique path if necessary. Do not replace the baseline during later builds.
- [ ] **Step 4: Establish the starting tests.** Run `cargo test --all`; expect success, or investigate and record pre-existing failures before proceeding.
- [ ] **Step 5: Write failing seam tests.** In `tests/unit/record.rs` add `evaluation_preserves_spans_ids_priority_and_acceptance` and `publication_is_redacted_and_nonterminal_limits_are_preserved`. Use one provider token, an earlier custom capture on the same line, an accepted ID, and an inline ignore. Exact assertions:

```rust
assert_eq!(prepared[0].line, 17);
assert_eq!(prepared[0].id, FindingId::new(b"input.rs", captured_bytes));
assert_eq!(suppressions.accepted, 1);
assert_eq!(ignored_findings.len(), 0);
assert_eq!(ignored_suppressions.inline, 1);
assert_eq!(outcome.stats.findings_detected, 3); // Limits.findings = 2
assert_eq!(outcome.findings.len(), 2); // after Collector::finish
assert_eq!(outcome.exit_code(), 2);
assert!(!rendered.as_bytes().windows(token.len()).any(|w| w == token.as_slice()));
```

  Construct the variables with existing registry/config/collector test patterns; compare complete callback order against direct registry detection, not sorted callbacks. Add a near-`u64::MAX` publication test proving the current callback records `CounterOverflow` without turning it into a registry-returned error.
- [ ] **Step 6: Verify RED.** Run `cargo test --lib scanner::record::tests -- --nocapture`. Expect missing seam/module symbols initially, or failing assertions; distinguish setup failures from the intended missing behavior.
- [ ] **Step 7: Implement the interfaces and delegate `detect_record` to them.** Preserve when suppressions merge and which error wins if merging fails. Do not move line/byte progress accounting out of `LineSession`/the existing reader yet, and do not change `rules/*`.
- [ ] **Step 8: Verify GREEN and serial regression contracts.** Run `cargo test --lib scanner::record::tests`, `cargo test --lib scanner::engine::`, `cargo test --lib scanner::stream::`, then `cargo test --test staged_cli --test worktree_cli`. Expect all tests to pass and unchanged existing snapshots/counters.
- [ ] **Step 9: Commit only this task's files.** Run `cargo fmt --all -- --check` and strict Clippy, then commit as `refactor: share safe record preparation and publication`.

## Task 2: Plan bounded newline-aligned waves without copying input

**Files:** Create `src/scanner/batch.rs`, `tests/unit/batch.rs`; modify `src/scanner/mod.rs`.

**Interfaces:** Consumes `ScanError`, `READ_BUFFER_BYTES`; produces:

```rust
#[derive(Clone, Copy)]
pub(super) struct BatchLimits {
    pub target_bytes: usize, pub hard_bytes: usize,
    pub max_batches: usize, pub max_findings: usize,
}
pub(super) const BATCH_LIMITS: BatchLimits = BatchLimits {
    target_bytes: 32 * 1024, hard_bytes: 64 * 1024,
    max_batches: 8, max_findings: 128,
};
pub(super) const MIN_PARALLEL_FILE_BYTES: u64 = 256 * 1024;
#[derive(Clone, Copy)]
pub(super) struct LineBatch {
    pub start: usize, pub end: usize, pub first_line: u64, pub lines: u64,
}
pub(super) struct WavePlan {
    pub batches: [LineBatch; 8], pub len: usize,
}
pub(super) fn plan_wave(
    bytes: &[u8], first_line: u64, max_batches: usize, limits: BatchLimits,
) -> Result<WavePlan, ScanError>;
```

Only `batches[..len]` are valid. Descriptors own numeric locations, not secrets; no raw-byte `Debug`. `plan_wave` examines at most 256 KiB and caps the descriptor count at the minimum of the requested count, configured count, and eight.

- [ ] **Step 1: Write failing tests `wave_planner_obeys_exact_budgets`, `wave_planner_preserves_crlf_empty_and_incomplete_lines`, and `wave_planner_stops_before_oversized_lines_and_location_overflow`.** Assert production constants exactly, every nonempty descriptor ends at LF, spans are contiguous/nonoverlapping and <=64 KiB, `len <= 8`, and later `first_line` equals the previous descriptor's first line plus its LF count. With reduced limits `{ target_bytes: 4, hard_bytes: 8, max_batches: 8, max_findings: 128 }`, use `b"a\r\n\nlast"`: only the first four bytes are eligible, retaining CR. A nine-byte physical record stops planning before that record; no incomplete suffix is a batch. Two lines starting at `u64::MAX` return `CounterOverflow`; one representable line must not fail merely because an unused next line would overflow.

```rust
let limits = BatchLimits { target_bytes: 4, hard_bytes: 8, ..BATCH_LIMITS };
let plan = plan_wave(b"a\r\n\nlast", 10, 8, limits).unwrap();
assert_eq!(plan.len, 1);
let b = plan.batches[0];
assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 4, 10, 2));
assert!(matches!(plan_wave(b"a\nb\n", u64::MAX, 8, limits), Err(ScanError::CounterOverflow)));
assert!(plan_wave(b"a\n", u64::MAX, 8, limits).is_ok());
```
- [ ] **Step 2: Verify RED.** Run `cargo test --lib scanner::batch::tests::wave_`. Expect missing planner interfaces or incorrect boundary assertions.
- [ ] **Step 3: Implement `plan_wave`.** Greedily include complete records until the target is reached, close at LF, never cross the hard cap, and stop at the first unsuitable record. Ignore all dummy entries after `len`. Use the fixed descriptor array, not a line-offset vector or string splitting. Zero requested descriptors returns an empty plan.
- [ ] **Step 4: Verify GREEN.** Run `cargo test --lib scanner::batch::tests::wave_` and `cargo test --lib scanner::chunk_tests`. Include exact 32/64/256 KiB boundaries and a >10 MiB borrowed test input to prove inspection remains window-bounded.
- [ ] **Step 5: Commit.** Format/check Clippy and commit as `feat: plan bounded complete-line scan waves`.

## Task 3: Lease globally bounded scratch and prepare unpublished helper results

**Files:** Modify `src/scanner/batch.rs`, `tests/unit/batch.rs`; use Task 1's support module.

**Interfaces:** Consumes Task 1's `RecordContext/evaluate_record`, Task 2's descriptors/limits, and `engine::Limits`. Produces:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplayReason { Capacity, Counter }
pub(super) struct BatchDelta {
    pub attempted_lines: u64, pub completed_lines: u64,
    pub bytes: u64, pub suppressions: Suppressions,
}
pub(super) struct PreparedBatch {
    pub findings: Vec<Finding>, pub delta: BatchDelta,
    pub terminal: Option<ScanError>, pub replay: Option<ReplayReason>,
}
pub(super) struct HelperScratch { pub histogram: Histogram, pub result: PreparedBatch }
pub(super) struct HelperPool { /* short-lock available slots + atomic diagnostics */ }
pub(super) struct HelperLease<'a> { /* pool reference + exclusively owned scratch */ }
// HelperPool::new(workers: usize, limits: BatchLimits) -> Self
// HelperPool::try_acquire(&self) -> Option<HelperLease<'_>>
// HelperPool::snapshot(&self) -> BatchMetrics
// HelperLease::scratch_mut(&mut self) -> &mut HelperScratch
// HelperLease::drop returns cleared scratch only after the holder finishes publication.
pub(super) fn prepare_batch(
    bytes: &[u8], batch: LineBatch, context: RecordContext<'_>,
    limits: Limits, batch_limits: BatchLimits, scratch: &mut HelperScratch,
);
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchMetrics {
    pub waves: u64, pub helper_batches: u64,
    pub capacity_replays: u64, pub counter_replays: u64,
    pub no_slot_fallbacks: u64, pub peak_slots: usize,
}
pub struct ScanRun { pub outcome: ScanOutcome, pub batching: BatchMetrics }
```

`BatchMetrics` is observability only; never insert these fields into semantic `ScanStats`. Re-export `BatchMetrics`/`ScanRun` from `scanner` when used by public entry points. Atomics update once per scheduling/replay event, not once per token, and saturate rather than changing scan errors. All callers validate worker widths before `HelperPool::new`.

For deterministic concurrency tests, define test-only `BatchHooks` in `tests/unit/parallel_support.rs`: optional `Arc<dyn Fn() + Send + Sync>` `before_owner`, and optional `Arc<dyn Fn(u64) + Send + Sync>` `before_helper/after_helper` callbacks receiving the descriptor's first line. Add test-only `HelperPool::set_hooks(&mut self, hooks: BatchHooks)`, configured before sharing the arena. Invoke hooks outside bookkeeping locks at those named execution points. No global mutable hooks, sleep-based ordering, or production hook fields.

- [ ] **Step 1: Write failing lease tests.** `helper_leases_are_global_nonblocking_and_reusable`: `new(4, BATCH_LIMITS)` grants three leases, a fourth attempt returns `None`, dropping one restores one slot, peak slots never exceeds three, and `new(1, ...)` grants none. Move leases into scoped jobs to prove `Send`; retain a completed lease until a controlled publication signal to prove completion alone does not make its result capacity available. Exercise acquisition contention and nested acquisition without holding a bookkeeping lock over a barrier.

```rust
let helpers = HelperPool::new(4, BATCH_LIMITS);
let leases: Vec<_> = (0..3).map(|_| helpers.try_acquire().unwrap()).collect();
assert!(helpers.try_acquire().is_none());
assert_eq!(helpers.snapshot().peak_slots, 3);
drop(leases);
assert!(helpers.try_acquire().is_some());
assert!(HelperPool::new(1, BATCH_LIMITS).try_acquire().is_none());
```
- [ ] **Step 2: Write failing preparation tests.** `prepared_batches_match_serial_records_without_publication`, `prepared_batches_replay_at_129_without_losing_findings`, and `accepted_ignored_and_reused_batches_do_not_consume_capacity`. At 128 nonaccepted findings require a ready result; at 129 require `replay == Some(ReplayReason::Capacity)` and no publishable provisional state. For 129 accepted or ignored candidates require no capacity replay. Assert partial prior findings and attempted/completed-line/byte deltas for a later `LineLimit` error under reduced test `Limits`. Assert slots/results are cleared between uses and contain no raw token in `Debug`-capable report objects.

```rust
assert_eq!(ready_128.replay, None);
assert_eq!(ready_128.findings.len(), 128);
assert_eq!(overflow_129.replay, Some(ReplayReason::Capacity));
assert!(overflow_129.findings.is_empty());
assert_eq!(accepted_129.replay, None);
assert!(accepted_129.findings.is_empty());
assert_eq!(accepted_129.delta.suppressions.accepted, 129);
```
- [ ] **Step 3: Verify RED.** Run `cargo test --lib scanner::batch::tests::helper_` and `cargo test --lib scanner::batch::tests::prepared_`. Expect missing lease/preparation behavior.
- [ ] **Step 4: Implement global leasing and `prepare_batch`.** Use a small available-slot container with nonblocking admission (e.g. `Mutex::try_lock`); contention/full capacity returns `None`. Jobs receive owned leases, never thread-indexed mutable references. Preallocate only bounded slot result capacity; clear/reuse it on release. Stop evaluating subsequent records after replay or a terminal error. Registry callbacks cannot be interrupted directly: use a sticky capacity flag, never push the 129th finding, and discard the whole provisional result after that record finishes.
- [ ] **Step 5: Verify GREEN.** Run the two filtered suites and all `scanner::batch::tests`. Assertions must prove `findings.len()/capacity <= 128` per slot, slots <=width-1, and no external collector/emitter calls during preparation. Use reduced capacity in additional tests to cover all replay/error branches cheaply. Add `diagnostics_saturate_without_affecting_scan_results`, setting internal atomic counters to `u64::MAX` and asserting they remain at that value after another event without producing a scan error.
- [ ] **Step 6: Commit.** Format/check Clippy and commit as `feat: prepare scans with bounded leased helper state`.

## Task 4: Execute ordered waves and preserve file-fragment semantics

**Files:** Modify `src/scanner/batch.rs`, `src/scanner/engine.rs:103-163,437-465`, `tests/unit/batch.rs`, `tests/unit/engine.rs`.

**Interfaces:** Consumes Tasks 1–3 and existing `chunk::{ReadProgress, LineFragment, visit_line_fragments}`, `LineSession`. Produces:

```rust
pub(super) fn scan_serial_batch(
    bytes: &[u8], batch: LineBatch, context: RecordContext<'_>, limits: Limits,
    progress: &mut ReadProgress, line: &mut LineSession,
    outcome: &mut ScanOutcome, collector: &Mutex<Collector>,
    emitter: Option<&SharedEmitter>,
) -> Result<(), ScanError>;
pub(super) fn publish_batch(
    result: &mut PreparedBatch, batch: LineBatch, context: RecordContext<'_>,
    limits: Limits, progress: &mut ReadProgress, outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>, emitter: Option<&SharedEmitter>,
) -> Result<Option<ReplayReason>, ScanError>;
pub(super) fn execute_wave(
    bytes: &[u8], plan: &WavePlan, context: RecordContext<'_>, limits: Limits,
    batch_limits: BatchLimits, helpers: &HelperPool, progress: &mut ReadProgress,
    line: &mut LineSession, outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>, emitter: Option<&SharedEmitter>,
) -> Result<bool, ScanError>; // true: a capacity replay occurred
// Worker::file_with_batches has Worker::file's arguments plus
// batches: Option<(&HelperPool, BatchLimits)>; Worker::file delegates with None.
```

`publish_batch` returns `Ok(Some(reason))` before any mutation when replay is necessary; `Ok(None)` means committed. On a terminal error it commits only prior/failing-line effects that the serial path would retain and returns that error. `execute_wave` is called inside the scan's private `pool.install` context. `read_file_records_into` is a private engine function with `read_records_into`'s existing arguments plus `&HelperPool` and `BatchLimits`, returning `Result<(), ScanError>`; generic reader/Git APIs retain the original visitor. If H helpers are leased, execute only the leading H+1 descriptors; on zero helpers scan the first descriptor serially and return. The caller advances the underlying buffer by the actual `ReadProgress.bytes_read` delta, never the entire planned range.

- [ ] **Step 1: Write failing ordered-publication tests.** `wave_discards_later_results_after_owner_or_helper_failure`: reduce target/hard/line limits so three batches are small; use barriers/hooks to finish the last helper first. Assert no last-batch finding/suppression/error is published after the earlier failure, retain prior findings, count the failing attempted line when appropriate, and exclude its unconsumed bytes. Test both an owner failure and a helper failure. `wave_preserves_nonterminal_source_finding_limit`: lower `Limits.findings`, assert scanning continues, the retained set/counters match serial, and completion/error status matches baseline.
- [ ] **Step 2: Write failing replay/accounting tests.** `wave_replay_is_exactly_once_and_disables_future_dense_helpers`: use a two-worker/one-helper fixture, overflow staging, require complete serial-equivalent counts and output, capacity-replay metric increments once, and no further helpers for that file after the first capacity replay. In a multi-helper fixture, already-spawned helpers in that same wave may also need replay: resolve each once; disabling applies to future waves, not discarding valid current-wave records. `wave_counter_preflight_replays_without_partial_mutation`: initialize each outcome/progress counter near `u64::MAX`, including suppression counters; preflight must not mutate and serial replay must produce the same error/retained state as the original visitor. Include partial findings before a registry-returned error using a larger test-only hard batch and an oversized recognized candidate; production constants stay unchanged.

```rust
let before = semantic_key(&outcome);
let before_progress = (progress.bytes_read, progress.lines_scanned);
assert_eq!(publish_batch(&mut prepared, descriptor, context, limits, &mut progress,
    &mut outcome, &collector, None), Ok(Some(ReplayReason::Counter)));
assert_eq!(semantic_key(&outcome), before);
assert_eq!((progress.bytes_read, progress.lines_scanned), before_progress);
// After serial replay and Collector::finish:
assert_eq!(semantic_key(&replayed), semantic_key(&serial));
```
- [ ] **Step 3: Write failing file-driver equivalence tests.** `batched_file_fragments_match_serial_at_every_read_split`: use a test-only adapter calling the private driver with reduced batch limits and `BufReader` capacities `[1, 2, 7, 17, 4096, READ_BUFFER_BYTES]`. Compare `semantic_key` with the serial visitor on LF/CRLF, empty lines, invalid UTF-8, trailing ignores, accepted IDs, custom anchored/duplicate captures, an unterminated final line, and long lines between short lines. A faulting reader must retain completed lines, discard unfinished-line state, and return exit 2 with safe diagnostics. A short reader buffer is not EOF.
  Add `partially_granted_wave_consumes_only_its_resolved_prefix`: hold some global leases, plan eight descriptors, and assert exactly H+1 descriptors advance progress; scanning the remaining buffer must reproduce every original byte/line exactly once. After an early error, retain progress for completed records without consuming the failing/later records.
- [ ] **Step 4: Verify RED.** Run `cargo test --lib scanner::batch::tests::wave_` and `cargo test --lib scanner::engine::tests::batched_`. Expect missing execution/file integration or mismatched semantics.
- [ ] **Step 5: Implement serial replay, transactional preflight, and ordered execution.** Preflight all relevant aggregate additions plus the whole prospective descriptor range against progress counters before publishing. Conservative replay is preferable to partial mutation; use the existing serial visitor with a `Cursor` only over an LF-terminated batch. Preserve callback order within each batch; aggregate suppression/attempt counters; successful byte/line progress excludes the failing record. Lease only enough slots for ready later descriptors, spawn them in `rayon::scope`, scan the first descriptor on the owner, join all helpers, then resolve them in descriptor order. Release leases only after publication/discard; short-lock state must not span scope waits.
- [ ] **Step 6: Implement file-only acquisition.** At column 1 plan borrowed waves; otherwise emit the next bounded fragment into the existing `LineSession`. Maintain the visitor's checked-before-callback progress ordering, Interrupted retry, CR retention, genuine EOF handling, and abort-on-error behavior. Never pass an incomplete read-window tail through a `Cursor` visitor that would invent EOF. Do not inspect helpers while a line session is active. If a capacity replay occurs, set a per-file `helpers_enabled = false`; scarce slots alone do not permanently disable batching. Remove Task 2's temporary dead-code allowance.
- [ ] **Step 7: Verify GREEN and independence.** Run all batch/engine/chunk/stream unit suites and staged/worktree integration suites. Assert helpers can overlap owner work using a deterministic two-party barrier in a two-thread private pool; do not use sleep-based speed assertions. Ensure every scoped job joins on all tested error paths and state can be reused for another file.
- [ ] **Step 8: Commit.** Format/check strict Clippy and commit as `feat: execute file line batches with ordered publication`.

## Task 5: Share line helpers with the existing directory/glob pool

**Files:** Modify `src/scanner/scope.rs:115-137,203-283,348-365,541-600`, `src/scanner/mod.rs`, `tests/unit/scope.rs`.

**Interfaces:** Consumes `HelperPool`, `BATCH_LIMITS`, `Worker::file_with_batches`, existing `dynamic_claim`. Produces one optional helper arena on `Runner`, created with its existing private pool; and:

```rust
pub fn scan_directory_with_diagnostics(
    root: &ScopeRoot, selected: &Path, pattern: Option<&str>, registry: &Registry,
    options: ScopeOptions, emitter: Option<SharedEmitter>,
) -> ScanRun;
```

Preserve all existing public directory signatures and their `ScanOutcome` returns. A diagnostics-bearing internal run function may underlie them; keep test-only resource `Limits` injection. Re-export `BatchMetrics/ScanRun` from `scanner`; diagnostics are a release-benchmark seam, not extra mandatory terminal output.

- [ ] **Step 1: Write failing tests `few_large_files_use_helpers_in_the_same_private_pool`, `all_file_lanes_busy_never_wait_for_helpers`, and `helper_arena_tracks_lazy_pool_lifetime`.** Use 1/2/4 eligible files and worker widths `[1, 2, 4, 8]`; prove helpers start using the existing pool's `current_num_threads/current_thread_index` and test hooks. Assert `peak_slots <= workers - 1`, helpers are absent before pool admission, resource denial remains a clean serial fallback, and existing lazy-pool/count/byte-threshold tests retain their contracts. Update existing `Runner` test initializers for the new field.
- [ ] **Step 2: Write equivalence tests for large mixed scopes, glob exclusions and overflow.** Compare semantic keys to one-worker scans for ignores, tracked exceptions, binary exclusions, nested repositories, dense files and >10,000 global findings. Preserve the existing 300-file test's exact counts and completed-file semantics. Include concurrently owned files exhausting all slots; signal completion rather than using a barrier that needs more runnable jobs than pool capacity.

```rust
assert_eq!(semantic_key(&parallel.outcome), semantic_key(&serial.outcome));
assert!(parallel.batching.helper_batches > 0); // eligible one-file, four-worker fixture
assert!(parallel.batching.peak_slots <= 3);
assert_eq!(overflow.outcome.stats.findings_detected, 12_000);
assert_eq!(overflow.outcome.findings.len(), 10_000);
assert_eq!(overflow.outcome.stats.files_completed, 300);
```
- [ ] **Step 3: Verify RED.** Run `cargo test --lib scanner::scope::tests::helper_`, `cargo test --lib scanner::scope::tests::few_large_`, and `cargo test --lib scanner::scope::tests::all_file_`.
- [ ] **Step 4: Wire the shared arena and diagnostics entry point.** Build it only after successful pool creation. Pass a reference in `dynamic_claim`'s processing closure, preserve source assignment/discovery, and call `file_with_batches` only for metadata-eligible input. Never hold the arena lock across file processing. Snapshot diagnostics after all jobs finish; failures still return a `ScanOutcome` with the correct error. Pool construction errors must not be silently treated as resource fallback.
- [ ] **Step 5: Verify GREEN.** Run `cargo test --lib scanner::scope::tests`, `cargo test --test scope_cli`, and existing tracked-policy suites. At this point file CLI thread rejection is still expected; Task 6 changes that contract.
- [ ] **Step 6: Commit.** Format/check strict Clippy and commit as `feat: share line helpers across parallel scope scans`.

## Task 6: Enable configurable parallel single-file CLI scans

**Files:** Modify `src/scanner/engine.rs:192-228`, `src/cli.rs:20-22,229-245,275-283`; modify `tests/unit/engine.rs`, `tests/unit/cli.rs`, `tests/scope_cli.rs`, `README.md`.

**Interfaces:** Consumes shared helper execution, `execution::{resolve_threads, build_pool}`, and `ScanRun`. Produces:

```rust
#[derive(Clone, Copy)]
pub struct FileScanOptions { pub workers: usize }
pub fn scan_file_with_options(
    path: &Path, label: &Path, source_id: u32, registry: &Registry,
    options: FileScanOptions, emitter: Option<SharedEmitter>,
) -> ScanRun;
```

Keep `scan_file`, `scan_file_with_registry`, `scan_file_with_registry_and_emitter`, and both reader functions serial with unchanged signatures. Validate new options before attempting scanning; width 0/65 returns `ScopeLimit`. Default CLI thread resolution is shared with directory scans; an options-bearing file call lazily creates a private pool only for eligible files with width >1.

Use a private `scan_file_with_options_using_builder` with the public function's arguments plus `builder: impl FnOnce(usize) -> Result<rayon::ThreadPool, ScanError>`, returning `ScanRun`. The public function delegates with the existing `build_pool` wrapper; tests inject `Err(ScanError::Pool)` and verify the complete options-entry error path without relying on OS thread exhaustion. Serial wrappers still route through `Worker::file` with no helper arena.

- [ ] **Step 1: Write failing API tests.** `file_options_preserve_serial_wrappers_and_lazy_admission`: widths `[1, 2, 4]` give equal semantic outcomes; width 1 and sub-256-KiB input have zero helper metrics; an empty file completes with zero lines/bytes and no pool build; a large clean/sparse input admits helpers; widths 0/65 return exit 2 with `ScopeLimit`. Exercise injected pool-construction failure with the existing builder seam and require `Pool`, not successful fallback. Preserve missing-file, symlink and binary handling.
- [ ] **Step 2: Update executable contract tests deliberately.** Replace `directory_thread_option_is_supported_but_file_scope_rejects_it` and `thread_environment_only_applies_to_directory_scans_and_file_option_is_validated_early` in `tests/scope_cli.rs`, rather than deleting them. New assertions:

```rust
assert_eq!(run(&root, &["scan", "--threads", "2", "nested/key"]).status.code(), Some(1));
assert_eq!(run_with_threads_env(&root, &["scan", "input.txt"], Some("invalid")).status.code(), Some(2));
assert_eq!(run_with_threads_env(&root, &["scan", "--threads", "1", "input.txt"], Some("invalid")).status.code(), Some(0));
```

  Preserve redaction assertions. An excluded file with valid `--threads 2` is excluded/clean, not an unsupported-thread error; invalid thread values are still validated before exclusions. Keep missing/duplicate/0/65 thread-option tests, and keep `--staged/--diff` with `--threads` rejected. Test a large single file at 1/2/4 workers and compare parsed counters/IDs while ignoring elapsed time. Do not mutate process environment from multithreaded Rust unit tests; subprocess environment overrides are isolated.
- [ ] **Step 3: Verify RED.** Run `cargo test --test scope_cli` and `cargo test --lib scanner::engine::tests::file_options_`. Expect the old file rejection or missing options API.
- [ ] **Step 4: Implement the options entry point and CLI routing.** Resolve threads once for every supported file/directory scope. Use the shared emitter, current policy/exclusions/labels, and `.outcome` from the new run. Preserve staged/diff routing before file thread resolution and their explicit-threads rejection. Update help exactly to say `--threads applies to file, directory and glob scans (1-64)` and update the rejection diagnostic to `--threads is supported only for file, directory and glob scans`.
- [ ] **Step 5: Verify GREEN.** Run `cargo test --test scope_cli --test cli --test policy_cli --test accept_cli --test staged_cli --test worktree_cli --test hook_cli` and relevant engine/CLI unit tests. Verify old public serial calls retain their no-arena routing and equal the new one-worker outcome even on an eligible file; test the new diagnostic fields and invalid-width branches directly.
- [ ] **Step 6: Commit.** Format/check strict Clippy and commit as `feat: support shared-pool parallel single-file scans`.

## Task 7: Measure the experiment, enforce gates, and document actual results

**Files:** Create `scripts/line_batch_measure.py`, `tests/line_batch_measurement.py`, `benches/line_batches.rs`, `docs/research/parallel-line-batches-results.md`; modify `scripts/rss_launcher.c`, `Cargo.toml`, `benches/README.md`, `docs/technical-design.md`, and execution notes in `README.md`.

**Interfaces:** Consumes immutable baseline and both new diagnostics-bearing library APIs. Register `[[bench]] name = "line_batches", harness = false`. The Python harness uses these named seams:

```python
create_fixture(parent: Path, case: str) -> dict
measure_once(binary: Path, fixture: dict, threads: int | None) -> dict
compare_results(baseline: dict, candidate: dict) -> dict
```

`create_fixture` returns metadata only: selected path, mode (`file/directory/staged/diff`), known files/lines/bytes/findings/exit, and private synthetic leak needles. `measure_once` returns only safe metrics and counters. `compare_results` returns speedup, regression percentage, sample count and gate eligibility; unmatched workloads/cache/rules cannot be called a comparison.

Use case names `file_{clean,sparse}_{short,long}` for direct-file fixtures and `dir{1,2,4}_{clean,sparse}_{short,long}` for directory fixtures, plus `many_tiny`, `mixed`, `custom`, `dense`, `giant`, `staged`, and `diff`. Expand those combinations programmatically. Known policy files must be included in counts/bytes if they lie inside the selected scope; alternatively keep explicit benchmark configuration outside the selected scope. Git bytes count added payload only, excluding LF/framing. Baseline file cases run once per case with `threads=None`, and their serial result is reused for comparison with each candidate width; never pass explicit threads to staged/diff scans.

- [ ] **Step 1: Write failing measurement tests.** In `tests/line_batch_measurement.py`, test accounted fixtures, sample percentiles, invalid arguments, baseline-file argument compatibility, safe results, and accurate resource parsing. Generate cases for 1/2/4 files of exactly 50,000 lines with short code-like and longer assignment records, clean/sparse cases, plus many tiny/mixed/custom/dense/giant/staged/diff inputs. Sparse inserts replace existing records, retaining the intended line count. Explicitly assert 50,000 lines per large file, actual generated byte totals, and no returned source/report contents. A fake argument recorder must show baseline file scans omit `--threads`; candidate file scans use it; directory scans compare identical requested thread widths. Never infer observed helper activity from `min(threads, files)`.

```python
fixture = create_fixture(parent, "file_clean_short")
self.assertEqual(fixture["expected_lines"], 50_000)
self.assertEqual(fixture["expected_files"], 1)
self.assertEqual(fixture["selected"].stat().st_size, fixture["expected_bytes"])
self.assertNotIn("contents", fixture)
self.assertNotIn("--threads", recorded_baseline_file_args)
self.assertEqual(recorded_candidate_file_args[-2:], ["--threads", "4"])
self.assertGreaterEqual(comparison["speedup"], 1.5)  # synthetic 30-ms / 20-ms inputs
```
- [ ] **Step 2: Verify RED.** Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'line_batch_measurement.py'`. Expect missing harness/resource support or intended contract failures.
- [ ] **Step 3: Implement the native resource mode.** Add backward-compatible `--metrics` support to the RSS launcher: legacy invocation still writes one integer to fd 3; metrics mode writes JSON keys `peak_rss_native`, `user_seconds`, and `system_seconds`. In metrics mode the executable/argv starts after `--metrics`; preserve exit forwarding and Interrupted handling. Python converts Darwin's native bytes to KiB; Linux's native value is already KiB. Test both launcher modes, missing child, exit forwarding, and malformed metrics.
- [ ] **Step 4: Implement bounded fixtures and CLI measurement.** Reuse existing streaming stdout/stderr validation and percentile conventions instead of collecting dense reports. Invoke the native metrics mode and validate counters, exit status, and leak needles across chunk boundaries on both stdout and stderr. Add a ballast test proving Python's 96 MiB allocation is not counted as scanner RSS. Sparse records stay within the 10,000 retained-finding limit; the dense case may exceed it and must distinguish total detected from retained/output findings and exit 2 rather than assuming every detection is printed.
- [ ] **Step 5: Implement the release-library benchmark.** Use the two diagnostics-bearing APIs to exercise matching file/directory fixture classes at 1/2/4/8 workers, print aggregate counters/bytes and `BatchMetrics` only, and assert complete serial semantic equivalence before accepting timings. Use at least 15 samples and keep fixture generation out of timing. This companion establishes actual waves/helper/replay frequencies; label it separately from CLI timings, not as identical process-startup evidence. Don't change `ScanStats` or terminal output merely to expose metrics.
- [ ] **Step 6: Verify GREEN.** Build with `cargo build --locked --release`; run the new Python suite, `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'measurement_tools.py'`, and `cargo bench --bench line_batches`. The existing RSS-launcher users must still parse their original integer output.
- [ ] **Step 7: Run baseline/candidate measurements.** The new harness CLI accepts `--baseline`, `--candidate`, `--samples`, `--threads`, repeatable `--case`, and `--output`. Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/line_batch_measure.py --baseline /tmp/opencode/rayloc-line-batch-baseline --candidate target/release/rayloc --samples 15 --threads 1 2 4 8 --output /tmp/opencode/rayloc-line-batches-results.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/longline_measure.py --binary baseline=/tmp/opencode/rayloc-line-batch-baseline --binary candidate=target/release/rayloc --sizes-mib 1 5 10 64 256 --samples 15 --output /tmp/opencode/rayloc-line-batch-longlines.json
```

  Baseline direct-file runs are genuinely serial, irrespective of a candidate's requested width. Record hardware/CPU/OS/Rust/Git, both hashes, active policy, actual bytes, thread arguments/effective control, cache state, medians/p95, CPU and RSS. Keep fixture/rule/scope validation mandatory on every timed sample. Giant/staged/diff rows must not pretend batching was enabled. Do not use the older `e2e_measure.py` full-case assumptions uncritically: its giant-line exit and built-in-count descriptions are stale; use its tested primitives or the new fixtures with current literal expectations.
- [ ] **Step 8: Enforce gates and report, not speculate.** Compute `baseline_median / candidate_median` for the representative one-file clean/sparse four-worker cases, targeting >=1.5. Check candidate medians <=1.10 times their comparable baselines for tiny/multi-file/single-worker/staged/diff/giant/dense cases. If a gate fails, first inspect CPU utilization, helper/replay metrics, pool startup, and matching cost; tune only the spec-authorized internal batch settings and re-run correctness tests plus affected measurements. If the shared-pool approach still fails, stop and report before widening architecture or semantics. Record all final constants and unsuccessful measurements, not just the best case.
- [ ] **Step 9: Update documentation with measured behavior.** Document same-pool batching, serial APIs, file CLI threads/environment, giant-line/Git exclusions, dense fallback, bounded helper metadata, and measured memory. Keep historical research reports intact; replace only current execution statements in README/technical design/benchmark instructions. Store summarized results and safe reproducibility metadata in the research Markdown; do not commit raw fixtures, full reports, or scratch binaries.
- [ ] **Step 10: Run the full verification gates.** Expect every command to succeed and the strict report to show all production functions exercised:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo bench
cargo coverage
cargo llvm-cov --locked --workspace --all-features --ignore-filename-regex '(^|/)(tests|benches)/' --fail-under-functions 100 --fail-under-lines 97 --fail-under-regions 97
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'line_batch_measurement.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'measurement_tools.py'
git diff --check
```

  Install coverage tooling only if absent, using AGENTS.md's documented commands. If coverage or lint fails, add missing production-path tests or fix code; never hide a production module. Performance gates need their own evidence in addition to these commands.
- [ ] **Step 11: Commit and hand off for review.** Commit only Task 7's files and any justified constant tuning as `perf: validate bounded parallel line batch scanning`. Use verification-before-completion and requesting-code-review; report measured gates, limitations, redaction/equivalence results, and the exact remaining risks. Follow the user-selected execution method; do not merge or push without authorization.

## Executor Completion Checklist

- [ ] Every task's RED/GREEN evidence and focused commits recorded; no unexplained changes to recognizers or Git behavior.
- [ ] All five Review Focus conditions covered by the named tests; helper caps and input lifetime proven, not inferred from memory usage.
- [ ] All existing public serial signatures preserved and new public entry points exercised by tests.
- [ ] Exact semantic keys agree for serial/parallel fixtures, including failures and counters; no raw-secret output or unsafe diagnostic formatting.
- [ ] Benchmark gates evaluated on immutable comparable binaries; no startup/cache/thread mismatch presented as a speedup.
- [ ] Formatting, Clippy, tests, benches, alias coverage and stricter coverage gates pass with fresh evidence.
- [ ] Written results distinguish an achieved improvement from an unmet target; no claim that extra threads accelerate a single giant physical line.

## Execution Handoff

The written spec is approved; this plan still needs user review and an execution-method choice. Do not implement merely because the plan exists.

- **Subagent-driven (recommended):** fresh implementer and reviewer per task, followed by whole-branch review. The shared scratch/publication interfaces and secret-scanner failure semantics justify the additional review cost.
- **Native:** one agent executes the sequential tasks in this session, followed by an independent whole-branch review. Less context/review overhead, but no independent gate between tasks.
