# Stream Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task; use superpowers:subagent-driven-development only if that execution method is selected. Steps use checkbox (`- [ ]`) syntax for tracking. The user approved implementation.

**Goal:** Add `rayloc redact` for stdin, an explicit file, and an optional child command while keeping data streams free of Rayloc messages.

**Architecture:** A bounded byte-record filter reuses the immutable detector registry, merges sensitive intervals and writes replacement bytes. File and stdin modes share that filter; command mode applies it concurrently to enabled child channels, inheriting disabled channels unchanged. An independent secure report writer receives aggregate outcomes only.

**Tech Stack:** Rust 2024/MSRV 1.85, standard-library I/O/processes/threads, existing detector/configuration modules, stdlib Python for measurements. No new runtime dependencies.

**Spec:** [Stream redaction design](../specs/2026-10-28-stream-redaction-design.md).

## Execution status

The stdin, file and command modes, report summaries, private-key block masking,
and core regression tests are implemented in `feat/stream-redaction`. The full
test suite, formatting, Clippy, MSRV tests, benchmark, and the repository's
95%/95%/98% coverage alias have passed on intermediate revisions. The stricter
97% lines/regions and 100% functions gate has not yet passed. Fault-injection
coverage, repeat performance qualification, and final verification remain open.

## Global Constraints

- Rust edition 2024; minimum Rust version 1.85. Target Linux and macOS.
- Add no runtime dependencies or network calls.
- Compile policy regexes once per process and share immutable policy between channels.
- Never load an entire input into memory; memory must be independent of stream length.
- Reader buffer: 256 KiB per filtered channel. Maximum physical-line payload: 1,048,576 bytes excluding LF, including a trailing CR when present.
- Preserve the existing 65,536-byte candidate limit and 10,000-match per-line limit.
- Require at least 97% production line and region coverage and 100% function coverage.
- Preserve existing scan, preview, accept, hook, Git diff, and reporting behavior.
- Never print detected secret bytes on an enabled channel or in Rayloc diagnostics. Explicitly disabled channels intentionally pass raw producer output unchanged.

Keep the proposed decisions in the spec visible during review: command name,
wrapper-only channel flags, record latency/limit, full PEM masking, secure report
naming, and 0/1/2 status including mapping an unsuccessful child to 2.

## Review Focus

1. A read boundary or overlapping match must never release a credential prefix/suffix; test every token split, overlapping captures and detector errors after earlier callbacks (Task 1).
2. Private-key headers alone are insufficient protection; test all six labels, body lines, closing suffixes and unfinished blocks independently per channel (Tasks 2 and 5).
3. A paused producer, stderr lock or a full second pipe must not hang ordinary processing; test pre-EOF delivery, idle channels, asymmetric EOF and simultaneous large writes with deadlines (Tasks 4 and 5).
4. A disabled channel is unmodified producer data, not discarded data or a clean scan; test all four boolean combinations with redirects and actual secrets on disabled channels (Task 5).
5. Explicit file input must match piped input without using stdin or modifying the file; test native paths, policy location, >10 MiB input and failure-only reports (Task 4).

## File map and dependency order

| Path | Change and responsibility |
| --- | --- |
| `src/lib.rs` | Register private `redact` module |
| `src/redact/mod.rs` | New fixed error categories, checked statistics and run outcomes |
| `src/redact/filter.rs` | New record reader/filter, interval union, write accounting |
| `src/redact/pem.rs` | New private-key interval state |
| `src/redact/report.rs` | New secure report file and summary writer |
| `src/redact/cli.rs` | New parser, policy setup, stdio/file dispatch |
| `src/redact/command.rs` | New child lifecycle and two concurrent channels |
| `src/rules/builtin.rs` | Share existing private-key labels without changing detection |
| `src/rules/mod.rs` | Add a private-key-enabled registry accessor for the filter |
| `src/cli.rs` | Help text and early redact dispatch before acquiring stderr lock |
| `tests/unit/redact_filter.rs`, `tests/unit/redact_pem.rs` | New pure/filter state tests |
| `tests/unit/redact_report.rs`, `tests/unit/redact_cli.rs`, `tests/unit/redact_command.rs` | New report/parser/coordination tests |
| `tests/redact_cli.rs`, `tests/redact_command_cli.rs` | New real executable and Unix routing tests |
| `tests/unit/builtin.rs` | Regression assertions for shared marker definitions |
| `scripts/measure_redaction.py`, `tests/redaction_measurement_tools.py` | New reproducible measurement harness and bookkeeping tests |
| `docs/research/stream-redaction-results.md` | New aggregate qualification evidence |
| `README.md`, `tests/README.md`, `benches/README.md` | Usage, failure/status semantics and validation instructions |

Execute **1 → 2 → 3 → 4 → 5 → 6**. Tasks 1–3 produce independently testable
internal components; Task 4 exposes the complete stdio/file vertical slice;
Task 5 adds command capture; Task 6 qualifies the finished feature. Do not create
a new public API to let benchmarks call private internals.

## Preparation

- [ ] Read the reviewed spec and this plan; obtain design approval before product edits. Preserve the latest user addition: positional file mode is required.
- [ ] Inspect `git status --short`, applicable `AGENTS.md`, current revision and policy. Preserve the unrelated untracked `game.html` present during planning. Use the git-workflow/worktree skills at execution time if isolation is needed; do not overwrite existing work.
- [ ] Run `cargo test --all` and `cargo bench` on the unchanged source. Build `cargo build --locked --release`; preserve its executable and SHA-256 under `target/redaction-baseline/` before rebuilding. Record compiler/OS/CPU, effective policy, binary size and benchmark results.
- [ ] Record the coverage mismatch: `cargo coverage` currently gates 95/95/98, while this spec requires 97/97/100. Run the stricter command in Task 6; do not weaken checks or exclude production code.

## Shared interfaces

Keep these types internal to `crate::redact`. They define task boundaries, not
new public library contracts. Safe `Debug` output is permitted only for counters,
fixed categories and OS-independent enums; never derive it for raw input/options.

```rust
pub(crate) enum Mode { Stdio, File, Command, Invalid }
pub(crate) enum Source { Stdin, File, Stdout, Stderr }
pub(crate) enum RedactError {
    Arguments, Policy, Open, NotRegularFile, Read, Write, Flush,
    LineLimit, Detection, InvalidSpan, CounterOverflow, UnterminatedKey,
    ReportCreate, ReportWrite, Spawn, Wait, Worker,
}
pub(crate) struct Stats {
    pub bytes_read: u64, pub bytes_written: u64, pub records: u64,
    pub detections: u64, pub redactions: u64,
    pub private_key_blocks: u64, pub unterminated_blocks: u64,
}
pub(crate) struct FilterOutcome {
    pub stats: Stats, pub error: Option<RedactError>,
}
pub(crate) enum ChildResult { Exited(i32), Signalled(i32), Unavailable }
pub(crate) struct SourceSummary {
    pub source: Source,
    pub outcome: Option<FilterOutcome>, // None = deliberately inherited/passthrough
}
pub(crate) struct RunSummary {
    pub mode: Mode, pub sources: Vec<SourceSummary>, // at most two
    pub child: Option<ChildResult>, pub error: Option<RedactError>,
    pub elapsed: std::time::Duration,
}
impl FilterOutcome { pub(crate) fn exit_code(&self) -> u8; }
impl RunSummary { pub(crate) fn exit_code(&self) -> u8; }
```

All counter increments are checked. Map detector and OS errors into fixed
categories, never `error.to_string()`. A failed record contributes bytes actually
read/written but not a successfully processed record. `detections` counts emitted
detector spans before union; `redactions` counts written merged sensitive intervals,
including PEM body intervals. Keep partial failure counts honest. A report write
failure overrides the computed run exit code to 2.

### Task 1: Build the bounded, byte-preserving filter

**Files:** Create `src/redact/mod.rs`, `src/redact/filter.rs`,
`tests/unit/redact_filter.rs`; modify `src/lib.rs`.

**Interfaces:**

- Consume existing `Registry::detect_line`, `Histogram`, and fixed scanner errors.
- Produce the shared types above, `FilterOutcome::exit_code`, and:

```rust
pub(crate) const MAX_RECORD_BYTES: usize = 1_048_576;
pub(crate) fn filter(
    input: &mut dyn std::io::BufRead,
    output: &mut dyn std::io::Write,
    registry: &crate::rules::Registry,
) -> FilterOutcome;
```

- [ ] Write `clean_bytes_round_trip_exactly`: empty input, empty lines, LF/CRLF, Unicode, invalid UTF-8, NUL, lone CR, trailing spaces and missing final LF all satisfy `output == input`, status 0 and exact byte/record counts.
- [ ] Write `captures_merge_without_releasing_unchecked_records`: construct synthetic custom rules with overlapping/adjacent capture spans; assert the specified union replacements, retained punctuation and status 1. Trigger a detector error after a callback and assert none of that record was emitted. Never put genuine credentials in fixtures.
- [ ] Write `every_read_split_has_identical_redaction`: a short-chunk reader splits a synthetic supported token at every byte; compare with one-read output. Also split CRLF and the EOF boundary.
- [ ] Write `record_and_lifetime_limits_are_distinct`: exactly 1,048,576 payload bytes succeed; one extra fails with no bytes from that record. Test 65,536-byte candidate boundaries, per-record match overflow, injected invalid span, interrupted reads, partial writes, broken pipe, flush/read errors and checked counter overflow. Stream >10,000 separate matching records successfully.
- [ ] Run `cargo test --lib redact_filter`; expect the newly referenced filter/types to be missing before implementation.
- [ ] Implement bounded `fill_buf`/`consume` accumulation, retaining LF/CRLF separately for detection/output. Detect the whole record before any output; validate and sort/union spans. Write original slices and `[REDACTED]` directly without a second whole-record output copy. Flush per completed record/EOF; return partial safe counters on failures.
- [ ] Ensure no unbounded findings collector, lossy conversion, binary skip or regex compilation occurs in the loop. Keep the 256 KiB buffer at the input-owner boundary; unit readers can use smaller capacities.
- [ ] Run `cargo test --lib redact_filter` and `cargo test --lib registry`; expect all pass. Inspect the diff and commit this tested component with a focused message.

### Task 2: Extend sensitive intervals across private-key blocks

**Files:** Create `src/redact/pem.rs`, `tests/unit/redact_pem.rs`; modify
`src/redact/filter.rs`, `src/rules/builtin.rs`, `src/rules/mod.rs`,
`tests/unit/builtin.rs`, `tests/unit/registry.rs`.

**Interfaces:**

- Consume Task 1's record filter and interval merging.
- Produce `PemState::new()`, a per-record operation returning sensitive ranges,
  `Registry::private_key_enabled(&self) -> bool`, and an EOF operation identifying an
  unfinished block. Use byte ranges relative to the current record only:

```rust
pub(crate) struct PemState { /* current label, no retained body */ }
pub(crate) struct PemRecord {
    pub sensitive: Vec<std::ops::Range<usize>>,
    pub blocks_started: u64,
}
impl PemState {
    pub(crate) fn new() -> Self;
    pub(crate) fn record(
        &mut self, content: &[u8], enabled: bool,
    ) -> Result<PemRecord, RedactError>;
    pub(crate) fn unfinished(&self) -> bool;
}
```

Keep per-record vectors bounded by record size and the same match budget; return
an error for too many markers before releasing the record rather than silently
truncating ranges.

- [ ] Write `all_six_private_labels_hide_body_and_preserve_terminators`: generate begin/end pairs from shared labels and assert no body bytes survive; LF/CRLF/empty body lines retain their original boundaries. Public-key and certificate input stays unchanged.
- [ ] Write `same_line_blocks_keep_visible_prefix_and_suffix`: cover same-line close, multiple blocks, a second ordinary secret after a close, split reads, nested and mismatched markers. Assert one state never ends on a different label.
- [ ] Write `unfinished_key_masks_through_eof_and_fails`: no closing marker yields status 2, masked remainder and one unfinished-block count. Disabled marker policy yields ordinary detector behavior without entering PEM state.
- [ ] Run `cargo test --lib redact_pem`; expect missing module/state before implementation.
- [ ] Share the existing private-key label/marker definition at crate visibility and add `Registry::private_key_enabled`. Keep the builtin rule's existing marker-only results unchanged; avoid constructing/compiling patterns in loops. Implement per-record PEM intervals without storing the full block; test the accessor for default and disabled policy.
- [ ] Integrate state into `filter`: detect ordinary secrets on the original complete record, merge those spans with PEM intervals, and count private-key blocks. Skip ordinary detection only when the entire content is already covered by a PEM interval. Do not run regexes on sliced visible segments: that would change anchor/context semantics. Test an anchored custom rule spanning a PEM boundary and a detector-limit failure on a partially covered record; the latter must withhold the whole record.
- [ ] Run `cargo test --lib redact_pem`, `cargo test --lib redact_filter`, `cargo test --lib builtin` and `cargo test --lib registry`; expect all pass, including marker-only scan regressions. Review and commit.

### Task 3: Add secure, bounded report files

**Files:** Create `src/redact/report.rs`, `tests/unit/redact_report.rs`;
modify `src/redact/mod.rs` for run-level status aggregation.

**Interfaces:**

- Consume `RunSummary`, fixed categories and safe counters from Task 1.
- Produce `RunSummary::exit_code()` and:

```rust
pub(crate) struct Report { /* owned file, safe timing/identity metadata */ }
impl Report {
    pub(crate) fn create() -> Result<Self, RedactError>;
    pub(crate) fn finish(&mut self, summary: &RunSummary) -> Result<(), RedactError>;
}
```

Private construction/writer helpers accept deterministic time, PID and directory
or injected failing writers for tests. No user-visible report path option.

- [ ] Write `exclusive_creation_is_private_and_collision_safe`: assert `/tmp` naming shape, mode `0600`, distinct simultaneous reports, existing files/symlinks unchanged, and error after 64 occupied names. Use an injected temporary directory for collision tests.
- [ ] Write `reports_are_aggregate_and_never_contain_source_metadata`: check initial `status=running`, final per-source fields for all three modes, passthrough unknown counts, child code/signal, timestamps and 0/1/2 precedence. Assert no source bytes, token previews, paths, arguments, arbitrary custom names or injected OS diagnostic text appear.
- [ ] Write `report_failures_cannot_be_success`: initial create/header failure and final write/flush failure return fixed errors. An unfinished report has no final-success row.
- [ ] Run `cargo test --lib redact_report`; expect missing report implementation.
- [ ] Implement `create_new` + Unix `OpenOptionsExt::mode(0o600)`, timestamp/PID/collision naming, initial header flush and bounded final summaries. Do not use `TMPDIR` or the terminal emitter. `RunSummary::exit_code` gives errors/nonzero child priority over redactions; both disabled plus successful child is 0.
- [ ] Run `cargo test --lib redact_report` and `cargo test --lib redact_filter`; expect all pass. Review and commit.

### Task 4: Ship stdin and explicit-file CLI modes

**Files:** Create `src/redact/cli.rs`, `tests/unit/redact_cli.rs`,
`tests/redact_cli.rs`; modify `src/cli.rs`, `src/redact/mod.rs`, `README.md`.

**Interfaces:**

- Consume `filter`, `Report`, existing `config::discover_root`/`config::load` and
  `Registry::compile`. Set `inline_ignores = false`; do not run file acceptance.
- Produce OS-native argument parsing and shared setup, including command-shaped
  options needed by Task 5:

```rust
pub(crate) enum Input {
    Stdin, File(std::path::PathBuf),
    Command { program: std::ffi::OsString, args: Vec<std::ffi::OsString>,
              stdout: bool, stderr: bool },
}
pub(crate) struct Options { pub config: Option<std::path::PathBuf>, pub input: Input }
pub(crate) enum Action { Help, Run(Options) }
pub(crate) fn parse(args: &[std::ffi::OsString]) -> Result<Action, RedactError>;
pub(crate) fn run(args: Vec<std::ffi::OsString>) -> u8;
```

- [ ] Write parser table tests for all valid forms in the spec and invalid duplicate/missing flags, channel flags without a command, multiple files, file+command conflicts and missing programs. After `--`, preserve every native child argument verbatim. Help is accepted only alone and creates no report.
- [ ] Write executable tests comparing `redact file` against piping the same bytes from the same working directory: output/status/content counters match, source contents/permissions stay unchanged, stdin is unused, and stderr is empty. Cover spaces, Unix non-UTF-8 paths, symlinks, no final LF, invalid bytes, >10 MiB generated file, unreadable/missing files, directory and FIFO rejection before opening. Privileged test runners must use an injected open failure for the unreadable branch.
- [ ] Add policy tests: defaults outside Git without a Git executable; root policy plus explicit overlay; identical CWD policy for stdin/file despite a different file parent; malformed policy returns 2 before reads; inline ignore and accepted IDs cannot bypass streams; disabled/custom/entropy policies retain documented semantics.
- [ ] Add a deadline-based test with a live producer: a complete short line is visible before EOF, an incomplete token is withheld until LF/EOF, and the final output is exact. Add argument/config/open failures whose sensitive strings occur in neither data channel nor report.
- [ ] Run `cargo test --test redact_cli` and `cargo test --lib redact_cli`; expect missing dispatch/parser before implementation.
- [ ] Integrate an early `redact` dispatch in `cli::run` before the existing stderr lock is acquired. Keep existing `run_with_args`/scan behaviors intact. Add the command to top-level help and a dedicated redact help string with literal examples.
- [ ] Implement strict parsing and file/stdio execution. Exact help returns directly; all other redact invocations attempt a report before validating/reading/starting data. Open only readable regular files, follow regular-file symlinks, use a 256 KiB `BufReader`, and feed both input modes through the same filter. Generate one bounded summary and return 2 on report finalization failure. Never invoke the terminal emitter or echo input-derived errors.
- [ ] Add README examples for stdin/file/process substitution and line latency. Document flags as command-only and file mode as output-to-stdout, with no source rewrite. Command-mode parsing may exist internally, but do not advertise wrapper execution until Task 5 wires it; if exercised early, return a fixed report-only execution error.
- [ ] Run the new suites and `cargo test --test cli --test policy_cli --test scope_cli`; expect no regressions. Verify generated reports for only the test PIDs and clean up only those reports. Review and commit.

### Task 5: Capture child channels without merging them

**Files:** Create `src/redact/command.rs`, `tests/unit/redact_command.rs`,
`tests/redact_command_cli.rs`; modify `src/redact/cli.rs`, `src/redact/mod.rs`,
`README.md`.

**Interfaces:**

- Consume parsed command inputs, immutable registry, `filter`, and run summaries.
- Produce:

```rust
pub(crate) fn capture(
    program: &std::ffi::OsStr, args: &[std::ffi::OsString],
    stdout: bool, stderr: bool, registry: &crate::rules::Registry,
) -> RunSummary;
```

Create the report/load policy in the caller before `capture`. Inherit command
stdin/environment/CWD. Keep the child handle on the coordinator thread; pass
only enabled pipe readers and their corresponding output handles to workers.

- [ ] Write `all_channel_flag_combinations_preserve_destinations`: a synthetic child writes distinct supported secrets to both outputs. For every boolean pair, enabled streams are masked, disabled streams are byte-identical, no channel is discarded/swapped, report passthrough counts are unknown, and only enabled redactions affect finding status.
- [ ] Write `concurrent_channels_complete_without_lock_deadlocks`: generate simultaneous stdout/stderr writes larger than pipe capacity, idle stderr with active stdout and the reverse, early EOF on either stream, >10,000 matches and PEM state confined to one channel. Use test deadlines with kill/reap on timeout rather than hanging CI.
- [ ] Write `child_lifecycle_is_observable_and_safe`: verify inherited stdin/CWD/environment, OS-native arguments including a literal `--`, direct execution with no shell interpretation, nonzero/signal exits reported as 2 after draining output, spawn/wait failure and absent child on argument/policy/report-create failure. Report paths/arguments must remain absent.
- [ ] Write injected worker/write/flush failures where the direct child remains running. Assert the coordinator notices promptly, kills/reaps it, joins workers, preserves safe earlier output and returns 2 without deadlocking. Test the two-disabled case with no filter threads.
- [ ] Run `cargo test --test redact_command_cli` and `cargo test --lib redact_command`; expect missing capture integration.
- [ ] Implement concurrent workers with a bounded completion/error notification channel and coordinator polling of both worker events and `child.try_wait()`. Do not block in `child.wait()` before errors can be observed. One failure stops the child; normal exit drains both outputs. Cleanup assumes downstream writes can progress, as specified; killing the child cannot interrupt a worker blocked on a stalled output sink. Convert worker panic/join failure into a fixed error without invoking source-bearing diagnostics; avoid worker code paths that panic.
- [ ] Wire command dispatch and document one-process command examples, 0/1/2 status, numeric child status in reports, inherited stdin and process-supervision non-goals. Disabled channels use direct `Stdio::inherit()`, not a raw-copy worker.
- [ ] Run both new suites plus `cargo test --test redact_cli --test cli`; expect all pass. Review and commit.

### Task 6: Qualify shell composition, performance and coverage

**Files:** Extend `tests/redact_cli.rs`, `tests/redact_command_cli.rs`;
create `scripts/measure_redaction.py`, `tests/redaction_measurement_tools.py`,
`docs/research/stream-redaction-results.md`; update `tests/README.md`,
`benches/README.md`, `README.md` and this plan's checkboxes.

**Interfaces:** Consume the release CLI and frozen baseline from Preparation.
No new production API or dependency is produced.

- [ ] Add a Bash integration test running the documented two substitutions with explicit waits for both substitution processes, capturing their statuses and both destinations. Assert two reports, separate redacted outputs and independent completion. Add `2>&1 | rayloc redact` coverage showing all content is on stdout and no artificial channel labels are invented.
- [ ] Add a generated source beyond 10 MiB with bounded line lengths and >10,000 detections. Cover file and stdin with identical expected bytes using incremental comparisons/hashes; assert no retained findings cap and no whole-input allocation in production. Keep expected output computation independent of the implementation's interval algorithm.
- [ ] Write bookkeeping tests for the stdlib measurement harness: input-size accounting, exit 1 as successful redaction rather than failed measurement, nonzero child status, output digest validation and RSS units (Linux KiB versus macOS bytes). Run `python3 -m unittest discover -s tests -p redaction_measurement_tools.py` before/after the harness implementation.
- [ ] Implement the harness with reproducible generated clean/secret-dense fixtures and common CWD/policy; send payload output to validated files or draining readers. Measure 16 MiB and 128 MiB stdin/file runs, two active child channels, release startup/record latency, throughput and Rayloc peak RSS. Use repeated samples and label hardware, sample counts and direct-process versus child memory correctly. Keep raw synthetic streams and reports under `target/` or owned temporary files, not research docs.
- [ ] Compare existing scanner benchmark results against the immutable pre-change baseline and report measured redaction costs separately. Inspect RSS scaling for the two sizes at identical record length and policy; investigate any growth proportional to total input. Record limits and observed latency honestly, not an unsupported speed guarantee.
- [ ] Run the complete required checks below. All must pass; inspect numeric coverage from the final stricter command. Fix meaningful missing production/error-path coverage without excluding code, skipping assertions, raising limits to bypass tests or weakening existing checks.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo bench
cargo coverage
cargo llvm-cov --locked --workspace --all-features --ignore-filename-regex '(^|/)(tests|benches)/' --fail-under-functions 100 --fail-under-lines 97 --fail-under-regions 97
```

- [ ] Review every spec acceptance item against its executable test and measurement. Check exact stdout/stderr bytes, report secrecy, bounded buffers, all three modes, partial-record behavior, errors and disabled-channel exceptions. Run `git diff --check` and inspect only this feature's changed files.
- [ ] Write aggregate qualification results and limitations; link them from tests/benchmark docs. Update README to describe the completed three modes and report location. Commit the reviewed feature evidence; do not merge, release or deploy without the user's separate instruction.

## Handoff

The user approved the design and plan and requested implementation. The tasks
share filter/report contracts; verification remains required before completion.
