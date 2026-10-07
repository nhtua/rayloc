# Bounded parallel line batches

Status: proposal for written review; implementation is not yet authorized.
Source baseline: `8662919` on `main`, inspected 2026-10-06.

## Intent and scope

The user identified file-level parallelism as a potential bottleneck when a scan
contains only a few files with roughly 40,000–50,000 lines each. They selected
bounded batches of complete lines in the existing Rayon pool as the first
approach to try, retaining parallel multi-file scanning.

The goal is improved CPU-bound throughput for a few large, many-line files, not
a guaranteed speedup based on line count alone. Detection results, source
locations, acceptance IDs, redaction, error behavior, and bounded memory remain
mandatory. This is an architectural experiment with a benchmark acceptance gate.

Included:

- CLI file, directory, and glob scans.
- Complete-line batch detection using the same private pool as file detection.
- Serial fallback for small inputs, scarce helper resources, dense results,
  incomplete lines, and individual lines unsuitable for batching.
- Tests, reproducible measurements, and documentation of the execution model.

Excluded:

- Parallelizing fragments of one physical line.
- Changing staged/diff scanning, Git acquisition, or patch parsing.
- Async runtimes, producer/consumer channels, extra reader threads, whole-file
  loading, memory mapping, new dependencies, and changes to secret recognizers.
- Prefix dispatch optimizations in `builtin::match_at()`.

## Current architecture

`scope::Runner::flush()` dynamically assigns file jobs to reusable `Worker`
instances using `execution::dynamic_claim()`. A claimed file stays with one
worker until completion. The private Rayon pool is admitted lazily according to
the existing file-count and estimated-byte thresholds.

Each worker owns a 256 KiB read buffer, a `LineSession`, and a histogram.
`chunk::visit_line_fragments()` reads borrowed fragments in source order.
`LineSession::push()` runs complete-line detection directly for ordinary lines
and retains bounded streaming state for longer lines. State resets at each real
LF/EOF, so distinct complete physical lines are independent.

`engine::detect_record()` calls the registry and immediately publishes findings
to the collector/emitter. That immediate publication is not safe for speculative
later batches: an earlier batch may still fail. Explicit-file CLI scans currently
use one worker and reject `--threads`.

The earlier byte-chunk design deliberately deferred intra-file parallelism. This
proposal adds it without replacing the established giant-line streaming path.

## Selected approach

Use scoped, borrowed-buffer waves. A file owner lends bounded complete-line runs
from its existing read buffer to helper jobs. Jobs execute within the current
private Rayon pool; no file creates another pool. The owner scans the first
batch serially while helpers evaluate later batches, joins the wave, then
publishes helper results in source order before advancing/reusing the reader
buffer. It must not publish any later owner work ahead of an unresolved earlier
helper batch.

Rayon supports nested operations in the current pool and work stealing. This
makes unused file-scanning capacity available to line-batch jobs without adding
OS threads. It does not make resource ownership or publication order automatic;
those remain explicit scanner responsibilities.

### Initial scheduling constants

These are internal trial settings, not additional CLI flags:

| Setting | Initial value |
| --- | --- |
| Existing read window | 256 KiB, unchanged |
| File size hint for helper admission | At least 256 KiB |
| Target complete-line batch size | 32 KiB |
| Hard complete-line batch size | 64 KiB, including LF bytes |
| Maximum descriptors in a borrowed wave | 8 |
| Minimum useful wave | At least 2 eligible batches and 1 helper slot |
| Helper slots across the scan | At most `workers - 1` |
| Provisional findings per helper slot | 128 |

File metadata is only a scheduling hint; actual verified reads determine scan
coverage, counters, and completion. A failed helper admission uses the serial
path, not a scan error. Thresholds may be adjusted based on the specified
benchmarks, with final values recorded in the measurement report.

### Global helper ownership

One scan-scoped batch executor owns reusable helper slots alongside its private
pool. A slot contains exclusive histogram/scratch state and bounded provisional
result storage. Slots are leased nonblockingly before spawning jobs and returned
only after their results are published or discarded.

The maximum slot count is based on the configured pool width, not on the number
of files. No per-file helper arena is created. No waiting for helper capacity is
allowed inside the Rayon pool: if slots are unavailable, the file owner scans
serially. Short bookkeeping locks must not be held during matching, spawning,
joining, publication, or output. A pool-construction failure remains the existing
execution error; helper-capacity fallback must not mask it.

Reserve only slots that have eligible work. The owner participates in scanning
and need not reserve a slot for its normal serial state. If only some slots are
available, expose fewer batches and leave the remainder for subsequent visits.
Nested execution must not obtain mutable scratch by indexing the current Rayon
thread: jobs own their leases, including during work stealing and reentrancy.

## Acquisition and batch boundaries

Add a file-only batch-aware acquisition path. Keep the existing generic fragment
visitor and Git paths available unchanged.

1. Finish any physical line already in progress through `LineSession`.
2. At a real line boundary, inspect at most the existing read-window budget.
3. Find leading LF-terminated complete lines and partition a bounded run into
   batches, each carrying a borrowed byte range and its original first line.
4. Preserve line bytes exactly: remove LF for detection, retain CR, and never
   decode the payload as UTF-8.
5. Run the owner batch and scoped helper jobs. Do not consume/refill the borrowed
   reader buffer until all jobs are joined and their outcomes are resolved.
6. Feed any incomplete or unbatched remainder through the established path.

Batch boundaries occur only between physical lines. A line larger than the hard
batch budget is scanned serially; a line crossing a reader boundary continues
through the existing streaming session. Never grow a batch indefinitely while
searching for LF. The final unterminated line is finalized only at real EOF.
Empty lines count as physical lines; a trailing LF does not invent another line.

Descriptors represent batches, not every line in the file. Helpers enumerate
lines within their borrowed ranges using checked location arithmetic. No
per-line `String`, raw-value copy, or whole-file line index is introduced.

## Detection and publication

Keep `Registry::detect_line_with_suppressions()` and the recognizers unchanged.
Extract only the shared record preparation/publication responsibilities needed
to avoid duplicating rule priority, accepted-ID filtering, and redaction logic.
Existing serial entry points retain their behavior.

A helper:

- Evaluates its complete lines in source order using exclusive histogram state.
- Preserves built-in, JOSE, context, and custom-rule priority and span dedup.
- Calculates acceptance IDs from the original path and complete captured value.
- Immediately converts recorded values to `RedactedString`.
- Returns bounded redacted findings, aggregate local counters, successful-byte
  progress, and its first terminal detection error if any.
- Never writes to the global collector, emitter, or file outcome directly.

Prepared batches do not retain raw captured secrets. Borrowed input descriptors
must not derive raw-byte `Debug` output or appear in diagnostic messages.

Publish results in increasing source offset within each file, using the current
collector rules. This preserves per-file emission order and deterministic final
retention; cross-file streaming output remains completion-dependent as it is
today. Use bounded aggregate counters rather than allocating one report object
for each clean line.

The existing global retained-findings cap remains 10,000. Temporary capacity is
separate: at most `128 * (workers - 1)` provisional findings across the scan,
at most 8,064 with the current 64-thread ceiling. Pending results retain their
slot leases, so finishing out of order cannot accumulate an unbounded queue.

### Dense-result and accounting fallback

If a helper would exceed its 128-finding staging capacity, mark the batch for
serial replay and discard its provisional result. Do not truncate findings,
invent `FindingLimit`, publish a partial batch, or count speculative work twice.
The owner re-evaluates the original borrowed bytes through the serial path at
the batch's publication turn. The read buffer remains alive until replay ends.

Apply the same replay rule if aggregate publication cannot faithfully preserve
serial checked-counter behavior, such as an addition near `u64::MAX`. Replay is
not a scan failure; it trades throughput for exact existing semantics. This
version intentionally prioritizes clean and sparse-finding workloads. Measure
the dense fallback cost explicitly.

## Errors, progress, and completion

Preserve the first terminal failure within each source, regardless of which
helper finishes first. Join all scoped jobs before releasing input, but discard
results after the earliest failing batch/line. Do not publish speculative later
findings, suppressions, errors, or completion counts.

Preserve findings emitted before a terminal error, including any emitted during
the failing line before its recognizer returns an error. A source-local finding
count that exceeds the current cap remains a nonterminal recorded error where
the existing serial path continues; do not confuse that behavior with a
registry-returned terminal error. Tests must pin both cases.

Count an attempted failing line as the current driver does. Report byte progress
only for successfully consumed fragments/records: the current driver does not
advance successful-byte progress for a fragment whose callback fails. Merely
reading ahead into the already bounded buffer does not count as committed scan
progress. Count each committed byte and line once, never once per replay.

Keep source labels sanitized, unreadable-file/binary handling unchanged, and
exit-code precedence unchanged: 2 for errors, otherwise 1 for findings, else 0.
Mark a file completed only according to its resolved, non-speculative outcome.

## CLI and library compatibility

For CLI file scans, resolve the same 1–64 thread budget used for directory scans,
including `RAYON_NUM_THREADS` and the automatic maximum of eight. Accept
`--threads` for file scans, and update help and execution documentation.
Create the private pool lazily only for eligible inputs; `--threads 1` always
keeps the serial path. Existing small scans should not pay pool startup costs.

Directory/glob scans keep their file discovery and dynamic claiming. Pass the
shared batch executor to eligible file owners rather than building a new pool.

Preserve existing public serial file/reader functions and their signatures.
Provide an options-bearing file entry point for the CLI and benchmarks; serial
wrappers use one worker. No helper executor is passed to staged/diff acquisition,
which continues rejecting `--threads` and using the established fragment path.

## Module boundaries

- `src/scanner/batch.rs`: bounded descriptor construction, helper slots,
  speculative batch evaluation, and ordered wave resolution.
- `src/scanner/engine.rs`: file-only acquisition integration and shared safe
  record preparation/publication helpers; retain existing serial APIs.
- `src/scanner/execution.rs` and `scope.rs`: one private pool, scan-scoped helper
  ownership, and propagation into file work. Keep file discovery unchanged.
- `src/cli.rs`: file thread selection and the options-bearing entry point.
- `tests/unit/` and CLI/scope integration tests: scheduling, fallback, and result
  equivalence. Add benchmark cases and update execution documentation.

Do not expand this work into detector refactoring, asynchronous output, or a
general-purpose job scheduler. No dependency is needed beyond the existing
Rayon and standard library.

## Tests and benchmark acceptance

Tests must force thresholds down on small fixtures and prove that helpers execute
concurrently using barriers or execution hooks, not fragile timing assertions.
Exercise every new production function and its error/fallback branches.

Compare complete serial and parallel outcomes, excluding elapsed time and
existing cross-file streaming order, for:

- LF, CRLF, empty lines, non-UTF-8 bytes, and missing final LF.
- Findings at batch/read boundaries and long lines between eligible short lines.
- Built-ins, JOSE, contextual entropy, custom anchors/captures, duplicate spans,
  disabled rules, trailing ignores, placeholders, and accepted IDs.
- Dense replay, per-line/global finding overflow, terminal candidate errors,
  partial-line/read errors, and checked counter overflow.
- Deliberately reordered helper completion and fatal errors in earlier batches.
- Resource exhaustion, partially granted helper slots, one worker, all workers
  owning files, and repeated scans with reusable state.
- Exact byte/line counts, deterministic retained findings, bounded slots and
  buffer capacities, no leaks, unchanged staged/diff behavior, and CLI arguments.

Capture an immutable baseline release binary before implementation. Compare
identical rules, scopes, hardware, cache state, and compiler options. Record
baseline/candidate hashes, worker count, input bytes, median/p95, CPU utilization
where available, peak RSS, and fallback frequency. Use at least 15 timed samples
after warm-up; fixture creation and compilation are outside timing.

Benchmark one, two, and four files of 50,000 ordinary code-like lines; include
both short identifiers and longer assignments, clean and sparse-finding cases.
Also run many tiny files, mixed-size files, custom-rule-heavy input, dense
findings, and the existing giant-line workloads at 1/2/4/8 workers.

Acceptance:

1. Exact semantic equivalence and all resource/verification tests pass.
2. On a machine with at least four logical CPUs, four-worker scanning of the
   representative one-large-file clean/sparse corpus targets at least 1.5x the
   baseline CLI median. This is a gate to measure, not an achieved claim.
3. Existing short-file, multi-file, single-worker, staged/diff, and giant-line
   benchmark medians regress by no more than 10% under comparable conditions.
4. Report and investigate dense replay overhead; it is not an exemption from
   the regression gate. If helper speculation causes excessive dense overhead,
   disable further helpers for that file after the first capacity replay and
   remeasure. Keep that adaptation deterministic and tested.
5. Raw input storage remains bounded by the existing per-lane budgets; document
   measured auxiliary scratch/result RSS instead of asserting a total RSS cap.

If these targets are not met, report the results and adjust the internal batch
thresholds or seek approval for a revised approach. Do not silently widen the
scope to channels, mappings, or changed detection semantics.

Before completion run `cargo fmt --all -- --check`, strict all-target/all-feature
Clippy, `cargo test --all`, `cargo bench`, and `cargo coverage`. The checked-in
coverage alias must pass its enforced line/region and complete-function gates;
production code must not be excluded. Publish benchmark limitations explicitly.

## Research basis

- [Rayon 1.12 ThreadPool](https://docs.rs/rayon/1.12.0/rayon/struct.ThreadPool.html):
  nested operations use the current pool and tasks can be stolen by idle workers.
- [Rayon ParallelBridge](https://docs.rs/rayon/1.12.0/rayon/iter/trait.ParallelBridge.html):
  sequential items are pulled individually with synchronization; order is not
  guaranteed. This argues against one `par_bridge()` item per source line.
- [Rayon ParallelSlice](https://docs.rs/rayon/1.12.0/rayon/slice/trait.ParallelSlice.html):
  borrowed slices support parallel partitioning, but scanner-defined complete
  line boundaries and source metadata remain necessary.
- `docs/technical-design.md`: mutable-file mapping restrictions, raw payload
  budgets, whole-line semantics, and private-pool requirements.
- `docs/superpowers/specs/2026-10-06-byte-chunk-scanning-design.md`: preserve the
  established streaming line lifetime and evaluate intra-file parallelism
  separately with profiles and ordering costs.
