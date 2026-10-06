# Bounded byte chunk scanning implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for native execution, or superpowers:subagent-driven-development if the user selects delegation. Follow tasks in order. This document is a proposal; review the design and plan before implementing.

**Goal:** Scan arbitrarily long physical text lines with bounded buffers while preserving fast matching, added-only Git semantics, and redaction.

**Architecture:** Keep whole-line matching for lines up to 256 KiB. Larger lines enter a stateful session for provider/JOSE framing, context and trailing ignores, and bounded custom windows. Preserve existing custom configurations with a 1 MiB whole-line compatibility budget and explicit exit-2 diagnostics for unsupported long input.

**Tech stack:** Rust 2024, MSRV 1.85, standard buffered I/O, existing regex/regex-syntax, existing Rayon pool. No additional dependencies.

**Spec:** [Byte chunk scanning design](../specs/2026-10-06-byte-chunk-scanning-design.md).

## Global constraints

- File read buffer and payload fragments: 256 KiB.
- Short-line fast path: 256 KiB; enabled legacy custom whole-line storage: 1 MiB.
- Captured candidate values and windowed full-regex matches: 64 KiB.
- Shared custom window: at most 320 KiB, including right lookahead.
- Total raw payload-buffer capacities per lane: at most 1.5 MiB without legacy storage and 2.25 MiB with it; this includes the provider carry, custom regex window, candidates, read buffer, and reusable line storage. Report metadata and findings separately.
- Pending unique captured spans per line and retained global findings: 10,000 each.
- Compile regexes once, preserve program/cache/rule limits, add no dependency.
- Preserve byte columns, accepted fingerprints, rule precedence, disabled-rule behavior, and mode-specific byte/line counters.
- Any captured value retained in a finding uses `RedactedString`; no source-bearing state implements revealing `Debug`/`Display`.
- Exit 0 means a complete clean scan; exit 1 means complete with findings; exit 2 takes precedence for incomplete scans.
- Raw Git metadata and structural patch records retain their 1 MiB budget. Content payload length has no physical-line ceiling.
- Public whole-line matching APIs retain their signatures and semantics.
- Preserve Rayon scheduling, binary sampling policy, source snapshots, process status checks, and file admission behavior.
- Required coverage: at least 97% lines/regions and 100% production functions, including entry point and error formatters.
- Ordinary engine/scope median runtime must regress by no more than 10% on comparable repeated runs.

## Review focus

1. A token at an artificial fragment end must not be emitted before its actual terminator; Task 2 tests every token split and over-limit continuations.
2. A trailing ignore after megabytes of content must suppress earlier provisional matches; Tasks 3 and 5 test quotes, URI comments, exact suffixes, and delayed emission.
3. A bounded capture does not make the complete regex bounded; Task 4 tests unbounded context, assertions, greedy alternatives, and full-match ownership.
4. A long deleted/context Git line must neither trigger scanning nor masquerade as a header; Task 6 tests huge non-additions, payload prefixes, hunk counts, and partial EOF.
5. Reader fragmentation and worker count must not change results, counters, fingerprints, or overflow handling; Tasks 5, 7, and 8 exercise differential scans, forced short reads, parallel runs, and RSS/capacity gates.

## File map and dependency order

| File | Responsibility |
| --- | --- |
| `src/scanner/chunk.rs` (new) | Physical-line fragments and checked acquisition progress |
| `src/scanner/stream.rs` (new) | Short/long-line session, pending redacted entries, publication |
| `src/rules/stream.rs` (new) | Borrowed candidate event and shared streaming contracts |
| `src/rules/builtin.rs`, `src/rules/jose.rs` | Incremental token framing around existing validators |
| `src/rules/context.rs` | Incremental assignment/directive state and bounded field classification |
| `src/rules/window.rs` (new), `src/rules/mod.rs` | Custom HIR classification, partitioned sets, shared windows |
| `src/scanner/engine.rs`, `src/scanner/mod.rs` | Worker integration, safe errors, compatibility constants |
| `src/scanner/diff.rs`, `git.rs`, `staged.rs` | Incremental patch framing, strict parser, detector routing |
| `src/scanner/worktree.rs` | Preserve acquisition/snapshot invariants through shared driver |
| `tests/unit/*.rs`, `tests/*_cli.rs` | Boundary, differential, error, and real-executable coverage |
| `benches/engine.rs`, `scripts/parallel_measure.py` | Detection and process performance measurements |
| `technical-design.md`, `README.md`, `docs/development-decisions.md`, `tests/README.md`, `benches/README.md` | Resource contract, compatibility, benchmark commands |

Tasks 2–4 consume Task 1's contracts. Task 5 connects them. Task 6 integrates
Git. Task 7 validates external behavior. Task 8 measures and documents the result.
Implement sequentially to keep shared interfaces coherent.

## Task 1: Byte fragments and streaming contracts

**Files:** Create `src/scanner/chunk.rs`, `src/rules/stream.rs`, and `tests/unit/chunk.rs`; modify `src/scanner/mod.rs` and `src/rules/mod.rs` to register modules.

**Interfaces:**

```rust
// scanner::chunk; no Debug on source-bearing types
pub(crate) const CHUNK_BYTES: usize = 256 * 1024;
pub(crate) enum LineEnd { Lf, Eof }
pub(crate) struct LineFragment<'a> {
    pub payload: &'a [u8],
    pub line: u64,             // one-based source line
    pub column: u64,           // one-based byte column of payload start
    pub end: Option<LineEnd>,
}
#[derive(Default)]
pub(crate) struct ReadProgress {
    pub bytes_read: u64,
    pub lines_scanned: u64,
}
pub(crate) fn visit_line_fragments(
    reader: &mut dyn std::io::BufRead,
    progress: &mut ReadProgress,
    emit: impl FnMut(LineFragment<'_>) -> Result<(), ScanError>,
) -> Result<(), ScanError>;

// rules::stream; borrowed bytes exist only during callback
pub(crate) struct Candidate<'a> {
    pub rule: RuleId,
    pub span: std::ops::Range<u64>, // zero-based physical-line byte offsets
    pub value: &'a [u8],
    pub priority: u16,             // providers 0, JOSE 1, context 2, custom 3+index
}
```

- [ ] Write `fragments_preserve_lf_crlf_empty_and_final_eof`: input `b"ab\r\n\nlast"` emits first-line payload `ab\r`, one empty second line, then `last` with EOF; lines = 3, bytes = 9. Check exact one-based columns and LF exclusion from payload.
- [ ] Write `reader_slice_is_split_to_chunk_budget`: a `Cursor` exposing a 3 MiB slice emits payloads no larger than `CHUNK_BYTES`, with monotonic columns and exactly one line end.
- [ ] Write `fragment_progress_survives_interrupted_and_failed_reads`: reuse the injected-reader pattern in `tests/unit/engine.rs`; retry Interrupted, preserve progress on real error, and do not emit a successful EOF event after failure. Test checked line/column/byte overflow and callback errors.
- [ ] Run `cargo test --lib scanner::chunk_tests` and confirm missing-interface failures.
- [ ] Implement bounded `fill_buf`/`consume` traversal. Preserve progress after errors. Payloads are borrowed; finalization may use an empty end fragment after earlier bytes were delivered. Never allocate a complete line.
- [ ] Run the same tests; require all pass. Commit these contract/reader changes with `feat: add bounded physical-line fragments`.

## Task 2: Incremental provider and JOSE framing

**Files:** Modify `src/rules/builtin.rs`, `src/rules/jose.rs`, `src/rules/stream.rs`, `tests/unit/builtin.rs`, and `tests/unit/jose.rs`.

**Consumes:** `Candidate` and the existing `Registry`, provider tables, disabled IDs, format validators, and `MAX_CANDIDATE_BYTES`.

**Produces:** Internal `ProviderState` and `JoseState`, each with `new() -> Self`, `reset(&mut self)`, `push(&mut self, bytes: &[u8], registry: &Registry, emit: impl FnMut(Candidate<'_>)) -> Result<(), ScanError>`, and `finish(&mut self, registry: &Registry, emit: impl FnMut(Candidate<'_>)) -> Result<(), ScanError>`. Offsets advance once per payload byte and reset to zero each line.

- [ ] Write `provider_results_are_identical_at_every_split`: for each short existing positive/negative provider fixture, feed every possible two-fragment split and compare rule/span/value during callbacks to the complete-slice recognizer. For maximum-size candidates sample splits at prefixes, delimiters, and chunk/candidate boundaries to keep the suite bounded.
- [ ] Write `provider_waits_for_real_boundary`: pushing a valid-looking prefix emits nothing until delimiter/line end; an AWS word continuation invalidates the match. Include prefixes split one byte at a time, nested provider priority, private-key markers, Slack segments, and disabled branches.
- [ ] Write `stream_candidate_limit_is_exact`: a valid framed 65,536-byte provider/JOSE candidate preserves existing acceptance semantics; the corresponding 65,537-byte candidate returns `CandidateLimit` without allocating that byte. Malformed trailing padding/segments never accept a shorter valid prefix.
- [ ] Write `jose_oversized_run_without_dots_is_not_a_candidate`: multi-MiB alphanumeric content completes cleanly; append sufficient dots to the same framed run and verify the over-limit classification. Test empty signatures/JWE segments, GitHub installation tokens, and a JOSE prefix embedded in a longer invalid run.
- [ ] Run `cargo test --lib rules::builtin::tests` and `cargo test --lib rules::jose::tests`; establish failures for the new streaming cases.
- [ ] Implement resumable framing using existing format validation; retain at most one 64 KiB candidate buffer for each recognizer. Keep previous-byte and provider coverage state. Reuse bounded validation logic; do not copy every fragment into per-rule buffers or repeatedly rescan a growing prefix.
- [ ] Repeat targeted tests and commit with `feat: stream provider and JOSE candidates`.

## Task 3: Incremental context and exact ignore directives

**Files:** Modify `src/rules/context.rs`, `tests/unit/context.rs`, and `tests/context_detection.rs`.

**Consumes:** `Candidate`, `Registry`, `Histogram`, and existing context/suppression contracts.

**Produces:** `ContextState` with `new`, `reset`, `push`, and `finish` as in Task 2, taking an additional `&mut Histogram` and `&mut Suppressions`; `DirectiveState` with `new() -> Self`, `reset(&mut self)`, `push(&mut self, bytes: &[u8])`, and `finish(&self) -> bool`. Candidate priority is 2. Directive inspection remains independent of context comment/value scanning.

- [ ] Write `context_and_directive_match_at_every_split`: compare complete and fragmented matching/suppressions for existing assignments, quoted fields, escapes, passwords, AWS secrets, Bearer headers, placeholders, references, checksums, and unsupported expressions.
- [ ] Write `operator_after_long_whitespace_rejects_candidate`: the candidate may complete before megabytes of spaces, but a later `+`/`.` must preserve existing context rejection. Carry provisional candidate metadata/bytes within 64 KiB until the lookahead decision.
- [ ] Write `directive_requires_exact_outside_quote_suffix`: test `#` and `//`, `://`, a first unrelated comment, escaped quotes, trailing whitespace/CR, invalid suffixes, quoted text containing `rayloc:ignore`, and an unterminated quote. Split every directive byte and quote escape pair.
- [ ] Write `huge_irrelevant_fields_and_values_keep_bounded_state`: stream multi-MiB names and unrelated quoted values containing embedded provider text; the context lexer itself remains bounded. Names ending in recognized suffixes retain current classification; checksum components/camel transitions crossing fragments remain correct.
- [ ] Run `cargo test --lib rules::context::tests` and `cargo test --test context_detection`, confirming new streaming tests initially fail.
- [ ] Implement incremental grammar and finite field classifiers. Preserve the existing grammar, including where it stops at comments. Track irrelevant strings without retaining their contents. Validate entropy/placeholders only after a complete relevant candidate; retain existing suppression meanings.
- [ ] Repeat targeted tests and commit with `feat: preserve context and ignores across chunks`.

## Task 4: Safe custom regex windows and legacy classification

**Files:** Create `src/rules/window.rs` and `tests/unit/window.rs`; modify `src/rules/mod.rs` and `tests/unit/registry.rs`.

**Consumes:** `Candidate`, existing parsed HIR, existing compiled custom rules, configuration order, and regex size limits.

**Produces:**

```rust
pub(crate) enum RuleInput {
    Windowed { max_match_bytes: usize },
    WholeLine,
}
pub(crate) fn classify_input(hir: &regex_syntax::hir::Hir) -> RuleInput;
impl Registry {
    pub(crate) fn requires_whole_line(&self) -> bool;
    pub(crate) fn max_window_match_bytes(&self) -> usize;
}
```

Also produce `WindowState` with `new() -> Self`, `reset(&mut self)`, and `push`/`finish` receiving `&Registry`, `&mut Histogram`, and a `Candidate` callback. `Registry::detect_legacy_line(bytes: &[u8], histogram: &mut Histogram, emit: impl FnMut(Candidate<'_>)) -> Result<(), ScanError>` runs only the whole-line partition. Both partitions retain original custom indices for rule IDs and priority.

- [ ] Write `classifies_full_expression_and_assertions`: `corp_([a-z]{16})` is Windowed with 21-byte maximum; `corp_([a-z]+)` and `prefix.*(SECRET)` are WholeLine despite short potential captures; `^corp_[a-z]{16}$`, `\bcorp_[a-z]{16}\b`, and Unicode assertions use WholeLine. A full expression of 65,536 bytes is Windowed; 65,537 is WholeLine if it fits compilation budgets. Disabled WholeLine rules do not set the registry restriction.
- [ ] Write `window_matches_preserve_full_match_search_progress`: compare complete-slice results for every split, greedy/lazy bounded alternatives, optional capture absence, empty captures, entropy failures, and captures starting later than full-match start. Per-rule iteration advances by full-match end even if nothing is emitted.
- [ ] Write `windows_have_no_duplicate_or_premature_capture`: place matches around owned-start boundaries, including a maximum-size match and UTF-8 literals split inside code points. Right lookahead preserves greedy choice; captured-span dedup cannot repair an incorrectly framed match.
- [ ] Write `legacy_partition_keeps_existing_configurations`: all existing unbounded patterns compile and retain current short-line outputs; the window partition never executes those expressions.
- [ ] Run `cargo test --lib rules::window::tests` and `cargo test --lib rules::tests`, confirming new-interface failures.
- [ ] Implement conservative HIR classification and partitioned RegexSets. Share one window at most 320 KiB; retain per-rule absolute search cursors. Search only mature starts with complete right lookahead, flush all remaining starts at real line end, and emit using full-match ownership. Use `captures_at` to retain iterator semantics; compile nothing during searches.
- [ ] Repeat targeted tests and commit with `feat: classify and window bounded custom rules`.

## Task 5: Transactional line sessions and file-engine integration

**Files:** Create `src/scanner/stream.rs` and `tests/unit/stream.rs`; modify `src/scanner/engine.rs`, `src/scanner/mod.rs`, `tests/unit/engine.rs`, `tests/unit/engine_collector.rs`, and `tests/unit/scanner.rs`.

**Consumes:** Tasks 1–4, existing `Collector`, `FindingId`, `RedactedString`, `ScanOutcome`, suppression merging, and emitter.

**Produces:**

```rust
pub(crate) struct LineSession { /* private reusable state */ }
impl LineSession {
    pub(crate) fn new() -> Self;
    pub(crate) fn push(
        &mut self, fragment: LineFragment<'_>, source_id: u32, path: &[u8],
        registry: &Registry, outcome: &mut ScanOutcome,
        collector: &std::sync::Mutex<Collector>,
        emitter: Option<&crate::report::emitter::SharedEmitter>,
    ) -> Result<(), ScanError>;
    pub(crate) fn abort_line(&mut self);
}
```

Add `ScanError::RuleWindowLimit` with the exact safe message in the spec.
`Worker` owns a reusable `LineSession`. Internal acquisition receives fragments;
existing public file/reader signatures stay unchanged. Retain `MAX_LINE_BYTES`
and `LineLimit` as documented compatibility items; use explicit legacy/metadata
constants for their remaining responsibilities.

- [ ] Write `short_path_and_stream_path_are_equivalent`: generate supported lines at 256 KiB−1/exact/+1 and 1 MiB−1/exact/+1, with mixed providers/context/bounded regexes. Compare findings, IDs, suppression counters, and line locations to complete-slice detection. Elapsed time is excluded.
- [ ] Write `long_clean_line_and_end_secret_complete`: stream 5/10/64 MiB clean lines and lines with one synthetic credential near the beginning, around a chunk boundary, and at EOF. Assert exit 0/1 as appropriate, exact bytes, line 1, correct large columns, and completion count 1.
- [ ] Write `long_line_ignore_delays_all_publication`: an emitter spy sees no early finding before EOL; a distant trailing ignore yields zero findings and one inline suppression. An ignored line containing >10,000 ordinary candidates does not get a provisional finding-limit error. Candidate-limit errors remain exit 2.
- [ ] Write `line_priority_acceptance_and_overflow_are_stable`: overlapping detector captures pick existing priority; accepted fingerprints preserve current counters; test 10,000/excess dedup limits, repeated full spans, disabled rules, and one-versus-many fragment input. Pending storage never exceeds the cap.
- [ ] Write `legacy_rule_limit_is_explicit_with_partial_supported_results`: enabled unbounded custom rule plus a >1 MiB line returns RuleWindowLimit, reports supported built-in matches, completes reading later lines, and never increments files_completed. A disabled legacy rule permits a complete scan. Legacy patterns retain exact outputs below their cap.
- [ ] Write `failure_discards_unfinished_line_only`: injected read error retains completed-line findings, publishes none from the unfinished line, returns exit 2, and records known safe source path. Test checked large-column conversion/overflow with injected state rather than enormous allocations.
- [ ] Run `cargo test --lib scanner::stream::tests`, `cargo test --lib scanner::engine::tests`, and `cargo test --lib scanner::tests`; confirm new expectations fail.
- [ ] Implement promotion from short buffer to streaming exactly once. Build redacted pending entries immediately, resolving duplicate priority before accepted-ID decisions. At overflow retain the canonical first 10,000 by priority then captured start/end, using a bounded secondary ordering index; record a tentative overflow flag. Finalize only on true end markers; reuse existing collector publication outside its lock. Store RuleWindowLimit in the outcome and continue supported scanning. Reuse bounded storage across files, abort unfinished state on reader failure, and merge acquisition progress once even after errors.
- [ ] Replace obsolete `LineLimit` assertions and private `Limits.line_bytes` test configuration with short-path promotion/legacy-budget assertions. Keep finding-cap injection tests; remove unused production line-assembly helpers so full function coverage does not require obsolete code.
- [ ] Add capacity assertions inside owning-module tests for every raw buffer, including maximum candidates, windows, and legacy storage. Avoid a new production accessor solely for tests.
- [ ] Repeat targeted tests and `cargo test --test context_detection --test context_review --test accept_cli`; commit with `feat: scan long physical lines with bounded sessions`.

## Task 6: Stream Git content without weakening patch validation

**Files:** Modify `src/scanner/diff.rs`, `src/scanner/git.rs`, `src/scanner/staged.rs`, `src/scanner/worktree.rs`, `tests/unit/diff.rs`, `tests/unit/git.rs`, `tests/unit/staged.rs`, and `tests/unit/worktree.rs`.

**Consumes:** `LineSession`, `LineFragment`, existing raw bindings/parser phase machine, exclusions, snapshots, and source IDs.

**Produces:** `Parser::fragment(record_fragment: &[u8], end_record: bool, emit: impl FnMut(Event<'_>)) -> Result<(), DiffError>` and an additional `Event::AddedFragment { source_id: u32, new_line: u64, column: u64, payload: &[u8], starts_run: bool, ends_line: bool }`. Keep `Parser::record` as a complete-input wrapper that emits its existing `Event::Added`; use a private common parser routine so content validation has one implementation. Existing public parser users continue compiling; adding an event variant is an API change that must be called out in release notes.

The patch acquisition driver passes at most 256 KiB fragments and signals LF
completion. The final record fragment includes LF and only it has `end_record`
set; earlier fragments contain no LF. Reject disagreement between the end flag
and terminator. Raw records and structural metadata remain bounded complete records.
Use a distinct `MAX_METADATA_RECORD_BYTES = 1024 * 1024`, rather than importing
the engine's old content limit. Keep `MAX_RECORD_BYTES` as a documented legacy
alias for metadata if required for library compatibility.

- [ ] Write `fragmented_parser_matches_complete_record_events`: normalize Added/AddedFragment events into complete added lines and compare all current patch fixtures, split at every byte, including type-change sections and no-newline markers.
- [ ] Write `huge_added_deleted_and_context_lines_are_validated`: 10 MiB `+` payload produces one line of detector fragments; 10 MiB `-`/space payload produces none. Include embedded `diff --git`, `@@`, `+++`, and backslash text in payloads; it must never become metadata.
- [ ] Write `counts_and_markers_apply_once_per_physical_record`: fragmented records consume one old/new count, preserve new-line numbers and starts_run, and reset detector state at real boundaries. Invalid indicators/counts fail before routing added payload.
- [ ] Write `partial_huge_record_and_structural_overflow_fail_closed`: truncated EOF, malformed no-newline markers, oversized metadata, incorrect IDs/paths, dirty gitlinks, and a parser already failed all return errors. Discard provisional current-line findings while retaining prior complete lines.
- [ ] Write `staged_stream_errors_keep_safe_source_attribution`: candidate/legacy errors use known sanitized relative labels; before binding, use pathless errors. Suppressed/excluded content must still preserve strict protocol validation.
- [ ] Run `cargo test --lib scanner::diff::tests`, `cargo test --lib scanner::git::tests`, `cargo test --lib scanner::staged::tests`, and `cargo test --lib scanner::worktree::tests` to establish failures.
- [ ] Implement record-fragment classification by parser phase and first indicator; accumulate only structural records. Reserve/check available hunk sides before payload routing, commit counts once at LF, and invalidate permanently on framing errors. Drain non-addition bodies without accumulation. Adapt staged/worktree shared consumption to LineSession; retain Git process-exit and snapshot checks. Count added payload bytes once and never include diff prefix/overlap in columns.
- [ ] Repeat targeted tests and `cargo test --test staged_cli --test worktree_cli`; commit with `feat: stream long Git patch payloads`.

## Task 7: Real-executable regressions and detection quality

**Files:** Modify `tests/cli.rs`, `tests/policy_cli.rs`, `tests/staged_cli.rs`, `tests/worktree_cli.rs`, `tests/scope_cli.rs`, `tests/accept_cli.rs`, `tests/hook_cli.rs`, and `tests/support/mod.rs`. Modify corpus labels only if adding explicit supported boundary records; existing statistical expectations must not be loosened.

**Consumes/produces:** Existing CLI and report contracts; no new flags. Extend reusable fixture generation to write large inputs in bounded blocks, avoiding real credentials and giant committed literals.

- [ ] Add `large_single_line_cli_contract`: existing direct-file, directory, and glob CLI scans of >10 MiB content return 0/1 correctly with exact locations. Library reader tests cover stream input; the CLI currently has no stdin scan mode. Check full synthetic values are absent from stdout/stderr; debug formatting exposes no full source value.
- [ ] Add `large_minified_staged_and_diff_scan_added_only`: create a synthetic Git repository with a >10 MiB line; test partial staging, unstaged-only credentials, deleted/context-only credentials, ignored lines, valid final EOF, and complete added secrets. Include SHA-1/SHA-256 and alternate indexes using existing harness support.
- [ ] Add `legacy_custom_cli_error_and_accepted_id`: a valid existing unbounded rule remains usable on short input, emits an actionable path-specific exit-2 error on long input, and a disabled rule removes only that compatibility restriction. Accept the same captured secret/path ID in short and fragmented long files.
- [ ] Add `parallel_chunk_output_is_deterministic`: mix large lines, many small files, overlapping matches, and finding overflow at 1/8/32 workers; compare final retained findings/counters, allowing the existing live-emitter ordering contract. Do not require live output to be globally ordered.
- [ ] Add `long_line_hook_blocks_and_clean_line_commits`: real Git hook returns 1 for complete detected-secret input, 2 for incomplete custom-rule coverage, and permits a complete clean large-line commit.
- [ ] Run the targeted integration suites before changing any discovered implementation defects; confirm each new assertion is meaningful. Resolve failures in the owning Task 2–6 module, without weakening fixtures or removing coverage.
- [ ] Run `cargo test --all` and `python3 scripts/detection_baseline.py --check` after the release build in Task 8. Require supported findings and suppression expectations remain intact; commit integration regressions with `test: cover large-line scan modes and redaction`.

## Task 8: Benchmark alternatives, enforce gates, and document behavior

**Files:** Modify `benches/engine.rs`, `benches/README.md`, `scripts/parallel_measure.py`, `tests/README.md`, `README.md`, `technical-design.md`, and `docs/development-decisions.md`. Create `docs/research/byte-chunk-scanning-results.md` and its machine-readable `.json` report.

**Consumes/produces:** Existing measurement harness/report shape, plus long-line workload cases and declared capacity/RSS/runtime gates. Keep benchmark validation active so a fast incomplete scan cannot be recorded as success.

- [ ] Extend fixture generation with 1/5/10/64/256 MiB single-line sizes and an opt-in 1 GiB performance case. Add real minified syntax, sparse secrets near boundary/end, dense candidates, long ignored lines, valid bounded custom patterns, and adversarial whole-line regex patterns. Fixture generation uses bounded writes.
- [ ] Add forced 1/2/3/7/4,096/256 KiB reader fragments and verify identical supported outcomes outside the timed region. Assert raw-buffer capacity plateaus for generated 64 MiB/1 GiB streams; include legacy/no-legacy paths and pending-finding caps.
- [ ] Build immutable release variants for the original 1 MiB cap, experimental 5 MiB and 10 MiB caps, and chunking in isolated execution checkouts. Change both Git acquisition/parser caps in cap experiments, preserve all other code, and record revisions/patches. Label these experimental builds; do not ship all alternatives.
- [ ] Measure original engine/scope cases and long-line cases at 1/8/32/64 workers, one untimed warm pass then at least 15 timed repetitions for stable short/medium cases. Use at least three timed repetitions for the 1 GiB case, report the smaller sample count, and treat its p95 as exploratory. Run sequentially without concurrent compilation.
- [ ] Require no more than 10% median regression for ordinary short-line engine/scope cases; re-run only when variance or changes justify it. Measure RSS/CPU/throughput and output delay. Require clean single-line peak RSS growth from 64 MiB to 1 GiB to stay within 8 MiB at fixed worker count after warmup on the reference Linux host. Record exact buffer capacities separately; count child Git RSS separately from rayloc.
- [ ] Report exit-2 cap failures as unsupported, not as throughput wins. Only compare successful full scans across designs. Document measured 5/10 MiB memory costs and whether existing custom iterators show a significant slowdown.
- [ ] Update resource tables and matching contracts: no built-in physical-line ceiling; unchanged candidate/finding budgets; conservative legacy regex policy and safe message; line-end publication latency; no guaranteed within-file multicore acceleration. Explain raising caps as an optional interim product choice. Correct obsolete statements only in current contracts; historical research reports keep their dated results.
- [ ] Run all required checks on the final implementation:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo bench
cargo coverage
cargo build --locked --release
python3 scripts/detection_baseline.py --check
python3 scripts/artifact_smoke.py /home/liam/Dev/github.com/nhtua/rayloc/target/release/rayloc
```

Use the actual execution checkout's absolute binary path for artifact smoke.
Require each command to pass and publish real coverage numbers with no production
exclusions. Install coverage tooling only if absent, following AGENTS.md.
`tests/README.md` currently says 98% while the enforced alias/AGENTS.md use 97%;
make the documentation agree with the enforced gate, without lowering the alias.

- [ ] Self-review all spec requirements against completed tasks, resolve test/performance failures, and commit with `perf: validate and document bounded chunk scanning`.

## Delivery and review

Recommended execution: native, sequential implementation because these tasks
share line lifetime, byte offset, callback, and error contracts. Delegation is
available if the user selects it; do not initiate it as part of this planning task.
Review the custom fallback and delayed long-line emission in the design before
starting. Scope any interim 5/10 MiB cap release independently so it does not
obscure correctness or performance measurements for chunking.

This plan does not claim all custom regexes can scan arbitrary-length lines.
It promises supported built-in and bounded custom scanning, preserves existing
configurations, and makes incomplete custom coverage an explicit error.
