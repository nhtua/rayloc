# Builtin Detection Precision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user authorized implementation and PR creation on 2026-10-08; this document does not authorize merging or release.

**Goal:** Remove verified member-reference and configuration-key false positives while preserving credential detection in source code and measured scanner performance.

**Architecture:** Compute a grammar hint once per source and share operator-association and qualified-reference classifiers between the complete-line and incremental lexers. Skip definite non-binding labels and unquoted qualified references; retain unresolved bare values, credential comparisons, and every supported literal/provider/custom branch. Carry the hint through each reader and helper path, then validate accuracy and speed against an immutable checkout baseline.

**Tech Stack:** Rust 2024/MSRV 1.85, existing regex/Rayon/scanner pipeline, standard-library byte checks, existing stdlib Python measurement tooling. No new dependencies.

**Spec:** [Builtin detection precision design](../specs/2026-10-08-builtin-detection-precision-design.md).

## Global Constraints

- Rust edition 2024; minimum Rust version 1.85.
- Add no runtime dependencies, network calls, models, or language parsers.
- Keep the existing 256 KiB reader/chunk buffers and 64 KiB candidate limit.
- Never load a complete file larger than 10 MB into memory; retain bounded streaming.
- Compile policy regexes once; preserve Rayon execution and immutable shared policy.
- Scan only added lines in staged/reference modes; preserve source line and byte columns.
- Normal output, debug formatting, diagnostics, and research artifacts contain no raw credentials.
- Preserve exit codes 0 for clean, 1 for findings, and 2 for incomplete/error scans.
- Require at least 95% production line and region coverage and 98% function coverage.
- File extensions, test paths, and identifier-shaped values alone never exempt credentials.
- The user authorized reading original finding source files; source review does not authorize editing those repositories.
- Keep entropy defaults/overrides/caps, provider signatures, marker handling, custom-rule semantics, and credential-in-tests policy as specified.
- Add no dummy/synthetic-specific exceptions, field-name exemptions, or test-directory bypasses; reviewed intentional findings use existing `rayloc:ignore` / `rayloc accept` controls.

## Review Focus

1. Opaque identifier-shaped values and bare weak passwords in `.py`/`.ts` must still report; source grammar is not a blanket exception (Tasks 1–3).
2. The environment-key ternary is clean while real credential object properties inside a ternary and hardcoded password comparisons still report (Task 2).
3. Quotes, explicit policy, independent provider/custom matches, and oversize/error paths preserve their contracts (Tasks 2–3).
4. Split operators, multiline object keys, CRLF/EOF, long-line promotion, mixed-source worker reuse, and helper replay preserve locations/counters (Tasks 2–3).
5. A mixed line containing both a symbol and a secret cannot pass accuracy evaluation merely because some finding was emitted (Task 4).

---

## Preparation

- [x] Use the existing `.worktrees/builtin-detection-precision` worktree on `fix/builtin-detection-precision`; do not create another worktree. Read the revised spec and applicable `AGENTS.md`, preserve `b0ecc6e` as the recorded implementation base, and confirm source has not changed since planning. The worktree's earlier debug build and 431-test baseline passed; that is not a release/performance baseline.
- [x] Build the unchanged checkout with `cargo build --locked --release` and preserve its executable as `target/precision-baseline-rayloc`. Record its SHA-256, compiler, active policy, CPU/OS/Git, and binary size. The user confirmed the installed research executable was built from `4a5bed8`; compare the new candidate with the unchanged `b0ecc6e` checkout instead.
- [x] Record the existing accuracy baseline and `cargo bench --bench engine` results before detector edits. Later run the new paired CLI harness against this preserved executable; measurement-harness development may occur after the binary is frozen.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py \
  --binary target/precision-baseline-rayloc --output target/precision-before.json
cargo bench --bench engine
```

Expected: a complete accuracy report and the benchmark's scope/finding assertions
pass. Review any drift from committed historical results before proceeding.
Store measurements under `target/` until a safe aggregate report is ready.

### Task 1: Define conservative association and reference evidence

**Files:** Create `src/rules/assignment.rs`, `tests/unit/assignment.rs`; modify `src/rules/mod.rs` to register the internal module and re-export `SourceSyntax`.

**Interfaces produced:**

```rust
pub enum SourceSyntax { Text, Code } // Copy, Clone, Debug, Eq, PartialEq
impl SourceSyntax { pub fn from_path(path: &[u8]) -> Self; }
pub(crate) enum AssociationKind { Assignment, Pair, Equality, NonAssociation }
pub(crate) struct Association {
    pub kind: AssociationKind, pub operator_len: usize,
}
pub(crate) fn classify_association(
    syntax: SourceSyntax, before_name: Option<u8>, operator_prefix: &[u8],
) -> Association;
pub(crate) enum ReferenceKind { None, Template, Code }
pub(crate) struct FieldEvidence {
    pub password: bool, pub aws: bool, pub authorization: bool,
    pub checksum: bool, pub generic: bool,
}
pub(crate) fn classify_reference(
    value: &[u8], quoted: bool, syntax: SourceSyntax,
) -> ReferenceKind;
pub(crate) fn classify_fields(
    normalized_tail: &[u8], full_len: usize, checksum: bool,
) -> FieldEvidence;
```

The `checksum` parameter carries the existing whole-name component result; the
bounded streaming tail alone must not erase a checksum component earlier in a
long name. Exact names require `full_len == normalized_tail.len()`. Suffix fields
use the existing underscore word boundary.

`before_name` is the preceding significant source byte outside the candidate name;
record it when the lexer starts that name. `operator_prefix` contains up to three
source bytes starting at `=` or `:`. In `Text`, consume the legacy single delimiter.
In `Code`, consume complete `==`/`===` as `Equality`, single `=` as `Assignment`,
and single `:` as `Pair`; `=>`, `::`, `:=`, and a `:` whose name follows `?` are
`NonAssociation`. Invalid input returns `NonAssociation` with zero consumed bytes.
Callers wait for sufficient lookahead or physical EOF before invoking this helper.

- [x] Write `source_syntax_uses_only_supported_code_suffixes`: every code suffix from the spec maps to `Code`, including uppercase variants and non-UTF-8 parent components; `.env`, `.sh`, `.ps1`, `.yaml`, `.json`, `.md`, empty paths and `.ts.bak` map to `Text`.
- [x] Write `association_evidence_preserves_values_and_rejects_ternary_labels`: assert the kinds and operator lengths above for code/text, including a name after `?`, names after `{`/`,`/record start, equality comparisons, and all EOF lookahead lengths. A quoted question mark inside a name is not `before_name`; `Text` retains `PASSWORD==value` as a single-delimiter assignment.
- [x] Write `reference_classification_respects_quotes_and_source`: all 13 distinct verified member-reference values classify as `Code` only when unquoted in `Code`; their quoted forms classify as `None`. Newly recognized members classify as `None` in `Text`; existing `${PASSWORD}` interpolation remains `Template` in both quote modes.
- [x] Write `reference_grammar_requires_qualification_and_complete_components`: accept `args.api_key`, `input.env.KEY`, `crate::KEY`, `node->secret`, `client?.credential`; return `None` for `TOKEN`, `ANTHROPIC_AUTH_TOKEN`, a 16-byte opaque alphanumeric fixture, `.field`, `args.`, `a..b`, `2token`, `abc-def`, `api.key!`, malformed operators, and non-ASCII identifiers. `None` preserves eligibility rather than dropping the value.
- [x] Write `field_evidence_preserves_all_existing_suffixes`: `allow_credentials`, `credentials`, `access_token`, `client_secret`, and all existing streaming provider suffixes retain evidence. Assert password/AWS/header/checksum flags, normalized camel forms, long-tail exact-name protection, and no added field-name exceptions.
- [x] Run `cargo test --lib assignment`; expect failure because the classifier module/functions are absent.
- [x] Implement the declared interfaces using static byte slices and bounded loops. Recognize complete operator roles and the definite ternary-label case; preserve uncertain eligibility. Apply existing template exclusions, quote-sensitive legacy programming prefixes, and the qualified-only reference grammar in `Code`. Allocate no strings, tables, or candidate buffers; do not compile a regex. Calls/indexes remain the lexers' existing unsupported-expression checks.
- [x] Run `cargo test --lib assignment`; expect all new tests to pass.
- [ ] Commit the classifier and its tests as `feat: classify credential associations and qualified references`.

### Task 2: Fix association and value roles in both context detectors

**Files:** Modify `src/rules/context.rs`, `src/rules/mod.rs`, `tests/unit/context.rs`, `tests/unit/registry.rs`, `tests/context_detection.rs`.

**Consumes:** Task 1's classifier interfaces.

**Interfaces produced:**

```rust
impl Registry {
    pub fn detect_line_in_source(
        &self, bytes: &[u8], syntax: SourceSyntax,
        histogram: &mut Histogram, suppressions: &mut Suppressions,
        emit: impl FnMut(RuleId, Range<usize>),
    ) -> Result<(), ScanError>;
}
impl ContextState {
    pub(crate) fn with_syntax(syntax: SourceSyntax) -> Self;
}
```

Keep `detect_line` and `detect_line_with_suppressions` as `Text` wrappers around
the new method. Add `syntax: SourceSyntax` immediately after `bytes` in internal
`context::detect`; `ContextState` stores the same hint. Its existing `new` uses
`Text`; reset preserves the stored hint. Do not route complete lines through a
fresh incremental state machine.

Each lexer records the significant byte before a name, then defers association
selection until its <=3-byte operator probe is complete. Consume the exact
operator length, scan equality-associated values using the existing strong-field
rules, and resume searching after non-associations. Preserve a real key that starts
the physical line; no opening-brace prerequisite or cross-line state is allowed.

- [x] Write `code_members_do_not_become_generic_or_password_findings`: reconstruct the 13 verified members under `Code` in their dictionary/struct/object/keyword forms. Assert zero findings and one reference suppression per eligible association; include `appPassword: credentials.clientSecret`, `password=credentials.clientSecret)`, and `externalCredential: row.externalCredential ?? null`. # rayloc:ignore
- [x] Write `ternary_environment_key_names_are_not_secret_values`: the exact verified `route.auth === "api_key" ? "ANTHROPIC_API_KEY" : "ANTHROPIC_AUTH_TOKEN"` line emits no context finding/reference suppression. Repeat with other names and whitespace so the fix depends on operator role, not provider spelling or a blacklist. An actual `auth_token='ANTHROPIC_AUTH_TOKEN'` assignment remains eligible. # rayloc:ignore
- [x] Write `source_code_literals_are_not_exempted_by_identifier_shape`: in `Code` and `Text`, `api_key=` followed by the fixture constructed from `concat!("Q7v2n9B4", "x6M1z8K3")` produces `ContextSecret`, and `password=aaaaaaaa` produces `PasswordAssignment`. Include uppercase, underscore-containing, hex, short random and quoted controls selected to meet existing gates; `allowCredentials='opaque fixture'` retains its original eligibility. # rayloc:ignore
- [x] Write `equality_and_real_properties_inside_conditionals_keep_literals_eligible`: `password=='weakweak'` and `password === 'weakweak'` report the actual inner span. `flag ? {api_key: 'opaque fixture'} : fallback` still reports its genuine property. A standalone `api_key: 'opaque fixture',` physical line reports without preceding-line context. A metadata ternary followed by a real password assignment on the same line retains that finding. # rayloc:ignore
- [x] Write `quoted_reference_spellings_remain_password_literals`: `password='self.DUMMY_API_KEY'`, `password='config.password'`, and `password='ANTHROPIC_AUTH_TOKEN'` produce one `PasswordAssignment` with the exact inner span. `password='aaaaaaaa'` remains detected; `password='${PASSWORD}'` remains suppressed. # rayloc:ignore
- [x] Write `text_values_and_provider_custom_matches_keep_their_contract`: under `Text`, `password=self.DUMMY_API_KEY` and `PASSWORD=aaaaaaaa` report. Under `Code`, a provider-shaped bare identifier still yields its provider rule, and an explicit custom rule still matches a suppressed code-reference span. Assert no raw values in normal reporting. # rayloc:ignore
- [x] Write `context_source_syntax_matches_at_every_input_split`: compare `Registry::detect_line_in_source` with `ContextState::with_syntax` at every two-way split and byte-by-byte feeding. Assert rule/span/counter/error parity for `=`, `==`, `===`, `=>`, `:`, `::`, `:=`, ternary labels, quotes/escapes, `.`, `->`, `?.`, closing `)`, whitespace, EOF, CRLF, and disabled branches. A question mark inside a quoted name/value cannot contaminate the next association; split lookahead cannot consume the next assignment.
- [x] Write `shared_fields_cover_complete_and_streaming_paths`: every existing provider-associated field suffix, including `allow_credentials`, has identical evidence in both implementations. Include a name longer than 64 normalized bytes with a strong suffix and an earlier checksum component.
- [x] Write `intentional_test_credentials_use_existing_review_controls`: synthetic/dummy-named concrete values and provider fixtures still report in a `.test.ts` source. Exact trailing `rayloc:ignore` suppresses, `--no-inline-ignores` restores the finding, and `rayloc:ignored` is not a supported directive. Existing acceptance remains path/value-bound; add no new auto-acceptance policy.
- [x] Write `oversize_code_references_and_reference_counter_overflow_fail`: enabled 64 KiB + 1 candidates produce `CandidateLimit` before suppression, even with an inline ignore; an exhausted reference counter produces `CounterOverflow`. Disabled branches preserve their existing limit behavior.
- [x] Run `cargo test --lib context`, `cargo test --lib registry`, and `cargo test --test context_detection`; expect the new behavior/parity assertions to fail before integration.
- [x] Integrate association probing while searching for bindings, then shared field/reference classification during value evaluation. Enforce enabled-candidate limits before value suppression. Non-associations do not create candidates or reference counters; real comparisons retain candidate checks. Add code-only `)` framing in both lexers; preserve quoted/text framing and checked counters.
- [x] Run the three targeted commands again; expect all assertions to pass. Document intended operator-span, quoted-prefix, and shared-field corrections. Never relabel an identifier-shaped secret as a reference to make a test pass.
- [x] Commit as `fix: distinguish member references and key expressions from credentials`.

### Task 3: Carry grammar evidence through every acquisition and execution path

**Files:** Modify `src/scanner/record.rs`, `src/scanner/stream.rs`, `src/scanner/engine.rs`, `src/scanner/batch.rs`, `src/scanner/staged.rs`; modify their affected tests in `tests/unit/record.rs`, `tests/unit/engine.rs`, `tests/unit/stream.rs`, `tests/unit/batch.rs`; extend `tests/context_detection.rs`, `tests/staged_cli.rs`, `tests/worktree_cli.rs`, `tests/scope_cli.rs`.

`worktree.rs` uses staged's common patch pipeline, so ensure it receives the hint
there; modify it only if a separate path is discovered during execution.

**Consumes:** `SourceSyntax` and `Registry::detect_line_in_source`.

**Interfaces produced:** Add `syntax: SourceSyntax` to internal `RecordContext`;
add `LineSession::begin_source(&mut self, syntax: SourceSyntax)`. Insert a
`syntax: SourceSyntax` argument immediately after `path` in internal
`engine::detect_record`; update all call sites. Public file/reader APIs retain
their signatures.

- [x] Write `file_scanning_uses_grammar_without_trusting_code_paths`: member-reference assignments are clean in `.py`/`.rs`/`.ts` and remain eligible as password text in `.env`/`.sh`/unknown extensions. In every source, quoted weak/opaque controls and unquoted identifier-shaped opaque/weak values still report. The environment-key ternary is clean in `.ts`; a real `auth_token='ANTHROPIC_AUTH_TOKEN'` binding still reports. An unnamed reader retains `Text` handling. # rayloc:ignore
- [x] Write `source_syntax_survives_long_line_promotion_and_resets_between_sources`: a >512 KiB physical line puts `api_key=` across the 256 KiB promotion boundary, then checks equality-associated and weak-password positives plus reference suppression. Reuse one session for `.ts`, `.env`, `.ts`, with an abort before changing source syntax.
- [x] Write `helper_batches_and_serial_scanning_agree_on_source_syntax`: force helper admission for `.ts`/`.env`, compare rule/location, source ID, suppression, byte, line, and exit results with serial execution, and force capacity replay. Existing helper-slot tests cover exhaustion/no-slot fallback.
- [x] Write `staged_code_references_preserve_index_scope` and `reference_diff_uses_the_path_syntax`: stage an isolated added object property with its opening brace unchanged, a metadata ternary, quoted/unquoted positives in `.ts`, and a text-mode `.env` positive. Both staged and reference scans have partial or untracked working-tree changes and assert only their selected additions and correct line coordinates.
- [x] Run the targeted integration tests and `cargo test --lib stream`, `cargo test --lib record`, `cargo test --lib batch` after adding the assertions; the new path-specific cases failed before syntax propagation.
- [x] Compute syntax once at `read_records_into`/`read_file_with_batches` source entry and once per patch binding in `staged.rs`. Initialize the line session and copied `RecordContext` with that value. `LineSession` passes it to complete records and its `ContextState`; reset/abort clears transaction data and retains syntax until `begin_source` replaces it. Helper preparation and serial replay consume `RecordContext.syntax` without path work inside their line loops. `batch.rs` already forwards the copied context and required no production change.
- [x] Update affected internal test constructors/call sites. Targeted suites passed, formatting and strict Clippy passed, and `cargo test --all` ran 332 tests successfully before one unrelated existing staged CLI unit failed. Confirmed the same failure with the frozen baseline binary: `scan --staged` on either checkout reports `cannot read tracked scope metadata`, so that test failure predates these changes. Recheck full-suite status during final verification.
- [x] Commit as `feat: preserve source syntax across scanner execution paths`.

### Task 4: Freeze and evaluate precision fixtures with occurrence checks

**Files:** Create `tests/corpus/detection/precision-calibration.jsonl`, `tests/corpus/detection/precision-held-out.jsonl`; modify `scripts/detection_baseline.py`, `tests/detection_evaluator.py`, `tests/corpus/detection/README.md`.

**Interfaces produced:** Existing rows retain their behavior. New rows optionally
add a safe basename `source_path` (default `source`) and `expected_findings`, a
list of `{rule, line, column}` records using report IDs and 1-based locations.
An optional `expected_findings_no_inline` list overrides that expectation for
`--no-inline-ignores`; absent that field, reuse `expected_findings`.
Evaluator CLI adds repeatable `--corpus LABEL=PATH`, and an optional
`--expected PATH` baseline-report argument for `--check` (default remains the
historical committed report). Preserve existing default partitions and record
metrics; add occurrence TP/FP/FN and mismatch counts only for explicitly annotated
partitions. Evaluator functions retain the current `evaluate(binary, corpus, inline=True)` signature.

- [x] Write `test_source_paths_preserve_unquoted_configuration_detection`: optional `.ts` and `.env` fixture paths reach the real CLI; omitted `source_path` retains Text behavior. Reject absolute paths and parent traversal without printing row contents.
- [x] Write `test_occurrence_scoring_detects_missing_and_extra_findings`: expected and actual rule/location multisets match exactly; a line with one correct finding, one missing positive, and one extra finding records TP=1, FN=1, FP=1. Record-level success cannot erase these errors.
- [x] Write `test_occurrence_expectations_follow_inline_policy`: an ignored synthetic password has no expected normal-policy finding and one expected finding with inline ignores disabled; score both independently while retaining the original partitions' intentional policy-FP accounting.
- [x] Write `test_precision_partitions_remain_chunked_and_independent`: fields remain `text_parts`/`value_parts` chunks of at most eight characters; opaque positive values do not overlap partitions; original partitions remain untouched. Include all preview-derived reference forms in 18 occurrences across both partitions, with structural variation in held-out.
- [x] Run the evaluator unittest module before implementation; path metadata, occurrence metrics, path rejection, and new partitions failed as expected.
- [x] Implement optional source paths and repeatable `--corpus LABEL=PATH`, `--expected PATH`, and occurrence annotations with standard-library parsing. Derive rule/line/column from terminal metadata only; count multisets; reject malformed paths/annotations and incomplete scans; never print fixture values.
- [x] Create and review labeled partitions before the formal candidate evaluation: include 13 reference forms/18 occurrences, ternary selectors, code/text controls, isolated keys, credential comparisons, `allow_credentials`, provider markers, and unresolved aliases labeled unsupported with empty expected findings. Freeze hashes in fixture commit `bd397c4`; no held-out relabeling or threshold tuning was performed.
- [x] Keep unresolved bare aliases honestly labeled `supported=false` and retain them in record-level precision/recall. Candidate results have zero supported qualified-reference/key-expression extras and zero supported-positive misses; the frozen baseline has 10 and 7 supported extras in the two partitions.
- [x] Run unit and CLI tests, then evaluate preserved baseline and candidate on both fixed partitions with inline ignores enabled and disabled. Candidate occurrence results are 0 FP/0 FN for both; disabled inline policy adds exactly the annotated occurrence. `--check --expected target/precision-after-expanded.json` passes. The historical report remains unchanged; default historical comparison records the intentional quoted-reference rule eligibility change and is documented in the corpus README.

```sh
cargo build --locked --release
PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py \
  --binary target/precision-baseline-rayloc \
  --corpus precision-calibration=tests/corpus/detection/precision-calibration.jsonl \
  --corpus precision-held-out=tests/corpus/detection/precision-held-out.jsonl \
  --output target/precision-before-expanded.json
PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py \
  --binary target/release/rayloc \
  --corpus precision-calibration=tests/corpus/detection/precision-calibration.jsonl \
  --corpus precision-held-out=tests/corpus/detection/precision-held-out.jsonl \
  --output target/precision-after-expanded.json
```

- [x] Require zero FPs for supported qualified-reference/key-expression fixtures and zero supported-positive misses; check the frozen baseline and candidate on exact same fixture hashes and inspect per-partition occurrence changes. Preserve the historical report and known limitations. Keep the reviewed candidate report as the later `--expected` input.
- [x] Commit the evaluator change and tests as `test: evaluate source-aware detection precision by occurrence` (`6962b65`). Commit reviewed safe aggregate accuracy evidence with Task 6.

### Task 5: Measure the precision change without reducing scanned scope

**Files:** Create `scripts/context_precision_measure.py`, `tests/context_precision_measure.py`; modify `benches/README.md`. Reuse `scripts/e2e_measure.py`'s native RSS launcher and safe measurement conventions; add no runtime instrumentation to the scanner.

**Interfaces produced:** Script arguments `--binary LABEL=PATH` (repeatable,
requiring baseline and candidate), `--samples` (default 21), `--threads` (default
1 and 8 for directory cases), and `--output`. JSON includes executable/source/corpus
hashes, exact bytes, findings, exits, median/p95, peak RSS, hardware/toolchain/cache
metadata, per-workload ratios, and each spec gate outcome. Any incomplete sample
is an error rather than a speed result.

- [x] Write `test_precision_measurement_checks_scope_and_gate_boundaries`: fixed mock samples at 1.03 baseline time, +0.5 ms/+5% p95, and +256 KiB/+1% RSS pass exactly at their specified bounds and fail above them. Missing bytes, exit 2, missing expected positives, swapped executable labels, and invalid sample counts fail. Tests contain no actual benchmark timing assertions.
- [x] Run the new measurement-harness unittest module before implementation; import failed because the harness did not exist.
- [x] Implement the stdlib paired harness with alternating binary order, one untimed warmup per binary/workload, bounded fixture writing, native scanner-only RSS, and `scan --silent` parsing. Exact finding counts, exits, bytes, redaction, and diagnostics are checked for each binary. Custom cases stay below the 10,000-finding cap.
- [x] Cover the 16 MiB clean source, 16 MiB/4,096-reference source (directory batch path), a 6,000-baseline-finding dense file, a >512 KiB line with 256 references and an operator split at 256 KiB, generic accept/reject and unresolved alias controls, weak/equality passwords, provider/JOSE/marker/custom cases, 2,000 mixed files at one/eight workers, and 0/10/100/1,000 staged additions. Every positive has per-binary mandatory findings and byte assertions; candidate reference-only scopes have zero findings.
- [x] Run measurement unit tests and the paired CLI harness for 21 alternating samples. Run the 40-sample engine benchmark and full repository benchmarks in both baseline and candidate worktrees on the same host/toolchain. The native RSS tool excludes Python fixture memory; CLI timings include scanner startup/Git/report summary.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/context_precision_measure.py \
  --binary baseline=target/precision-baseline-rayloc \
  --binary candidate=target/release/rayloc --samples 21 --threads 1 8 \
  --output target/precision-performance.json
cargo bench
PYTHONDONTWRITEBYTECODE=1 python3 scripts/e2e_measure.py \
  --samples 3 --large-mb 1024 --output target/precision-e2e-extended.json
```

- [x] Confirm all spec gates across 14 paired workloads: candidate median ratios are 0.176–1.010, all large fixed medians are within 3%, every startup/staged p95 increase is below 0.5 ms, and every RSS change is within `max(256 KiB, 1%)`. No gate required a repeat. The engine microbenchmark is 7.720 ms candidate vs 7.637 ms baseline median (1.011x), with 8.228 vs 8.172 ms p95. Full scope benchmark 4,096-file/16-KiB cases measure 2.655/1.354/0.363 s candidate and 2.677/1.372/0.373 s baseline at 1/2/8 workers. Record the complete safe aggregate in Task 6; these are warm-cache local measurements, not universal speed guarantees.
- [ ] Commit as `perf: measure builtin precision without narrowing scan scope`.

### Task 6: Validate and document the completed change for approval

**Files:** Modify `README.md`, `docs/research/p4-context-jose.md`, `docs/technical-design.md`, `docs/development-decisions.md`, `benches/README.md`; create `docs/research/builtin-detection-precision-results.md` and `docs/research/builtin-detection-precision-results.json` from reviewed aggregate evidence.

- [ ] Document grammar hints rather than trusted code paths: exact suffixes, text/pathless fallback, non-binding ternary labels, retained credential comparisons, qualified-only/quote-sensitive references, unresolved bare values, unchanged strong fields including `allow_credentials`, literal/provider/custom criteria, and counter units. Document `rayloc:ignore`/`rayloc accept` with no new dummy/test exceptions and the corrected 95% lines/regions, 98% functions coverage gates. Keep provider-format and private-key-material work deferred.
- [ ] Run all repository-required checks and the MSRV suite:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo +1.85.0 test --locked --all
cargo bench
cargo coverage
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p detection_evaluator.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p context_precision_measure.py
```

The user's corrected spec gates are 95% lines/regions and 98% functions, matching
`cargo coverage`. Preserve those gates and exercise every new production helper;
do not exclude production functions to satisfy coverage. Run final benchmarks once for the final build;
repeat only for new changes or unresolved performance concerns.

- [ ] Re-run the accuracy checks against the reviewed candidate report with `--expected` and `--check`; confirm occurrence/recall/redaction gates. Record the final binary SHA and confirm it is the same binary measured for performance.
- [ ] Use the candidate Rayloc to re-preview vLLM and the equivalent Paperclip relative glob; source review is now authorized. Compare source/input hashes and occurrence locations, not just totals. With unchanged policy/input, all 18 verified members plus the one environment-selector error should disappear and the 24 literal/provider/marker occurrences should remain. Investigate drift without adding dummy exceptions, auto-accepting findings, or modifying target files.
- [ ] Produce safe results documenting changes, per-family/length/context confusion, occurrence counts, all performance/RSS gates, resource/error checks, and limitations. Do not commit raw preview output, positive values, or source excerpts. State whether any gate is unmet.
- [ ] Commit documentation/results as `docs: record builtin detection precision and performance`.
- [ ] Request review of the actual implementation and evidence before integration/release. Execution approval does not authorize publishing or merging.

## Plan review and execution boundary

The tasks cover all spec requirements: conservative association/reference evidence (1), operator/quote/field/rule
semantics and limits (2), every source/execution path (3), accuracy and negative
controls (4), runtime/RSS gates (5), and full verification/reporting (6).
Provider format tightening, private-key material validation, statistical models,
and full bare-symbol resolution remain outside this change. New dummy-literal
exceptions are explicitly excluded by the user's review.

The worktree and its earlier debug-build/test baseline already exist. The user
approved implementation and PR creation. Complete preparation and the six tasks
in order, updating these checkboxes as work lands and recording blockers or design
changes before proceeding. Request implementation review before creating the PR;
do not merge or release.
