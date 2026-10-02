# Development decisions

Recorded on 2026-10-01 for the first P1/P2 library slice. The user requires a test
for every function, production coverage exceeding 98%, and short standard-library
implementations in preference to external dependencies.

## Dependencies and detection

The implementation adds zero external crates. Core provider signatures use static
prefix/marker tables and short byte recognizers. All rules share the same bounded
reader and preserve complete spans, ASCII boundary checks, source order, and
positive/negative fixtures. A recognized span is visited once, preventing nested
compact-token prefixes from causing repeated suffix scans. Provider body minima
are explicitly scanner heuristics, with medium confidence where format lengths
have not been established as provider guarantees.

The core rules cover AWS access key IDs, the six documented GitHub prefixes,
Stripe secret/restricted test/live prefixes, Slack/GovSlack webhook domains, and
ordinary/RSA/EC/DSA/OpenSSH/encrypted private-key markers. They do not validate
credential activity, JOSE structure, AWS secret-access-key context, or generic
password/entropy candidates; those remain P3/P4 work.

The existing OS-native CLI parser stays in place and adds injectable output
boundaries for tests. Configuration, custom regexes, ignores, directory/Git modes,
and hooks remain unavailable through the CLI. The low-level library accepts
already-selected sources and does not imply policy discovery. P3 will assess a
bounded YAML implementation and a justified regex dependency against the full
schema/grammar requirements, retaining MSRV 1.85. Rayon remains the planned P5
parallelism backend under the repository's traversal contract.

## Secret lifetime and memory bounds

`RedactedString` discards input bytes at construction and retains only a private
marker. Match evaluation borrows the reader's source bytes; findings retain safe
source IDs, spans, fixed rule metadata, and a fully masked value. This is stronger
than copying a secret into a private vector solely to print `[REDACTED]` later.
Formatting has no raw getter, byte slicing, or serialization path. Reports omit
source excerpts and filenames until safe path rendering is implemented.

Regular files use a 256-KiB `BufReader`, lines are capped at 1 MiB, candidates at
64 KiB, and retained findings at 10,000. Line allocation grows geometrically but
never requests capacity above the line cap. A finding holds no credential copy.
Overflow is an incomplete scan with exit 2; scanning after finding overflow
continues counting detections while retaining the first source-ordered findings.
P5 must extend this to a bounded, globally deterministic parallel collector.

Explicit symlinks/non-regular files are rejected. Unix device/inode comparison
detects a substituted opened file. File selection checks are best effort under
concurrent filesystem mutation; atomic cross-platform no-follow opening and
snapshot guarantees are not claimed by this low-level API.

## Tests, coverage, and CI

Unit tests live outside production modules but are included with `#[cfg(test)]`
so private functions and failure paths remain testable. Integration tests run
the real CLI and therefore exercise both `main` and its stdio adapter.

`scripts/coverage.py` uses Python's standard library and installed compatible LLVM
executables to instrument Rust, merge unit/integration/child-process profiles,
and enforce >98% lines/regions plus 100% functions. Only test/support/benchmark
source is excluded; all production Rust is counted. A separate target directory
keeps instrumented builds apart from normal development and benchmarks.
[Rust coverage reference](https://doc.rust-lang.org/rustc/instrument-coverage.html).

The local Rust 1.88.0 compiler's profiles were successfully read by the installed
AMD LLVM 22 tools. CI installs Rust's matching LLVM tools and checks both stable
and Rust 1.85.0. The local machine has no Rust 1.85 toolchain; the newly added CI
configuration has not yet run on GitHub.

The release benchmark measures the core byte engine over a small, warm synthetic
corpus, including finding construction. It is a development baseline for this
slice, not a performance claim about complete v1 detection or staged scans.

## User decisions — 2026-10-02

These decisions supplement the initial library implementation. Approved choices
remain in force during implementation; pending questions are not approvals.

| Question | User answer | Recorded decision |
| --- | --- | --- |
| Q1: dependencies for YAML, regex, and Git-style ignores | "follow recommendation, using library is ok as YAML lib only use for parsing config file, does not affect performance." | Allow narrowly justified parsing/matching dependencies; prefer the standard library for short, correct implementations. YAML parsing belongs to policy loading, not per-line detection. Measure startup/configuration costs; parsing outside the detection loop does not make those costs zero. Verify selected dependencies against Rust 1.85 and record their justification. |
| Q2: YAML language | "follow recommendation" | Accept one document with ordinary mappings, sequences, and scalars. Reject anchors/aliases, merge keys, custom tags, duplicate/unknown fields, and multiple documents. Preserve schema version "1" and existing examples. |
| Q3: explicit configuration policy | Initially "use alternative"; clarified as "Merge configuration; keep repository .raylocignore" | Merge explicit `--config` over discovered configuration. Retain repository `.raylocignore`; external configuration does not replace ignore policy. |
| Q4: input-derived report metadata | "follow recommendation" | Initially use fixed categories and stable source/rule numbers for reports. Withhold raw custom IDs/descriptions and paths until safe rendering is implemented. Configuration failures use safe category/location numbers without snippets. |

P3's Q1–Q4 user-policy choices are confirmed. Parser selection, numeric budgets,
dependency graph/MSRV checks, and adversarial validation are engineering work,
not further requests for approval. Fix and regression-test the P2 `ghs_`
Base64url-hyphen span/candidate-limit defect before exposing CLI scanning.

## Later-package decisions and remaining question

Q5–Q10 were confirmed on 2026-10-02. Existing added-lines-only, redaction, error precedence,
tracked-file, and hook-preservation contracts remain in force.

| Question | Package | Status / user answer | Decision / pending recommendation |
| --- | --- | --- | --- |
| Q5: standalone entropy mode | P4 | "follow recommendation" after the entropy explanation | Use context-associated entropy detection for v1; standalone entropy detection is deferred. Provider signatures and strong password assignments remain independent branches. |
| Q6: generated-directory defaults and ignore priority | P5 | "These directories are usually ignore by .gitignore, we should just follow ignore priority .gitignore -> .raylocignore" | No automatic `target/`, `node_modules/`, or `vendor/` exclusions. Apply applicable repository `.gitignore` first, then higher-priority `.raylocignore`. Preserve tracked/explicit-file eligibility and Git-administration exclusion. Remove the unimplemented `exclude_defaults` setting from planned schema/examples. |
| Q7: glob matches all excluded by scanner policy | P5 | "follow recommendation" | Count regular-file matches before policy. If all are excluded, return 0 with zero scanned files and an explicit excluded-scope report. A glob matching no regular files returns 2. |
| Q8: active hooks directory and framework integration | P9 | "Use alternative. also research to use python's pre-commit package command setting to install our tools as well." | `rayloc hook install` selects Git's active hooks directory, including configured custom/shared `core.hooksPath`, without another opt-in. Preserve unmanaged hooks and idempotence. Prepare a Python pre-commit framework integration; see the research note below. |
| Q9: v1 platforms | P10 | "Linux and MacOS" | Prepare Linux musl and macOS artifacts; defer Windows. Retain the proposed x86_64/aarch64 architecture targets for those OSes, subject to matching validation. |
| Q10: distribution channels | P10 | "prepare both channels" | Prepare release archives/checksums and crates.io package validation/documentation, including revising `publish = false` when packaging is ready. Actual publication remains a separate release action. |

[Pre-commit integration research](research/pre-commit-integration.md) records the
proposed Rust-language hook manifest, installation commands, staged-scan scope,
and the framework's current `core.hooksPath` limitation. Integration remains P9
work; no framework hook has been installed or advertised as available.

For Q3, document and test field-level scalar/list/ID-conflict precedence during
P3 implementation; merging must not silently discard discovered fields or allow
duplicate rule IDs. No external ignore-policy replacement is selected. In staged
mode, discovered base configuration and repository ignore policy must still come
from the pinned index snapshot.

Other open gates can be resolved through implementation and measurement:
parser/regex/global memory budgets, bounded scope bookkeeping, deterministic
overflow collection, Git fixture isolation and compatibility, held-out corpus
partitions, calibrated thresholds, serial/parallel crossover, measured latency,
RSS, and binary size. P6/P8 patch/reference semantics are already specified.
