# Development decisions

Recorded on 2026-10-01 for the first P1/P2 library slice. The original slice
required a test for every function, production coverage exceeding 98%, and short
standard-library implementations in preference to external dependencies.

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

`RedactedString` retains at most a 4-byte ASCII-printable prefix, never more
than a quarter of the value, and discards the rest at construction. Values under
8 bytes or with non-ASCII prefixes retain nothing. `Display` prints the prefix
and a fixed-width mask (`ghp_********`) so length is not disclosed; `Debug`
always prints `[REDACTED]`. Match evaluation borrows the reader's source bytes;
findings retain source IDs, spans, fixed rule metadata, and the masked value.
Formatting has no raw getter or serialization path. Reports omit source
excerpts. Paths are recorded only for sources with retained findings (bounded by
the findings limit) and only when valid UTF-8 without control or bidi formatting
characters and at most 4 KiB; otherwise reports fall back to source IDs.

The original P1/P2 slice used a 256-KiB `BufReader`, 1-MiB physical-line cap,
64-KiB candidates, and 10,000 retained findings. The current bounded scanning
design removes the built-in physical-line ceiling. It reads 256-KiB fragments,
and raw payload-buffer capacity is capped at 1.5 MiB per lane without legacy
whole-line rules and 2.25 MiB when such a rule is enabled. Captured candidates
remain limited to 64 KiB and retained findings to 10,000. Enabled custom rules
that require whole-line matching retain the 1-MiB compatibility budget; longer
lines yield exit 2 with
`custom rule requires whole-line input beyond compatibility limit`, while
supported rules continue scanning. A detected over-limit candidate also yields
exit 2. Long-line findings are held until line end for trailing inline-ignore
evaluation. A finding holds no raw credential copy. Finding overflow continues
counting detections while retaining bounded, deterministic findings.

Explicit symlinks/non-regular files are rejected. Unix device/inode comparison
detects a substituted opened file. File selection checks are best effort under
concurrent filesystem mutation; atomic cross-platform no-follow opening and
snapshot guarantees are not claimed by this low-level API.

## Tests, coverage, and CI

Unit tests live outside production modules but are included with `#[cfg(test)]`
so private functions and failure paths remain testable. Integration tests run
the real CLI and therefore exercise both `main` and its stdio adapter.

`cargo coverage` (a Cargo alias for `cargo llvm-cov`) instruments Rust, merges
unit/integration/child-process profiles, and enforces >=97% lines/regions plus
100% functions. It replaced a custom Python driver; cargo-llvm-cov is a
development tool, not a crate dependency. Only test/support/benchmark source is
excluded; all production Rust is counted. Its separate target directory keeps
instrumented builds apart from normal development and benchmarks. CI gates
coverage on stable because Rust 1.85 instruments trivial error-mapping closures
as separate functions.
[Rust coverage reference](https://doc.rust-lang.org/rustc/instrument-coverage.html).

CI installs Rust's matching LLVM tools and cargo-llvm-cov, runs every other check
on both stable and Rust 1.85.0, and runs the coverage gate on stable.

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

## P3 — strict policy and explicit-file scanning (2026-10-02)

The explicit-file CLI now loads repository-root `.rayloc.yaml` through Git; outside
Git it uses the canonical selected file's parent. Parent policy outside that root
is never inherited. Explicit `--config` overlays present scalar values, merges
entropy class keys, appends custom rules in document order, and unions disabled
IDs. Duplicate IDs within/across rule lists, collisions with built-ins, duplicate
keys and disables within a document fail. Disabled IDs are resolved against the
final merged registry, allowing explicit policy to disable a discovered custom
rule. Defaults apply after merging. The discovered root `.raylocignore` remains
in force. Explicit selection overrides Git ignore patterns but scanner ignores
and Git administration exclusions still apply; exclusions are counted and an
all-excluded file scope is labelled `EXCLUDED`. Symlinks/nonregular scan targets
and nonregular policy inputs are rejected.

YAML accepts one ordinary document and rejects anchors, aliases, tags, merge
keys, duplicate/unknown fields and unsupported schema IDs. YAML scalar types are
enforced: `version` is the string `"1"` (plain numeric `1` fails), IDs/patterns/
descriptions/severities are strings, entropy gates are unquoted numbers, and
capture indexes are nonnegative integer scalars. YAML 1.2 boolean/null/numeric
resolution is respected, including ordinary unquoted text strings. Every failure
is a fixed category; raw paths, input arguments, custom labels, snippets and child
stderr never enter diagnostics. Reports identify custom rules with stable numeric
IDs, fully mask values, and sort retained findings by source, line, byte span and
rule. Provider signatures bypass generic/custom entropy thresholds.

Dependencies were selected from their official manifests and validated by an
actual locked build/test on Rust 1.85.0, rather than trusting declarations alone:

- [`yaml-rust2` 0.13.0](https://github.com/Ethiraric/yaml-rust2/blob/v0.13.0/Cargo.toml)
  is the current release, declares Rust 1.85.0, and is used only for configuration
  parsing. Default encoding support is disabled: configuration must be UTF-8.
  Its event API allows resource accounting and forbidden-construct rejection
  before tree construction; a handwritten YAML grammar would be substantially
  larger and error-prone. The wrapper builds only bounded ordinary values.
- [`regex` 1.13.1](https://github.com/rust-lang/regex/blob/1.13.1/Cargo.toml) and
  [`regex-syntax` 0.8.11](https://docs.rs/crate/regex-syntax/0.8.11/source/Cargo.toml)
  are current releases with Rust 1.65 requirements. Regex features are `std`,
  `perf`, and `unicode`; byte matching retains ASCII secrets in non-UTF-8 sources.
  The direct syntax dependency reuses regex's existing dependency, adding no
  second syntax engine. HIR minimum lengths reject empty languages/matches;
  captured HIR maximum lengths and conservative alphabet unions prove impossible
  entropy gates without attempting arbitrary regex-language inference.
- [`ignore` 0.4.29](https://docs.rs/crate/ignore/0.4.29/source/Cargo.toml) implements
  the full Git ignore grammar, escaping, anchoring, negation and directory rules.
  Ancestor exclusion is checked explicitly so an ignored parent must be
  re-included before a descendant whitelist can take effect. Current 0.4.33
  declares Rust 1.88; 0.4.30 lacks a rust-version declaration but its let chains
  failed actual Rust 1.85 compilation. Version 0.4.29 passes. The lockfile also
  retains compatible `globset` 0.4.19; 0.4.20 requires Rust 1.88. No walker or
  parallel directory implementation is enabled through the CLI in P3.

Budgets are explicit and adversarially exercised:

| Resource | P3 limit |
| --- | --- |
| YAML/ignore read input | 1 MiB plus one overflow sentinel byte |
| YAML events / nesting depth | 8,192 events / 16 nested containers |
| Custom rule count / pattern size / aggregate pattern bytes | 256 / 16 KiB / 256 KiB |
| Rule ID bytes | 128 ASCII alphanumeric, dash or underscore bytes |
| Individual compiled regex / shared set | 256 KiB / 16 MiB |
| Aggregate individual program budget | At most 256 × 256 KiB = 64 MiB |
| Lazy DFA cache per regex or set | 256 KiB (at most 64.25 MiB across 256 rules plus set) |
| Regex syntax nesting | Engine's bounded default of 250 |
| Ignore lines / per-line size / aggregate text | 1,024 / 16 KiB / 256 KiB |
| Git root discovery output | 1 MiB; overflow kills/reaps child and fails |
| File fragment / Git structural metadata / captured candidate | 256 KiB / 1 MiB / 64 KiB |
| Physical source line | No built-in length ceiling; 1-MiB compatibility cap for enabled legacy custom regexes |
| Raw payload-buffer capacity per lane | 1.5 MiB without legacy storage; 2.25 MiB with it |
| Retained findings | 10,000 globally within the explicit-file scan |

Regex/ignore input and compiler budgets are bounds, not exact whole-process RSS
claims. Parsing and compilation occur before any selected file reader starts.
Custom rules match physical byte records only; they cannot match across lines.
An absent optional capture and an empty captured value produce no finding.
Optional entropy measures captured bytes with a reused 256-bin `usize` histogram
and `f64` comparisons. Length/alphabet impossibility checks are conservative for
Unicode: uncertain alphabets permit all 256 byte values rather than rejecting an
attainable gate. Generic class overrides are validated/stored for P4's context
branch, not applied to provider signatures. Both documents and programmatic
numeric policy are validated before registry compilation.

P3 preserves built-in-only `scan_reader`/`scan_file` and adds registry-aware reader
and file entry points. P4 owns context, JOSE, inline exclusions and deduplication;
P5 owns multi-source globally ordered overflow selection. P3 retains the bounded
collector's first evaluated detections on overflow and returns exit 2, with
retained output sorted by source location. Directory/glob/Git-target/hook modes
remain unavailable. The P2 `ghs_` hyphen truncation and candidate-limit bypass are
fixed and covered by a red/green regression.

Local P3 release measurements (30 independent launches per scope, one clean
physical line outside Git, includes Git root-discovery fallback and CLI startup):
0 custom rules: median 0.967 ms; 32 custom rules: median 1.551 ms; 256 custom rules: median 4.125 ms.
The stripped local release executable is 2,458,424 bytes. The required
synthetic engine benchmark scanned 2.212 MB in 0.0028 s (800.89 MB/s, one
thread); these local warm measurements are development evidence, not whole-v1
acceptance or held-out detection-quality claims.

## P10 — release readiness (2026-10-04)

The complete v1 CLI is implemented. Earlier scaffold-only statements above are
historical slice descriptions. Production dependencies remain the justified
YAML/regex/ignore/glob/Rayon set; P10 adds no Rust dependency. The C program under
`scripts/` is a benchmark-only launcher compiled by `cc`, not a scanner runtime
requirement. It measures native scanner RSS without inheriting Python's fixture
heap; a 96-MiB ballast regression exercises that measurement boundary.

The fixed synthetic detection confusion/suppression counts now form an explicit
regression gate; numerical quality claims remain limited to that corpus. Warm
startup-inclusive file/directory/staged and extended 1.024-GB measurements are
recorded in [release baseline](research/release-baseline.md). Under 5-ms staged
latency and 500MB/s/core are still stretch goals. Files exceeding 10 MB continue to
stream; observed RSS remains bounded for the extended file workload.

Cargo publishing is restricted to crates.io and a narrow package include list
retains production/test/bench/source-validation inputs while excluding worktrees,
coordination notes, CI files and generated outputs. Package validation and a
publication dry run do not authorize publication. Native release CI prepares
four Linux-musl/macOS architecture archives, executes extracted binaries and
actual linkage gates, collects checksums and tests source installs on 1.85.
Runtime support for those platforms requires green native jobs at the exact
release SHA. Local GNU-host evidence cannot replace musl/macOS evidence. No
published release or Cargo registry install is advertised.

## Bounded physical-line scanning measurements (2026-10-06)

The bounded scanner adds no dependencies and removes the built-in physical-line
ceiling while keeping raw payload-buffer capacities within 1.5 MiB per lane, or
2.25 MiB when an enabled legacy whole-line custom regex requires compatibility
storage. That fallback remains capped at 1 MiB and returns an explicit exit-2
incomplete-scan error beyond the cap while supported detectors continue. Raising
the fallback cap is an interim choice that increases input-sized memory and
retains a larger cutoff.

The benchmark compared the PR #15 1 MiB cap, experimental 5/10 MiB caps, and the
active chunk implementation on the same sparse minified-line fixtures. Chunking
completed all measured 1–256 MB files at about 129–206 MB/s with 5.3–5.6 MiB
peak process RSS; whole-line variants reached about 398–500 MB/s within their
configured limits and used more RSS as lines grew. The ordinary 272-KiB engine
benchmark medians were 3.182 ms on baseline and 3.333 ms with chunking (4.74%
slower). A separate 256-file/16-KiB-per-file one-worker scope benchmark measured
40.36–41.60 ms on baseline and 48.31–48.85 ms with chunking (16–21% slower),
exceeding the 10% scope gate. This scope regression remains unresolved. These
are warm synthetic results, not dense-finding, custom-regex, Git-patch, 1-GiB,
cold-cache, or real-repository claims. See the
[full report](research/byte-chunk-scanning-results.md) and its JSON data.

A new artifact characterization found that staged edits completely reversed in
the workspace can cause Git to rewrite its index cache during direct-diff
acquisition. Existing stamp validation safely returns 2. Optional-lock/config
switches did not resolve the observation on local Git 2.55 or2.30, so no race
safeguard was weakened; this remains a documented conservative limitation.
Deferred P4/P5 delimiter/glob/duplicate-ignore-compile minors are recorded in the
release baseline for final whole-branch review.
