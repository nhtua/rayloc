# Implementation and sub-agent review report

This report tracks the implementation, tests, independent review, and fixes for
P3–P10 of [the implementation plan](implementation-plan.md). A package closes
only after its acceptance evidence and review gate pass. Actual publication is
outside this implementation task.

| Package | Implementation | Independent review | Verification | Status |
| --- | --- | --- | --- | --- |
| P3 | Strict bounded YAML/merge, compiled custom rules/captured entropy, exclusions, explicit-file CLI (`f0729c4`) | Both findings fixed at `ebc63d2`; independent re-review approved | 59 tests on stable/1.85; functions 100%, lines 99.35%, regions 98.12%; required checks pass | Complete |
| P4 | Context/password/JOSE/suppressions (`cda4344`, `7a5185e`) | Four Important findings fixed; re-review approved; one Minor retained for final triage | 88 Rust +2 evaluator tests; functions100%, lines98.99%, regions98.08%; stable/MSRV and required checks pass | Complete |
| P5 | Bounded directory/glob scope and deterministic parallel collector (`9a7012b`, `e31e715`) | Two Important scope defects fixed; re-review approved; two Minor observations retained | 139 tests on current Git, Git 2.30 and Rust 1.85; functions 100%, lines 98.91%, regions 98.02%; required checks pass | Complete |
| P6 | Strict bounded raw-binding and unified-patch parser (`94d0588`, `39d359f`) | Hunk-gap/empty-side finding fixed; re-review approved | 158 tests, locked Rust 1.85; functions 100%, lines 98.96%, regions 98.18%; required checks pass | Complete |
| P7 | Pending | Pending | Pending | Not started |
| P8 | Pending | Pending | Pending | Not started |
| P9 | Pending | Pending | Pending | Not started |
| P10 | Release preflight research identifies native runners, linkage checks, Cargo package checks, and Git-floor tests | Pending implementation review | Native jobs and artifact smoke tests pending | Research only |

## P3

The implementing agent added bounded policy parsing, strict types, rule compiler
budgets, explicit configuration merging, safe numeric metadata, file exclusions,
and reusable captured-value entropy. It also corrected the complete GitHub
installation-token span. The independent reviewer confirmed those boundaries
and requested two fixes: return exit 2 for genuine Git discovery failures rather
than selecting nested policy, and restrict `/dev/full` testing to Linux.

Reported initial verification: formatting, strict Clippy, all tests, engine
benchmark, coverage, release build, and Rust 1.85 locked tests pass. The small
warm benchmark measured 800.89 MB/s; this is a development measurement, not the
complete v1 throughput result. Both findings are now fixed and independently approved. Genuine discovery
failures return exit 2, including missing Git inside a repository; only recognized
outside-Git cases fall back. Child diagnostics are bounded and withheld. A Unix
socket fixture replaces the Linux device assumption. Final 59 tests pass, with
100% function, 99.35% line, and 98.12% region coverage. No open P3 review findings.

## P4

The implementing agent added assignment/header context, alphabet/length entropy
heuristics, concrete password and AWS secret assignments, standard-library JOSE
validation, exact scoped suppressions, the CI inline-ignore switch, safe counters,
and provider-preferred span deduplication without new dependencies.

Independent review reproduced four defects. Regression tests now protect password
independence from checksum exclusions, candidate limits before suppression,
skipping disabled context branches, and rejection of padded GitHub app-token
prefixes. The reviewer approved the fix round; a numeric-prefix opaque-token
`=suffix` span edge case is recorded as Minor for final review.

The separately seeded synthetic corpus has 70 calibration and 70 held-out records.
Held-out precision and recall are 98%; calibration precision is 97.96% and recall
96%. Known cases include a public-example false positive, an unsupported short
password miss, and a calibration entropy miss. Thresholds were not tuned; this
small record-level evaluation does not establish real-repository accuracy. See
[detailed results](research/detection-baseline.md). Final verification passed all
required commands and actual Rust1.85 tests with 100% function, 98.9910% line,
and 98.0769% region coverage.

## P5

Directory and glob scans now apply layered Git and scanner ignore policy while
keeping tracked and explicitly selected files eligible. Bounded traversal and a
streaming tracked-file cursor feed a deterministic global collector. A reusable
Rayon pool starts for larger scopes; the measured tiny-file crossover selected
256 entries. [Scope measurements](research/p5-scope.md) record throughput, RSS,
resource limits, and slower dense-finding parallel scans.

Independent review found two scope-boundary defects. Regression tests and fixes
now exclude separate Git administration belonging to nested repositories before
file admission and reject selected directory symlinks even with trailing slashes.
The re-review approved both fixes. Two Minor observations remain for final triage:
a character-class brace can be rejected by the glob precheck, and the directory
CLI path compiles root scanner policy twice. The final 139 tests pass on current
Git, Git 2.30, and Rust 1.85; formatting, strict Clippy, benchmark, and coverage
gates pass at 231/231 functions, 98.9103% lines, and 98.0193% regions.

## P6

The pure parser validates authoritative NUL raw metadata and unified patch
framing before emitting only added bytes with new-side line numbers. Its tests
exercise type changes, quoted and non-UTF-8 paths, no-newline markers, malformed
records, exact size limits, and bounded adversarial hunk sequences. Independent
review found that mismatched old/new hunk gaps could invent source lines;
regressions now require equal omitted-context gaps and valid empty/EOF anchors.
The scoped re-review approved the fix.

All 158 tests, locked Rust 1.85, formatting, strict Clippy, benchmarks, and
coverage pass: 273/273 functions, 98.9600% lines, 98.1840% regions. P7 owns
Git process acquisition and binding the two streams. P8 must handle unknown
working-tree new object IDs explicitly; the pure parser validates pinned-tree
identities and does not claim working-tree acquisition support.
