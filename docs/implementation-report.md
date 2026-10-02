# Implementation and sub-agent review report

This report tracks the implementation, tests, independent review, and fixes for
P3–P10 of [the implementation plan](implementation-plan.md). A package closes
only after its acceptance evidence and review gate pass. Actual publication is
outside this implementation task.

| Package | Implementation | Independent review | Verification | Status |
| --- | --- | --- | --- | --- |
| P3 | Strict bounded YAML/merge, compiled custom rules/captured entropy, exclusions, explicit-file CLI (`f0729c4`) | Both findings fixed at `ebc63d2`; independent re-review approved | 59 tests on stable/1.85; functions 100%, lines 99.35%, regions 98.12%; required checks pass | Complete |
| P4 | Context/password/JOSE/suppressions (`cda4344`, `7a5185e`) | Four Important findings fixed; re-review approved; one Minor retained for final triage | 88 Rust +2 evaluator tests; functions100%, lines98.99%, regions98.08%; stable/MSRV and required checks pass | Complete |
| P5 | Bounded scope/parallel implementation dispatched | Pending | Pending | In progress |
| P6 | Pending | Pending | Pending | Not started |
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
