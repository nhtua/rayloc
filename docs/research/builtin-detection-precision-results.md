# Builtin detection precision results

Date: 2026-10-08. Candidate: `6962b651842f18fc76bc74cf59f04d297c04c17d`; frozen baseline: `b0ecc6ebebc81fbe42d7aeb495929ea04c2ca1ee`.

## Accuracy

The new calibration and held-out fixtures each contain 19 annotated records.
Calibration has 8 supported positive occurrences and 11 negatives; held-out has
8 supported positive occurrences and 11 negatives. The fixture SHA-256 values
are recorded in the [JSON aggregate](builtin-detection-precision-results.json).
Only safe occurrence locations and rule IDs are compared; fixture values are
not included here.

| Partition and policy | Baseline TP / FP / FN | Candidate TP / FP / FN | Candidate precision / recall |
| --- | ---: | ---: | ---: |
| Calibration, inline ignores enabled | 7 / 10 / 1 | 8 / 0 / 0 | 100% / 100% |
| Held-out, inline ignores enabled | 7 / 7 / 1 | 8 / 0 / 0 | 100% / 100% |
| Held-out, inline ignores disabled | — | 9 / 0 / 0 occurrences | record-level policy FP: 1 |

Baseline false positives were 10 and 7 supported-negative occurrences,
respectively; each partition also missed one supported-positive comparison.
The candidate produced no supported-positive misses, no supported-negative
extras, and no occurrence mismatches in either partition. It retained the
positive controls for weak passwords, opaque values, strong suffix fields,
credential comparisons, providers, private-key markers, and text-mode
assignments. The inline-disabled held-out result includes the explicitly
annotated ignored-line occurrence, as expected.

These compact synthetic partitions validate the reviewed grammar cases. Their
perfect candidate score is not an estimate of accuracy on arbitrary
repositories. The [committed evaluator report](detection-baseline.json) was
refreshed for CI after reviewing the older corpus: two quoted password literals
per partition now count as false positives against the preserved labels, and
reference suppressions fall from three to one. Positive predictions are unchanged.
The [baseline notes](detection-baseline.md) preserve the original P4 measurements
and explain the refreshed counts. Expanded checks explicitly compare against the
reviewed candidate report.

## Performance and resource use

The immutable release binaries have equal size (3,015,488 bytes). Baseline SHA-256
is `c049db280880dc6ca7d3dea3cc901a27a388a5e863e17b1ef0492900fef935e7`; candidate
SHA-256 is `66645a2e7ecdb9ae77e32966397ff177f5e0170c48ea55f0b2fe277a3b91b8b4`.
That candidate hash is the binary measured in the 21-sample paired run.

All 14 paired latency and RSS gates passed. Large workload median ratios ranged
from 0.176× to 0.984× baseline. Startup/staged ratios ranged from 0.862× to
1.010×; the largest p95 increase was 0.070 ms. Every peak-RSS delta remained
within `max(256 KiB, 1%)`. Both binaries processed the same fixture byte counts;
the harness asserted expected findings and exit status per workload. Workloads
included clean and reference-heavy 16 MiB sources, dense associations, a 600 KiB
single line crossing the 256 KiB boundary, 2,000-file directories at 1/8
workers, staged scopes, and password/provider/JOSE/custom-rule controls.

The 40-sample engine benchmark measured 7.637 ms baseline versus 7.720 ms
candidate median (1.011×), with p95 of 8.172 ms versus 8.228 ms. The full scope
benchmark's 4,096-file, 16 KiB-per-file medians were 2.677/1.372/0.373 seconds
baseline and 2.655/1.354/0.363 seconds candidate at 1/2/8 workers. These are
warm-cache measurements from the recorded host, not cold-cache or universal
performance guarantees. Per-workload timings, percentiles, bytes, findings, RSS,
host details, and gates are in the [safe JSON aggregate](builtin-detection-precision-results.json).

## Original preview scope comparison

Both binaries were run against the same current repository snapshots and exact
preview scopes. The baseline/candidate pairs were compared as sets of
`(relative path, line, byte column, rule ID)`, with no match values retained in
this report. There were no added locations.

| Scope | Baseline findings | Candidate findings | Removed locations | Unchanged locations |
| --- | ---: | ---: | ---: | ---: |
| vLLM repository preview | 8 | 0 | 8 | 0 |
| Paperclip `server/src/services/*.ts` | 35 | 24 | 11 | 24 |

The vLLM removals were at `examples/applications/rag/retrieval_augmented_generation_with_langchain.py:183:25`, `examples/applications/rag/retrieval_augmented_generation_with_llamaindex.py:58:25`, `rust/src/cmd/src/cli.rs:640:32`, `tests/utils.py:705:21`, `tests/utils.py:715:21`, `tests/utils.py:725:21`, `tests/utils.py:734:46`, and `vllm/entrypoints/serve/middleware/register.py:27:27`; all had rule ID `context-secret`.

Paperclip removals were `ai-provider-routing.ts:31:57`, `chat-channels.ts:7643:24`, `local-ai-credentials.ts:44:55`, `setup-token-transport-binding.ts:350:68`, `tool-access.ts:15786:26`, `tool-access.ts:1634:25`, `tool-access.ts:2267:25`, `tool-gateway.ts:4246:54`, `tool-gateway.ts:4991:54`, `tool-gateway.ts:5033:59`, and `vercel-connect.ts:259:17`. Ten were `context-secret`; the `chat-channels.ts` occurrence was `password-assignment`. Candidate locations and rule IDs matched the other 24 baseline findings exactly.

The vLLM snapshot was at `6ad2e06c4a5bdd878977dfccc7443831e4fdc889`; its tracked-index manifest SHA-256 was `f0649c73dc03b5c134682c307ec4422c7ca7d2534fc796eaae02e50e96a2eaa8`. Paperclip was at `ceabc3bc880676c49eee907a8d736f961a1358eb`; the tracked manifest for `server/src/services/*.ts` (863 entries, of which Rayloc completed 612 after configured exclusions) hashed to `f70f39ec07e86f85a96a2a28b74e369049fc3d6b6c19627e31777826f07a8ef8`. The manifest hashes cover Git index paths, modes, and object IDs; they identify the committed input snapshot without copying source content into this report.

## Scope and limits

The source hint selects bounded lexer behavior for supported code suffixes; it
does not parse a language, resolve symbols, or infer data flow. No runtime
dependency or network call was added. Provider formats and private-key material
validation were not expanded. No target-repository source excerpts or raw
preview output are included in this report.

Final verification passed: formatting, strict Clippy, all tests on the active
toolchain and Rust 1.85, the full benchmark suite, both Python evaluator suites,
and the candidate accuracy comparison. Production coverage was 96.61% lines,
95.34% regions, and 99.50% functions against gates of 95%, 95%, and 98%.
`cargo coverage` itself returned an unrecognized-subcommand error in this
environment; the equivalent `cargo llvm-cov` command with the exact configured
exclusions and thresholds completed successfully. The JSON aggregate records
the command and results.
