# First reproducible detection baseline — 2026-10-02

P4 evaluated the real release CLI against 70 calibration and 70 separately held-out
synthetic records. Opaque bodies are generated from different seeds; fixed format
markers and published placeholders recur. Labels were fixed before evaluation.
No threshold was tuned using either partition. The results are record-level
accuracy on this small corpus, not estimates for real repositories or live
credential validity. All supported mandatory Rust fixture assertions pass;
this broader corpus deliberately includes policy exclusions and known limitations.

Reproduce from the repository root:

```sh
cargo build --release
PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p detection_evaluator.py
```

The evaluator runs each fixture in an isolated temporary directory with inherited
Git environment removed, checks raw fixture-value leakage, and evaluates both
normal inline policy and `--no-inline-ignores`. The committed
[detailed results](detection-baseline.json) include corpus SHA-256, family,
context, byte-length, suppression and clean-byte metrics. The corpus and label
semantics are in [the corpus README](../../tests/corpus/detection/README.md).

| Partition / policy | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Calibration, normal | 48 | 1 | 2 | 19 | 97.9592% | 96% |
| Held-out, normal | 49 | 1 | 1 | 19 | 98% | 98% |
| Calibration, no inline ignores | 48 | 3 | 2 | 17 | 94.1176% | 96% |
| Held-out, no inline ignores | 49 | 3 | 1 | 17 | 94.2308% | 98% |

The common false positive is a documented public random example under `api_key`:
context and entropy cannot establish whether a literal is actually sensitive.
Both partitions contain one false negative for a concrete password shorter than
the supported eight-byte minimum. Calibration has one additional false negative
for a supported 20-byte Base64-class generic value below the provisional empirical
entropy threshold. Held-out supported positives all pass; this does not validate
that threshold statistically. The standalone entropy branch remains deferred.

| Family | Calibration TP / FN | Held-out TP / FN |
| --- | ---: | ---: |
| AWS ID / secret assignments | 3 / 0 | 3 / 0 |
| GitHub opaque / app forms | 7 / 0 | 7 / 0 |
| Stripe | 4 / 0 | 4 / 0 |
| Slack | 2 / 0 | 2 / 0 |
| Private-key markers | 6 / 0 | 6 / 0 |
| JWS / unsecured / JWE | 3 / 0 | 3 / 0 |
| Generic hex | 5 / 0 | 5 / 0 |
| Generic alphanumeric | 5 / 0 | 5 / 0 |
| Generic Base64 | 4 / 1 | 5 / 0 |
| Generic other bytes | 5 / 0 | 5 / 0 |
| Supported password assignments | 4 / 0 | 4 / 0 |
| Short passwords, outside supported minimum | 0 / 1 | 0 / 1 |

Each normal-policy partition records two inline suppressions, three placeholders,
three references, three checksum contexts and two generic homogeneity/sequence
filters. Disabling directives changes two deliberately ignored records to policy
false positives per partition; the other suppression counts remain unchanged.
These are reason counts with different units, described in
[the detection contract](p4-context-jose.md), not a claim that every exclusion
would otherwise be a detection.

There are only 756 calibration and 780 held-out clean bytes. The corresponding
1,322.75 and 1,282.05 false positives per clean decimal MB are arithmetically
correct but unstable tiny-denominator metrics. The corpus does not establish a
real-world false-positive budget; reviewed clean repositories and substantially
larger independent data are still needed before choosing numerical quality gates.

Validation also includes the full mandatory Rust suite, strict formatting/Clippy,
locked Rust 1.85 and all-function production coverage. The existing release
`cargo bench` driver reported 298.87 decimal MB/s over 2.212 MB accumulated across
40 passes and 40,960 findings on one thread. This is an in-memory provider-focused
microbenchmark, with lazy registry startup included once, not an end-to-end,
complete-workload, cold-cache or latency-percentile claim. Environment: AMD Ryzen
9 9950X, Linux 7.1.13-2-MANJARO, rustc 1.88.0. New context/JOSE accuracy has been
measured; representative per-branch throughput remains later benchmark work.
