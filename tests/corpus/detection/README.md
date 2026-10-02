# First detection corpus

`calibration.jsonl` and `held-out.jsonl` each contain 70 fixed, manually labeled
synthetic records. Opaque bodies were generated with separate deterministic seeds
817 and 2317. Full generated opaque values are separate between partitions; fixed
format markers and published placeholders necessarily recur. No threshold was
tuned after viewing either partition. This is a held-out value partition, not a
held-out repository benchmark or a statistical quality guarantee.

Labels describe sensitivity/policy of the synthetic fixture. `secret=true` means
this record stands in for a credential; `supported` distinguishes a supported
branch from an intentionally short password or documented public example.
Inline-ignore records have clean labels under the default policy and therefore
become intentional policy false positives with `--no-inline-ignores`.

Generic family labels refer to the generator alphabet; actual class selection
uses byte composition with hex/alphanumeric/Base64/other precedence. Generated
Base64/other samples can contain only alphanumeric bytes.

Coverage includes provider signatures, context/length/alphabet classes, weak
passwords, escaped strings, checksum/reference/exact placeholder exclusions,
malformed compact JOSE, directives and known limitations. Random generic values
can fail a provisional empirical-entropy gate despite being labeled secrets;
this is counted honestly as a false negative. Public random examples under strong
secret field names illustrate a false positive. No token is a live credential and
no activity was verified. Labels and predictions are at record level, not
per-occurrence span matching.

Run `cargo build --release` then
`PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py`.
The evaluator runs the real binary in isolated temporary directories without
inherited Git environment, checks fixture-value leakage, and outputs safe
aggregate confusion/precision/recall, per-family/context/length results,
false positives per clean decimal MB, suppression counts and corpus SHA-256.
Use the separate mandatory Rust fixtures for the supported-format regression
gate; this corpus measures broader labeled accuracy, including limitations.
