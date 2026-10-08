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

`precision-calibration.jsonl` and `precision-held-out.jsonl` add source suffixes
and exact expected occurrences for this source-aware detector change. Their
`expected_findings` arrays contain only rule IDs and 1-based line/byte-column
locations; `expected_findings_no_inline` independently describes the
`--no-inline-ignores` policy when present. Each row's optional `source_path` is a
safe basename passed to the real scanner, so `.py`, `.rs`, `.ts`, and `.env`
exercise the same suffix selection used for repository files. Omitted paths keep
the original pathless Text behavior. Opaque positive values are distinct across
the two new partitions. Unresolved bare aliases remain unsupported observations
with their labeled expected finding list; they are included in record-level
precision/recall and are not used to waive supported occurrence errors.
The frozen partition SHA-256 values are `f4ea1e3bde4ea0d68d102069f771b9be4ad4d291b5147b6421b84a74c110e893`
for calibration and `24afc5096207825f2544edf7e36309d0ff2625055ef74ca495b0caf892b3186c`
for held-out.

For these explicitly annotated partitions the evaluator compares multisets of
`{rule, line, column}` records and reports occurrence TP/FP/FN, mismatching-row
count, supported-positive misses, and supported-negative extras. `--corpus
LABEL=PATH` adds an independent JSONL partition. `--expected PATH` selects the
report compared by `--check`; the historical committed report remains the
default. Invalid, absolute, or traversing source basenames and incomplete scans
are evaluation errors. Reports contain aggregate metadata only and never print
fixture values.
The original record report stays frozen. Its two quoted-reference labels now
produce intentional record-level drift because quoted programming-looking text
is eligible as a literal; compare subsequent builds with a reviewed candidate
report via `--expected` rather than rewriting the historical report.

Committed records store `text_parts` and `value_parts` as strings of at most
eight characters. The evaluator joins them only at runtime, writes the original
source bytes to isolated temporary files, and still checks the complete expected
value for output leakage. This keeps complete credential-shaped synthetic
fixtures out of Git history without weakening detection or changing labels.
Corpus SHA-256 values identify the stored chunked JSONL representation.

Run `cargo build --release` then
`PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py`.
The evaluator runs the real binary in isolated temporary directories without
inherited Git environment, checks fixture-value leakage, and outputs safe
aggregate confusion/precision/recall, per-family/context/length results,
false positives per clean decimal MB, suppression counts and corpus SHA-256.
Use the separate mandatory Rust fixtures for the supported-format regression
gate; this corpus measures broader labeled accuracy, including limitations.
