# Release-readiness baseline

Measured 2026-10-04 on Megalodon, AMD Ryzen 9 9950X (16 cores/32 logical CPUs),
Linux 7.1.13-2-MANJARO, rustc 1.88.0, Git 2.55.0. All ten built-ins/default
entropy and inline policy are active; files/staged work is serial, directory work
admits up to eight workers. Filesystem cache is warm from fixture creation plus
an untimed pass. No cache flushing or cold-cache claim. The
[complete JSON](release-baseline.json) records exact corpus sizes, executable
SHA-256, hardware and rule settings, family/context/length accuracy and all scope
measurements. See the [benchmark guide](../../benches/README.md) to reproduce.

Startup-inclusive latency uses a small native benchmark launcher, scanner startup,
policy, Git and rendering. Peak RSS comes from native wait4, including waited Git
children; Python fixture allocations are excluded. The 96-MiB-ballast regression
proves that boundary. Median is conventional; p95/p99 use nearest rank of 21
samples. Binary size is 2765632 bytes (stripped GNU-host executable,
not a musl/macOS release artifact).

| Workload | Bytes scanned | Median ms | p95 ms | p99 ms | Peak RSS KiB | MB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| directory_16MB | 16781312 | 23.729 | 24.793 | 28.184 | 4804 | 707.21 |
| file_gt10MB | 12000022 | 44.948 | 46.378 | 48.427 | 4908 | 266.98 |
| giant_line | 1048598 | 1.487 | 1.699 | 1.732 | 5712 | — |
| many_tiny | 38420 | 4.212 | 4.691 | 4.773 | 4856 | 9.12 |
| staged_lines0_files1 | 0 | 6.199 | 6.949 | 7.190 | 5316 | — |
| staged_lines0_files10 | 0 | 6.043 | 6.435 | 6.590 | 5308 | — |
| staged_lines1000_files1 | 18002 | 6.762 | 7.025 | 7.087 | 5576 | 2.66 |
| staged_lines1000_files10 | 18002 | 6.876 | 7.254 | 7.271 | 5576 | 2.62 |
| staged_lines1000_files100 | 18002 | 7.299 | 7.482 | 7.524 | 5328 | 2.47 |
| staged_lines100_files1 | 1802 | 6.435 | 7.113 | 7.153 | 5556 | 0.28 |
| staged_lines100_files10 | 1802 | 6.772 | 7.051 | 7.066 | 5592 | 0.27 |
| staged_lines100_files100 | 1802 | 7.278 | 7.423 | 7.803 | 5348 | 0.25 |
| staged_lines10_files1 | 182 | 6.148 | 6.606 | 7.874 | 5588 | 0.03 |
| staged_lines10_files10 | 182 | 6.573 | 6.903 | 7.083 | 5584 | 0.03 |

Every nonempty staged workload contains a supported finding, not only clean
records. The giant line deliberately returns 2 after one fully masked finding;
its unscanned remainder is not a throughput result. Staged bytes are added record
content excluding LF delimiters and patch framing. Many-tiny scope is 2,000 files
with 20 mandatory findings; directory throughput is 256 files/256 findings.

The separate extended run scanned 1,024,000,024 bytes (1.024 decimal GB) in
3.680 s median, 3.684 s slowest of three, at
278.24 MB/s and 4824 KiB peak RSS, with a finding
at the end. It supplies a bounded-memory observation, not a stable tail estimate.
The extended run preceded the new medium-directory case; its file fixture/rules
and RSS launcher are identical. Fixture creation and compilation are untimed.

Preloaded complete detection engine, 40 warm passes, one worker:
`engine: bytes=272384 samples=40 workers=1 median_ms=2.016 p95_ms=2.060 p99_ms=2.082 MB/s=135.11 findings=204800; precompiled 10 built-ins + custom, warm cache`. This exercises provider/JOSE/context/password/custom
acceptance, custom entropy, and directive/reference/checksum suppression. Rules
are precompiled. It excludes process/Git/filesystem/rendering. In-process scope
measurements cover 1/2/8 workers, ordinary bounded records plus one supported
finding per file, and pool/discovery startup. Five samples give p95/p99 equal to
the slowest observation; full results are in JSON. Both stretch goals—under 5 ms
startup-inclusive staged scans and 500 MB/s/core—remain unmet on this workload.

## Accuracy and regression gates

Held-out synthetic records retain TP49/FP1/FN1/TN19: 98% record precision and
recall. Calibration retains TP48/FP1/FN2/TN19: 97.9592% precision and 96% recall.
Normal held-out supported positives have zero misses. The calibration random
20-byte generic candidate remains a known empirical-threshold miss, and each
partition includes a password below the supported length. The false positive is
a public random example under a strong secret field name. No thresholds changed.
Per-provider/length/context counts and suppression effects are recorded in JSON
and the [detection report](detection-baseline.md).

Held-out clean bytes are only 780; one false positive means 1,282.05 per clean
decimal MB. This tiny denominator does not establish a real-world noise budget
or statistical guarantee. With inline ignores disabled, held-out FP rises to 3
and precision to 94.2308%; recall stays 98%. Normal suppressions remain inline 2,
placeholder 3, reference 3, checksum 3 and generic-filter 2 in each partition.

Mandatory supported Rust fixtures require 100% detection. Every leak assertion
requires zero complete synthetic values. `detection_baseline.py --check` now
requires the previously measured confusion/supported-miss and suppression counts
across both partitions and both directive policies; held-out supported misses
must remain zero. Intentional detection/policy changes require review of labels
and explicit baseline updates. Resource gates require correct byte/finding scope,
exit 2 on oversized lines/candidates/configuration/retained findings, and existing
bounded-streaming tests. For matching local hardware/rules/cache/corpus, a repeat
exceeding twice the recorded median latency or peak RSS is an investigation
trigger, rather than a new universal performance guarantee. Broader numerical
precision/noise gates require larger independent reviewed repositories first.

## Remaining release evidence

Local Rust 1.85, Git 2.30/current suites, mandatory formatting/Clippy/bench/coverage,
installed-package artifact smoke and source-package verification pass. Native
Linux musl x86_64/aarch64 and macOS x86_64/aarch64 execution/linkage remain CI gates.
Remote pinned-SHA pre-commit installation also belongs to those jobs. No release,
registry version, downloaded platform artifact or native macOS pass is claimed.

Deferred review observations remain: opaque numeric-prefix `ghs_` can consume an
`=suffix` delimiter; glob brace precheck rejects `[}]`; directory CLI compiles
root `.raylocignore` twice. These are compatibility/performance minors, recorded
for whole-branch review; measurements include the duplicate policy work. The
Git index-cache cancellation case remains a conservative incomplete-scan error;
fixing it requires a proven snapshot protocol rather than weakening race checks.
