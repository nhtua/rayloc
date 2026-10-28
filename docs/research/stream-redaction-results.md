# Stream redaction measurements

Preliminary local measurement on Linux 7.1.13, x86-64, AMD Ryzen 9 9950X,
Rust 1.88.0, intermediate release build with SHA-256
`b4a86e24d87816ca311b236bf5373c259e84d1a63400d1c9dee5c2bf2250e37a`.
The invocation used default policy outside a Git
repository and wrote filtered output to `/dev/null`; each size was measured
once, so these are observations rather than a stable performance baseline.

| Input | Elapsed | Throughput |
| --- | ---: | ---: |
| 16 MiB, clean newline-delimited text | 0.853 s | 19.67 MB/s |
| 128 MiB, clean newline-delimited text | 6.590 s | 20.37 MB/s |

The unchanged base scanner's `cargo bench --bench engine` reported 33.44 MB/s;
the candidate reported 33.96 MB/s on the same mixed-rule fixture (40 warm
samples each, separate runs). Its workload, reporting, and input differ from
the stream measurements, so these numbers do not compare stream redaction to
file scanning. Repeated latency measurements remain to be measured before
making performance claims.

The `scripts/measure_redaction.py` harness subsequently measured three 16 MiB
file runs and verified each output digest. Clean runs ranged from 18.40 to
19.07 MB/s; synthetic-token runs ranged from 47.17 to 49.31 MB/s. `wait4`
reported peak RSS of approximately 21–22 MiB, which may include the forked
Python process before `exec` and should not be treated as a precise measurement
of Rayloc alone. These are local measurements, not a release performance gate.

A second intermediate release build (SHA-256
`375cb8171fc91575b12348f1f4f48736093d1621a81d80d51fb520adec259d39`)
measured 19.35–19.65 MB/s for clean records and 49.38–49.70 MB/s for
synthetic-token records over three 16 MiB samples, with validated output digests.

One 128 MiB sample with the same harness produced 18.64 MB/s for clean records
and 46.72 MB/s for synthetic-token records; peak RSS was approximately 22 MiB
for each. Both runs validated the redacted output digest.

A single 16 MiB-per-channel command-mode sample validated each output digest
and achieved a combined 37.00 MB/s for clean records and 81.24 MB/s for
synthetic-token records. This includes the two producer processes and is not
directly comparable to the single-file measurements.

A debug regression test with 10,001 adjacent synthetic private-key blocks on
one record now reaches the finding limit in about 0.01 seconds. The original
marker search repeatedly scanned the remaining record and was interrupted after
more than 15 seconds; the revised search advances through marker prefixes once.

The approved strict coverage gate requires 97% lines and regions and 100% of
functions. The unchanged base measured 96.61% lines, 95.32% regions, and 99.50%
functions. The implementation measured 96.14% lines, 95.04% regions, and
97.77% functions on an intermediate revision, so the strict gate was not met.
No production paths were excluded from coverage.
