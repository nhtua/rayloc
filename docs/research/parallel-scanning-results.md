# Directory-scan parallelism

Measured 2026-10-06 on AMD Ryzen 9 9950X (16 physical / 32 logical CPUs),
Linux 7.1.13-2-MANJARO, rustc 1.88.0. Release executable: 2,835,264 bytes,
SHA-256 `273d279bc37c0c928a6843079da629be676f9d4f63c1f8578fdfe23546f75b8d`.
All measurements are warm-cache, after one untimed scan, with no cache flush.
The harness runs cases sequentially, checks files/bytes/findings/exclusions/exit
and redaction for every sample, and reports median and nearest-rank p95 wall time,
median user/system CPU, and peak RSS. Fifteen timed samples were used for the
thread matrix. Synthetic fixtures contain no real credentials.

| Workload | Bytes | Threads | Median ms | p95 ms | Median user ms | Median system ms | Peak RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 files, 4 MiB each | 134,217,728 | 1 | 1,040.36 | 1,084.41 | 1,030.19 | 10.98 | 24,048 |
| 32 files, 4 MiB each | 134,217,728 | 2 | 592.28 | 624.90 | 1,145.87 | 9.98 | 24,048 |
| 32 files, 4 MiB each | 134,217,728 | 8 | 170.65 | 197.68 | 1,291.65 | 10.99 | 24,048 |
| 32 files, 4 MiB each | 134,217,728 | 16 | 111.34 | 137.01 | 1,605.65 | 19.04 | 24,048 |
| 32 files, 4 MiB each | 134,217,728 | 32 | 94.36 | 116.63 | 2,678.31 | 21.03 | 24,048 |
| 256 uniform files | 134,217,728 | 1 | 1,038.71 | 1,131.97 | 1,023.50 | 9.98 | 24,048 |
| 256 uniform files | 134,217,728 | 8 | 169.12 | 185.35 | 1,311.82 | 11.97 | 24,048 |
| 256 uniform files | 134,217,728 | 16 | 107.75 | 114.47 | 1,619.31 | 14.97 | 24,048 |
| 256 uniform files | 134,217,728 | 32 | 92.71 | 99.54 | 2,725.27 | 27.31 | 24,048 |
| 256 clustered files (32 large first) | 134,447,104 | 1 | 1,039.52 | 1,072.74 | 1,026.10 | 8.97 | 24,044 |
| 256 clustered files (32 large first) | 134,447,104 | 8 | 167.77 | 185.06 | 1,286.97 | 11.58 | 24,044 |
| 256 clustered files (32 large first) | 134,447,104 | 16 | 119.16 | 133.40 | 1,631.51 | 13.88 | 24,044 |
| 256 clustered files (32 large first) | 134,447,104 | 32 | 100.28 | 120.34 | 2,620.71 | 18.99 | 24,044 |
| 256 tiny files in 32 directories | 65,536 | 1 | 2.29 | 2.37 | 1.31 | 0.94 | 24,048 |
| 256 tiny files in 32 directories | 65,536 | 8 | 1.68 | 1.86 | 2.31 | 1.09 | 24,048 |
| 256 tiny files in 32 directories | 65,536 | 32 | 2.41 | 2.49 | 2.69 | 8.45 | 24,048 |

The original 32-file gate ignored `RAYON_NUM_THREADS`: before the change, the
same 32 × 4 MiB workload measured about 1.05 seconds at 1, 8, and 32 environment
threads. The new byte admission plus dynamic claiming reduces its median by
6.1× at eight threads and 11.0× at 32. At 32 threads it uses roughly twice the
aggregate CPU of eight for 1.8× lower elapsed time. The automatic default
therefore remains eight; explicit thread selection is available for users whose
workloads benefit from more.

The equal-byte clustered and uniform cases are within 1.01× at eight threads
and 1.08× at 32, meeting the local 1.5× balancing target. Tiny-directory
latency remains within 1 ms of the serial result. Maximum observed RSS stays
around 24 MiB across worker counts; this is process-level peak RSS, not an
isolated estimate of scanner-owned buffers.

For the admitted 32-file case, one thread used the serial lane without creating
a pool; requests for 2/8/16/32 configured a private pool of that size. Dynamic
claiming caps active file work at the lesser of the pool size and eligible files
in each batch. The 800-finding, eight-file fixture remained below both
admission thresholds and created no pool (one active lane), despite a request
for eight.

The repository checkout was also scanned once per setting with the release
binary: 109/109 files, 894,357 bytes, 22,211 lines, 76 redacted findings, and
exit 1 were identical at 1/8/32 threads. Wall time was 81.1/62.9/61.2 ms.
This one-pass check is not a stable benchmark and is not the user's exact
five-second corpus. That reported workload remains unidentified and unverified.

The output probe produced 800 findings in 2.5–2.7 ms with an immediately drained
pipe. An intentionally throttled pipe reader (10 ms per read) raised median wall
time to 133 ms. This isolates a slow-sink ceiling; a printer thread could let
scanning finish earlier, but cannot shorten time needed to drain the same output.
The bounded producer/consumer scan queue and asynchronous reporter are deferred
until profiling a matching real workload shows discovery or output materially
dominates. Current measured scans are already sub-3 ms for tiny directory trees
and the primary large-file workload is CPU-bound.

The separate `single_large` fixture remains single-file sequential work by
design. Parallelizing records within a file needs a separate design that
preserves streaming, line boundaries, offsets, and partial-read semantics.
