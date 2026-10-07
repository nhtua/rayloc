# Secret scanner speed comparison

Measured on 2026-10-07 using the installed scanner binaries and the eight repositories specified in `speed-test-instruction.md`.

## Requested pivot table

| Aspect | rayloc ⭐ | trufflehog | gitleaks | betterleaks |
| --- | --- | --- | --- | --- |
| Avg elapsed time per MB (s/MB) | 0.008240 (+88.36%) | 0.065088 (+8.05%) | 0.070790 (0%) | 0.008976 (+87.32%) |
| Avg CPU time per MB (CPU s/MB) | 0.044926 (+91.56%) | 0.158976 (+70.14%) | 0.532378 (0%) | 0.064619 (+87.86%) |
| Avg peak resident memory (MB) | 10.892 (+97.15%) | 382.050 (0%) | 121.009 (+68.33%) | 135.781 (+64.46%) |

For the pivot and per-target elapsed-time tables, each row’s largest value is labeled `(0%)`. `(+x%)` means a value is x% lower than that baseline: `(baseline − value) / baseline × 100`, rounded to two decimal places using the displayed values.

Each tool has 24 measurements: three runs for each of eight targets. These are arithmetic means of each run’s normalized value, with equal weight per target. MB means 1,000,000 bytes.

The CPU-time and elapsed-time rows divide each run’s GNU Time CPU seconds and wall seconds by the tool’s reported processed MB. The memory row is the mean of each run’s **maximum resident set size**, converted to MB; it is an absolute memory measurement.

For **Avg CPU time per MB**, smaller means less measured CPU work per reported processed MB. This is more informative about CPU cost than GNU Time’s CPU percentage, though tools may report different processed volumes and their scan coverage may differ. GNU Time’s CPU percentage remains available for every run in the detailed data. A higher CPU percentage means the program kept more cores busy on average; it can be a sign of effective parallel processing when throughput improves, and should not be read as a flaw or a direct measure of algorithm quality. The numbers in the summary use CPU seconds rounded to hundredths in the per-run table.

## Observations

Mean wall time per repository was **0.695 s** for rayloc, **1.934 s** for trufflehog, **2.594 s** for gitleaks, **0.463 s** for betterleaks.

The lowest mean wall time on each target was recorded by betterleaks on 5 of eight targets, rayloc on 3 of eight targets.

Rayloc’s mean peak RSS was **10.892 MB**. The other tools’ mean peak RSS values were 382.050 MB (trufflehog), 121.009 MB (gitleaks), 135.781 MB (betterleaks).

Tool-reported processed volumes differ substantially. The normalized pivot compares each tool against its own reported volume; the wall-time table compares the time users wait for each default directory scan. These results do not establish equal scan coverage or detection accuracy.

## Mean elapsed time by target

Seconds, averaged over three runs. Lower values mean less wall time for the specified command.

| Target | rayloc ⭐ | trufflehog | gitleaks | betterleaks |
| --- | --- | --- | --- | --- |
| llama.cpp | 0.943 (+78.76%) | 3.680 (+17.12%) | 4.440 (0%) | 0.820 (+81.53%) |
| vllm | 1.093 (+75.51%) | 2.490 (+44.21%) | 4.463 (0%) | 0.697 (+84.38%) |
| claude-code | 0.157 (+84.90%) | 1.040 (0%) | 0.290 (+72.12%) | 0.190 (+81.73%) |
| opencode | 0.827 (+48.73%) | 1.613 (0%) | 1.460 (+9.49%) | 0.423 (+73.78%) |
| ponytail | 0.010 (+98.90%) | 0.910 (0%) | 0.210 (+76.92%) | 0.077 (+91.54%) |
| OpenShell | 0.180 (+86.50%) | 1.333 (0%) | 1.133 (+15.00%) | 0.327 (+75.47%) |
| paperclip | 0.833 (+86.95%) | 2.223 (+65.17%) | 6.383 (0%) | 0.590 (+90.76%) |
| hindsight | 1.520 (+35.95%) | 2.180 (+8.13%) | 2.373 (0%) | 0.583 (+75.43%) |

## Mean reported processed volume by target

Decimal MB, averaged over three runs. The denominator comes from rayloc’s `byte(s) read`, TruffleHog’s final `bytes` counter, and Gitleaks/Betterleaks’ `scanned ~… bytes` summaries. The latter summaries label the byte count as approximate.

| Target | rayloc ⭐ | trufflehog | gitleaks | betterleaks |
| --- | --- | --- | --- | --- |
| llama.cpp | 102.326008 | 1517.650046 | 569.062450 | 1275.405362 |
| vllm | 116.659769 | 576.383894 | 124.579771 | 449.746509 |
| claude-code | 15.055251 | 21.148894 | 4.052491 | 16.646545 |
| opencode | 102.985811 | 159.752235 | 98.142760 | 174.486592 |
| ponytail | 0.963098 | 2.213728 | 0.665141 | 1.818097 |
| OpenShell | 33.064569 | 50.405892 | 32.284659 | 40.503813 |
| paperclip | 137.519219 | 205.569631 | 121.220450 | 166.391179 |
| hindsight | 216.906540 | 343.442253 | 72.437488 | 292.067821 |

## Measurement method

- Fresh measurement window: `2026-10-07T12:56:18.452860-06:00` through `2026-10-07T12:58:39.229208-06:00`.
- Three sequential passes; scanners never ran concurrently with one another. Targets used the instruction’s order. Tool order rotated between passes: rayloc/trufflehog/gitleaks/betterleaks, trufflehog/gitleaks/betterleaks/rayloc, then gitleaks/betterleaks/rayloc/trufflehog.
- All 96 measurements came from the fresh offline run. Earlier pilots and network-enabled runs were excluded.
- GNU Time 1.10 measured each scanner process directly with `\time -v -o <timing-file>`. Output filtering ran outside the timed scanner. A collector extracted numeric summaries and discarded findings and raw scanner diagnostics.
- Elapsed time is GNU Time’s wall time, including startup and shutdown, rather than the scanner’s internal timer. CPU is GNU Time’s `Percent of CPU this job got`; memory is `Maximum resident set size (kbytes)`.
- TruffleHog used `--no-verification --no-update`. Betterleaks validation/analysis was not enabled. No tool configuration or concurrency environment overrides were set.
- Other settings, thread counts, configuration discovery, exclusions, decoding, and archive behavior were left at each tool’s defaults. Repository-local configuration can therefore affect scan scope.
- Filesystem caches were not cleared. Pilot activity preceded these runs, so results represent scans with potentially warm caches rather than a cold-cache benchmark. The host was not isolated from unrelated work.
- No scan timeout was applied. Scanner exit statuses 0 and 1 were retained; status 1 denotes findings for rayloc, Gitleaks, and Betterleaks. TruffleHog returns 0 with findings unless `--fail` is requested.

Commands corresponding to the measurements (in Bash):

```bash
\time -v -o rayloc.time rayloc scan "$dir" --silent
\time -v -o trufflehog.time trufflehog filesystem "$dir" --no-verification --no-update 2>&1 | rg "finished scanning"
\time -v -o gitleaks.time gitleaks dir "$dir"
\time -v -o betterleaks.time betterleaks fs "$dir" --silent
```

For each run:

```text
processed_MB = reported_bytes / 1,000,000
elapsed_per_MB = GNU_Time_wall_seconds / processed_MB
CPU_time_per_MB = (GNU_Time_user_seconds + GNU_Time_system_seconds) / processed_MB
peak_RSS_MB = GNU_Time_max_RSS_kbytes × 1,024 / 1,000,000
pivot_value = mean(eight target means, each based on three runs)
```

GNU Time reports RSS in KiB on this Linux host. Its CPU percentage is `(user_seconds + system_seconds) / elapsed_seconds × 100`; it can exceed 100% when multiple cores are active and describes average CPU use relative to wall time, rather than total CPU work. Total CPU work per reported MB is `(user_seconds + system_seconds) / processed_MB`. A higher CPU percentage means more cores were busy on average; it does not by itself mean a better algorithm or better use of idle CPUs. Assess that by comparing throughput and wall time under the same scan workload and available CPU limit.

GNU Time’s elapsed values have 0.01-second resolution here. The 0.01-second rayloc scans on `ponytail` are especially sensitive to rounding, and the small target strongly affects the unweighted normalized averages. Extra displayed decimal places in the pivot describe the calculation rather than measurement precision.

## Host and tools

- CPU: AMD Ryzen 9 9950X 16-Core Processor; 16 physical cores and 32 logical CPUs.
- RAM: 64.67 GB as reported by Linux system memory statistics.
- Platform: Linux 7.1.13-2-MANJARO, x86_64.
- Targets: the eight repository checkouts listed in the target snapshots below.

| Tool | Version | Command |
| --- | --- | --- |
| rayloc ⭐ | 2026.10.7 | `rayloc` |
| trufflehog | trufflehog 3.99.0 | `trufflehog` |
| gitleaks | 8.30.1 | `gitleaks` |
| betterleaks | 2.0.0-rc.1 | `betterleaks` |

The installed rayloc binary was benchmarked; this worktree’s uncommitted source edits were not rebuilt for this comparison. Binary SHA-256 hashes were checked again after collection:

| Tool | SHA-256 |
| --- | --- |
| rayloc ⭐ | `4e444a54e08586bc2205565c3f177bf446d9a18f0559232d92fb27bd63a39538` |
| trufflehog | `bcbdd2627c3f96e641edec60e3ccf36fc12afa4ffead5f32c98f8dbe7373cedc` |
| gitleaks | `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509` |
| betterleaks | `3ca27237a244caea0eecdd00fe6bd98dd685097fbf326e68b032dad1084a9eda` |

## Target snapshots

Inventory counts regular files without following symlinks. Disk bytes are provided for context and are not the pivot denominators. `.git` objects, skipped files, archives, and decoded content can make tool-reported volumes differ from disk bytes.

Repository HEADs, regular-file counts, and aggregate file sizes were checked again after collection and matched the initial snapshots; this check does not compare every file’s contents.

| Target | HEAD | Regular files | Disk MB including .git | Disk MB excluding .git |
| --- | --- | --- | --- | --- |
| llama.cpp | `674faf97897e69caa538a7d6c0eb9f2edbe3a1a8` | 9127 | 1271.335811 | 825.593760 |
| vllm | `6ad2e06c4a5bdd878977dfccc7443831e4fdc889` | 7625 | 479.378722 | 154.211984 |
| claude-code | `09651d3d164af78681ada19f4d2b805c45bbdc79` | 1556 | 27.649305 | 15.055251 |
| opencode | `b1fe25ab5ecc9f9bc911a8a2e6a51565cc764322` | 6598 | 199.621395 | 124.285639 |
| ponytail | `552acd5efd0aeae2583a12efe39373d2f076f25e` | 187 | 2.890857 | 1.737901 |
| OpenShell | `e406c2befbe65501409026d49259602669f7246a` | 1943 | 42.096633 | 33.877479 |
| paperclip | `ceabc3bc880676c49eee907a8d736f961a1358eb` | 8946 | 185.455952 | 140.294664 |
| hindsight | `a77c1f3412a7b82f36588dffce1a8d7480e99cc7` | 5062 | 431.386318 | 247.541015 |

## Scan diagnostics

The following completed scans emitted error diagnostics. Their measurements are included as observed command behavior, so they should not be interpreted as error-free coverage of every file:

| Target | Tool | Run | Error diagnostic lines | Recognized diagnostic categories |
| --- | --- | --- | --- | --- |
| llama.cpp | betterleaks | 1 | 1 | archive, tar, unexpected eof, read |
| llama.cpp | betterleaks | 2 | 1 | archive, tar, unexpected eof, read |
| llama.cpp | betterleaks | 3 | 1 | archive, tar, unexpected eof, read |

Betterleaks reported archive-reading diagnostics containing `unexpected EOF` on `llama.cpp`. The report retains the timing and reported volume while flagging this archive parsing limitation.

No network failure diagnostics were observed in the fresh run. TruffleHog verification was disabled for every reported measurement.

## Per-run measurements

All 96 runs are listed below in target/tool/run order. `CPU s` is GNU Time user plus system time. `Exit` is the scanner’s exit status. Peak RSS retains both the raw KiB value and its decimal MB conversion.

| Target | Tool | Run | Reported bytes | Processed MB | Wall s | CPU % | CPU s | Peak RSS KiB | Peak RSS MB | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| llama.cpp | rayloc | 1 | 102326008 | 102.326008 | 0.94 | 502 | 4.71 | 10840 | 11.100160 | 1 |
| llama.cpp | rayloc | 2 | 102326008 | 102.326008 | 0.93 | 512 | 4.78 | 12356 | 12.652544 | 1 |
| llama.cpp | rayloc | 3 | 102326008 | 102.326008 | 0.96 | 500 | 4.82 | 11288 | 11.558912 | 1 |
| llama.cpp | trufflehog | 1 | 1517650046 | 1517.650046 | 3.68 | 1805 | 66.56 | 488040 | 499.752960 | 0 |
| llama.cpp | trufflehog | 2 | 1517650046 | 1517.650046 | 3.68 | 1813 | 66.88 | 473632 | 484.999168 | 0 |
| llama.cpp | trufflehog | 3 | 1517650046 | 1517.650046 | 3.68 | 1816 | 66.94 | 474524 | 485.912576 | 0 |
| llama.cpp | gitleaks | 1 | 569062450 | 569.062450 | 4.45 | 2129 | 94.74 | 128764 | 131.854336 | 1 |
| llama.cpp | gitleaks | 2 | 569062450 | 569.062450 | 4.44 | 2154 | 95.76 | 134316 | 137.539584 | 1 |
| llama.cpp | gitleaks | 3 | 569062450 | 569.062450 | 4.43 | 2180 | 96.75 | 132036 | 135.204864 | 1 |
| llama.cpp | betterleaks | 1 | 1275405362 | 1275.405362 | 0.81 | 1859 | 15.18 | 168436 | 172.478464 | 1 |
| llama.cpp | betterleaks | 2 | 1275405362 | 1275.405362 | 0.83 | 1860 | 15.44 | 187196 | 191.688704 | 1 |
| llama.cpp | betterleaks | 3 | 1275405362 | 1275.405362 | 0.82 | 1897 | 15.72 | 181236 | 185.585664 | 1 |
| vllm | rayloc | 1 | 116659769 | 116.659769 | 1.10 | 446 | 4.93 | 12944 | 13.254656 | 1 |
| vllm | rayloc | 2 | 116659769 | 116.659769 | 1.09 | 452 | 4.96 | 13096 | 13.410304 | 1 |
| vllm | rayloc | 3 | 116659769 | 116.659769 | 1.09 | 442 | 4.82 | 11668 | 11.948032 | 1 |
| vllm | trufflehog | 1 | 576383894 | 576.383894 | 2.49 | 1496 | 37.38 | 400420 | 410.030080 | 0 |
| vllm | trufflehog | 2 | 576383894 | 576.383894 | 2.49 | 1493 | 37.30 | 407724 | 417.509376 | 0 |
| vllm | trufflehog | 3 | 576383894 | 576.383894 | 2.49 | 1493 | 37.18 | 395084 | 404.566016 | 0 |
| vllm | gitleaks | 1 | 124579771 | 124.579771 | 4.46 | 2416 | 107.94 | 116892 | 119.697408 | 1 |
| vllm | gitleaks | 2 | 124579771 | 124.579771 | 4.49 | 2413 | 108.44 | 122424 | 125.362176 | 1 |
| vllm | gitleaks | 3 | 124579771 | 124.579771 | 4.44 | 2426 | 107.94 | 120860 | 123.760640 | 1 |
| vllm | betterleaks | 1 | 449746509 | 449.746509 | 0.69 | 1409 | 9.79 | 144212 | 147.673088 | 1 |
| vllm | betterleaks | 2 | 449746509 | 449.746509 | 0.71 | 1409 | 9.99 | 144552 | 148.021248 | 1 |
| vllm | betterleaks | 3 | 449746509 | 449.746509 | 0.69 | 1375 | 9.58 | 145168 | 148.652032 | 1 |
| claude-code | rayloc | 1 | 15055251 | 15.055251 | 0.15 | 537 | 0.82 | 7148 | 7.319552 | 1 |
| claude-code | rayloc | 2 | 15055251 | 15.055251 | 0.16 | 540 | 0.85 | 6392 | 6.545408 | 1 |
| claude-code | rayloc | 3 | 15055251 | 15.055251 | 0.16 | 537 | 0.88 | 6620 | 6.778880 | 1 |
| claude-code | trufflehog | 1 | 21148894 | 21.148894 | 1.03 | 337 | 3.50 | 328048 | 335.921152 | 0 |
| claude-code | trufflehog | 2 | 21148894 | 21.148894 | 1.04 | 343 | 3.59 | 333428 | 341.430272 | 0 |
| claude-code | trufflehog | 3 | 21148894 | 21.148894 | 1.05 | 342 | 3.59 | 324420 | 332.206080 | 0 |
| claude-code | gitleaks | 1 | 4052491 | 4.052491 | 0.29 | 223 | 0.66 | 104728 | 107.241472 | 0 |
| claude-code | gitleaks | 2 | 4052491 | 4.052491 | 0.29 | 219 | 0.63 | 107344 | 109.920256 | 0 |
| claude-code | gitleaks | 3 | 4052491 | 4.052491 | 0.29 | 213 | 0.61 | 103604 | 106.090496 | 0 |
| claude-code | betterleaks | 1 | 16646545 | 16.646545 | 0.20 | 965 | 1.98 | 97552 | 99.893248 | 1 |
| claude-code | betterleaks | 2 | 16646545 | 16.646545 | 0.19 | 906 | 1.74 | 95080 | 97.361920 | 1 |
| claude-code | betterleaks | 3 | 16646545 | 16.646545 | 0.18 | 866 | 1.62 | 96664 | 98.983936 | 1 |
| opencode | rayloc | 1 | 102985811 | 102.985811 | 0.83 | 586 | 4.87 | 13068 | 13.381632 | 1 |
| opencode | rayloc | 2 | 102985811 | 102.985811 | 0.82 | 590 | 4.83 | 13308 | 13.627392 | 1 |
| opencode | rayloc | 3 | 102985811 | 102.985811 | 0.83 | 588 | 4.88 | 13008 | 13.320192 | 1 |
| opencode | trufflehog | 1 | 159752235 | 159.752235 | 1.62 | 883 | 14.30 | 385332 | 394.579968 | 0 |
| opencode | trufflehog | 2 | 159752235 | 159.752235 | 1.60 | 885 | 14.18 | 368128 | 376.963072 | 0 |
| opencode | trufflehog | 3 | 159752235 | 159.752235 | 1.62 | 884 | 14.33 | 365664 | 374.439936 | 0 |
| opencode | gitleaks | 1 | 98142760 | 98.142760 | 1.45 | 1672 | 24.29 | 118608 | 121.454592 | 1 |
| opencode | gitleaks | 2 | 98142760 | 98.142760 | 1.48 | 1651 | 24.58 | 118132 | 120.967168 | 1 |
| opencode | gitleaks | 3 | 98142760 | 98.142760 | 1.45 | 1627 | 23.72 | 123496 | 126.459904 | 1 |
| opencode | betterleaks | 1 | 174486592 | 174.486592 | 0.43 | 1333 | 5.82 | 144632 | 148.103168 | 1 |
| opencode | betterleaks | 2 | 174486592 | 174.486592 | 0.42 | 1360 | 5.76 | 145096 | 148.578304 | 1 |
| opencode | betterleaks | 3 | 174486592 | 174.486592 | 0.42 | 1341 | 5.66 | 144720 | 148.193280 | 1 |
| ponytail | rayloc | 1 | 963098 | 0.963098 | 0.01 | 409 | 0.04 | 5636 | 5.771264 | 0 |
| ponytail | rayloc | 2 | 963098 | 0.963098 | 0.01 | 400 | 0.04 | 5312 | 5.439488 | 0 |
| ponytail | rayloc | 3 | 963098 | 0.963098 | 0.01 | 450 | 0.04 | 6152 | 6.299648 | 0 |
| ponytail | trufflehog | 1 | 2213728 | 2.213728 | 0.91 | 142 | 1.29 | 273636 | 280.203264 | 0 |
| ponytail | trufflehog | 2 | 2213728 | 2.213728 | 0.91 | 140 | 1.28 | 275108 | 281.710592 | 0 |
| ponytail | trufflehog | 3 | 2213728 | 2.213728 | 0.91 | 142 | 1.29 | 274676 | 281.268224 | 0 |
| ponytail | gitleaks | 1 | 665141 | 0.665141 | 0.21 | 127 | 0.26 | 81472 | 83.427328 | 0 |
| ponytail | gitleaks | 2 | 665141 | 0.665141 | 0.21 | 142 | 0.30 | 86464 | 88.539136 | 0 |
| ponytail | gitleaks | 3 | 665141 | 0.665141 | 0.21 | 133 | 0.28 | 91216 | 93.405184 | 0 |
| ponytail | betterleaks | 1 | 1818097 | 1.818097 | 0.07 | 465 | 0.36 | 64140 | 65.679360 | 0 |
| ponytail | betterleaks | 2 | 1818097 | 1.818097 | 0.08 | 481 | 0.38 | 61888 | 63.373312 | 0 |
| ponytail | betterleaks | 3 | 1818097 | 1.818097 | 0.08 | 465 | 0.36 | 63568 | 65.093632 | 0 |
| OpenShell | rayloc | 1 | 33064569 | 33.064569 | 0.18 | 667 | 1.23 | 8512 | 8.716288 | 1 |
| OpenShell | rayloc | 2 | 33064569 | 33.064569 | 0.18 | 666 | 1.24 | 8436 | 8.638464 | 1 |
| OpenShell | rayloc | 3 | 33064569 | 33.064569 | 0.18 | 666 | 1.22 | 9176 | 9.396224 | 1 |
| OpenShell | trufflehog | 1 | 50405892 | 50.405892 | 1.33 | 521 | 6.94 | 352068 | 360.517632 | 0 |
| OpenShell | trufflehog | 2 | 50405892 | 50.405892 | 1.33 | 517 | 6.91 | 364048 | 372.785152 | 0 |
| OpenShell | trufflehog | 3 | 50405892 | 50.405892 | 1.34 | 528 | 7.12 | 367020 | 375.828480 | 0 |
| OpenShell | gitleaks | 1 | 32284659 | 32.284659 | 1.17 | 1121 | 13.21 | 118300 | 121.139200 | 1 |
| OpenShell | gitleaks | 2 | 32284659 | 32.284659 | 1.11 | 990 | 11.00 | 117904 | 120.733696 | 1 |
| OpenShell | gitleaks | 3 | 32284659 | 32.284659 | 1.12 | 1126 | 12.64 | 120720 | 123.617280 | 1 |
| OpenShell | betterleaks | 1 | 40503813 | 40.503813 | 0.33 | 869 | 2.88 | 120632 | 123.527168 | 1 |
| OpenShell | betterleaks | 2 | 40503813 | 40.503813 | 0.34 | 972 | 3.33 | 127368 | 130.424832 | 1 |
| OpenShell | betterleaks | 3 | 40503813 | 40.503813 | 0.31 | 858 | 2.66 | 120444 | 123.334656 | 1 |
| paperclip | rayloc | 1 | 137519219 | 137.519219 | 0.83 | 650 | 5.45 | 12804 | 13.111296 | 1 |
| paperclip | rayloc | 2 | 137519219 | 137.519219 | 0.84 | 649 | 5.51 | 13096 | 13.410304 | 1 |
| paperclip | rayloc | 3 | 137519219 | 137.519219 | 0.83 | 657 | 5.44 | 12988 | 13.299712 | 1 |
| paperclip | trufflehog | 1 | 205569631 | 205.569631 | 2.21 | 1007 | 22.32 | 383368 | 392.568832 | 0 |
| paperclip | trufflehog | 2 | 205569631 | 205.569631 | 2.23 | 999 | 22.27 | 379968 | 389.087232 | 0 |
| paperclip | trufflehog | 3 | 205569631 | 205.569631 | 2.23 | 1002 | 22.36 | 376992 | 386.039808 | 0 |
| paperclip | gitleaks | 1 | 121220450 | 121.220450 | 6.36 | 2525 | 160.70 | 135264 | 138.510336 | 1 |
| paperclip | gitleaks | 2 | 121220450 | 121.220450 | 6.36 | 2525 | 160.66 | 145832 | 149.331968 | 1 |
| paperclip | gitleaks | 3 | 121220450 | 121.220450 | 6.43 | 2533 | 162.93 | 133800 | 137.011200 | 1 |
| paperclip | betterleaks | 1 | 166391179 | 166.391179 | 0.58 | 1121 | 6.53 | 153060 | 156.733440 | 1 |
| paperclip | betterleaks | 2 | 166391179 | 166.391179 | 0.59 | 1098 | 6.50 | 147532 | 151.072768 | 1 |
| paperclip | betterleaks | 3 | 166391179 | 166.391179 | 0.60 | 1132 | 6.85 | 143316 | 146.755584 | 1 |
| hindsight | rayloc | 1 | 216906540 | 216.906540 | 1.50 | 698 | 10.51 | 13092 | 13.406208 | 1 |
| hindsight | rayloc | 2 | 216906540 | 216.906540 | 1.54 | 687 | 10.59 | 14856 | 15.212544 | 1 |
| hindsight | rayloc | 3 | 216906540 | 216.906540 | 1.52 | 693 | 10.54 | 13488 | 13.811712 | 1 |
| hindsight | trufflehog | 1 | 343442253 | 343.442253 | 2.18 | 1212 | 26.42 | 382752 | 391.938048 | 0 |
| hindsight | trufflehog | 2 | 343442253 | 343.442253 | 2.17 | 1216 | 26.45 | 384516 | 393.744384 | 0 |
| hindsight | trufflehog | 3 | 343442253 | 343.442253 | 2.19 | 1204 | 26.46 | 395696 | 405.192704 | 0 |
| hindsight | gitleaks | 1 | 72437488 | 72.437488 | 2.32 | 2061 | 47.95 | 122520 | 125.460480 | 1 |
| hindsight | gitleaks | 2 | 72437488 | 72.437488 | 2.38 | 2102 | 50.19 | 124556 | 127.545344 | 1 |
| hindsight | gitleaks | 3 | 72437488 | 72.437488 | 2.42 | 2106 | 51.16 | 126892 | 129.937408 | 1 |
| hindsight | betterleaks | 1 | 292067821 | 292.067821 | 0.59 | 1451 | 8.64 | 166340 | 170.332160 | 1 |
| hindsight | betterleaks | 2 | 292067821 | 292.067821 | 0.58 | 1451 | 8.50 | 167500 | 171.520000 | 1 |
| hindsight | betterleaks | 3 | 292067821 | 292.067821 | 0.58 | 1373 | 8.02 | 152032 | 155.680768 | 1 |
