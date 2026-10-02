# Scanning benchmarks

`cargo bench --bench engine` runs a standard-library core-engine benchmark over
preloaded synthetic records: ordinary content plus a GitHub-shaped token, 1,024
copies, 40 repeated scans, one thread. It includes record reading, built-in
signature matching, finding construction, and full-mask value construction.
Assertions verify findings and byte counts before timing results are reported.

Reported MB/s uses decimal MB (1,000,000 bytes). This small warm workload measures
the current core provider engine only; it excludes process startup, policy,
directory traversal, terminal rendering, Git, generic/context rules, and JOSE
validation. Do not extrapolate it to the complete scanner or pre-commit latency.

Add separate end-to-end file/directory and staged benchmarks as those modes are
implemented. Follow technical-design section 9 for corpus, hardware, cache,
percentile, thread-count, and peak-RSS reporting.
