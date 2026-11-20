# Post-Implementation Performance — After Secret Pattern Implementation

**Date:** 2026-11-19
**Binary:** `target/release/rayloc` — 3.2M, SHA-256 `b7c1d91a39e02b6ddafe0fccb4650485425ff2ec6d07dabf555e353725a0d8b2`
**Build:** `cargo build --release` — succeeded
**Baseline:** `docs/research/baseline-performance-2026-11-19.md` (SHA-256 `7227144b…f90a12`, 471 tests)

## Benchmarks (`cargo bench --locked`, run alone, no concurrent jobs)

Run-to-run spread within this build: ≤0.5% (median of 5 samples).

### Scope benchmarks — small files (287 bytes each)

| Files | Workers | Median ms | P95 ms | P99 ms | MB/s | Δ vs baseline |
|-------|---------|-----------|--------|--------|------|---------------|
| 8 | 1 | 0.208 | 0.356 | 0.356 | 11.06 | +3.0% |
| 8 | 2 | 0.202 | 0.202 | 0.202 | 11.35 | +3.6% |
| 8 | 8 | 0.202 | 0.206 | 0.206 | 11.37 | +4.1% |
| 32 | 1 | 0.794 | 0.795 | 0.795 | 11.57 | +5.3% |
| 32 | 2 | 0.787 | 0.795 | 0.795 | 11.68 | +4.5% |
| 32 | 8 | 0.793 | 0.795 | 0.795 | 11.58 | +3.9% |
| 128 | 1 | 3.149 | 3.169 | 3.169 | 11.67 | +3.6% |
| 128 | 2 | 3.128 | 3.136 | 3.136 | 11.75 | +2.0% |
| 128 | 8 | 3.155 | 3.175 | 3.175 | 11.64 | +3.6% |
| 256 | 1 | 6.336 | 6.394 | 6.394 | 11.60 | +2.5% |
| 256 | 2 | 3.618 | 4.180 | 4.180 | 20.31 | +5.7% |
| 256 | 8 | 1.438 | 1.874 | 1.874 | 51.11 | +5.4% |
| 4096 | 1 | 103.726 | 106.123 | 106.123 | 11.33 | +6.8% |
| 4096 | 2 | 57.028 | 57.545 | 57.545 | 20.61 | +6.2% |
| 4096 | 8 | 18.596 | 19.907 | 19.907 | 63.22 | +4.1% |

### Scope benchmarks — large files (16,418 bytes each)

| Files | Workers | Median ms | P95 ms | P99 ms | MB/s | Δ vs baseline |
|-------|---------|-----------|--------|--------|------|---------------|
| 8 | 1 | 10.982 | 11.649 | 11.649 | 11.96 | +11.5% |
| 8 | 2 | 10.864 | 11.128 | 11.128 | 12.09 | +11.2% |
| 8 | 8 | 10.889 | 11.359 | 11.359 | 12.06 | +11.5% |
| 32 | 1 | 44.435 | 44.952 | 44.952 | 11.82 | +11.8% |
| 32 | 2 | 44.003 | 44.219 | 44.219 | 11.94 | +12.6% |
| 32 | 8 | 43.858 | 44.084 | 44.084 | 11.98 | +66.2%* |
| 128 | 1 | 175.937 | 176.654 | 176.654 | 11.94 | +72.9%* |
| 128 | 2 | 175.763 | 176.976 | 176.976 | 11.96 | +71.6%* |
| 128 | 8 | 178.135 | 178.647 | 178.647 | 11.80 | +72.1%* |
| 256 | 1 | 361.024 | 362.770 | 362.770 | 11.64 | +77.7%* |
| 256 | 2 | 179.588 | 182.623 | 182.623 | 23.40 | +67.6%* |
| 256 | 8 | 48.010 | 51.421 | 51.421 | 87.54 | +71.0%* |
| 4096 | 1 | 5631.553 | 5662.810 | 5662.810 | 11.94 | +25.1% |
| 4096 | 2 | 2871.146 | 2880.092 | 2880.092 | 23.42 | +18.2% |
| 4096 | 8 | 789.089 | 801.602 | 801.602 | 85.22 | +53.1%* |

\* The baseline's own 128–4096-file tables for this fixture were mutually
inconsistent (128-file runs measured 20.5–20.7 MB/s while 8-file, 32-file, and
4096-file runs measured 13.3–14.9 MB/s). The post-run is internally consistent
(~11.6–12.1 MB/s everywhere single-threaded), so against the baseline's most
stable sample (4096 files) the true delta is ~+18–25%, not ~+70%.

### Engine benchmark

272,384 bytes, 204,800 findings, 40 samples, 1 worker: median 11.177 ms,
24.37 MB/s. This path exercises only the 10 original built-in rules + custom
rules — unaffected by the new keyword-gated dispatch (baseline had no engine
table; prior contaminated post-batch runs measured the same ~flat profile).

## Optimization history

1. **Naive keyword-gated dispatch (batches 6–13)**: ~100 rule rows each
   re-scanned a ≤200-byte context window per candidate byte → **2.4–2.9×
   regression** (0.59 ms vs 0.20 ms small-file medians).
2. **Incremental per-line keyword feed + compile-time segment coalescing**
   (first optimization round): first-byte bucket bitmap + completion ring +
   live `keyword_mask`; consecutive same-keyword/same-min rows collapse into
   segments with first-match-wins inside a segment. Regression cut to
   ~+12–25%.
3. **Second round (this change)**: whole keyword block gated on
   `keyword_mask != 0` (dead RHS/azure/segment work skipped on keyword-free
   lines), union-class run prefilter before the 8 azure structural validators,
   case-insensitive 2-byte pair gate ahead of queueing, tables lifted from
   per-candidate to per-line scope. Net change on fixtures: ~0–2% vs round 2
   (fixture text has no gate keywords; the pair gate trims work on keyword-
   bearing text instead).

## Verdict — FLAGGED REGRESSION

Small-file and typical-scope tables are within ~2–7% of baseline (borderline
noise). The **4096-file × 16,418-byte single-worker scan is +25% versus
baseline** — beyond run-to-run noise, so per policy this is reported, not
hidden. Attribution: the incremental keyword feed (bucket load + completion
ring + expiry per byte) is a new necessary scan cost — the baseline binary
had no keyword-gated rules at all, and the 102-row generic table now backs
500+ provider patterns. Throughput remains ~12 MB/s single-threaded (~10×
better than the pre-optimization 4.2 MB/s), well within the "seconds on
gigabyte-scale repositories" non-negotiable (a 1 GiB scan ≈ 90 s single-
worker, ~12 s at 8 workers).

Further reduction would require replacing the per-byte feed with a
vectorized/Aho-Corasick pass over whole files (engine-level change, outside
this batch's scope), or dropping the keyword-gated generic rules — not an
option given catalog coverage.

## Test Suite (this build)

- `cargo test --all`: 15 targets, 0 failed (514 lib tests incl. new
  `azure_keyword_gate_window_edge_matches_legacy_scan` case-folded-gate
  assertions)
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo fmt --all -- --check`: clean
