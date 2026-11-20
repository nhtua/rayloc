# Baseline Performance — Before Secret Pattern Implementation

**Date:** 2026-11-19  
**Commit:** Working tree at `.worktrees/secret-pattern-implementation`  
**Source:** `docs/research/secret-pattern-expansion.md` approach

## Binary

- **Size:** 3.2M
- **SHA-256:** `7227144b52e1e867184944647ed40a91810fe7120aa7bef455ff946700f90a12`
- **Build:** `cargo build --release` — succeeded

## Benchmarks (`cargo bench --locked`)

### Scope benchmarks — small files (287 bytes each)

| Files | Workers | Median ms | P95 ms | P99 ms | MB/s |
|-------|---------|-----------|--------|--------|------|
| 8 | 1 | 0.202 | 0.282 | 0.282 | 11.36 |
| 8 | 2 | 0.195 | 0.219 | 0.219 | 11.80 |
| 8 | 8 | 0.194 | 0.196 | 0.196 | 11.81 |

### Scope benchmarks — 32 files (287 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 0.754 | 0.775 | 0.775 | 12.18 |
| 2 | 0.753 | 0.761 | 0.761 | 12.19 |
| 8 | 0.763 | 0.771 | 0.771 | 12.03 |

### Scope benchmarks — 128 files (287 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 3.041 | 3.069 | 3.069 | 12.08 |
| 2 | 3.066 | 3.111 | 3.111 | 11.98 |
| 8 | 3.045 | 3.062 | 3.062 | 12.06 |

### Scope benchmarks — 256 files (287 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 6.184 | 6.662 | 6.662 | 11.88 |
| 2 | 3.424 | 3.782 | 3.782 | 21.46 |
| 8 | 1.364 | 2.057 | 2.057 | 53.85 |

### Scope benchmarks — 4096 files (287 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 97.122 | 98.197 | 98.197 | 12.10 |
| 2 | 53.681 | 53.873 | 53.873 | 21.90 |
| 8 | 17.863 | 18.287 | 18.287 | 65.81 |

### Scope benchmarks — 8 files (16,418 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 9.850 | 10.513 | 10.513 | 13.33 |
| 2 | 9.774 | 9.798 | 9.798 | 13.44 |
| 8 | 9.770 | 9.830 | 9.830 | 13.44 |

### Scope benchmarks — 32 files (16,418 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 39.729 | 39.821 | 39.821 | 13.22 |
| 2 | 39.071 | 39.520 | 39.520 | 13.45 |
| 8 | 26.397 | 26.624 | 26.624 | 19.90 |

### Scope benchmarks — 128 files (16,418 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 101.727 | 105.756 | 105.756 | 20.66 |
| 2 | 102.458 | 102.743 | 102.743 | 20.51 |
| 8 | 103.527 | 104.132 | 104.132 | 20.30 |

### Scope benchmarks — 256 files (16,418 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 203.192 | 204.352 | 204.352 | 20.68 |
| 2 | 107.169 | 107.838 | 107.838 | 39.22 |
| 8 | 28.071 | 28.693 | 28.693 | 149.73 |

### Scope benchmarks — 4096 files (16,418 bytes each)

| Workers | Median ms | P95 ms | P99 ms | MB/s |
|---------|-----------|--------|--------|------|
| 1 | 4502.760 | 4793.145 | 4793.145 | 14.93 |
| 2 | 2429.412 | 2574.400 | 2574.400 | 27.68 |
| 8 | 515.563 | 518.944 | 518.944 | 130.44 |

## Test Suite

- `cargo test --all`: 471 tests pass, 0 failed
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo fmt --all -- --check`: clean

## Notes

This baseline was captured BEFORE adding any new RuleId variants, prefix constants, or dispatch logic. The current `RuleId` enum has ~100 variants and `BUILTIN_IDS` lists 10 builtin IDs. The catalog documents 525 provider patterns + 10 generic + 1 AI-detected = 536 total, with ~200+ needing new RuleId variants and detection logic.