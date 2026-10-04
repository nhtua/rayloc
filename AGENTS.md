# AGENTS.md

This document provides instructions, constraints, and architectural guidelines for AI coding agents working on `rayloc`.

---

## 1. Project Overview & Philosophy

`rayloc` is an ultra-fast secret and sensitive information scanner written in Rust. Its primary use case is as a pre-commit hook and CI check that intercepts secrets before they reach git remotes.

The name comes from the Vietnamese **rây lọc** (a fine-mesh strainer/sieve). Unlike a coarse pasta colander, `rayloc` allows clean code and normal content to pass while trapping microscopic impurities (API keys, private keys, tokens, and high-entropy strings).

### Core Non-Negotiables

1. **Extreme Speed**: Scans must execute in milliseconds on local git diffs and seconds on gigabyte-scale repositories. Use parallel execution (`rayon`), memory-mapped files where appropriate, and compiled regex sets.
2. **Zero Secret Leaks (Auto-Redaction)**: Under no circumstances should `rayloc` print raw detected secrets to stdout/stderr. Every match must be redacted (e.g., `AKIA...****...9X2A`).
3. **Zero-Noise Filtering**: Secret detection must balance high recall with low precision noise using layered checks (Regex pattern matching -> Shannon entropy calculation -> Path filtering -> Contextual verification).
4. **Deterministic & Minimal Dependencies**: Keep external dependencies lean. The resulting binary must compile down to a single, portable executable with minimal dynamic links.

---

## 2. Project Architecture & Code Structure

(Bellow are modifiable suggestions structure)

```
rayloc/
├── src/
│   ├── main.rs            # CLI entry point and exit code handlers
│   ├── cli.rs             # Clap CLI definitions and subcommand routing
│   ├── scanner/
│   │   ├── mod.rs         # Core scanning pipeline controller
│   │   ├── engine.rs      # Parallel multi-file reader & match orchestrator
│   │   ├── diff.rs        # Git diff parser (processes added lines only)
│   │   └── redaction.rs   # Masking and formatting engine
│   ├── rules/
│   │   ├── mod.rs         # Rule definitions and rule loader
│   │   ├── builtin.rs     # Pre-compiled high-confidence rules (AWS, GitHub, JWT, RSA, etc.)
│   │   └── entropy.rs     # Shannon entropy calculator for string literals
│   ├── config/
│   │   ├── mod.rs         # Configuration loader (.rayloc.yaml)
│   │   └── ignore.rs      # .raylocignore matcher using `ignore` / glob matching
│   └── report/
│       └── terminal.rs    # ANSI Terminal report renderer
├── tests/                 # Integration tests and fixture files
├── .rayloc.yaml           # Default repository rules config
└── .raylocignore          # Default ignore paths
```

---

## 3. Mandatory Engineering Rules for AI Agents

When editing or extending `rayloc`, strict adherence to the following rules is required:

### Rule 1: Memory & Performance

* Do NOT load full files into memory if they exceed 10MB unless using memory mapping (`memmap2`).
* Use stream buffering or line-by-line chunking for large files.
* Ensure all regexes are compiled **once** using `LazyLock` or `regex::RegexSet`. Do not recompile regexes inside loop iterations.
* Use `rayon` for directory traversal and multi-file processing pipelines.

### Rule 2: Git Diff Parsing (`git diff`)

* When scanning in `--diff` or `--staged` mode, parse unified diff output strictly.
* **Scan ONLY lines added (`+`)**. Do NOT report secrets in deleted lines (`-`) or unchanged context lines.
* Maintain correct line numbers mapped back to the working tree or staging index.

### Rule 3: Redaction Safeguard

* Any struct representing a `Match` must wrap the target value in a custom `RedactedString` wrapper that overrides `Display` and `Debug` implementations to print masked strings (e.g., `[REDACTED]`).
* Never use `println!("{secret}")` in debugging or logging.

### Rule 4: Error Handling & Exit Codes

* **Exit 0**: Clean scan. No secrets found.
* **Exit 1**: Secrets detected (intercepts Git commit or CI build).
* **Exit 2**: Execution/Configuration error (e.g., malformed `.rayloc.yaml`, unreadable files).

### Rule 5: Tests, Coverage & Dependencies

* Every production function must be exercised by tests, including formatters,
  error paths, and the executable entry point.
* Production coverage must be at least 98%. Run `cargo coverage` (an alias for
  `cargo llvm-cov` in `.cargo/config.toml`; install with
  `cargo install cargo-llvm-cov --locked` and `rustup component add llvm-tools-preview`).
  It requires >=98% line and region coverage and 100% function coverage. Test
  helpers and benchmark drivers are excluded; production code must not be excluded.
* Prefer the Rust standard library for short, bounded implementations. Add an
  external dependency only when the capability cannot be implemented shortly
  and correctly, and record the justification. Avoid redundant libraries.

---

## 4. Development Workflow & Commands

AI agents must verify changes using the following toolchain commands:

```bash
# 1. Format code according to Rust standard formatting
cargo fmt --all -- --check

# 2. Run Clippy with strict warnings
cargo clippy --all-targets --all-features -- -D warnings

# 3. Execute all unit and integration tests
cargo test --all

# 4. Benchmark secret scanning speed against test fixtures
cargo bench

# 5. Enforce production coverage (>=98% lines/regions, all functions exercised)
cargo coverage
```

---

## 5. Secret Detection Mechanics

When you start working on design, planning or implementations on certain features, you may need to refer [technical design document](./technical-design.md)
