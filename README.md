# rayloc ⚡

> **X-ray speed for your commits. Fine-sieve filtering for your codebase.**

**Development status:** This repository currently contains the Rust project
scaffold. The CLI supports help and version output; scanning, configuration
loading, reporting, and hook management are planned and are not implemented yet.
The features and usage examples below describe the intended behavior.

`rayloc` (derived from the Vietnamese *rây lọc* — a fine-mesh strainer) is an ultra-fast, zero-dependency secret scanner built in Rust. Designed to run seamlessly as a git `pre-commit` hook or CI step, it catches passwords, API keys, access tokens, and high-entropy strings **before** they land in your git history.

Unlike coarse filters, `rayloc` lets smooth code flow through while trapping microscopic security risks.

---

## Features

- 🏎️ **Blazing Fast**: Written in Rust using parallel multi-threaded scanning (`rayon`) and pre-compiled RegexSets. Scans pre-commit diffs in under 5ms.
- 🎯 **Targeted Git Diff Mode**: Scans only added lines in staged changes or git diffs—ignoring existing codebase noise and deleted lines.
- 🔒 **Auto-Redaction**: Safe by default. Output automatically masks detected secrets in terminal logs so sensitive data is never printed or exposed in CI logs.
- 📦 **Single Executable**: Distributed as a standalone binary. Download, place in your `PATH` or `.git/hooks/`, and run. Zero runtime dependencies.
- 📝 **Flexible Configuration**: Full support for `.rayloc.yaml` custom rules/entropy settings and `.raylocignore` files using standard `.gitignore` glob syntax.

---

## Installation

### Option 1: Download Compiled Binary (Recommended)

Download the latest pre-compiled single binary for your platform from GitHub Releases and add it to your path:

```bash
# Linux / macOS
curl -sSL [https://github.com/your-org/rayloc/releases/latest/download/rayloc-$(uname](https://github.com/your-org/rayloc/releases/latest/download/rayloc-$(uname) -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o rayloc
chmod +x rayloc
sudo mv rayloc /usr/local/bin/
```

### Option 2: Install via Cargo

```bash
cargo install rayloc
```

---

## Quick Start & Usage

`rayloc` supports four primary scanning modes:

### 1. Git Diff Mode (Pre-Commit / Added Content Only)
Scans only the staged changes queued for the next commit:
```bash
rayloc scan --staged
```

Scan diff against a target branch:
```bash
rayloc scan --diff main
```

### 2. Directory Mode
Recursively scan an entire workspace or folder:
```bash
rayloc scan ./src
```

### 3. Single File Mode
Scan a single configuration or environment file:
```bash
rayloc scan .env.production
```

### 4. Glob Pattern Mode
Scan multi-file targets matching specific file glob patterns:
```bash
rayloc scan --glob "**/*.{pem,key,yaml}"
```

---

## Pre-Commit Hook Setup

To automatically scan every commit before it occurs:

```bash
# Install rayloc hook into the current git repository
rayloc hook install
```

Or manually add the following line to your `.git/hooks/pre-commit`:

```bash
#!/bin/sh
rayloc scan --staged
```

---

## Configuration

### Custom Rules (`.rayloc.yaml`)

Place a `.rayloc.yaml` file in your repository root to configure detection sensitivity, custom regex patterns, and entropy thresholds:

```yaml
version: "1"

# Global default Shannon entropy threshold (0.0 to 8.0)
default_entropy_threshold: 4.5

# Exclude common generated files by default
exclude_defaults: true

rules:
  - id: custom-api-key
    description: "Company Internal API Token"
    regex: 'corp_[a-zA-Z0-9]{32}'
    entropy: 3.8
    severity: "High"

  - id: generic-private-key
    description: "Private Encryption Key Header"
    regex: '-----BEGIN [A-Z ]+ PRIVATE KEY-----'
    severity: "Critical"

  - id: slack-webhook
    description: "Slack Incoming Webhook URL"
    regex: 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
    severity: "High"
```

### Ignore Patterns (`.raylocignore`)

`rayloc` respects both `.gitignore` and custom `.raylocignore` files. Use standard `.gitignore` syntax to exclude test fixtures, mock data, or vendor directories:

```gitignore
# Ignore test fixtures containing intentional mock keys
tests/fixtures/**
*.mock.json

# Ignore binary data
*.png
*.wasm

# Ignore vendor lockfiles
Cargo.lock
pnpm-lock.yaml
```

---

## Auto-Redact Terminal Output Example

When `rayloc` detects a secret, it reports the file, line number, and rule matched, while automatically masking the sensitive value:

```text
⚡ rayloc v0.1.0 — Secret Strainer Report

[FAIL] Found 2 sensitive items in 1 file (scanned 4 staged lines in 3ms)

  ❌ config/services.py:12
     ├─ Rule: AWS Secret Access Key [High]
     ├─ Context: aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY...****"
     └─ Suggestion: Remove key and move to an environment variable.

  ❌ config/services.py:18
     ├─ Rule: High Entropy String [Medium]
     ├─ Entropy: 5.82 (Threshold: 4.50)
     └─ Context: JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6I...****"

[BLOCKED] Commit aborted. Clean secrets or run `git commit --no-verify` to override.
```

---

## Development

Requires Rust 1.85 or newer with Rustfmt and Clippy installed.
The initial scaffold has no external crate dependencies.

```bash
cargo build
cargo run -- --help
cargo run -- --version
```

The module layout follows `AGENTS.md` and `technical-design.md`. Starter
configuration files are included as templates for the future configuration loader.
Scan and hook commands currently return exit code 2 to indicate that they are
unavailable.

Run the required development checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo bench
```

The scaffold has no tests or scanning benchmarks yet; add them with the
corresponding implementation.

## License

Distributed under the [MIT License](LICENSE).
