# rayloc ⚡

> **X-ray speed for your commits. Fine-sieve filtering for your codebase.**

**Development status:** This repository currently contains the Rust project
scaffold. The CLI supports help and version output; scanning, configuration
loading, reporting, and hook management are planned and are not implemented yet.
The features and usage examples below describe the intended behavior.

`rayloc` (derived from the Vietnamese *rây lọc* — a fine-mesh strainer) is a secret scanner being built in Rust for fast local scans. Designed to run as a git `pre-commit` hook or CI step, it aims to catch passwords, API keys, access tokens, and context-associated high-entropy strings **before** they land in your git history.

Unlike coarse filters, `rayloc` lets smooth code flow through while trapping microscopic security risks.

---

## Features

- 🏎️ **Fast Scanning**: Planned parallel scanning (`rayon`) and regexes compiled once per process. Under 5ms for small staged scans is a stretch goal; end-to-end performance has not been measured yet.
- 🎯 **Targeted Git Diff Mode**: Scans only added lines in staged changes or git diffs—ignoring existing codebase noise and deleted lines.
- 🔒 **Auto-Redaction**: Safe by default. Output automatically masks detected secrets in terminal logs so sensitive data is never printed or exposed in CI logs.
- 📦 **Single Executable**: Planned standalone binaries with no extra language runtime. Git modes and hook management require Git to be installed.
- 📝 **Flexible Configuration**: Planned `.rayloc.yaml` custom rules/entropy settings and `.raylocignore` files using standard `.gitignore` syntax.

Detection and performance contracts are described in the
[technical design](technical-design.md), with evidence and experiments in the
[design validation report](docs/research/technical-design-validation.md).

---

## Installation

Build the current scaffold from this checkout:

```bash
cargo build --release
./target/release/rayloc --help
```

Standalone release downloads and registry installation are planned. The package
currently has `publish = false`; scanning is not available in the built scaffold.

---

## Quick Start & Usage

`rayloc` is designed to support four primary scanning modes:

### 1. Git Diff Mode (Pre-Commit / Added Content Only)
Scans only the staged changes queued for the next commit:
```bash
rayloc scan --staged
```

Scan tracked working-tree changes against a commit or branch, including staged
and unstaged changes (untracked files are excluded):
```bash
rayloc scan --diff main
```

This compares directly with `main`; it does not scan history or use a merge base.

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

Or manually integrate the following into your active Git `pre-commit` hook
(Git may use a custom hooks directory):

```bash
#!/bin/sh
exec rayloc scan --staged
```

---

## Configuration

### Custom Rules (`.rayloc.yaml`)

Place a `.rayloc.yaml` file in your repository root to configure detection sensitivity, custom regex patterns, and entropy thresholds:

```yaml
version: "1"

# Generic fallback entropy threshold in bits/byte (0.0 to 8.0).
# Built-in alphabet thresholds are separate; provider rules bypass this gate.
default_entropy_threshold: 4.5

# Exclude common generated files by default
exclude_defaults: true

rules:
  - id: custom-api-key
    description: "Company Internal API Token"
    regex: 'corp_[a-zA-Z0-9]{32}'
    entropy: 3.8
    severity: "High"

  - id: custom-private-key-marker
    description: "Private Encryption Key Header"
    regex: '-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----'
    severity: "Critical"

  - id: custom-slack-webhook
    description: "Slack Incoming Webhook URL"
    regex: 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
    severity: "High"
```

Custom rules add to built-ins and check entropy only when `entropy` is specified.
The optional entropy gate measures the secret capture (the whole match by
default). Custom regexes match individual physical lines in the initial design.

### Ignore Patterns (`.raylocignore`)

Directory/glob scans apply repository `.gitignore` patterns to untracked paths;
tracked files and explicitly selected files remain eligible. `.raylocignore`
applies in every mode, including staged scans. Hidden files such as `.env` are
included. Staged scans use policy from the index, so unstaged policy edits do not
change their scope. Use explicit exclusions for intentional mock data:

```gitignore
# Ignore test fixtures containing intentional mock keys
tests/fixtures/**
*.mock.json

# Explicit dependency-directory exclusion
vendor/
```

Exclusions reduce coverage and are counted in reports. Lockfiles and
binary-looking content are not automatically safe to skip; raw-byte scanning
does not imply archive extraction or UTF-16 decoding.

---

## Auto-Redact Terminal Output Example

When `rayloc` detects a secret, it reports the file, line number, and rule matched, while automatically masking the sensitive value:

```text
⚡ rayloc v0.1.0 — Secret Strainer Report

[FAIL] Found 2 sensitive items in 1 file (scanned 4 staged lines)

  ❌ config/services.py:12
     ├─ Rule: AWS Secret Access Key [High]
     ├─ Value: [REDACTED]
     └─ Suggestion: Remove key and move to an environment variable.

  ❌ config/services.py:18
     ├─ Rule: High Entropy String [Medium]
     ├─ Entropy: 5.82 (Threshold: 4.50)
     └─ Value: [REDACTED]

[FAIL] Remove exposed credentials and store them outside source code.
```

Values are fully masked and source lines are omitted by default. Standalone scans
report findings; when run as a pre-commit hook, a nonzero status blocks the commit.
Exit codes are 0 for a completed clean scan, 1 for findings, and 2 for execution,
configuration, or incomplete-scan errors (including errors alongside findings).

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
