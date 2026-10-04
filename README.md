# rayloc

[![Rust checks](https://github.com/nhtua/rayloc/actions/workflows/ci.yml/badge.svg)](https://github.com/nhtua/rayloc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A fast, offline secret scanner that stops credentials before they reach your Git remote.**

**rayloc** is pronounced *RAY-lock*: /ˈreɪ.lɒk/ (UK), /ˈreɪ.lɑːk/ (US).

The name comes from the Vietnamese *rây lọc*, a fine-mesh sieve used in the kitchen
to strain out the bits you don't want. rayloc does the same for your code: clean
code passes through, while API keys, private keys and tokens get caught.

- **Fast**: parallel scanning with regexes compiled once.
- **Built for Git**: scans staged changes, diffs against a ref, or whole directories.
- **Never leaks what it finds**: values are always masked in the output.
- **Single static binary**: no runtime and no network access.

```text
$ rayloc scan .
rayloc — FINDINGS
1 finding(s); 1 retained; 1 of 1 file(s) completed; 2 line(s); 51 byte(s) read
0 file(s) excluded
Suppressed: inline=0; placeholder=0; reference=0; checksum=0; generic-filter=0
Elapsed: 0.692 ms

src/app.py:2:8
Rule: GitHub token signature (github-token)
Severity: High; Medium confidence
Value: ghp_********
Remove exposed credentials from source code.
```

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [What it detects](#what-it-detects)
- [Configuration](#configuration)
- [Ignoring files and lines](#ignoring-files-and-lines)
- [Reports and exit codes](#reports-and-exit-codes)
- [Performance](#performance)
- [Contributing](#contributing)

## Quick start

```sh
# 1. Install
curl -fsSL https://raw.githubusercontent.com/nhtua/rayloc/main/install.sh | sh

# 2. Block commits that contain secrets
cd your-repo
rayloc hook install

# 3. Or scan on demand
rayloc scan .
```

## Installation

### Install script (recommended)

The script detects your platform, verifies the archive against `SHA256SUMS`, and
copies `rayloc` to `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/nhtua/rayloc/main/install.sh | sh
```

| Variable             | Purpose                                  |
| -------------------- | ---------------------------------------- |
| `RAYLOC_VERSION`     | Pin a release, e.g. `2026.10.4`          |
| `RAYLOC_INSTALL_DIR` | Install somewhere other than `~/.local/bin` |

### Prebuilt binaries

[GitHub Releases](https://github.com/nhtua/rayloc/releases) has binaries for Linux
(static musl) and macOS, on x86_64 and aarch64.

<details>
<summary>Manual install steps</summary>

Replace `VERSION`, and replace `TARGET` with one of `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `x86_64-apple-darwin` or `aarch64-apple-darwin`:

```sh
curl -fsSLO https://github.com/nhtua/rayloc/releases/download/vVERSION/rayloc-VERSION-TARGET.tar.gz
curl -fsSLO https://github.com/nhtua/rayloc/releases/download/vVERSION/SHA256SUMS
grep rayloc-VERSION-TARGET.tar.gz SHA256SUMS | shasum -a 256 -c -
tar -xzf rayloc-VERSION-TARGET.tar.gz
mkdir -p ~/.local/bin && install -m 755 rayloc-VERSION-TARGET/rayloc ~/.local/bin/rayloc
```

</details>

### From source

Requires Rust 1.85 or newer:

```sh
cargo install --locked --path .
```

### Requirements

- Git is required for policy discovery, Git scopes and hook installation. It is
  tested with Git 2.30 and current Git on Linux.
- Windows is not supported yet.

## Usage

```sh
rayloc scan                                  # current directory
rayloc scan ./src                            # a directory
rayloc scan .env.production                  # a single file
rayloc scan --glob '**/*.{pem,key,yaml}'     # a repository-relative glob
rayloc scan --staged                         # lines added to the index
rayloc scan --diff main                      # tracked changes against a commit
```

| Option                | Description                                         |
| --------------------- | --------------------------------------------------- |
| `--config <file>`     | Merge an extra policy file over the repository one  |
| `--no-inline-ignores` | Disable `rayloc:ignore` comments (useful in CI)     |

### Staged and diff modes

- **`--staged`** scans only lines added to the index, including partially staged
  files. Configuration and ignore files are also read from the index.
- **`--diff <ref>`** compares the final content of tracked files with that commit,
  covering both staged and unstaged changes. It skips untracked files, does not
  scan history and does not use a merge base.

> [!NOTE]
> If staged edits are completely reversed in the working tree, Git may rewrite its
> index cache while rayloc reads the diff. rayloc then reports an incomplete scan
> (exit 2) rather than risk missing a change.

### Pre-commit hook

Install a managed hook directly:

```sh
rayloc hook install
```

This respects `core.hooksPath` and linked worktrees, keeps any existing unmanaged
hook, and can be re-run safely. The hook runs `rayloc scan --staged`, and a
non-zero exit blocks the commit.

Or use the [pre-commit](https://pre-commit.com) framework, which runs your
installed `rayloc`:

```yaml
repos:
  - repo: https://github.com/nhtua/rayloc
    rev: v2026.10.4
    hooks:
      - id: rayloc-staged
```

See the [hook instructions](docs/hooks.md) for details, including the optional
pre-commit Rust backend.

## What it detects

| Category          | Coverage                                                          |
| ----------------- | ----------------------------------------------------------------- |
| AWS               | Access key IDs and secret key assignments                         |
| GitHub            | Opaque tokens (`ghp_`, `gho_`, `github_pat_`, …) and app forms    |
| Stripe            | Secret and restricted keys                                        |
| Slack             | Slack and GovSlack webhooks                                       |
| Private keys      | PEM private-key markers                                           |
| JWT / JOSE        | Compact tokens, checked for valid structure                       |
| Generic secrets   | High-entropy values in assignments, and strong password literals of 8+ bytes |
| Custom            | Your own regexes in [`.rayloc.yaml`](#configuration)              |

A finding means a credential **may** be exposed. rayloc does not check whether it
is still active.

**Out of scope for v1:** passwords shorter than 8 bytes, archive contents, UTF-16
files, obfuscated values and multi-line rules.

## Configuration

Add a `.rayloc.yaml` to your repository root. Custom rules are added to the
built-in rules:

```yaml
version: "1"
default_entropy_threshold: 4.5
disabled_rules: [github-token]
rules:
  - id: company-token
    regex: 'corp_([A-Za-z0-9]{32})'
    secret_group: 1      # capture group to check and report (default: whole match)
    entropy: 3.8         # optional minimum entropy for the captured value
    severity: "High"
```

- Each rule matches against a single line.
- `--config <file>` merges on top of the repository policy: settings override,
  rules are appended and disabled rules are combined.
- The parser is strict. Unknown fields, duplicate keys or IDs, YAML aliases or
  tags, and multiple documents are rejected with exit 2.

## Ignoring files and lines

**Files.** Directory and glob scans skip untracked files matched by `.gitignore`,
then apply `.raylocignore` (same syntax), which takes priority:

```gitignore
# .raylocignore
fixtures/
*.snap
```

- Hidden files are scanned. There are no built-in exclusions for `vendor/` or
  generated directories.
- Symlinks are not followed. Binary-looking files are still scanned.
- Tracked files and explicitly named files can still be excluded by `.raylocignore`.

**Lines.** Add a trailing comment to suppress a single line:

```python
API_KEY = "example-not-a-real-key"  # rayloc:ignore
```

`// rayloc:ignore` also works. Use `--no-inline-ignores` to enforce scanning in CI.

## Reports and exit codes

| Exit code | Meaning                                                       |
| --------- | ------------------------------------------------------------- |
| `0`       | Scan completed, no secrets found                              |
| `1`       | Secrets found                                                 |
| `2`       | Configuration error, execution error or incomplete scan       |

If both apply, errors (exit 2) take precedence over findings.

Each finding shows its path, line and byte column (1-based), rule, severity and a
masked value.

- **Values** show at most a 4-byte printable prefix, never more than a quarter of
  the value, followed by a fixed-length mask (`ghp_********`). Short or non-ASCII
  values print `[REDACTED]`.
- **Paths** that are not UTF-8, contain control or bidi characters, or exceed
  4 KiB are shown as `source #N`.
- Source snippets, custom rule labels, CLI arguments and Git error output are
  never printed.

**Limits:** 256 KiB reads, 1 MiB per line and per config file, 64 KiB per
candidate and 10,000 retained findings. Exceeding a limit returns exit 2.

## Performance

See the [measured release baseline](docs/research/release-baseline.md) for numbers
and methodology. On the held-out synthetic corpus, rayloc reaches 98% precision
and recall. That corpus is too small to estimate a real-world false-positive rate.
Staged scans under 5 ms and 500 MB/s per core are goals, not guarantees yet.

## Contributing

Run these checks before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo bench --locked
cargo coverage
```

`cargo coverage` requires 98% line and region coverage and 100% function coverage.
Set it up with:

```sh
cargo install cargo-llvm-cov --locked
rustup component add llvm-tools-preview
```

Further reading:

- [Technical design](technical-design.md)
- [Development decisions](docs/development-decisions.md), including dependency
  choices (YAML, regex, ignore/glob and Rayon only)
- [Test guide](tests/README.md) and [benchmark guide](benches/README.md)
- [Release process](docs/release.md)

## License

Distributed under the [MIT License](LICENSE).
