# rayloc

`rayloc` (Vietnamese *rây lọc*, a fine-mesh sieve) scans files and added Git lines
for potential credentials. It runs offline, masks every finding completely, and
returns 0 for a completed clean scan, 1 for findings, or 2 for configuration,
execution or incomplete-scan errors. Errors take precedence over findings.

The v1 implementation supports files, directories, repository-relative globs,
staged snapshots, direct reference diffs, YAML policy, Git-style scanner ignores,
and a managed pre-commit hook. Release artifacts and crates.io publication are
being validated; no published download or registry installation is advertised.

Build with Rust 1.85 or newer:

```sh
cargo build --locked --release
cargo install --locked --path .
rayloc --help
```

Git is required for policy discovery, Git scopes and hook installation. Linux
integration tests pass with Git 2.30 and current Git. Native CI prepares Linux
musl and macOS binaries for x86_64/aarch64; successful jobs on the release commit
are required before platform support is advertised. Windows is deferred. See
[release preparation](docs/release.md) for archive, linkage and source-package gates.

```sh
rayloc scan .env.production
rayloc scan ./src
rayloc scan --glob '**/*.{pem,key,yaml}'
rayloc scan --staged
rayloc scan --diff main
rayloc hook install
```

An omitted target scans the current directory. `--staged` scans added index lines,
including partially staged files; configuration and ignores also come from the
index. `--diff main` compares tracked final working-tree content directly with
that commit, including staged and unstaged changes. It excludes untracked files
and does not scan history or use a merge base. A known conservative limitation:
when staged edits are completely reversed in the workspace, Git may rewrite its
index cache during diff acquisition; rayloc returns incomplete-scan exit 2.

Provider signatures cover AWS IDs/secret assignments, GitHub opaque and app
forms, Stripe secret/restricted keys, Slack/GovSlack webhooks and private-key
markers. Compact JOSE candidates receive structural checks. Generic entropy
requires assignment context; strong password literals of at least eight bytes
have a separate branch. Findings identify potential exposure, without claiming
credential activity. Shorter passwords, archive extraction, UTF-16 decoding,
obfuscated values and arbitrary multiline rules are outside the v1 contract.

Repository `.rayloc.yaml` custom regexes add to built-ins and compile once. Each
rule matches one physical byte line. Optional entropy measures the configured
secret capture (default: the complete match):

```yaml
version: "1"
default_entropy_threshold: 4.5
rules:
  - id: company-token
    regex: 'corp_([A-Za-z0-9]{32})'
    secret_group: 1
    entropy: 3.8
    severity: "High"
```

`--config PATH` merges present scalar settings over discovered policy, merges
entropy class keys, appends rules with unique IDs, and unions disabled rules.
Unknown fields, duplicate keys/IDs, aliases, tags and multiple YAML documents
fail safely. `--no-inline-ignores` disables `rayloc:ignore` comment directives.

Directory/glob scopes use repository `.gitignore` for untracked paths, then
higher-priority `.raylocignore`. Tracked and explicitly selected files remain
eligible for scanner exclusions. Hidden files are included. There are no implicit
`vendor/` or generated-directory exclusions, no global/parent ignore policy and no
symlink traversal. All-excluded scopes are labeled `EXCLUDED`; zero regular glob
matches return 2. Raw-byte scanning includes binary-looking files.

Reports show numeric source IDs and fixed rule metadata, locations in 1-based
byte columns, suppression/exclusion counters and `[REDACTED]` values. Paths,
custom labels, source snippets, CLI arguments and child stderr are withheld.
Input limits are 256-KiB reads, 1-MiB physical records/configuration, 64-KiB
candidates and 10,000 retained findings; exceeded limits return 2.

`hook install` resolves Git's active hook directory including `core.hooksPath`
and linked worktrees, preserves unmanaged hooks, and installs an executable,
idempotent `rayloc scan --staged` hook. A nonzero hook status blocks commits.
[Hook instructions](docs/hooks.md) also describe the optional tested Python
pre-commit 4.6.2 Rust backend and its staged-only scope.

Performance results and limitations are in [the measured release baseline](docs/research/release-baseline.md).
Under-5-ms staged latency and 500 MB/s/core remain stretch goals. The fixed
held-out synthetic corpus achieves 98% record precision and recall; its small
clean denominator cannot establish a real-world false-positive rate.

Run the required checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo bench --locked
cargo coverage
```

`cargo coverage` needs `cargo install cargo-llvm-cov --locked` and
`rustup component add llvm-tools-preview`. Production Rust requires >=98% line/region and 100% function coverage. See the
[test guide](tests/README.md), [benchmark guide](benches/README.md) and
[technical design](technical-design.md). Dependencies are narrowly scoped to
YAML, regex, ignores/globs and Rayon, with decisions in
[development decisions](docs/development-decisions.md).

Distributed under the [MIT License](LICENSE).
