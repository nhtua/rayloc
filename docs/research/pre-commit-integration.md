# Python pre-commit framework integration

Researched on 2026-10-02 for P9. This is a proposed integration, not an installed
hook or currently supported rayloc command. Staged scanning must pass P7 before
this hook can ship.

## Installation backend

Use `language: rust`. The framework builds hook repositories using Cargo and
caches their binaries. Its implementation installs the checked-out repository
with `cargo install --bins --root <environment> --path .`; crates.io publication
is not required for this route. Missing Rust can be bootstrapped, and an existing
usable Cargo toolchain can be reused. Initial setup can involve downloads and
compilation; normal hook execution uses the cached binary.
[Official Rust backend](https://github.com/pre-commit/pre-commit/blob/main/pre_commit/languages/rust.py).

Python/pre-commit is an optional developer-side hook manager, not a runtime
dependency of the rayloc binary. No Python wrapper package or redundant scanner
implementation is needed.

## Proposed repository manifest

Add `.pre-commit-hooks.yaml` during P9:

```yaml
- id: rayloc-staged
  name: rayloc staged secret scan
  entry: rayloc scan --staged
  language: rust
  pass_filenames: false
  always_run: true
  require_serial: true
  stages: [pre-commit]
```

These documented manifest fields disable filename arguments, permit execution
without matched filenames, and request a single process. The scope is determined
by rayloc's pinned index scan, not the framework's filename filters.
[Official manifest contract](https://pre-commit.com/#creating-new-hooks).

## Proposed consumer configuration and commands

After a tested release exists, consumers add `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nhtua/rayloc
    rev: <tested-release-tag>
    hooks:
      - id: rayloc-staged
```

Then install the framework and initialize both its Git hook and environments:

```sh
python3 -m pip install pre-commit
pre-commit install --install-hooks
```

For an existing framework-managed hook, `pre-commit install-hooks` initializes
missing environments without installing its Git script. Use
`pre-commit validate-manifest` and `pre-commit validate-config` in integration
validation. These are documented framework commands, not commands executed here.
[Official installation/CLI documentation](https://pre-commit.com/#command-line-interface).

## Scope and compatibility limits

The proposed `rayloc-staged` entry always scans index additions. A manual
`pre-commit run rayloc-staged --all-files` does not turn it into a repository-wide
scan: filenames are disabled and its entry remains `scan --staged`. Document this
clearly; consumers needing a full scan should use rayloc's directory CLI after
P5. A separate framework hook for whole-file scanning needs its own scope
contract and is not silently implied by this staged hook.

The framework's current installer refuses when Git's `core.hooksPath` is set.
Rayloc's direct installer remains the route for configured custom/shared active
hook directories. Do not automatically unset user Git configuration. The
framework also manages existing hooks through its own migration behavior;
rayloc's installer must still preserve unmanaged hooks independently.
[Official installer implementation](https://github.com/pre-commit/pre-commit/blob/main/pre_commit/commands/install_uninstall.py).

Before shipping, test isolated consumer repositories with actual framework
installation and commits: cached binary discovery, clean/findings/errors,
partial staging, index policy, no matching filenames, empty staged diff, and
unmanaged/framework-managed hook coexistence. Pin a tested framework version in
integration tests; verify supported Rust/MSRV and Linux/macOS environments.
Source inspection establishes feasibility, not completed integration validation.
