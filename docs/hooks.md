# Git commit hooks

Install the rayloc binary on `PATH`, then run in your Git working tree:

```sh
rayloc hook install
```

This selects Git's active hooks directory, including absolute or relative
`core.hooksPath`, shared directories, and linked worktrees. Relative hook paths
and `PATH` entries are interpreted from the worktree root, where Git executes
pre-commit hooks. A shared destination affects every repository using that hook.
The installed executable is:

```sh
#!/bin/sh
# Managed by rayloc.
exec rayloc scan --staged
```

Clean scans return 0; findings return 1; incomplete scans and configuration errors
return 2. All nonzero statuses block a commit. The scanner must remain on the
commit process's `PATH`; shell startup configuration is not loaded by this hook.
A missing scanner also blocks the commit. Bare repositories are unsupported.

Reinstallation preserves an identical managed hook and repairs missing executable
permissions. Other existing files, symlinks, and directories are preserved, with
exit 2 and manual integration guidance. Incorporate `rayloc scan --staged` into
your existing hook and propagate any nonzero status. The installer does not chain,
overwrite, or remove unmanaged hooks. It writes and synchronizes a temporary file
then publishes its executable inode with an atomic no-clobber hard link. A
filesystem without hard-link support fails safely. Concurrent managed installs
are supported; hostile simultaneous filesystem mutation is outside the snapshot
guarantee, as with other rayloc filesystem operations.

## Python pre-commit framework

Python's pre-commit package is an optional hook manager. The repository manifest
uses its Rust backend to build and cache the binary; Python is not a rayloc
runtime dependency. In a consumer repository, add `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nhtua/rayloc
    rev: <tested-commit-SHA-or-release-tag>
    hooks:
      - id: rayloc-staged
```

Replace the revision placeholder with the exact version you intend to use. Then:

```sh
python3 -m pip install pre-commit==4.6.2
pre-commit validate-config
pre-commit install --install-hooks
```

First installation needs Cargo/Rust and may download dependencies/toolchains.
Subsequent commits use the cached executable. The Rust backend installs source
without Cargo's `--locked`, so compatibility also depends on fresh dependency
resolution. For a framework hook already installed, `pre-commit install-hooks`
initializes its missing language environments without reinstalling its Git hook.
The framework controls migration of existing hooks; inspect its migration output.
Rayloc's direct installer treats a framework-managed hook as unmanaged and
preserves it. Choose the framework entry when adding rayloc to an existing
framework configuration.

Pre-commit 4.6.2 refuses hook installation when `core.hooksPath` is configured.
Use `rayloc hook install` for these destinations, or integrate the staged command
manually. Rayloc never unsets Git configuration to accommodate the framework.

The hook always scans additions in the staging index, using staged repository
policy, even for `pre-commit run rayloc-staged --all-files`. No filenames are
passed, execution is serial, and empty filename scopes still run. For a full
working directory scan, run `rayloc scan .` directly. Partially staged changes
are evaluated using index content; unstaged secrets do not become staged scope.
The framework may temporarily stash unstaged changes during a commit.

The reproducible Linux integration harness is
`scripts/test_pre_commit.py --repo <repository-path-or-URL> --rev <commit-SHA>`.
It requires pre-commit 4.6.2 and supports `--language-version 1.85.0` for a fresh
Rust backend installation on the minimum supported compiler. It operates only
in disposable consumer repositories with an isolated `PRE_COMMIT_HOME`.
Local validation does not establish macOS behavior; native platform verification
belongs to the release matrix. Hook execution also remains subject to Git's hook
policy and the caller's environment.
