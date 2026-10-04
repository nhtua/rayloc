# Validation guide

Production unit tests live in `tests/unit/`, included by owning modules to expose
private error paths. Integration suites run the real executable and isolated
synthetic Git repositories. The temporary-directory helper exclusively creates
and retries collisions, preserving another runner's directory. Concurrent broad
suites should still use separate Cargo target directories to avoid build locks.

Run `cargo test --locked --all` and `python3 scripts/coverage.py`. Production Rust
requires >98% lines/regions and 100% functions, including `main`, formatters and
failures; no production exclusions are allowed. Stable LLVM instrumentation
reports regions, without claiming branch coverage.

Coverage includes providers/custom/entropy/password/JOSE, all 0/1/2 exit paths,
strict YAML and resource budgets, byte/line/buffer boundaries, >10-MB sources,
redaction and sensitive metadata, scope/ignore/glob precedence, deterministic
parallel overflow, strict added-only patches, partial staging, alternate indexes,
unborn HEAD, worktrees, SHA-1/SHA-256, refs, hostile Git configuration/environment,
process failures/races, direct hooks and real blocked/clean commits.

The direct-reference cancellation characterization documents a conservative
exit-2 limitation when Git rewrites its index cache during acquisition. Other
snapshot-race safeguards remain mandatory.

After `cargo build --locked --release`, run the actual release/tooling tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/detection_evaluator.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p '*tools.py'
PYTHONDONTWRITEBYTECODE=1 python3 scripts/detection_baseline.py --check
python3 scripts/artifact_smoke.py /absolute/path/to/rayloc
```

The fixed calibration/held-out corpus labels synthetic records, rather than
credential activity. `--check` enforces measured confusion/supported-miss and
suppression counts, including known limits; mandatory supported Rust fixtures
require full detection and all output leak assertions require zero complete
values. Expanded statistical quality claims need independent data.

Artifact smoke executes the supplied extracted/installed executable against
clean/finding/error scopes, partial/index policy, deleted/context-only content,
unborn HEAD, alternate indexes, linked worktrees, direct refs, hook installation
and real commit blocking. Release CI runs this on four native architectures and
checks actual ELF/Mach-O linkage. [Release instructions](../docs/release.md)
cover source archives, checksum verification, MSRV installs and publication scope.
[Hook validation](../docs/hooks.md) covers the real Python pre-commit Rust backend.
