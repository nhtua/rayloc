# Integration tests

Production function tests live in `tests/unit/`, included from their owning
modules so private error paths remain testable. `tests/cli.rs` exercises the real
executable. `tests/support/` contains standard-library temporary-directory helpers.
Keep fixture repositories isolated from the checkout's scanner ignore policy.
Use synthetic fixtures only. Verify that stdout, stderr, and formatted findings
never expose a complete detected value, and that clean scans, findings, and
execution errors return exit codes 0, 1, and 2 respectively.

Run `cargo test --all` and `python3 scripts/coverage.py`. The coverage script
counts all production Rust source, requires >98% lines/regions and 100% functions,
and excludes test/benchmark code. Stable Rust does not provide branch coverage
through this instrumentation; region coverage is reported explicitly.

Current cases cover provider positives/negatives, ASCII boundaries, compact-token
overlap, CRLF/no final newline, NUL/invalid UTF-8, read-buffer splits, >10-MB files,
oversized lines/candidates/findings, counter overflow, failed/interrupted I/O,
file replacement metadata, symlink/non-regular selection, fully masked formatting,
report write failures, and safe CLI arguments/output errors. Policy/Git-mode tests
will be added with those features.
