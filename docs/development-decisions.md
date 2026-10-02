# Initial implementation decisions

Recorded on 2026-10-01 for the first P1/P2 library slice. The user requires a test
for every function, production coverage exceeding 98%, and short standard-library
implementations in preference to external dependencies.

## Dependencies and detection

The implementation adds zero external crates. Core provider signatures use static
prefix/marker tables and short byte recognizers. All rules share the same bounded
reader and preserve complete spans, ASCII boundary checks, source order, and
positive/negative fixtures. A recognized span is visited once, preventing nested
compact-token prefixes from causing repeated suffix scans. Provider body minima
are explicitly scanner heuristics, with medium confidence where format lengths
have not been established as provider guarantees.

The core rules cover AWS access key IDs, the six documented GitHub prefixes,
Stripe secret/restricted test/live prefixes, Slack/GovSlack webhook domains, and
ordinary/RSA/EC/DSA/OpenSSH/encrypted private-key markers. They do not validate
credential activity, JOSE structure, AWS secret-access-key context, or generic
password/entropy candidates; those remain P3/P4 work.

The existing OS-native CLI parser stays in place and adds injectable output
boundaries for tests. Configuration, custom regexes, ignores, directory/Git modes,
and hooks remain unavailable through the CLI. The low-level library accepts
already-selected sources and does not imply policy discovery. P3 will assess a
bounded YAML implementation and a justified regex dependency against the full
schema/grammar requirements, retaining MSRV 1.85. Rayon remains the planned P5
parallelism backend under the repository's traversal contract.

## Secret lifetime and memory bounds

`RedactedString` discards input bytes at construction and retains only a private
marker. Match evaluation borrows the reader's source bytes; findings retain safe
source IDs, spans, fixed rule metadata, and a fully masked value. This is stronger
than copying a secret into a private vector solely to print `[REDACTED]` later.
Formatting has no raw getter, byte slicing, or serialization path. Reports omit
source excerpts and filenames until safe path rendering is implemented.

Regular files use a 256-KiB `BufReader`, lines are capped at 1 MiB, candidates at
64 KiB, and retained findings at 10,000. Line allocation grows geometrically but
never requests capacity above the line cap. A finding holds no credential copy.
Overflow is an incomplete scan with exit 2; scanning after finding overflow
continues counting detections while retaining the first source-ordered findings.
P5 must extend this to a bounded, globally deterministic parallel collector.

Explicit symlinks/non-regular files are rejected. Unix device/inode comparison
detects a substituted opened file. File selection checks are best effort under
concurrent filesystem mutation; atomic cross-platform no-follow opening and
snapshot guarantees are not claimed by this low-level API.

## Tests, coverage, and CI

Unit tests live outside production modules but are included with `#[cfg(test)]`
so private functions and failure paths remain testable. Integration tests run
the real CLI and therefore exercise both `main` and its stdio adapter.

`scripts/coverage.py` uses Python's standard library and installed compatible LLVM
executables to instrument Rust, merge unit/integration/child-process profiles,
and enforce >98% lines/regions plus 100% functions. Only test/support/benchmark
source is excluded; all production Rust is counted. A separate target directory
keeps instrumented builds apart from normal development and benchmarks.
[Rust coverage reference](https://doc.rust-lang.org/rustc/instrument-coverage.html).

The local Rust 1.88.0 compiler's profiles were successfully read by the installed
AMD LLVM 22 tools. CI installs Rust's matching LLVM tools and checks both stable
and Rust 1.85.0. The local machine has no Rust 1.85 toolchain; the newly added CI
configuration has not yet run on GitHub.

The release benchmark measures the core byte engine over a small, warm synthetic
corpus, including finding construction. It is a development baseline for this
slice, not a performance claim about complete v1 detection or staged scans.
