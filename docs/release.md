# Release preparation

No registry version or GitHub release is published by the validation workflow.
Build from the checkout with Rust 1.85 or newer. Git modes, policy discovery and
hook installation require Git; Git 2.30 is the tested minimum on local Linux.
The native matrix prepares x86_64/aarch64 Linux musl and macOS archives. Support
claims require successful native jobs on the exact release commit. macOS is only
runtime tested on the runner OS (14 ARM and 15 Intel); older OS support is unverified.
Linux ELF artifacts must have no interpreter or needed libraries; macOS executables
may depend on `/usr/lib` and `/System/Library` system libraries.

Run `python3 scripts/release.py linkage --binary BINARY --target TARGET`, then
`python3 scripts/release.py archive --binary BINARY --target TARGET --output dist`.
The version comes from Cargo metadata. Archives contain executable `rayloc`, MIT
license, README and these instructions. Extract into a fresh directory and run
`python3 scripts/artifact_smoke.py /absolute/extracted/rayloc`. Collect the four
archives, run `python3 scripts/release.py checksums --output dist` and
`python3 scripts/release.py verify --output dist`. SHA256SUMS identifies bytes;
it does not assert signature authenticity or reproducible builds.

Validate the source package on a committed tree using `cargo package --locked`,
`cargo package --locked --list`, and `cargo publish --dry-run --locked`. The dry
run publishes nothing. Install the unpacked package using
`cargo install --locked --bins --path UNPACKED --root ISOLATED_ROOT`, then run the
artifact harness against `ISOLATED_ROOT/bin/rayloc`. CI also tests an unlocked
installation with Rust 1.85, matching the pre-commit Rust backend. Keep Cargo.lock
in the package. Inspect the archive for unexpected/internal material.

After review and all four native jobs pass, publication is a separate authorized
release action. Publish source only after rechecking crates.io name/version
availability. Upload only the four verified archives and SHA256SUMS to a reviewed
release; download/install commands can then reference artifacts that exist.
Until then use `cargo install --locked --path .` or the locally built binary.
