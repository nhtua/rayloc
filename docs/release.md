# Release preparation

No registry version or GitHub release is published by the validation workflow.
Build from the checkout with Rust 1.85 or newer. Git modes, policy discovery and
hook installation require Git; Git 2.30 is the tested minimum on local Linux.
The native matrix prepares x86_64/aarch64 Linux musl and macOS archives. Support
claims require successful native jobs on the exact release commit. macOS is only
runtime tested on the runner OS (macOS 15, ARM and Intel); older OS support is unverified.
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

## Publishing a GitHub release

Releases use date versions, `vYYYY.M.D` in UTC (for example `v2026.10.4`; Cargo
requires semver, so there are no leading zeros). At most one release is published
per day. To publish, run Actions > Release > Run workflow on `main`. The workflow:

1. computes today's version and stops if its tag already exists;
2. runs this validation matrix with the version stamped into `Cargo.toml` and
   `Cargo.lock` (`python3 scripts/release.py stamp --version VERSION`), so the
   archives and `rayloc --version` carry it;
3. rewrites the release pins of `README.md` to `vVERSION`
   (`python3 scripts/release.py sync-doc --version VERSION`), commits the version
   bump to `main` as `chore(release): vVERSION`, tags that commit `vVERSION`, and
   creates a GitHub release with the four archives and `SHA256SUMS`. The archives
   are built by step 2, so the `README.md` inside them names the previous release.

The push is atomic and fails if `main` moved after the dispatched commit; rerun
the workflow in that case. If `main` is protected, allow GitHub Actions to push
to it. `install.sh` installs the latest release (or `RAYLOC_VERSION`) after
verifying `SHA256SUMS`. crates.io publication remains a separate manual step;
recheck name/version availability first.
