# P8 tracked working-tree comparison

`scan --diff <ref>` pins exactly one commit via argument-array
`rev-parse --verify --end-of-options <ref>^{commit}`. Option-like and empty refs
are rejected. Both raw and patch commands compare that immutable object directly
to the tracked working tree, including staged and unstaged changes. Untracked
files, merge-base selection and history traversal are outside this scope.
Current working-tree `.rayloc.yaml` and `.raylocignore` apply, with the established
explicit config merge and inline-ignore override.

## Acquisition and resource contract

Common diff flags are shared with staged mode:

```
--no-color --no-ext-diff --no-textconv --no-renames --text
--inter-hunk-context=0 --diff-algorithm=myers --no-indent-heuristic
--no-function-context --no-relative --src-prefix=a/ --dst-prefix=b/
--output-indicator-new=+ --output-indicator-old=- --output-indicator-context=' '
--submodule=short --ignore-submodules=none -O/dev/null
```

The context indicator has a literal trailing space. Raw adds
`--raw -z --no-abbrev` (not `--unified=0`, which enables patch output on Git
2.30); patch adds `--patch --full-index --unified=0`. Each ends with the pinned
commit and `--`. No `--exit-code` is used. `core.quotePath=true` and literal
pathspec handling come from the shared Git command builder.

Git's present-side raw ZERO object ID means unknown. Acquisition first validates
raw framing, paths, modes, status, old IDs and absent-side ZERO rules. It resolves
every present new identity independently, including known IDs, before passing a
normalized binding to the strict parser. Known raw IDs must agree. Ordinary
regular/symlink M entries still require changed mode or identity; ZERO cannot
reach the resolved parser. Independent identities preserve mode-only equality
proof and empty-blob/truncated-section checks.

Regular files are opened, checked against `symlink_metadata` and handed directly
to `git hash-object --stdin --path=<repository-relative byte path>` as a regular
stdin descriptor. Git does not reopen the source pathname. Symlink ancestors are
rejected on observation. Link text is read with `read_link`, capped at 1 MiB and
hashed literally through bounded stdin without `--path`; its target is never
opened. Initialized gitlinks use their independently resolved submodule HEAD and
are counted as excluded. Unavailable or inconsistent identities fail safely.

Git's own canonical EOL and configured clean-filter conversions apply to regular
files. Real fixtures cover CRLF normalization, a configured `tr X A` clean filter,
non-UTF-8 names, and nested invocation with an alternate relative index. Clean
filters can execute configured external programs and may allocate internally;
this is inherited Git behavior, separate from scanner buffer bounds. The scanner
does not enable external diff or textconv helpers. No arbitrary large pipe is fed
to hash-object: Git 2.30 can buffer a nonregular stdin completely. Large regular
inputs instead use Git's regular-descriptor mmap/streaming implementation.

Original raw metadata, resolved metadata, and a 64-byte per-entry fingerprint
share a **64 MiB allocation-capacity budget**. Admission checks both retained
buffers; overflow returns incomplete/exit 2. Fingerprints record device, inode,
mode, length, mtime and ctime including nanoseconds. Metadata records retain the
existing 1 MiB framing limit. Acquisition uses 256 KiB Git stdout readers and
8 KiB concurrently discarded stderr buffers. Hash stdout permits a 65-byte OID
record plus one overflow sentinel. Recheck streams reuse bounded records instead
of allocating a second metadata snapshot. No file contents are retained in this
metadata budget. Existing policy, compiled-rule and 10,000-finding bounds remain
separate. Each of three policy slots is capped at 1 MiB; absent explicit policy
reuses the discovered path logically, with a second bounded read for comparison.

Before success, the scan repeats raw enumeration and independent identities and
compares fingerprints, original raw records and resolved records. It also rereads
policy bytes/fingerprints and checks HEAD plus the active index fingerprint/tree.
Same-length modifications can leave raw bytes identical; tests establish that
independent hashes catch the change. A separate test preserves current stat
metadata while comparing the earlier resolved identity to exercise that proof.
Same-content inode replacement is also rejected. These checks are best effort;
ABA/restored state and changes after the final read are not an atomic snapshot or
a promise about a future commit. Hashing costs one Git process/read per changed
present source, repeated during verification. No complete Git-scan throughput or
macOS execution claim is made by the existing engine/scope benchmarks.

## Narrow parser compatibility cases

Real Git 2.30.0 and 2.55.0 both emit a tab after `+++ "b/private\377 name"`.
P6 originally expected the tab only for unquoted space-containing paths. The
correction expects it whenever the authoritative path contains a space, while
retaining strict decoded path and trailer matching.

Both versions also return exit 0 with the following *dirty-only* initialized
submodule protocol (OID represents the same validated full commit on both sides):

```
:160000 160000 OID OID M<NUL>sub<NUL>
diff --git a/sub b/sub
--- a/sub
+++ b/sub
@@ -1 +1 @@
-Subproject commit OID
+Subproject commit OID-dirty
```

There is **no index header**. The resolved-worktree binding constructor permits
equal IDs solely for mode 160000 M; pinned-tree `RawBinding::parse` stays strict.
The parser's corresponding no-index variant validates both paths, the exact
single-line hunk, both literal commit records, the same full ID, and `-dirty`.
Extra records, missing records, alternate counts/anchors or altered suffixes
fail. It emits no source additions and counts one excluded file. This is a small
additional Git-specific grammar to maintain; unfamiliar variants fail safely
instead of bypassing patch validation. Changed submodule commits retain the
ordinary full-index protocol.

## Executed compatibility matrix

The complete suites run with `/usr/bin/git` 2.55.0 and the locally source-built
`/tmp/rayloc-git-2.30/bin/git` 2.30.0. The working-tree suite initializes and scans
both SHA-1 and SHA-256 repositories on each build, including ordinary/mode-only
changes, truncation, empty additions, symlinks and type changes. SHA-256 is not
skipped in this fixture. Test children isolate system/global Git config and
attributes; repository settings disable hooks, external attributes and excludes.
No new dependency was introduced. The locked full suite also runs on Rust 1.85.0.
