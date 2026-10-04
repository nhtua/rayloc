# P7: pinned staged acquisition

P7 adds `rayloc scan --staged`, including `--config` and
`--no-inline-ignores`. A positional target, `--glob`, or another scope flag cannot
be combined with `--staged`. Ref and working-tree diff acquisition remain P8.

## Snapshot and policy

Every Git command runs in the caller's original working directory, so relative
`GIT_INDEX_FILE` values retain Git's meaning. Git resolves the worktree root and
active index path; linked worktrees and invocation from a nested directory are
covered by real-repository tests. The scanner records the symbolic HEAD identity
and resolved commit, then calls `write-tree` to pin the index. Unmerged entries
fail. Existing HEAD resolves to its pinned commit's tree; unborn HEAD is accepted
only after verifying that its symbolic branch is absent. Git `mktree` supplies
an empty tree, and `hash-object --stdin` supplies the empty blob identity. Neither
object ID is hard-coded, and SHA-1 and SHA-256 repositories are exercised.

Root `.rayloc.yaml` and `.raylocignore` are read through `ls-tree -z` and
`cat-file blob` at the pinned index tree. Discovered policy must be a regular
blob, not a symlink, directory, or gitlink. Unstaged policy edits have no effect.
An explicit `--config` is still an explicitly selected filesystem policy,
merged over that snapshot policy with the existing configuration rules. Git
ignore policy never hides tracked or force-added staged content.

After validating both streams and successful child completion, the scanner
checks HEAD identity, the active index's device/inode/size and nanosecond
mtime/ctime, and another `write-tree` result. A mismatch or failed recheck
returns incomplete (exit 2), retaining any already collected redacted findings.
These are detectable-mutation checks, not an atomic transaction with a later
commit; a change after the final check remains possible. `write-tree` may write
tree/cache objects but does not change staged content or refs.

## Raw/patch protocol

Both commands use the same pinned base/index tree IDs and common controls:

```text
--literal-pathspecs -c core.quotePath=true diff
--no-color --no-ext-diff --no-textconv --no-renames --text
--inter-hunk-context=0 --diff-algorithm=myers --no-indent-heuristic
--no-relative --src-prefix=a/ --dst-prefix=b/
--output-indicator-new=+ --output-indicator-old=- --output-indicator-context=' '
--submodule=short --ignore-submodules=none -O/dev/null
```

The output flags differ deliberately:

- Raw: `--raw -z --no-abbrev`.
- Patch: `--patch --full-index --unified=0`.

**Do not add `--unified=0` to the raw command.** Real Git 2.30.0 and 2.55.0
probes establish that this option enables patch output even with `--raw`.
`--no-patch` is not a portable workaround: the probed Git 2.30 combination
suppressed raw output as well. The final integration suite runs against both
actual versions. `--text` prevents binary attributes or NUL content from hiding
additions; no external diff/textconv helper is executed.

The driver retains one raw binding and one patch lookahead, verifies monotonic
unique raw paths, and delegates all sections to the P6 strict parser. Every
binding is parsed even when scanner policy excludes it. Both EOFs and successful
children are required. Type changes retain one logical source ID across their
deletion/addition sections. Only parsed additions reach the common detector,
using index line numbers. Scan line counts cover eligible additions; byte counts
cover their payload bytes, excluding patch indicators and framing LF. The current
detector is line-local; histogram reuse
carries no source context across boundaries.

Symlinks scan their staged link text without following the filesystem target.
A new gitlink, a regular-to-gitlink type change, or a deleted gitlink counts once
as excluded. A gitlink-to-regular/symlink change scans the new source and counts
once as attempted/completed. Ordinary deletions complete with zero added lines.
Rename detection is disabled, so a rename scans all content at the added path;
this favors recall but may report unchanged credentials at a new pathname.
Body-only PEM additions beneath an unchanged private-key marker may be missed;
full-file scanning supplements this added-lines mode. LFS pointers and archives
are not decoded.

## Bounds and process ownership

No new dependency is added. The Git process owner pipes stdout and concurrently
drains/discards stderr with an 8-KiB scratch buffer. It waits for successful
children, and kills/reaps unfinished children on early errors or drop. Failure
to create the diagnostic thread also kills/reaps the already-started child.
Diagnostics, raw paths, source text, and object metadata never reach errors.

| Resource | Bound |
| --- | --- |
| Each streaming raw/patch read buffer | 256 KiB |
| Each raw or patch record | 1 MiB, including NUL or LF terminator |
| Retained raw header, path, previous path, patch lookahead | One of each, each bounded above |
| Git root/index/ref control output | 1 MiB per command |
| Object-ID command output | 65 bytes including LF |
| Each discovered configuration/ignore blob | 1 MiB input, plus one overflow sentinel byte |
| Ignore/compiler policy admission | Existing P3/P5 limits; allocation-capacity accounting preserved |
| Source identifiers | Checked u32, exhaustion fails before reuse |
| Other counters and coordinates | Existing checked u64/parser counters |
| Candidate and retained finding limits | 64 KiB and 10,000 globally |

These are individual resource bounds, not an exact RSS claim. Control values,
policy compilation, byte-to-path scratch, thread stacks, and Git's own process
memory are additional bounded or external costs. There is no eager whole-repo
path list and no total-stream-byte cap. A real >10-MiB fixture streams through
the scanner, while a single oversized record fails with exit 2. Error precedence,
malformed/truncated/excluded bindings, source/count exhaustion, interrupted
reads, stderr flooding, child failures and cleanup have dedicated tests.

The existing engine/scope benchmark runs remain required validation; they do
not measure end-to-end staged acquisition latency. No new staged performance
claim or macOS execution claim is made here.
