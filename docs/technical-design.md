# Technical Design: `rayloc` Secret Detection

Reviewed on 2026-10-01 against the README, project scaffold, primary technical
documentation, and synthetic experiments. This document specifies planned
behavior; the current CLI implements only help/version output. The
[validation report](docs/research/technical-design-validation.md) records evidence,
corrections, experiments, and remaining decisions.

## 1. Scope and invariants

`rayloc` is an offline scanner for files, directories, globs, and added Git diff
lines, with YAML configuration, ignore files, terminal reporting, and a managed
pre-commit hook. Prefer a small dependency graph and standalone platform-specific
executables. Git modes and hook management require an installed Git executable.
No network verification, telemetry, or downloading rules during scans.

- No raw detected values in stdout/stderr, diagnostics, `Display`, or `Debug`.
- Diff findings originate only from added lines, with new-side line numbers.
- Files exceeding 10 MB are streamed unless mapping has an enforceable safety
  justification. Memory is bounded independently of file size.
- Compile built-in/configured regexes once per process configuration.
- Use Rayon for directory discovery/scanning work, with a serial small-input
  path. Results remain deterministic despite parallel execution.
- Exit 0: selected scope completed without findings; exit 1: findings; exit 2:
  execution/configuration failure or incomplete scanning. Errors take precedence
  when findings and errors coexist.

High precision and recall are evaluation goals. Findings indicate potential
exposure, not proof that a credential is active. Neither zero false positives
nor detection of every possible secret is guaranteed.

Initial exclusions from scope: Git history traversal, archive extraction,
arbitrary decoding/obfuscation, language-complete parsing, remote verification,
and machine-readable reports. Extensions need separate contracts and tests.

## 2. Feature and input contracts

| README feature | Required behavior | Owner |
| --- | --- | --- |
| `scan --staged` | HEAD tree versus index snapshot; added content only | `scanner/diff.rs` |
| `scan --diff <ref>` | Resolved commit versus tracked working-tree content | `scanner/diff.rs` |
| `scan <directory>` | Bounded recursive traversal, including hidden files | `scanner/engine.rs` |
| `scan <file>` | Explicit regular file, including `.env` | `scanner/engine.rs` |
| `scan --glob <pattern>` | Repository-relative globset patterns | `config/ignore.rs` |
| Custom rules / entropy | Validated YAML and immutable compiled registry | `config/mod.rs`, `rules/mod.rs` |
| Git/scanner ignores | Mode-specific documented precedence | `config/ignore.rs` |
| Redaction / exit codes | Safe deterministic reports and typed errors | `scanner/redaction.rs`, `report/terminal.rs`, `main.rs` |
| `hook install` | Resolve active Git hook directory; preserve existing hooks | `cli.rs`, proposed `hook.rs` |

Accept exactly one target mode: path, glob, staged, or reference diff. Omitted
targets mean the current directory; invalid combinations return 2. Interpret
quoted globs internally, including `**/*.{pem,key,yaml}` brace alternatives.
Invalid patterns or zero glob matches return 2. An existing empty directory or
an empty valid Git diff is a successful empty scan.

`--diff main` has the content scope of `git diff main`: tracked working-tree
content relative to that commit, including staged and unstaged changes. It is
not a merge-base comparison or a history scan. Untracked files require file,
directory, or glob mode, or staging. A future CI merge-base mode needs a separate
explicit option.

## 3. Four stages with independent detection branches

```text
Sources -> path/scope filters -> bounded byte records with source locations
                                  |
                      +-----------+-------------+
                      |                         |
               Provider signatures      Generic assignments/literals
               + custom regexes         + strong password context
                      |                         |
               Rule-specific checks     Context + optional entropy
                      +-----------+-------------+
                                  |
                     Scoped exclusions + deduplication
                                  |
                  Redacted findings -> sorted terminal report
```

Stage 1 selects/reads records. Stage 2 identifies structural matches and generic
candidates. Stage 3 evaluates only rules requiring entropy/context. Stage 4
applies rule-specific exclusions. Requiring every candidate to pass every filter
would suppress short passwords, PEM markers, and formatted tokens.

### Stage 1: source selection and bounded reading

Filter paths before opening files. Use byte buffers and `regex::bytes` so invalid
UTF-8 does not hide searchable ASCII credentials. A 1,024-byte UTF-8/NUL probe is
not definitive binary classification: UTF-16 has NULs, and binary-looking content
can contain text secrets.

Initially scan raw bytes in selected regular files, including binary-looking
files. This finds embedded ASCII signatures without promising UTF-16/UTF-32
conversion or archive support. Document unsupported encodings; do not silently
skip content based on a binary heuristic. Recursive scans always exclude Git
administrative data.

Use `BufRead::fill_buf`/`consume` or equivalent bounded byte reads. `lines()`
requires UTF-8; unbounded `read_until` can allocate an entire giant line. Current
budgets after bounded chunk scanning:

| Resource | Limit / behavior |
| --- | --- |
| Per-worker read buffer / payload fragment | 256 KiB |
| Physical source line | No built-in length ceiling; scan incrementally |
| Structural Git metadata record | 1 MiB; exceeding fails closed |
| Enabled legacy whole-line custom regex | 1 MiB compatibility storage; longer lines return an incomplete-scan error while supported rules continue |
| Candidate value / JOSE token | 64 KiB; exceeding returns incomplete-scan error |
| Configuration input | 1 MiB plus parser depth/event/alias budgets |
| Custom rules | 256; pattern text at most 16 KiB each |
| Compiled regex programs | Explicit per-pattern and aggregate budgets |
| Retained findings | 10,000; exceeding returns 2 with partial results |
| Paths/work items | Bounded batches; no eager whole-repository collection |
| Raw payload buffers per scanning lane | At most 1.5 MiB without legacy custom storage; 2.25 MiB with it |

These are limits on individual resources, not total file size. The raw payload
budget includes read buffers, provider carry, custom regex windows, candidate
buffers, and reusable line or legacy storage; finding metadata and regex caches
are accounted separately. Never truncate a candidate and return clean. Built-ins
and finite, bounded custom regexes scan long lines incrementally. Regexes whose
full match cannot be proven bounded, or that use assertions, keep whole-line
semantics up to the compatibility budget; longer input produces
`custom rule requires whole-line input beyond compatibility limit` with safe
source attribution and exit 2. Raising that budget is an interim option that
increases memory with input size and still leaves a larger cutoff. Long-line
findings are held until the physical line ends so a trailing ignore directive
can suppress them. A single detected candidate remains limited to 64 KiB.
Fragments preserve byte offsets and line numbers across read boundaries. LF
increments line numbers; CRLF retains the CR in source columns.

Buffered reading is the default for mutable workspace files. File-backed
`memmap2` constructors are unsafe if another process changes the backing file.
Metadata checks and copy-on-write mapping do not establish immutability. Mapping
requires controlled immutable backing storage, a documented safety argument,
and measured benefit. [memmap2 safety documentation](https://docs.rs/memmap2/latest/memmap2/struct.MmapOptions.html)

Borrow spans during evaluation. Buffers, paths, configuration, and findings still
allocate; the goal is allocation-free rejected candidates, not a zero-allocation
end-to-end scanner.

### Stage 2: structural signatures and the rule registry

Short built-in signatures may use bounded byte-prefix recognizers with the same
boundary, capture, and fixture contracts, avoiding a dependency for simple
formats. The first library implementation uses this approach. When configurable
regex rules are introduced, compile a byte `RegexSet` and individual byte regexes with identical flags.
The set identifies matching rule indexes; matching individual regexes then
extract spans/captures. Short lines use whole-line matching. Longer lines use
stateful recognizers with bounded carry so quote/token boundaries across reader
fragments cannot hide embedded provider credentials. Findings are published
only at the real line end, allowing trailing ignore directives to suppress
earlier candidates.

`RegexSet` does not return locations/captures. Its documented search bound is
`O(m * n)` for compiled pattern size `m` and input length `n`; extraction adds
work. Match iteration can have worse bounds. Bound haystacks and regex program
sizes, reject empty matches, and test adversarial patterns. A universal one-pass
`O(n)` scanner claim is incorrect.
[RegexSet API](https://docs.rs/regex/latest/regex/bytes/struct.RegexSet.html),
[regex complexity and limits](https://docs.rs/regex/latest/regex/)

The regex engine already accelerates suitable literals. Add a separate
Aho-Corasick router only with benchmark evidence. It must not exclude unanchored
or custom rules. User keywords are hints unless their necessity is proven from
the pattern. Built-in regexes use `LazyLock` and literal tables are static;
custom rules compile once into an immutable
runtime registry, before workers start.

Each built-in includes ID, severity, confidence, secret capture, boundary checks,
positive/negative fixtures, authoritative reference, and review date. Severity
measures impact; confidence measures evidence.

| Family | Initial detection contract |
| --- | --- |
| AWS access key ID | Start with `(?:AKIA|ASIA)[A-Z0-9]{16}` and explicit ASCII boundaries. This detects an ID, not its secret counterpart or validity. Do not classify IAM user/group/role/policy IDs as access keys. |
| AWS secret access key | Separate context-specific rule for an assigned 40-character value with provider field names, captured value, and calibrated filtering; arbitrary 40-character strings are insufficient. |
| GitHub tokens | Cover `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_`, including legacy opaque forms and the new `ghs_APPID_JWT` installation form. Redact the whole token; historical exact lengths are not permanent guarantees. |
| Stripe credentials | Cover `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`; exclude publishable `pk_` keys. Test credentials still grant test-resource access. Body bounds are heuristics until supported by provider evidence. |
| Slack webhooks | Recognize `https://hooks.slack.com/services/` and GovSlack equivalents with bounded path segments. Do not assume fixed team/channel lengths without evidence. Redact the complete URL. |
| Private-key markers | `-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----`, including ordinary PKCS #8. Detect a sensitive marker, not a cryptographically validated key. Public-key/certificate headers are negatives. |
| JWT / JOSE | Bounded compact candidates with Base64url decoding and protected-header JSON checks. Handle three-segment JWS, unsecured JWT with empty signature, and five-segment JWE. Compact JWE alone does not prove its plaintext is JWT. Context affects confidence. Require neither `eyJ` prefixes nor padding. |

Provider references:
[AWS identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html),
[GitHub token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats),
[Stripe keys](https://docs.stripe.com/keys),
[Slack webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/),
[PKCS #8 labels](https://www.rfc-editor.org/rfc/rfc7468.html#section-10).
JOSE parsing follows [JWS](https://www.rfc-editor.org/rfc/rfc7515.html),
[JWE](https://www.rfc-editor.org/rfc/rfc7516.html), and
[JWT](https://www.rfc-editor.org/rfc/rfc7519.html). Structural checks cannot prove
signature validity, bearer use, or revocation. Do not suppress expired tokens
automatically or label structurally matching credentials active.

V1 custom regexes operate on one physical line; multiline matching is not
promised. Specialized PEM state can span consecutive records within the source
scope, never unrelated files/hunks. Added PEM markers are detected in diff mode;
body-only additions under an unchanged marker may be missed. Full-file mode
is necessary for that case.

### Stage 3: context and empirical entropy

Use a small lexer to associate values with assignment/key syntax (`=`, `:`, or
supported header forms). Support `.env`, YAML/JSON pairs, common code assignments,
and `Authorization: Bearer ...`; respect escaped quotes. Normalize case and split
snake/camel identifiers. Prefer `api_key`, `access_token`, `client_secret`,
`password`, `passwd`, `credential`, and `aws_secret_access_key`. Bare `key`,
`private`, or `auth` is weak evidence. A 30-character distance alone is insufficient.
Only contiguous added records contribute state in diff mode.

Use two generic branches:

- Context-associated high-entropy values: initially minimum 16 bytes, with
  length-specific calibration. Standalone high entropy is opt-in because hashes,
  encoded assets, and identifiers create noise.
- Strong password assignments: concrete literals at least 8 bytes long can be
  medium-confidence findings without an entropy gate. Reject documented exact
  placeholders and recognized environment/config references. Weak passwords
  remain secrets; shorter literals/ambiguous expressions require custom rules
  or future calibrated handling.

Compute empirical byte-frequency Shannon entropy:

```text
H(S) = -sum((count(byte) / n) * log2(count(byte) / n))
H(S) <= log2(min(alphabet_size, n))
```

This describes the observed string, not cryptographic strength or secrecy.
For 16 distinct bytes the maximum is 4.0; for 20 it is about 4.322. A 4.5 threshold
cannot detect either length. Short random samples also fall below alphabet-level
maxima. Use a reusable 256-bin histogram, `f64` accumulation, explicit empty-input
handling, and no rounding before comparisons. Measure captured secret bodies,
not prefixes, labels, or quotes. For non-ASCII values the unit is bits per byte,
not bits per Unicode character.

Classify alphabets in order: hex, alphanumeric, Base64/Base64url, other bytes.
They overlap, so precedence is explicit. Initial class thresholds are proposals:
hex 3.0, alphanumeric 4.2, Base64/Base64url 4.5. Other-byte candidates use
`default_entropy_threshold` (initially 4.5). For generic candidates, apply the
following proposed length cap after choosing the class threshold:

| Value length in bytes | Generic effective threshold |
| --- | --- |
| 16–23 | `min(class_threshold, 3.5)` |
| 24–31 | `min(class_threshold, 4.0)` |
| 32 or more | `class_threshold` |

This avoids making supported short lengths mathematically undetectable. The
caps are initial heuristics requiring held-out calibration, not estimated
probabilities or validated quality gates. They apply to generic class overrides
and the fallback, but never change an explicit custom rule's entropy gate.
Remove permitted trailing Base64 padding before measuring entropy. Do not
normalize by observed distinct symbols: a short all-distinct sample would score
perfectly.

Calibrate by length, format, and context. Established scanners also use 3.0/4.5,
but this does not validate rayloc accuracy.
[detect-secrets configuration](https://github.com/Yelp/detect-secrets)

### Stage 4: scoped exclusions and deduplication

- Placeholder exclusions are exact rule-specific values or anchored patterns.
  `EXAMPLE`, `test`, or `foo` substrings are never universal suppressions.
- Homogeneity/sequential filters affect generic entropy candidates, not provider
  signatures or strong password assignments.
- UUID/hash-shaped values are not intrinsically public. Suppress generic matches
  only in recognized checksum/digest contexts; retain hex `api_key` values.
- Validate encoding only for rules requiring it. JOSE deliberately omits Base64url
  padding; opaque generic tokens need not decode as Base64.
  [Base64 rules](https://www.rfc-editor.org/rfc/rfc4648.html),
  [JWS encoding](https://www.rfc-editor.org/rfc/rfc7515.html#section-2)
- `# rayloc:ignore` and `// rayloc:ignore` are supported trailing comments outside
  quoted values, suppressing that physical line only. Count explicit suppressions.
  Text inside a string is not a directive. Document supported lexer forms and
  defer complex language syntax. Proposed `--no-inline-ignores` disables directives
  for CI policy.
- Accepted findings: each finding carries a 5-character ID (25 bits of a
  SplitMix-finalized FNV-1a digest over the scope-relative path, a NUL and the
  value). `rayloc accept <id>` adds it to `accepted` in the root policy;
  matching candidates are dropped and counted as `accepted`. Path binding keeps
  the same value reportable elsewhere. The command never takes the value, and the
  truncated digest cannot reproduce it. Staged scans read the index policy.
- Retain suppression reasons/counts without retaining raw values. Test paths have
  no special trust unless explicitly ignored.
- Combine identical secret spans at a source location, preferring provider rules
  over generic duplicates. Preserve distinct occurrences. Merged redaction spans
  must not erase separate findings.

## 4. Git acquisition and strict patch parsing

Use `std::process::Command` argument arrays, never shell interpolation. Resolve
repository root through Git; support linked worktrees and `GIT_INDEX_FILE`.
Resolve refs with `git rev-parse --verify --end-of-options <ref>^{commit}`.
Invalid refs return safe typed errors without raw arguments or Git stderr.

Staged mode uses `git write-tree` to snapshot the active index, then compares it
to the resolved HEAD tree. This may write tree objects but does not change staged
contents or refs. For unborn HEAD, generate an empty tree through Git, without
hard-coding a SHA-1 ID. Unmerged entries return 2. Read policy from the same index
tree. Detectable concurrent index/HEAD changes return 2; the scan is not atomic
with a later commit. Ref mode pins the base commit and reads the working tree;
detectable mutation or metadata/patch disagreement returns 2. Full atomic
working-tree snapshots are outside the initial contract.

Read NUL-delimited raw metadata for authoritative paths/modes, and stream a patch
with identical endpoints and explicit settings:

```text
--no-color --no-ext-diff --no-textconv --no-renames --text
--unified=0 --inter-hunk-context=0 --diff-algorithm=myers
--no-indent-heuristic --no-relative --src-prefix=a/ --dst-prefix=b/
--output-indicator-new=+ --output-indicator-old=- --output-indicator-context=' '
```

Disable configuration-driven context expansion and control quoting. `--text`
prevents binary classification/attributes from silently hiding added bytes.
Budgets still apply; archives and LFS objects are not decoded (only checked-in
LFS pointers are scanned). Do not request `--exit-code`: a successful content diff
returns 0. Drain child stderr concurrently into a bounded discarded buffer;
require successful process completion before declaring a clean scan.

`-z` makes raw/name metadata safe, but does not NUL-delimit patch headers. Decode
Git C-quoted paths and preserve unquoted spaces. Do not split `diff --git` on
whitespace for paths. Bind patch sections to metadata and validate `+++` paths.
Parser state prevents added content beginning `+++` or `@@` from becoming headers.

For `@@ -old_start[,old_count] +new_start[,new_count] @@`:

| Hunk record | Action |
| --- | --- |
| `+content` | Scan after the first byte at `new_line`; increment new counter |
| `-content` | Do not scan; increment old counter |
| ` content` | Do not scan; increment both counters |
| `\ No newline at end of file` | Neither scan nor increment counters |

Omitted counts mean 1; zero means no lines on that side. Validate consumed counts,
integer overflow, transitions, and EOF. Reject malformed/combined merge diffs.
Deleted files produce no findings. Disabled rename detection intentionally scans
renames as deletion/addition, including all added content at the new path;
document the recall/noise tradeoff. Symlink blobs are link text, never followed;
submodule gitlinks are counted as excluded scope, not scanned source.

Staged findings/snippets never reread working-tree files. Index lines are used
for staged mode; working-tree lines for ref mode. Unchanged/deleted records are
read only for framing, never detector input or proximity context. This limits
body-only PEM/split-token detection; full-file scans supplement diff mode.
[Git diff behavior/formats](https://git-scm.com/docs/git-diff),
[index tree creation](https://git-scm.com/docs/git-write-tree),
[ref/path resolution](https://git-scm.com/docs/git-rev-parse).

## 5. Configuration and ignores

Discover root `.rayloc.yaml` in Git; outside Git use the selected directory or an
explicit file's parent. Do not inherit global scanner config silently. Explicit
`--config` merges over discovered configuration while retaining repository
`.raylocignore`. CLI values override merged config, which overrides built-in
defaults. Specify and test scalar/list/rule-ID merge precedence during P3.

Version `"1"` preserves README fields. Reject unknown fields, duplicate YAML keys
or rule IDs, invalid regex/globs, non-finite/out-of-range thresholds, invalid
capture indexes/severities, and unsupported versions. Diagnostics show location
and category without source excerpts.

| Field | Semantics |
| --- | --- |
| `version` | Required schema ID `"1"` |
| `default_entropy_threshold` | Generic other-byte fallback in [0, 8]; never an unconditional provider/custom gate |
| `entropy_thresholds` (proposed) | Optional hex/alphanumeric/Base64 overrides, validated against alphabet maxima; generic length caps still apply |
| `rules` | Custom additions to enabled built-ins |
| `disabled_rules` (proposed) | Explicit known IDs; unknown IDs fail |
| `rules[].entropy` | Optional captured-value gate; omission disables entropy for that rule |
| `rules[].secret_group` (proposed) | Capture index, default 0 (whole match) |
| `rules[].severity` | `Low`, `Medium`, `High`, `Critical`; default `High` |

Custom IDs colliding with built-ins fail. Replacement needs a future explicit
mechanism. Missing optional captures produce no finding. Reject rules capable
of empty matches. Diagnose unreachable entropy thresholds where value length
and alphabet constraints can be proven. Class-specific defaults override the
global fallback; per-rule entropy is independent of generic class thresholds.

Select a maintained YAML parser with tested Rust 1.85 compatibility and explicit
input/alias/depth limits. Evaluate `serde-saphyr` or alternatives before pinning;
do not automatically choose unmaintained `serde_yaml`.
[serde_yaml status](https://docs.rs/crate/serde_yaml/latest),
[serde-saphyr budgets](https://docs.rs/serde-saphyr/latest/serde_saphyr/).

| Ignore source | Directory / glob | Explicit file | Staged / ref diff |
| --- | --- | --- | --- |
| Repository `.gitignore` | Apply to discovered untracked paths; tracked remain eligible | Explicit selection overrides | Does not suppress tracked/index content |
| `.raylocignore` | Apply | Apply; explain excluded scope | Apply as scanner policy |
| Global Git ignores / `.git/info/exclude` | Disabled for reproducibility | Disabled | Disabled |

Git directory scans discover tracked paths in bounded metadata batches so Git
ignores cannot hide tracked `.env` files. The default `ignore` walker alone does
not implement this distinction. Outside Git, local Git ignore patterns act as
scanner exclusions. V1 `.raylocignore` is root-scoped with Git anchoring, order,
negation, and directory semantics. Nested `.gitignore` follows Git precedence.
Apply `.gitignore` first and higher-priority `.raylocignore` afterward; no
automatic generated/dependency-directory exclusion layer is added.
Scanner exclusions override Git whitelist rules. Later `.raylocignore` negations
follow standard semantics; pruned parents must be re-included before descendants.

Configure walker filters explicitly: include hidden files, do not follow symlinks,
disable global/parent-outside-root ignores and unrelated `.ignore` files.
Directories such as `target/`, `node_modules/`, and `vendor/` are excluded only
through applicable ignore files; lockfiles and test directories are not
automatically safe. Glob inclusion intersects
scanner exclusions. Count regular-file glob matches before policy: all excluded
matches return 0 with an explicit excluded-scope report, while no regular-file
matches returns 2. Count deliberate exclusions; traversal/read errors fail.
An ignored explicit file returns 0 with zero scanned files and an exclusion
reason, never described as scanned clean. An explicit symlink/non-regular file
returns 2; recursive traversal records these as excluded scope.

Staged scanner policy/hierarchical ignores come from the index snapshot: unstaged
policy edits cannot change a staged scan. Other modes read working-tree policy.
Repository policy remains repository-controlled; CI can supply external config.
[Git ignore semantics](https://git-scm.com/docs/gitignore),
[walker defaults](https://docs.rs/ignore/latest/ignore/struct.WalkBuilder.html),
[glob syntax](https://docs.rs/globset/latest/globset/).

## 6. Findings, redaction, and reporting

Records carry source IDs and byte spans. Runtime rule IDs are registry indexes,
not `&'static str`, because custom rules are dynamically loaded. Locations use
1-based lines/byte columns with half-open spans; byte columns differ from visual
or Unicode columns.

Raw bytes remain borrowed/internal during evaluation. Every match/candidate
retaining a target value uses a private `RedactedString`, never a public tuple
field, `Deref`, `AsRef`, derived raw `Debug`, or automatic raw serialization.
Prefer discarding bytes once decisions/spans are recorded. A minimal wrapper:

```rust
pub struct RedactedString {
    bytes: Vec<u8>, // Private; a narrow internal detector API is the only access.
}

impl std::fmt::Display for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
```

This sketch omits internal construction/access; no public raw getter. Source
buffers are not report objects. Reveal at most a 4-byte ASCII-printable prefix,
never more than a quarter of the value, followed by a fixed-width mask; mask
values under 8 bytes or with non-ASCII prefixes entirely. Byte-level ASCII
checks avoid Unicode slicing panics, and the fixed mask hides length.
Zeroization/core-dump protection is separate from safe formatting.

Default reports show safe location, rule, severity/confidence, optional entropy,
fixed advice, and a masked `Value: ghp_********`; omit source lines. Future context output
must redact all candidate spans, including suppressed candidates, before escaping
terminal controls. Withhold the whole line if coverage is uncertain.

Input-derived paths, custom IDs/descriptions, CLI arguments, YAML/regex errors,
and child stderr can contain secrets/control characters. Never forward raw
errors. Use fixed categories and safe location numbers; sanitize/redact paths
and custom labels, withholding ambiguous metadata. Renderers receive safe report
objects rather than raw targets/buffers.

Sort by normalized path bytes, line, start/end column, and rule ID. Include
scanned/excluded/suppressed counts and wall time. Label partial reports for exit 2.
Standalone scans report findings without claiming Git aborted a commit. A
nonzero hook status blocks Git. Do not automatically suggest `--no-verify`.

## 7. Parallelism, dependencies, and packaging

Directory and glob scans use one lazily created, private Rayon pool. `--threads`
selects 1–64 workers; absent that flag, `RAYON_NUM_THREADS` is honored and the
automatic default remains at most eight available CPUs. Explicit-file, staged,
and diff scans keep their existing execution model. Directory work is admitted
for parallel scanning at 256 files or 256 KiB of estimated input, then files
are dynamically claimed by lanes so filename order does not pin large files to
one lane. The byte hint affects scheduling only; verified reads determine
reported bytes and completion. Discovery classifies entries with
`DirEntry::file_type()` and preserves deterministic policy/source assignment.
Avoid nested `ignore` traversal and unrestricted global Rayon use. Revisit
producer/consumer discovery overlap or asynchronous reporting only when a
matching workload shows those stages dominate; bounded queues must count queued
and running paths, findings and output bytes against explicit budgets.
[Rayon bridge behavior](https://docs.rs/rayon/latest/rayon/iter/trait.ParallelBridge.html)

Prefer short, correct standard-library implementations before adding crates.
Candidate production dependencies where justified: `regex`, `rayon`, `ignore`, `globset`, `serde`,
a selected YAML parser, and minimal Base64/JSON support for JOSE. Evaluate Clap
against extending the current CLI parser. `memmap2`/direct `aho-corasick` are
optional optimizations. The scaffold currently has no external crates. Pin a
reviewed lockfile, test MSRV 1.85 with intended features, and measure binary size.

Build Linux standalone distributions using an appropriate static musl target;
verify actual dynamic dependencies. macOS uses required native system
libraries without an extra interpreter/runtime package. Binaries remain specific
to OS/architecture. V1 release targets are Linux and macOS; Windows is deferred.
Prepare both release archives/checksums and a validated crates.io package; actual
publication is a separate release action. Git CLI is the initial backend;
`git2`/libgit2 requires its own
build/packaging justification. Every production function needs tests; enforce
>=95% line/region coverage and complete function coverage. Publish installation commands only once matching
release artifacts or a Cargo package exist.
[Rust linkage reference](https://doc.rust-lang.org/reference/linkage.html)

## 8. Hook management

Resolve active hooks through Git, including `core.hooksPath`, linked worktrees,
and relative paths; `.git` may be a file. Invoking `rayloc hook install` selects
Git's active directory, including configured custom/shared destinations, without
another opt-in. Preserve unmanaged hooks. Default managed hook:

```sh
#!/bin/sh
# Managed by rayloc.
exec rayloc scan --staged
```

Check binary discoverability, write atomically with executable permissions, and
propagate scan status. Reinstalling an identical managed hook is idempotent.
An unmanaged existing hook returns 2 with manual integration instructions; do
not overwrite, silently chain, or delete it. Any future removal may remove only
verified managed content. A missing scanner fails the commit. Installation does
not override Git hook policy or guarantee every future commit is scanned.
Also prepare an optional Python pre-commit framework integration using a Rust
hook repository manifest; see [integration research](docs/research/pre-commit-integration.md).
Framework installation and rayloc's direct installer have separate destination
behavior, including the framework's current `core.hooksPath` limitation.
[Git hook execution](https://git-scm.com/docs/githooks),
[Git path resolution](https://git-scm.com/docs/git-rev-parse).

## 9. Performance and acceptance criteria

Under-5-ms total runtime and 500 MB/s/core are stretch goals, not validated
properties. Each process pays rule compilation/configuration, filesystem, and
Git startup costs; `LazyLock` does not persist across CLI invocations.

Measure separately:

- Engine throughput: preloaded bytes/precompiled complete rules, including
  extraction, entropy, exclusions, and findings.
- End-to-end file/directory throughput: startup, real reads/traversal, filtering,
  and rendering, with warm/cold cache stated.
- Hook latency: process start through exit, including Git/index snapshots; empty
  and 10/100/1,000-line diffs across multiple file counts.

Use release builds, repeated runs, median/p95/p99, CPU/OS/Rust versions, thread
count, corpus size/content, active rules, and cache conditions. Define MB/s and
one-core versus aggregate rates. Track peak RSS for >10-MB files, giant lines,
and many tiny files. Speed must not improve through silent scope omissions.

Evaluate synthetic format-valid positives and reviewed clean negatives across
formats, lengths, contexts, encodings, and boundaries. Keep calibration and
held-out values/repositories separate. Report precision, recall, per-family
counts, false positives per clean MB, and suppression effects. Require 100%
detection of mandatory supported-format fixtures and zero raw-value output in
leak tests. Set broader numerical quality gates after a credible labeled baseline.
Research results motivate evaluation; they are not rayloc performance claims.
[Comparative scanner study](https://arxiv.org/abs/2307.00714),
[SecretBench paper](https://arxiv.org/abs/2303.06729).

Required implementation coverage:

- Git: unborn HEAD, partial staging, deleted/context-only secrets, zero/omitted
  hunk counts, header-like content, multiple hunks, CRLF/no final newline, quoted
  and non-UTF-8 paths, renames, force-added ignored files, binary attributes,
  unmerged entries, alternate index, worktrees, invalid refs, and process failures.
- Detection: provider families, PKCS #8, unpadded JOSE/empty segments, low-entropy
  passwords, random short/hex keys, checksum context, exact placeholders,
  directives inside strings, escapes, long lines, and buffer-boundary matches.
- Config/paths: malformed/duplicate/unknown YAML fields, invalid/oversized rules,
  threshold precedence, nested ignores/negation/pruned parents, hidden `.env`,
  explicit ignored files, globs, symlinks, and read failures.
- Reporting: stdout/stderr/Display/Debug for short/Unicode/invalid-byte values,
  multiple secrets per line, custom metadata/parser errors/path controls,
  deterministic ordering, result limits, and mixed findings/errors.
- Hooks: installation, existing hooks, executable bit, shared/custom paths,
  missing scanner, and status propagation.

Complete `cargo fmt --all -- --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`,
and `cargo bench`. The zero-test scaffold cannot validate detection/performance.

## 10. Implementation sequence and open decisions

1. Safe value/report types and typed errors; byte-oriented file scanning with
   core provider rules, boundaries, and leak regression tests.
2. Strict configuration, captured-value entropy, generic/password context,
   reproducible ignores, and bounded parallel directory/glob scans.
3. Snapshot staged mode and strict patch parser, then reference mode; pass Git
   edge-case tests before enabling enforcement.
4. Hook lifecycle, packaging, and benchmark/accuracy harnesses; then publish
   measured performance.

Before pinning dependencies, settle YAML parser/MSRV and parser budgets. Before
tuning detection, establish held-out data and length-specific entropy tradeoffs.
Before release, fix supported OS/Git versions and artifact names. Memory mapping,
extra prefix routing, richer context, and broader decoding need measured evidence;
they are not prerequisites for correctness.

## 11. V1 implementation and release evidence (2026-10-04)

Sections above describe the original contract, not the current scaffold status.
The file/directory/glob, staged/reference, policy, context/JOSE and hook packages
are now implemented. YAML/MSRV/dependency and resource budgets are resolved in
[development decisions](docs/development-decisions.md). Standalone entropy,
memory mapping, extra prefix routing, language-complete parsing and decoding
extensions remain deferred. Reports show sanitized scope-relative paths and
prefix-masked values, falling back to numeric sources and full masks.

[Release baseline](docs/research/release-baseline.md) and its JSON provide warm
complete-workload engine, startup-inclusive file/directory/staged, extended-file
RSS, and held-out accuracy evidence. The two speed targets remain stretch goals.
Rust 1.85 and Git 2.30 are locally exercised on Linux. Native musl/macOS linkage,
architecture and runtime checks remain exact-SHA CI gates before support claims.
Archives/checksums and crates.io source validation are prepared separately from
publication. See [release instructions](docs/release.md).

Direct-reference scans conservatively return incomplete-scan error 2 when staged
edits reversed in the workspace cause Git's index cache to mutate during the
acquisition. Keep index/workspace race validation until a proven read-only
snapshot protocol replaces it. The release baseline lists deferred P4/P5 minor
compatibility/performance observations for whole-branch review.
