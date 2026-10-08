# Technical design validation

Review date: 2026-10-01. Scope: README feature promises, `technical-design.md`,
`AGENTS.md`, configuration templates, and the current Rust scaffold.

## Outcome and method

Retain Rust, compiled byte regexes, bounded parallel scanning, added-line Git
scanning, and an offline deployment model. Revise the detector's filtering
contracts, Git acquisition, redaction boundary, ignore semantics, configuration,
and performance claims before implementing the engine.

The review used primary library/provider documentation, IETF specifications,
Git manuals, scanner source/configuration, research papers, and local synthetic
experiments. Source facts and proposed design decisions are distinguished below.
No live credentials were used, no external verifier was contacted, and no actual
scanner accuracy or throughput was measured. The repository currently has no
scanning implementation, tests, or scanning benchmarks.

## Findings and decisions

| Area | Finding / evidence | Resulting design decision |
| --- | --- | --- |
| Four-stage gates | Original overview required all gates, while Stage 2 explicitly bypassed entropy. Format detection, generic entropy, and password context need different checks. | Preserve the structural bypass and make rule-dependent branches explicit. |
| Entropy and length | Empirical entropy is bounded by `log2(min(n, alphabet_size))`; a 4.5 gate cannot accept 16/20-byte strings or any hex string. Synthetic short random tokens frequently fail it. | Class thresholds, proposed generic caps of 3.5 for 16–23 bytes and 4.0 for 24–31 bytes, held-out calibration, and a separate strong password branch. |
| Regex architecture | A `RegexSet` reports rule membership, not captures or spans; complexity depends on compiled pattern size. Match iteration can be quadratic in haystack length. [RegexSet](https://docs.rs/regex/latest/regex/bytes/struct.RegexSet.html), [regex](https://docs.rs/regex/latest/regex/) | Set preselection plus precompiled individual extractors, bounded records/programs, and optional measured prefix routing. |
| AWS rule | AWS documents `AKIA`/`ASIA` as access-key prefixes, but `AIDA`, `AROA`, `AGPA`, and others identify IAM resources. [AWS identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) | Remove non-key IAM prefixes from the access-key rule; treat IDs separately from secret access keys. |
| GitHub rule coverage | README implies GitHub coverage but design listed only fine-grained PATs. Current docs include six token prefixes and a 2026 installation-token change. [GitHub formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats), [2026 notice](https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/) | Cover classic/OAuth/app/refresh/fine-grained tokens and `ghs_APPID_JWT`; review rules with dated fixtures. |
| Provider lengths | Stripe documents secret/restricted versus publishable credentials; Slack documents secret URLs and GovSlack. Exact body/team lengths in the original are not established by these docs. [Stripe](https://docs.stripe.com/keys), [Slack](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) | Include restricted/test keys and GovSlack. Mark scanner body bounds as heuristics requiring fixtures, not provider guarantees. |
| Private keys | PKCS #8 uses `PRIVATE KEY` and `ENCRYPTED PRIVATE KEY`. The original regex requires extra text before ` PRIVATE KEY`, so it misses the ordinary header. [RFC 7468 §§10–11](https://www.rfc-editor.org/rfc/rfc7468.html#section-10) | Optional recognized label prefix, explicit public-key negatives, and honest marker-level confidence. |
| JWT / Base64 | JWS uses unpadded Base64url. JWT permits unsecured tokens; JWE compact serialization differs from JWS. `eyJ` and nonempty signatures are not universal requirements. [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | Bounded structural parsing; no universal padding filter; JOSE confidence is separate from credential validity. |
| Hash/placeholder exclusions | Shape alone does not tell whether a value is public or secret. A keyword substring can occur inside a real credential. This is a design inference, not a provider guarantee. | Restrict exclusions to explicit values/rules and known checksum context. Never suppress all test credentials or homogeneous passwords. |
| Binary / hidden files | Byte regexes accept invalid UTF-8, and `ignore` defaults to skipping hidden files. A NUL probe would also suppress UTF-16. [byte RegexSet](https://docs.rs/regex/latest/regex/bytes/struct.RegexSet.html), [walker](https://docs.rs/ignore/latest/ignore/struct.WalkBuilder.html) | Include hidden files and scan selected raw bytes; state encoding/archive limits explicitly. |
| Memory mapping | File-backed maps require safety precautions if their backing file can change, including copy-on-write maps. [memmap2](https://docs.rs/memmap2/latest/memmap2/struct.MmapOptions.html) | Buffered workspace reads; mapping only with an enforceable immutable backing store. |
| Streaming | `BufRead` exposes bounded buffer access; line APIs alone do not establish a total memory budget. [BufRead](https://doc.rust-lang.org/std/io/trait.BufRead.html) | Explicit physical-line/candidate/buffer/queue/result budgets; hitting a limit cannot return clean. |
| Git modes | Cached diffs read the index; a one-ref diff reads tracked working-tree content. Git offers external helpers/text conversion and several patch formats. [git diff](https://git-scm.com/docs/git-diff) | Snapshot staged content, explicitly define ref semantics, disable helpers/textconv, force byte-content diffs, validate a single patch format. |
| Git paths | NUL metadata avoids pathname ambiguity, but patch paths still use quoting; verified locally. [diff formats](https://git-scm.com/docs/git-diff-tree), [revision parsing](https://git-scm.com/docs/git-rev-parse) | Authoritative raw metadata plus C-quoted patch-path decoding, byte paths, and safe ref arguments. |
| Ignore behavior | Git ignore files target untracked paths; tracked files are unaffected, and excluded parents cannot be traversed to reinclude a child. [gitignore](https://git-scm.com/docs/gitignore) | Preserve tracked-path eligibility; mode-specific Git versus scanner ignore policy; disable machine-global exclusions by default. |
| Config completeness | Original design did not specify custom rule merging, captures, threshold inheritance, errors, or schema validation. `serde_yaml` is unmaintained. [serde_yaml](https://docs.rs/crate/serde_yaml/latest), [parser budget alternative](https://docs.rs/serde-saphyr/latest/serde_saphyr/) | Strict versioned schema and resource budgets. Defer final parser choice until MSRV/dependency review. |
| Redaction | Original wrapper publicly exposed the string, implemented no `Debug`, and sliced UTF-8 at byte offsets. Redacting one match in a source line does not protect another value. | Private bytes, safe `Display` and `Debug`, full masking, no default excerpts, safe metadata/diagnostics. |
| Hooks / packaging | Git hooks can use custom paths and require executable permissions. Native executable linkage varies by target. [hooks](https://git-scm.com/docs/githooks), [linkage](https://doc.rust-lang.org/reference/linkage.html) | Safe/idempotent installation preserving existing hooks; platform-specific release validation and an explicit Git prerequisite. |
| Parallel performance | Rayon iterator bridging synchronizes serial input and does not preserve order. [Rayon](https://docs.rs/rayon/latest/rayon/iter/trait.ParallelBridge.html) | Bounded work batches, one pool, worker-local results, final sorting, and a small-input serial path. |
| Latency / accuracy | No implementation validates 5-ms/500-MB/s claims. Empirical scanner research documents precision/recall tradeoffs and file/rule-related misses. [comparative study](https://arxiv.org/abs/2307.00714), [SecretBench](https://arxiv.org/abs/2303.06729) | Make speed stretch goals measurable; add held-out detection evaluation and end-to-end benchmark contracts. |

## Synthetic experiments

Executed on 2026-10-01 using Python 3 and Git 2.55.0, in a temporary repository
outside the project. The temporary repository contained only obvious synthetic
strings. These are semantic probes, not engine benchmarks or implemented tests.

### Entropy feasibility

For a string with `n` bytes, empirical entropy cannot exceed `log2(n)`, because
there can be no more than `n` observed symbols. The alphabet imposes another bound.
Computed maxima:

| Length | Maximum bits/byte (if all distinct) |
| --- | ---: |
| 8 | 3.0000 |
| 16 | 4.0000 |
| 20 | 4.3219 |
| 22 | 4.4594 |
| 23 | 4.5236 |
| 24 | 4.5850 |
| 32 | 5.0000 |

A second probe generated 10,000 uniformly sampled strings per alphabet/length
with `random.Random(0)`, and measured the fraction passing a 4.5 threshold.
The generator traversed all alphanumeric lengths first, then all hex lengths.

| Alphabet | Length | Accepted / 10,000 | Mean empirical entropy |
| --- | ---: | ---: | ---: |
| Alphanumeric (62 symbols) | 16 | 0 | 3.7685 |
| Alphanumeric | 20 | 0 | 4.0331 |
| Alphanumeric | 24 | 496 | 4.2425 |
| Alphanumeric | 32 | 6,689 | 4.5450 |
| Alphanumeric | 40 | 9,754 | 4.7646 |
| Hex (16 symbols) | 16 | 0 | 3.2110 |
| Hex | 20 | 0 | 3.3616 |
| Hex | 24 | 0 | 3.4692 |
| Hex | 32 | 0 | 3.6140 |
| Hex | 40 | 0 | 3.6962 |

These results demonstrate a filter's length bias. They do not measure secret
recall: random strings are not a representative labeled credential corpus.
A lower threshold also admits more benign strings, so context/calibration matters.

Reproduction core:

```python
from collections import Counter
import math, random, string
rng = random.Random(0)
def entropy(value):
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())
for alphabet in (string.ascii_letters + string.digits, "0123456789abcdef"):
    for length in (16, 20, 24, 32, 40):
        measurements = [entropy("".join(rng.choice(alphabet)
                        for _ in range(length))) for _ in range(10000)]
        print(length, sum(h >= 4.5 for h in measurements),
              sum(measurements) / len(measurements))
```

### Private-key and Base64 checks

Applying the original header regex using Python's regex engine rejected
`-----BEGIN PRIVATE KEY-----` but matched the RSA, EC, ENCRYPTED, and OPENSSH // rayloc:ignore
variants. This establishes the optional-label bug; it does not verify Rust
regex performance or key validity. The corrected pattern includes all five.

A Base64url-encoded JSON header with padding removed decoded successfully after
restoring padding internally. This agrees with JWS requirements and demonstrates
why a blanket missing-padding rejection would suppress valid candidates.

### Git content and pathname checks

| Probe | Observed result | Consequence |
| --- | --- | --- |
| New repo with staged file, no HEAD | Cached diff emitted one added line | Unborn HEAD is valid staged input, not inherently an error. |
| Stage a new line, then replace it without staging | Cached diff contained staged value only | Scanner must use index bytes and index line numbers. |
| Same file, `git diff HEAD` | Patch contained current unstaged replacement | `--diff <ref>` needs explicit working-tree semantics. |
| Add a path matching `.gitignore` using `git add -f` | Path appeared in cached NUL metadata | Git ignores cannot suppress staged content. |
| Filename containing space, tab, and newline | NUL name metadata preserved full name | Whitespace/newline splitting loses paths. |
| Same filename with patch `-z` | `+++` header remained C-quoted | `-z` does not make patch paths NUL-delimited. |
| Staged file starting with NUL | Ordinary patch said binary files differed | Default Git binary handling omits detector input. |
| Same diff with `--text` | Patch included added NUL-containing payload | Explicit byte-content acquisition closes that omission. |

Reproduction sequence for the staging distinction:

```sh
git init -q /tmp/rayloc-git-probe
cd /tmp/rayloc-git-probe
git config user.email design@example.invalid
git config user.name 'Synthetic Design Validation'
printf 'old\n' > partial.txt
git add partial.txt
git diff --cached --unified=0
git commit -qm 'Synthetic baseline'
printf 'old\nstaged_synthetic_value\n' > partial.txt
git add partial.txt
printf 'old\nunstaged_synthetic_value\n' > partial.txt
git diff --cached --unified=0
git diff HEAD --unified=0
```

## Validation completed and remaining work

Required repository checks all passed:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`
- `cargo bench`

Tests and benchmark harnesses each contain zero tests. These results validate the
existing scaffold, not the new design's detection behavior or speed. Documentation
links/feature alignment and synthetic semantic probes provide the evidence for
this review. No Rust implementation or dependencies were added.

The revised design deliberately leaves these empirical decisions open:

1. Choose/pin a maintained YAML parser after Rust 1.85, parser-budget, license,
   and transitive-dependency review.
2. Calibrate generic thresholds by length/context using held-out synthetic
   credentials and reviewed clean files; define precision/recall gates from data.
3. Establish engine versus end-to-end baselines on named hardware. Extra literal
   routing, memory mapping, and parallelism thresholds require measured benefit.
4. Confirm current provider body formats with dated fixtures; do not turn
   community rule lengths into permanent provider guarantees.
5. Set supported OS/Git versions and release artifact names before publishing
   download or Cargo installation instructions.

The new budgets, generic length caps, password minimum length, ignore precedence,
snapshot strategy, rename handling, and full-mask output are proposed rayloc contracts. They are
engineering decisions informed by the evidence, not behavior mandated by the
external sources or already implemented by the scaffold.
