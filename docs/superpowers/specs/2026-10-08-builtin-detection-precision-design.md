# Builtin detection precision design

Status: revised after user review; implementation authorized on 2026-10-08.

Date: 2026-10-08. Rayloc source inspected: `b0ecc6e`, the issue worktree's base. This document and its
implementation plan define the approved implementation scope.

## Intent and constraints

Reduce findings for programming variables, constants, and expressions while
keeping Rayloc a fast, deterministic text scanner. Preserve detection of concrete
credentials, including weak passwords, unquoted configuration values, and provider
signatures. The user has now authorized inspection of the original finding source
files in vLLM and Paperclip. Finding lines have been checked against the preview
locations; fixture examples reproduce those lexical forms without copying
credential literals into documentation.

The review fixes three decisions: source code receives the same credential
detection requirements as other text; exclusions require evidence of a reference
or a non-binding expression; dummy/test credentials receive no new special treatment.
Reviewed intentional findings use the existing `rayloc:ignore` and `rayloc accept`
mechanisms. The spelling implemented by Rayloc is `rayloc:ignore`, not
`rayloc:ignored`.

Global constraints for implementation:

- Rust edition 2024; minimum Rust version 1.85.
- Add no runtime dependencies, network calls, models, or language parsers.
- Keep the existing 256 KiB reader/chunk buffers and 64 KiB candidate limit.
- Never load a complete file larger than 10 MB into memory; retain bounded streaming.
- Compile policy regexes once; preserve Rayon execution and immutable shared policy.
- Scan only added lines in staged/reference modes; preserve source line and byte columns.
- Normal output, debug formatting, diagnostics, and research artifacts contain no raw credentials.
- Preserve exit codes 0 for clean, 1 for findings, and 2 for incomplete/error scans.
- Require at least 95% production line and region coverage and 98% function coverage.
- File extensions, test paths, and identifier-shaped values alone never exempt credentials.

The existing explicitly requested `preview` command was used for this research.
Its raw output is local, outside the repository. Commit only aggregate evidence,
code symbols, and synthetic fixtures stored using the existing short-chunk convention.

## Evidence from preview

Installed executable: `/home/liam/.local/bin/rayloc`, version `2026.10.7`, SHA-256
`cffd7445b23b1e4cf40066acd902437c1547df3de80c5d7540e89f6fa12c50f1`.
The user confirmed that this installed build came from commit `4a5bed8`.
The implementation checkout is based on `b0ecc6e`; establish its own immutable
baseline before detector changes rather than comparing different revisions as if
they differed only in this fix.

### vLLM

Command: `rayloc preview /home/liam/Dev/installation/vllm`.

The scan reported eight findings, all `context-secret`, across four distinct values:

| Preview value | Occurrences | Bytes | Empirical entropy, bits/byte |
| --- | ---: | ---: | ---: |
| `args.vllm_api_key` | 2 | 17 | 3.734522 |
| `self.allow_credentials` | 1 | 22 | 3.697846 |
| `self.DUMMY_API_KEY` | 4 | 18 | 3.836592 |
| `args.allow_credentials` | 1 | 22 | 3.754442 |

Summary: 111.26 MiB read, 2,451,930 lines, 7,567 of 7,597 files completed;
37 exclusions; exit 1; reported elapsed time 1,091.885 ms. Counts are copied from
the report rather than reconciled into a new file-accounting interpretation.
This single scan is an observation, not a performance baseline.

### Paperclip

The supplied absolute glob returned exit 2 (`cannot enumerate selected scope`).
Rayloc's glob acquisition rejects absolute patterns. The successful equivalent
for the service directory was run with the Paperclip repository as working directory:

```sh
rayloc preview --glob 'server/src/services/*.ts'
```

This pattern selects immediate service `.ts` files; recursive coverage is not claimed.
The report contained 35 findings: 12 `context-secret`, 17 `password-assignment`,
three `openai-key`, two `private-key-marker`, and one `postgres-uri`.
It completed 612 of 612 files, read 13.89 MiB and 376,120 lines, and reported
104.892 ms. This also is a single observation.

Source inspection separates ten member-reference occurrences from one quoted
configuration-key occurrence:

| Preview value | Occurrences | Rule |
| --- | ---: | --- |
| `"ANTHROPIC_AUTH_TOKEN"` in a ternary environment-key selector | 1 | `context-secret` |
| `auth.accessToken` | 1 | `context-secret` |
| `deps.completeCredential` | 1 | `context-secret` |
| `input.credential` | 1 | `context-secret` |
| `row.externalCredential` | 2 | `context-secret` |
| `input.configPath` | 1 | `context-secret` |
| `grantRef.configPath` | 1 | `context-secret` |
| `input.env.COGNEE_API_KEY` | 1 | `context-secret` |
| `credentials.accessToken` | 1 | `context-secret` |
| `credentials.clientSecret` | 1 | `password-assignment` |

All eight vLLM occurrences and ten Paperclip member occurrences are unquoted
references. Examples include a Python dictionary value, a Rust struct field,
Python keyword arguments, TypeScript object properties, and `?? null` fallbacks.
The reported `credentials.clientSecret` is a reference assigned to `appPassword`,
not a hardcoded password.

Paperclip's `ai-provider-routing.ts:31` contains this non-secret expression:

```ts
route.auth === "api_key" ? "ANTHROPIC_API_KEY" : "ANTHROPIC_AUTH_TOKEN" # rayloc:ignore
```

It selects an environment-variable name inside `env[...]`; neither string is a
credential. Therefore the 43 preview findings include 18 reference errors and one
binding error. There are 13 distinct member-reference values; the earlier bare
constant hypothesis for `ANTHROPIC_AUTH_TOKEN` was incorrect.

The remaining 24 findings consist of 16 quoted password literals, two quoted
Bearer-token literals, three provider-shaped token occurrences, one URI with
credentials, and two private-key-marker occurrences. One marker is used by a
`startsWith` check. Those findings do not establish live credential activity;
their synthetic/test naming does not authorize automatic suppression. Marker-only
recognition remains the existing provider contract for this change.

## Cause in the inspected code

`src/rules/context.rs` has two implementations: complete-line `detect` and
incremental `ContextState`. Both identify a strong assignment name and capture
an unquoted right-hand token. `reference` knows a small prefix list such as
`config.` and `process.env`, but does not recognize arbitrary member access or
bare constants. Unquoted calls/indexes and certain following operators are
rejected separately; dots inside the captured value are still eligible.

`src/rules/entropy.rs::generic_passes` caps the effective threshold at 3.5 for
16–23 bytes. All four vLLM values clear this gate. Raising the threshold would
also lose short genuine tokens. The password branch has no entropy gate, so an
entropy adjustment would not address `credentials.clientSecret`.

The lexer also accepts any `:` or `=` after a plausible name without enough
operator evidence. It interprets `"ANTHROPIC_API_KEY" : "ANTHROPIC_AUTH_TOKEN"` # rayloc:ignore
inside the ternary as a secret-bearing key/value pair. Equality operators can
likewise be mistaken for assignment. This requires binding classification before
value classification; reference filtering alone cannot fix the quoted-key case.

`reference` also applies programming-reference prefixes to quoted values today.
Make those checks quote-sensitive so actual passwords such as `config.password`
remain eligible. An `allow_credentials` name exemption is unnecessary: its two
observed values are already proven member references. Keep literal values under
existing strong field names eligible instead of adding a field-name blacklist.

## Research and alternatives

| Approach | Accuracy implications | Runtime implications | Decision |
| --- | --- | --- | --- |
| Bounded binding and reference checks, with optional source grammar hints | Separates values from expressions and configuration-key labels; preserves unresolved value eligibility | Constant source metadata and small lexer state; candidate checks can avoid entropy work | Recommended first change |
| Candidate-only character n-gram or small statistical classifier | Could help readable labels and unfamiliar token shapes; needs labeled data and recall calibration | Linear candidate scoring and a static table; speed must be measured | Separate experiment if lexical errors remain |
| Full language parsing, data flow, transformer inference, or online verification | Can resolve broader context or activity; introduces syntax/data/model/service coverage limits | Larger startup, state, dependency or network costs | Outside the default scanning path |

Supporting primary sources, accessed 2026-10-08:

- Meli, McNiece, and Reaves, NDSS 2019, combine distinctive formats with entropy,
  word, and pattern filters. Their dictionary discussion explicitly identifies
  false negatives when random credentials contain ordinary words. Transfer the
  staged filtering idea; avoid a universal dictionary rejection.
  [How Bad Can It Git?](https://bradreaves.net/publication/mmr19/mmr19.pdf)
- Saha et al., COMSNETS 2020, identify variables, environment references, and
  function calls as false positives, and evaluate candidate features with a
  voting classifier. They report secret-class precision 84% and recall 89% on
  their test set. Those results support collecting context evidence, but do not
  establish Rayloc throughput or transferable accuracy.
  [Secrets in Source Code](https://secpriv.wien/fulltext/publik_302294.pdf)
- Samsung's CredData ground rules distinguish unquoted configuration values
  from variables in languages requiring quoted strings. They also retain
  credentials in test directories as positives. Use those distinctions in
  regression labeling; document differences from Rayloc's existing policy.
  [CredData ground rules](https://github.com/Samsung/CredData#ground-truth)
- Yelp's implementation has separate indirect-reference and ID-context filters;
  its dollar-prefix filter notes the risk of missing actual values beginning
  with `$`. This supports branch-scoped, syntax-aware exclusions.
  [detect-secrets heuristic filters](https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/filters/heuristic.py)
- KEYSENTINEL combines text parsing and several filters, including a learned
  password filter. Its implementation and evaluation use a different runtime
  and resource profile. Borrow the separation of candidate extraction and
  verification; require local evidence for performance.
  [Author paper](https://kee1ongz.github.io/paper/sp25-secret.pdf),
  [author implementation](https://github.com/XingTuLab/KEYSENTINEL)
- Huang et al., ISSTA 2026, describe StringGroup and transformer-based Secretron.
  The abstract motivates compact string context instead of noisy broad code
  context. This is a research direction, not evidence for adding inference to a
  millisecond pre-commit scanner. This review used the abstract.
  [Checked-In Secret Detection: Strings Are All You Need](https://arxiv.org/abs/2608.04523)

The recommendation is an engineering inference from these sources and the local
evidence. No paper establishes that all secrets can be distinguished from public
strings using entropy or local syntax alone.

## Proposed behavior

### Uniform credential detection with a source grammar hint

Introduce a copyable `SourceSyntax` enum with `Code` and `Text` variants.
Select `Code` only for these ASCII-case-insensitive suffixes:
`.py`, `.pyi`, `.rs`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`.
All other paths and unnamed readers use `Text`.

`Code` selects additional operator/reference grammar; it does not mean the file is
trusted, ignored, or restricted to quoted secrets. An unquoted opaque credential
that also matches the shape of a bare identifier stays eligible in `Code`.
Quoted passwords, short generic keys, hex values, provider signatures, JOSE, and
custom rules use the same acceptance criteria in both modes. Never filter a value
merely because it is bare, uppercase, snake case, camel case, or a valid identifier.

This small initial list enables the lexical rules needed by the observed sources.
Shell, PowerShell, `.env`, YAML, JSON,
Markdown, unknown extensions, and extensionless inputs retain text handling.
Adding a language requires its own literal/reference regressions.

Compute the hint once per source from its original path bytes, using existing
metadata only. Carry it through serial scanning, helper batches, fragmented lines,
staged index paths, and working-tree/reference diff paths. Do not inspect unchanged
lines or add file reads. Reused workers must replace the hint when sources change;
line resets preserve it. Existing public pathless detector/reader APIs default to
`Text`; provide an additive detector API taking an explicit hint for callers that
know source syntax.

### Establish binding evidence first

Add a small shared association classifier to the existing lexers. It consumes the
significant token before the potential name and at most three bytes of delimiter
lookahead. Retain that lookahead across input fragments; do not add a second pass
over every line, an AST, or file-wide symbol resolution.

In `Code`:

- A single `=` is an assignment delimiter. `==` and `===` are equality operators,
  not assignments, but a concrete value compared with a strong credential field
  remains eligible: `if (password === 'weakweak')` may expose a hardcoded password.
  Capture the actual value after the full operator rather than an `=` fragment.
  `=>` is not such an association. A colon beginning `::` or `:=` is not a property delimiter.
- A candidate name immediately following a significant `?` cannot turn a following
  `:` into a property binding: it is the true branch of a ternary. This applies to
  quoted and unquoted branch labels, including the verified environment selector.
- Real `=` bindings, object/dictionary `:` bindings, struct fields, keyword
  arguments, and existing authorization headers remain eligible. A question mark
  in a quoted name/value does not become an operator. A real object inside a
  ternary remains a real object: `flag ? {api_key: 'VALUE'} : fallback` still scans
  `VALUE` because the key follows `{`, not `?`.
- An uncertain token role retains existing candidate eligibility. Do not require
  every property to be preceded by `{` or `,`: valid properties can start a physical
  line inside a multiline object, including an isolated added line in a diff.

`Text` retains its assignment/header behavior, including unquoted `.env` values
beginning with `=`. Definite non-bindings never create context candidates; they
are not counted as reference suppressions. Their strings remain visible to the
independent provider/custom branches.

This is a narrow correction of operator roles, not a promise to parse arbitrary
ternaries or evaluate hardcoded literals nested inside unsupported expressions.
Do not suppress an entire line because it contains a comparison or ternary; real
credential assignments elsewhere on that line must still be scanned.

### Classify references without suppressing unresolved values

Add `src/rules/assignment.rs` for source hints, binding evidence, normalized field
evidence, and reference classification. Both context implementations call it before entropy
or the concrete-password/AWS context branches.

Classify a candidate using source syntax and whether it was quoted:

1. Preserve existing supported template/environment interpolation exclusions.
2. Apply programming-prefix exclusions such as `config.` or `settings.` only to
   unquoted values. A quoted `password='config.password'` is a concrete password.
3. In `Code`, recognize an entire unquoted qualified reference containing at least
   one explicit member/qualification operator:
   `IDENT (('.' | '::' | '->' | '?.') IDENT)+`, where
   `IDENT = [A-Za-z_][A-Za-z0-9_]*`. This includes arbitrary receivers and constants
   used through qualification, such as `self.DUMMY_API_KEY` or `constants.API_KEY`;
   no receiver-name allowlist is needed.
   A standalone `IDENT` is undecided and stays eligible. This prevents suppression
   of opaque alphanumeric credentials on the basis of a code suffix. Detecting
   every unresolved bare constant alias would require additional binding evidence;
   such cases retain existing reporting and can be explicitly reviewed.
4. Preserve the existing rejection of unquoted call/index and unsupported
   following-expression forms. Do not reinterpret quoted parentheses or dots
   as reference syntax. In `Code`, a closing `)` ends an unquoted assignment
   token so references inside function arguments receive the same classification.
5. Treat an unrecognized or non-ASCII shape as undecided and retain its existing
   eligibility. Do not reject every unquoted byte sequence just because the file
   has a code suffix. Do not reject dotted text values through the new grammar.

Reference decisions affect only `context-secret`, `password-assignment`, and
`aws-secret-access-key`. Provider signatures, JOSE, URI recognizers, and explicit
custom rules still run independently. A provider token that also resembles an
identifier remains reportable. Continue enforcing enabled candidate limits before
suppression, including on ignored lines.

Quoted credentials retain existing entropy/length rules. Passwords of at least
eight bytes still bypass entropy; generic minimum length remains 16. Keep all
entropy defaults, overrides, and length caps unchanged.

### Consistent field evidence

Share the normalized field classification used by `ContextState` and `detect`,
including the existing provider-associated suffixes that currently appear only
in the streaming implementation. Preserve long-name suffix and acronym behavior.

Keep the existing strong fields, including the existing suffix interpretation of
`allow_credentials`. Its unquoted boolean/member reference is not a credential;
an opaque literal in that assignment remains eligible under the current rule.
Do not add exceptions for `allow_credentials`, `allowCredentials`, configuration
key spelling, or any names containing `allow`, `token`, `credentials`, or `test`.

Use existing `reference` counters for new recognized code references. Preserve
checked accumulation and the counters' units. Field classification changes simply
prevent weak generic candidates from being formed; do not count them as references.

### Required examples

| Input form / source | Expected result |
| --- | --- |
| `api_key = args.vllm_api_key`, `.py` | No generic finding; reference counted | # rayloc:ignore
| `password: credentials.clientSecret`, `.ts` | No password finding; reference counted | # rayloc:ignore
| Verified environment-key ternary above, `.ts` | No context finding; not a binding |
| `auth_token = ANTHROPIC_AUTH_TOKEN`, `.ts` | Remains eligible; bare spelling alone is insufficient proof | # rayloc:ignore
| `api_key = input.env.COGNEE_API_KEY`, `.ts` | No generic finding; reference counted | # rayloc:ignore
| `api_key = client?.credentials`, `.ts` | No generic finding; reference counted | # rayloc:ignore
| `password = 'self.DUMMY_API_KEY'`, `.py` | Password finding | # rayloc:ignore
| `password = 'config.password'`, `.ts` | Password finding |
| `password=self.DUMMY_API_KEY`, `.env` | Password finding; new code grammar does not apply | # rayloc:ignore
| `password=aaaaaaaa`, `.env` or `.sh` | Password finding despite low entropy | # rayloc:ignore
| `api_key=<opaque 16-byte fixture>`, `.env` or unnamed reader | Existing entropy behavior |
| `api_key=<opaque 16-byte fixture>`, `.py` or `.ts` | Same generic acceptance as text; identifier shape is not an exclusion |
| `password=aaaaaaaa`, `.py` or `.ts` | Password finding despite being bare and low entropy | # rayloc:ignore
| `allowCredentials='opaque fixture'`, `.ts` | Existing generic entropy/length behavior |
| `api_key === 'opaque fixture'`, `.ts` | Credential-field comparison; existing entropy/length criteria apply |
| `password === 'weakweak'`, `.ts` | Password finding; equality does not make a hardcoded value safe |
| `flag ? {api_key: 'opaque fixture'} : fallback`, `.ts` | The actual object property remains eligible |
| Ternary metadata followed by `password='weakweak'` on the same line, `.ts` | Password finding survives | # rayloc:ignore
| A supported provider fixture inside a code reference/comment/string | Provider finding, subject only to existing explicit policy |

Require the 18 verified member occurrences and one ternary-key error to be clean
under the appropriate source grammar, with unchanged coordinates on remaining
findings. Preserve the 24 existing literal/provider/marker findings under the same
inputs and policy. If targets change, compare source hashes and reclassify the
changed occurrences instead of treating the historical count as an absolute gate.

## Literal policy and provider audit

Concrete credentials in tests remain reportable. Do not suppress
all `.test.ts` files, readable passwords, `synthetic`/`dummy` substrings, or the
word `password`. Add no synthetic/dummy-specific exclusions or test-file policy.
Keep the existing documented exact placeholders. After review, a user can add an
exact trailing `# rayloc:ignore` / `// rayloc:ignore` directive to the relevant
line or run `rayloc accept <id>` for the existing path/value-bound acceptance.
`--no-inline-ignores` continues to disable inline suppression. Do not pre-accept
the target repositories' findings or modify their files while researching this issue.

The accuracy goal is useful warnings about possible credentials without repeated
warnings for references, expressions, or configuration-key labels. Public strings
that still meet credential evidence use explicit review controls; they do not
become silent exceptions in the builtin detector.

A marker string alone is already described as `private-key-marker`, not a
validated private key. Distinguishing a harmless marker constant from a complete
PEM key requires additional bounded multiline evidence. That is a separate design;
this change preserves marker behavior and does not infer safety from a test path.

Audit findings for subsequent provider work:

- `api_key_match_with_min` shares a permissive alphabet/minimum across unrelated
  providers and rejects multiple underscores for every underscore-ending prefix.
  The trailing word test follows a loop that already consumes those characters,
  so it cannot establish the intended identifier distinction by itself.
- Short prefixes such as `hf_` need documented per-provider formats rather than
  universal underscore, dot, digit, case, entropy, or exact-length assumptions.
  [Hugging Face's documentation](https://huggingface.co/docs/hub/security-tokens)
  demonstrates the prefix but does not promise one permanent length/alphabet.
  [Gitleaks' current rule](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
  uses a narrower body shape; that is a comparison rule, not provider authority.
- Several existing provider variants are absent from the ten-entry `BUILTIN_IDS`
  policy lookup. Inventory this separately; changing rule registration or format
  coverage is not necessary to resolve the observed context errors.

Do not tighten provider contracts in this implementation without a separately
reviewed format matrix and recall evidence. GitHub itself notes changing token
versions and varying pattern precision.
[Supported scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)

## Accuracy and performance acceptance

Freeze baseline and candidate binaries, source revisions, policy, and corpus
hashes. Existing small detection partitions stay intact; evaluate added precision
partitions separately. Freeze calibration and held-out labels before running the
candidate. Split structural examples and independently generated values, not only
repeated seeds; synthetic results remain synthetic results.

Required gates:

- All 18 verified member occurrences and the one verified ternary-key error produce
  zero context findings; quoted password controls and the 24 retained target
  literal/provider/marker occurrences still report with unchanged policy/input.
- Identifier-shaped opaque values, bare weak passwords, real object properties
  within conditionals, and multiline object keys retain detection in code files.
- All mandatory supported positive fixtures retain detection and exact locations.
- Every previously detected supported positive in the old corpus remains detected;
  retain documented pre-existing misses rather than claiming universal 100% recall.
- Added supported qualified-reference/key-expression negatives have zero false
  positives, and supported positives have zero misses, including per-occurrence
  checks on mixed lines. Predeclared unresolved bare aliases remain honestly
  labeled limitations; include their errors in aggregate metrics rather than
  lowering the detection bar or relabeling them as credentials.
- Complete-line, streaming, serial/helper, and file/staged/reference results agree
  on rule, span, counters, and exit status for the same source syntax and scope.
- Report confusion counts, per-family/context/length results, and denominator
  bytes. Do not claim repository-wide precision from this small synthetic corpus.
- No raw positive fixture value appears in normal output, diagnostics, or artifacts.

The classifier adds no candidate allocation and performs bounded byte work.
Perform reference checks before histogram clearing/logarithms; preserve the
existing cap check before filtering. Integrate the decision in both current lexer
paths; avoid running a second lexer over every complete line or altering provider
routing as an unmeasured optimization.

Measure before/after release builds on identical synthetic workloads using paired,
alternating runs: ordinary clean code, reference-heavy code, generic accepted and
rejected literals, weak passwords, provider/JOSE/custom cases, >10 MB files,
>256 KiB lines, many tiny files, and 0/10/100/1,000 staged added lines. Include
one and eight workers where supported; use `--silent` for CLI performance.

Proposed non-regression gates, with repeat measurements if outside noise bounds:

- For each large fixed workload, candidate median time <= baseline median * 1.03.
- For startup/staged workloads, candidate p95 increase <= max(0.5 ms, baseline p95 * 0.05).
- Peak RSS increase <= max(256 KiB, baseline RSS * 0.01).
- No additional full-file reads, per-line path normalization, locks, or allocations
  from the new classifier; no throughput credit for incomplete/error scans.

These are proposed review gates, not measured speed claims or a guarantee that
three percent is free. An unexplained failure blocks completion until corrected
or the tradeoff is explicitly reviewed. Report hardware, compiler, rule settings,
sample count, cache state, binary hashes, scanned bytes, and finding counts. Use
40 in-process samples and 21 startup-inclusive samples; three samples of a 1 GB
run establish bounded behavior only, not reliable tail latency.

Run the repository's format, Clippy, full tests, benchmark, and coverage commands
during implementation. The user-selected coverage gates are 95% lines/regions
and 98% functions, matching `.cargo/config.toml`. Exercise every new production
helper and error path; do not exclude production code to satisfy the gates.

## Limitations and rollout

Source suffixes are grammar hints, not proof of valid code or permission to skip
credentials. Bare identifier-shaped values remain eligible. An unquoted dotted
text value stored in a code file can still be ambiguous with a member reference;
record this bounded lexical limitation and cover quoted controls, text formats,
unknown extensions, raw readers, and mixed-source worker reuse before rollout.
Unresolved bare constant aliases may remain noisy; neither character shape nor
a code extension provides enough evidence to safely resolve them in this change.

Multiline literals, raw-string prefixes, templates, arbitrary argument data flow,
and language-aware escape decoding remain outside this lexer change. Do not
silently treat unsupported forms as proven safe. Public random literals and actual
secrets can be textually indistinguishable; explicit acceptance remains necessary.

Ship the binding/reference distinction only after accuracy and performance gates.
Review any remaining actual preview findings as literals, incomplete syntax, or
provider-contract issues using Rayloc's output and the now-authorized source
review. Further changes to statistical filters, marker validation, or provider formats require their own evidence and
approval. The implementation plan is
`../plans/2026-10-08-builtin-detection-precision.md`.
