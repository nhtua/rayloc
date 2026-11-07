# Secret-pattern expansion implementation plan

Spec: `docs/research/secret-pattern-expansion.md`

## Context and constraints

This plan implements the approved bounded expansion of Rayloc's built-in detector
catalog without changing CLI or configuration contracts. It adds only source-backed
structural detector families and exact context aliases. It does not add a rule loader,
new dependencies, credential validation, or online verification. A performance
regression cannot be silently accepted: compare paired immutable binaries; if
measurements show degradation beyond run-to-run noise, stop and ask before adding
performance work.

Primary files:

- `src/rules/builtin.rs`
- `src/rules/assignment.rs`
- `tests/unit/builtin.rs`
- `tests/unit/builtin_coverage.rs`
- `tests/unit/assignment.rs`
- `tests/context_detection.rs`
- benchmark/evaluation harnesses only after reviewing intentional policy changes

## Task 1: CircleCI and GitLab structural families

Create or correct GitLab structural detectors and add CircleCI personal/project tokens.

Rules:

- `glpat-` plus exactly 20 `[A-Za-z0-9_-]`.
- `glrt-`, `glrtr-`, `gldt-`, `glft-`, `glffct-`, and `glsoat-` plus exactly 20
  `[A-Za-z0-9_-]`.
- `glimt-` plus exactly 25 `[A-Za-z0-9_-]`.
- `glagent-` plus exactly 50 `[A-Za-z0-9_-]`.
- `gloas-` plus exactly 64 `[A-Za-z0-9_-]`.
- `glptt-` plus exactly 40 lowercase hex.
- Existing `glcbt-` family remains available; preserve its current broader heuristic
  unless a separate source-backed contract is implemented.
- New IDs: `CircleCiPersonalToken`, `CircleCiProjectToken`.
- CircleCI tokens are `CCIPAT_` or `CCIPRJ_`, followed by a 22-byte base58 UUID body,
  `_`, and 40 lowercase or uppercase hex characters.
- Complete left and right boundaries and a bounded candidate span are mandatory.

Tests must add fixtures in `tests/unit/builtin.rs` and catalog fixtures where needed.
Run the tests and watch the new behavior fail before implementation. Then run
`cargo test --all --locked`.

## Task 2: Atlassian and Netlify structural families

Add `AtlassianApiToken` for `ATATT3` plus 186 `[A-Za-z0-9_=-]` bytes.
Add `NetlifyAccessToken` for `nfp_` plus 36 `[A-Za-z0-9_]` bytes.

Tests must include exact length, one-byte short/long bodies, trailing identifier
punctuation, and split streaming.

## Task 3: Fly.io structural family

Add `FlyioToken`:

- `fo1_` plus 43 `[A-Za-z0-9_-]`.
- `fm1a_`, `fm1r_`, and `fm2_` plus 100 through 512 `[A-Za-z0-9+/]` bytes and optional
  0-3 `=` padding.

## Task 4: PlanetScale structural families and prefix correction

Replace the obsolete `pscale_password_` standalone prefix with `pscale_pw_` for
`PlanetscalePassword`. Add `PlanetscaleToken` and `PlanetscaleOauthToken`:

- `pscale_tkn_`, `pscale_oauth_`, `pscale_pw_` plus 32 through 64 `[A-Za-z0-9_.=-]`.

## Task 5: Pinecone and Anthropic admin structural families

Add `PineconeApiKey` for `pcsk_` plus either five or six `[A-Za-z0-9]` bytes, `_`, and
63 `[A-Za-z0-9]` bytes.
Add `AnthropicAdminKey` for `sk-ant-admin01-` plus 93 `[A-Za-z0-9_-]` bytes ending in
`AA`.

## Task 6: Paddle and Plaid structural families

Add `PaddleApiKey` matching exactly:
`pdl_live_apikey_` or `pdl_sdbx_apikey_`, 26 lowercase alphanumeric bytes, `_`, 22
alphanumeric bytes, `_`, and three alphanumeric bytes.

Add `PlaidAccessToken` matching `access-sandbox-`, `access-development-`, or
`access-production-`, followed by a lowercase-hex UUID with the 8-4-4-4-12 grouping.

## Task 7: Sentry, Grafana, and Axiom structural families

Add `SentryPersonalToken` for `sntryu_` plus 64 lowercase hex.
Add `GrafanaServiceAccountToken` for `glsa_` plus 32 alphanumeric bytes, `_`, and eight
lowercase hex bytes.
Add `AxiomToken` for `xaat-` or `xapt-` plus one lowercase-hex UUID body.

## Task 8: Sonar and Kong structural families

Add `SonarQubeToken` for `squ_`, `sqp_`, or `sqa_` plus 40 lowercase hex.
Add `SonarQubeCloudToken` for `sqco_` plus 59 alphanumeric bytes.
Add `KongKonnectToken` for `kpat_` or `spat_` plus 49 alphanumeric bytes.

## Task 9: Security/vault structural families

Add `TruffleHogEnterpriseSecret` for `thog-secret-` plus 32 lowercase hex.
Add `DopplerToken` matching `dp.` followed by one of:

- `ct` plus `_` and 40-44 alphanumeric bytes;
- `pt` plus `_` and 40-44 alphanumeric bytes;
- `st` optionally followed by `.` plus 2-35 lowercase alphanumeric/underscore/dash
  bytes and `.` plus 40-44 alphanumeric bytes;
- `sa`, `scim`, or `audit` plus `_` and 40-44 alphanumeric bytes.

Add credential-bearing Tailscale families:

- `TailscaleApiToken`: `tskey-api-` plus a nonempty alphanumeric/underscore component,
  `-`, and another nonempty component.
- `TailscaleAuthToken`: `tskey-auth-` with the same bounded body.

## Task 10: Feature, comms, and gateway structural families

Add:

- `ResendApiKey`: `re_` plus two base58-style alphanumeric/underscore components with
  8 and 24 bytes respectively.
- `LaunchDarklyServerSdkToken`: `sdk-` followed by a lowercase-hex UUID body.
- `FlagsmithServerToken`: `ser.` followed by 43 `[A-Za-z0-9_-]` bytes.
- `GrowthBookSecretKey`: `secret_` followed by 16 through 64 `[A-Za-z0-9_-]` bytes.
- `PostHogPersonalToken`: `phx_` followed by 43 through 48 `[A-Za-z0-9_]` bytes.

## Task 11: Context aliases and public-prefix correction

Correct the standalone Supabase detector to `sb_secret_` only; leave
`sb_publishable_` out as a public identifier. Add secret-bearing context field aliases
only for opaque credentials that are not structurally detected:

- Bitbucket client secret / API token
- Cohere API key
- Neptune/Doppler/Uploadthing-style management credentials where the vendor documents
  a secret-bearing variable
- PlanetScale service token
- Together AI API key
- Unleash backend/admin token
- GrowthBook REST secret key
- PostHog personal API key
- Sleuth organization API key
- Jellyfish API token
- Novu secret key
- Courier backend auth token
- GitGuardian API key
- Fastly API token
- Zuplo management credentials
- APITemplate.io API key
- CraftMyPDF API key

Tests must confirm context names emit generic `context-secret`, public counterparts do
not emit provider-specific matches, and no provider-name string alone becomes a match.

## Task 12: Catalog/status and performance verification

Update `docs/research/secret-pattern-expansion.md` with final shipped status:
covered, corrected, context-only, public, or deferred. Do not claim speculative families.

Run these gates:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- --warnings-as-errors
cargo test --all --locked
cargo coverage
```

Record baseline and candidate release binary SHA, source commit, host/compiler, and
engine/scope results in `docs/research/secret-pattern-expansion.md`. Compare at least
five paired samples on immutable baseline/candidate binaries. If the candidate shows
degradation beyond ordinary noise, stop and report to the user; do not continue into
performance work without approval.
