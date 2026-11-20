# Secret Pattern Implementation Plan

**Date:** 2026-11-19  
**Status:** Draft  
**Worktree:** `.worktrees/secret-pattern-implementation`  
**Reference:** Design spec at `docs/superpowers/specs/2026-11-19-secret-pattern-implementation-design.md`

## Overview

Implement new secret detectors in `src/rules/builtin.rs` for all provider patterns documented in `docs/research/github-supported-secret-patterns.md`. All 525 provider patterns have documented patterns; ~200+ need new `RuleId` variants and detection logic.

## Prerequisites

- [ ] Worktree created at `.worktrees/secret-pattern-implementation`
- [ ] Catalog document copied to worktree
- [ ] Build succeeds: `cargo build`
- [ ] Tests pass: `cargo test --all`
- [ ] Clippy clean: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Format clean: `cargo fmt --all -- --check`

## Phase 0: Performance Baseline (BEFORE implementation)

### Task 0.1: Capture baseline performance metrics

Record baseline performance of the current binary BEFORE adding any new detectors. This follows the same approach as `docs/research/secret-pattern-expansion.md`:

```
cargo build --release
```

Then run benchmarks:

```
cargo bench --locked
```

Record:
- Binary size and SHA-256
- Engine median/p95 ms and MB/s
- Scope benchmark results at worker counts 1, 2, 8
- Full test suite results (`cargo test --all --locked`)

Save to: `docs/research/baseline-performance-2026-11-19.md`

**Acceptance criteria:**
- [ ] Baseline binary built and measured
- [ ] Baseline test results recorded
- [ ] Baseline benchmark results saved to file

## Phase 1: RuleId Enum and Metadata

### Task 1.1: Add new RuleId variants

Add ~200 new variants to the `RuleId` enum in `src/rules/builtin.rs`, following existing naming conventions. Group them logically by category after the existing entries.

**Files:** `src/rules/builtin.rs`

**Acceptance criteria:**
- [ ] All new variants compile
- [ ] Naming follows existing PascalCase convention
- [ ] Variants grouped by category with comments

### Task 1.2: Add metadata for each new RuleId

Add entries in `RuleId::metadata()` match arm for each new variant with:
- `id`: snake_case identifier
- `description`: human-readable
- `severity`: High (default for API keys/tokens)
- `confidence`: Medium for keyword-gated, High for prefix-based
- `reference`: vendor documentation URL

**Files:** `src/rules/builtin.rs`

**Acceptance criteria:**
- [ ] Every new variant has metadata entry
- [ ] All metadata fields populated correctly

## Phase 2: Prefix Constants

### Task 2.1: Add prefix byte constants

For each prefix-based detector, add `const PREFIX_NAME: &[&[u8]]` arrays following existing patterns (e.g., `GITHUB_PREFIXES`, `STRIPE_SECRET_PREFIXES`).

**Files:** `src/rules/builtin.rs`

**Acceptance criteria:**
- [ ] All prefix arrays defined as `&[&[u8]]`
- [ ] Prefix bytes match documented patterns
- [ ] Constants named descriptively (PROVIDER_PATTERN_PREFIXES)

### Task 2.2: Register prefixes in PROVIDER_HEAD_LITERALS

Add new prefix groups to the `PROVIDER_HEAD_LITERALS` array and any unique 2-byte heads to `PROVIDER_HEAD_EXTRA_LITERALS`.

**Files:** `src/rules/builtin.rs`

**Acceptance criteria:**
- [ ] All new prefix groups registered
- [ ] `PROVIDER_HEAD_BITS` bitmap auto-updates via `provider_head_bits()`

## Phase 3: Detection Logic

### Task 3.1: Add dispatch logic in `match_at`

Add calls to existing helper functions (`api_key_match`, `api_key_match_with_min`, `token_match`, etc.) for each new detector in the `match_at` function.

**Files:** `src/rules/builtin.rs`

**Acceptance criteria:**
- [ ] Each new rule has a dispatch branch
- [ ] Disabled rule check before each detector call
- [ ] Early return on match (first match wins)

### Task 3.2: Implement keyword-gated detectors

For patterns marked `keyword-gated`, implement context-based detection using the `context` module. Match on secret type name as keyword near candidate value.

**Files:** `src/rules/builtin.rs`, `src/rules/context.rs`

**Acceptance criteria:**
- [ ] Keyword-gated rules detect secrets near provider name keywords
- [ ] False positives minimized by keyword pre-filter

## Phase 4: Testing

### Task 4.1: Unit tests for each new detector

Add test cases in `tests/unit/builtin.rs` for each new detector:
- Positive samples (valid secrets)
- Negative samples (invalid/near-miss secrets)
- Use redacted output in assertions

**Files:** `tests/unit/builtin.rs`

**Acceptance criteria:**
- [ ] Every new detector has at least 1 positive and 1 negative test
- [ ] No raw secrets printed in test output
- [ ] Tests pass

### Task 4.2: Integration tests

Add integration tests for complex patterns (e.g., multi-segment tokens, URI-based patterns).

**Files:** `tests/integration/`

**Acceptance criteria:**
- [ ] Integration tests pass
- [ ] Coverage >=95% lines/regions, 100% functions

## Phase 5: Verification

### Task 5.1: Run full verification

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo coverage
```

**Acceptance criteria:**
- [ ] Formatting clean
- [ ] Clippy clean with -D warnings
- [ ] All tests pass
- [ ] Coverage meets thresholds

## Estimated Effort

| Phase | Tasks | Estimated Time |
|-------|-------|----------------|
| 1 | RuleId + metadata | 2-3 hours |
| 2 | Prefix constants | 1-2 hours |
| 3 | Detection logic | 4-6 hours |
| 4 | Testing | 3-4 hours |
| 5 | Verification | 1 hour |
| **Total** | | **11-16 hours** |

## Implementation Order (Priority)

1. **Prefix-based rules with clear patterns** (easiest to verify): Adobe, Apify, Canva, Cloudsmith, Databricks, Doppler, Dropbox, Duffel, Dynatrace, EasyPost, Elastic, Fastly, Flutterwave, Frame.io, FullStory, GitHub tokens, GitLab access token, HashiCorp Vault, Heroku, Hex, Highnote, Lob, Mailchimp/Mandrill, Mailersend, Mailgun, Mapbox, Meraki, Mercury, Midtrans, Neon, New Relic, Notion, NuGet, Octopus Deploy, Perplexity, Pinecone, PlanetScale, Postman, Prefect, Proctorio, Proof, Pulumi, PyPI, ReadMe, Resend, RubyGems, Salesforce OAuth2/Refresh, Shopify tokens, SSLMate, Stripe variants, Supabase tokens, Tailscale, Telegram, Typeform, Vercel tokens, Wakatime, Yandex tokens

2. **Keyword-gated rules** (require context module): Aikido, Airtable API key, Amazon AWS API key, Asana, Atlassian JWT, Authress, Bitbucket, Bitrise, Block Protocol, Cashfree, Cfx.re, Chief Tools, Clojars deploy, Cohere, Contentful web token, Contributed Systems, Coveo, Datadog, Datastax, DeepSeek, Defined Networking, DevCycle, DigitalOcean system token, Discord, Docker swarm, Fieldguide, Figma, Finicity, Firebase FCM, Flickr, Frame.io JWT, FullStory, GoCardless, GuardSquare, Hack Club, Hubspot (all 4), IBM, Intercom, Ionic (both), Iterative, JFrog (all 3), Langchain (both), LaunchDarkly, Lichess (both), Lightspeed, Limbar, Linear OAuth, LinkedIn, Localstack, LogicMonitor (both), Login with Amazon (both), Lovable Labs, MaxMind, MessageBird, Microsoft Power Automate, Midtrans (both), Mistral AI, MongoDB Atlas service account, Netflix NetKey, Oculus, OneChronos (all 5), OneSignal, Onfido (both), OpenVSX, Openweather, Oracle, Orbit, Paddle (both), PagerDuty (both), Palantir JWT, Pangea, Persona Identities (both), Pineapple Technologies, Pinterest (both), Planning Center (all 3), Plivo (both), Ramp (all 3), Raycast, Replicate, Rootly, RunPod, Salesforce (access token, marketing cloud, consumer secret), Samsara (both), Scalr, Segment, Siemens (both), Sindri, Slack (api token, workflow trigger, workflow webhook), Snowflake (all 3), SpaceX Starlink, Square sandbox, Tableau, Tavily, Telnyx, Temporal, Tencent WeChat App ID/Pay Token, Thunderstore, Twilio access token, Uniwise, Unkey, Val Town, VolcEngine (both), Wave (both), Weatherstack, Wandb, Workato, WSO2, ZenHub, Zuplo

3. **Generic patterns** (2 remaining): HTTP Basic Auth, HTTP Bearer Auth

## Phase 6: Performance Comparison (AFTER implementation)

### Task 6.1: Capture post-implementation performance metrics

Rebuild release binary with all new detectors and measure performance using the SAME workloads as Phase 0:

```
cargo build --release
cargo bench --locked
```

Record:
- Binary size and SHA-256
- Engine median/p95 ms and MB/s
- Scope benchmark results at worker counts 1, 2, 8
- Full test suite results

Compare against Phase 0 baseline:
- If performance degraded beyond run-to-run noise: STOP and report ratios/cause before proceeding
- If performance maintained or improved: proceed to Phase 7

**Acceptance criteria:**
- [ ] Post-implementation binary built and measured
- [ ] Performance comparison documented against baseline
- [ ] No unacceptable regression detected

### Task 6.2: Performance gate decision

Review paired measurements (baseline vs candidate) on identical inputs/compiler/policy/cache/worker counts:

- Engine/scope benchmarks
- Clean, reference-heavy, and token-dense inputs
- Long physical lines crossing chunk/candidate boundaries
- Peak RSS and binary size changes

**Acceptance criteria:**
- [ ] Performance ratios documented
- [ ] Run-to-run variation noted
- [ ] No regression beyond noise without explicit approval

## Phase 7: Documentation and Handoff

### Task 7.1: Update catalog with implementation status

Update `docs/research/github-supported-secret-patterns.md` to mark implemented patterns as Y.

### Task 7.2: Write implementation summary

Document what was implemented, patterns remaining, and any deviations from plan.

**Acceptance criteria:**
- [ ] Catalog updated with final Y/N status
- [ ] Summary document written

## Estimated Effort

| Phase | Tasks | Estimated Time |
|-------|-------|----------------|
| 0 | Performance baseline | 1 hour |
| 1 | RuleId + metadata | 2-3 hours |
| 2 | Prefix constants | 1-2 hours |
| 3 | Detection logic | 4-6 hours |
| 4 | Testing | 3-4 hours |
| 5 | Verification | 1 hour |
| 6 | Performance comparison | 1 hour |
| 7 | Documentation | 1 hour |
| **Total** | | **13-18 hours** |

## Implementation Order (Priority)

1. **Prefix-based rules with clear patterns** (easiest to verify): Adobe, Apify, Canva, Cloudsmith, Databricks, Doppler, Dropbox, Duffel, Dynatrace, EasyPost, Elastic, Fastly, Flutterwave, Frame.io, FullStory, GitHub tokens, GitLab access token, HashiCorp Vault, Heroku, Hex, Highnote, Lob, Mailchimp/Mandrill, Mailersend, Mailgun, Mapbox, Meraki, Mercury, Midtrans, Neon, New Relic, Notion, NuGet, Octopus Deploy, Perplexity, Pinecone, PlanetScale, Postman, Prefect, Proctorio, Proof, Pulumi, PyPI, ReadMe, Resend, RubyGems, Salesforce OAuth2/Refresh, Shopify tokens, SSLMate, Stripe variants, Supabase tokens, Tailscale, Telegram, Typeform, Vercel tokens, Wakatime, Yandex tokens

2. **Keyword-gated rules** (require context module): Aikido, Airtable API key, Amazon AWS API key, Asana, Atlassian JWT, Authress, Bitbucket, Bitrise, Block Protocol, Cashfree, Cfx.re, Chief Tools, Clojars deploy, Cohere, Contentful web token, Contributed Systems, Coveo, Datadog, Datastax, DeepSeek, Defined Networking, DevCycle, DigitalOcean system token, Discord, Docker swarm, Fieldguide, Figma, Finicity, Firebase FCM, Flickr, Frame.io JWT, FullStory, GoCardless, GuardSquare, Hack Club, Hubspot (all 4), IBM, Intercom, Ionic (both), Iterative, JFrog (all 3), Langchain (both), LaunchDarkly, Lichess (both), Lightspeed, Limbar, Linear OAuth, LinkedIn, Localstack, LogicMonitor (both), Login with Amazon (both), Lovable Labs, MaxMind, MessageBird, Microsoft Power Automate, Midtrans (both), Mistral AI, MongoDB Atlas service account, Netflix NetKey, Oculus, OneChronos (all 5), OneSignal, Onfido (both), OpenVSX, Openweather, Oracle, Orbit, Paddle (both), PagerDuty (both), Palantir JWT, Pangea, Persona Identities (both), Pineapple Technologies, Pinterest (both), Planning Center (all 3), Plivo (both), Ramp (all 3), Raycast, Replicate, Rootly, RunPod, Salesforce (access token, marketing cloud, consumer secret), Samsara (both), Scalr, Segment, Siemens (both), Sindri, Slack (api token, workflow trigger, workflow webhook), Snowflake (all 3), SpaceX Starlink, Square sandbox, Tableau, Tavily, Telnyx, Temporal, Tencent WeChat App ID/Pay Token, Thunderstore, Twilio access token, Uniwise, Unkey, Val Town, VolcEngine (both), Wave (both), Weatherstack, Wandb, Workato, WSO2, ZenHub, Zuplo

3. **Generic patterns** (2 remaining): HTTP Basic Auth, HTTP Bearer Auth

## Notes

- All new code must follow the existing code style and patterns in `builtin.rs`
- Regexes must be compiled once using `LazyLock` or `RegexSet` (already handled by `Registry::compile`)
- No raw secrets in debug output or test assertions
- The `RedactedString` wrapper must be used for all `Match` structs
- Performance baseline MUST be captured BEFORE implementation and compared AFTER — do not silently accept regressions