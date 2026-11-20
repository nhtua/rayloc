# Secret Pattern Implementation — Summary

**Date:** 2026-11-19
**Worktree:** `.worktrees/secret-pattern-implementation`
**Catalog:** `docs/research/github-supported-secret-patterns.md` (525 provider rows + 10 generic + 1 AI-detected)

## Result

All 536 catalog rows are now covered by detectors in `src/rules/builtin.rs`:

- **606 `RuleId` variants** (+ ~506 over the pre-task baseline), enum order == `ALL_RULE_IDS` order (verified).
- Coverage of the catalog by category:
  - 525/525 provider rows: each has a registered rule id, a registered prefix
    literal, or a keyword-gated rule with matching id (alias cases annotated in
    the catalog Pattern column).
  - 10/10 generic rows: private-key markers, connection-string URI rules, context
    rules, and the two new header detectors (`http-basic-authentication-header`,
    `http-bearer-authentication-header`).
  - 1/1 AI-detected row (`password`) via `password-assignment` / `context-secret`.

## Batch history

| Batch | Variants | Content |
|-------|----------|---------|
| 1 | 10 | Adobe, Aiven, Apify, Canva, Cloudsmith, Databento, HashiCorp Vault service token (prefix) |
| 2 | 36 | Databricks, Dropbox (+custom matcher), Duffel, Dynatrace, EasyPost, Elastic, Flutterwave, Frame.io, Highnote, Lob, Mailersend, Mailgun, Mapbox, Mercury, Midtrans, NaverCloud |
| 3 | 23 | Hex, NewRelic ×4, NuGet, OctopusDeploy, Pulumi, Postman ×2, ReadMe, Salesforce OAuth2/Refresh, Typeform, Vercel, Wakatime ×4 (UUID), Yandex |
| 4 | 40 | Bitrise, Buildkite (spec — never landed), CheckoutCom, CockroachLabs, Contentful, Lark ×5, LovableLabs, Polar (spec — never landed), Shippo, Sourcegraph ×5, Sslmate, WorkOS |
| 5 | fix | Sslmate body_len 43 + fixtures |
| 6 | 20 | Keyword-gated: Aikido ×2, Airtable, AWS key/session, Asana ×2, Atlassian JWT, Authress, Bitbucket PAT, Block Protocol, Cashfree, Cfx.re, Chief Tools, Cohere, Contentful web token, Contributed Systems, Coveo ×2, Datadog — + `keyword_gated_match` (200-byte context, assignment-RHS skip) |
| 7 | 17 | 1Password (`ops_eyJ` custom matcher), Adafruit, Beamer (exact-44 custom matcher), Cockroach `ccdb_`, CDS `ApiKey-v1 gcntfy`, Contentful PAT wiring (`CFPAT-`), Docker PAT/Org (`dckr_pat_`), Buildkite ×10 (`bk`) |
| 8 | 16 | Polar ×8 (re-adding the batch-4 spec gap), Azure structural ×8 with keyword validators (AZDO@76, 54-char `==`, 86-char base64, hex32 ×2, alnum32, Redis base64, `Q~` AAD) |
| 9 | 17 | Azure keyword-gated part 1 (anomaly detector … custom vision) |
| 10 | 17 | Azure part 2 (event grid … Luis authoring) |
| 11 | 17 | Azure part 3 (Luis … service bus) |
| 12 | 14 | Azure part 4 (SignalR … Entra ID) + `amazon-aws-temporary-access-key-id` |
| 13 | 12 | Apiclub, Asaas, Docker Swarm ×2, OneChronos ×5, OneSignal rich-auth token + HTTP Basic/Bearer header rules |
| 14 | 7 | Final coverage-diff gaps: Adobe ×5 (`adobe` keyword), `azure-logic-apps-url`, `azure-management-certificate` — applied inline (two subagent attempts failed silently) |

## Design decisions

- **Catalog is source of truth**; coverage judged at the **pattern level**: several
  GitHub secret types map to one rayloc rule when they share a pattern (e.g. the
  five `gh[pousr]_` GitHub token types → `github-token`; `dop_v1_` DigitalOcean
  personal/system; CircleCI/Wave/Stripe/hexpm/hf/readmeio alias rules). These
  are annotated in the catalog Pattern column, not duplicated as detectors.
- **Keyword-gated rows** (no distinctive prefix) use the 200-byte context keyword
  gate + word-run matcher, min 20 bytes, matching GitHub's semi-generic approach.
  The gate skips assignment RHS values (`= : > !`, incl. past one quote) since the
  context module already reports those; header rules are exempt (headers are RHS
  by design).
- **Hot-path optimization (post-implementation)**: the naive per-rule
  `context_has_keyword` scan re-walked a ≤200-byte window per rule row at every
  candidate byte (~100 rows), a ~2.9× scope-benchmark regression. Replaced with
  (1) an incremental per-line keyword feed: one cursor + first-byte bucket
  bitmap + completion ring maintaining a live `keyword_mask` (bit per keyword
  whose last occurrence starts inside the window), and (2) compile-time segment
  coalescing of consecutive rows sharing one keyword/minimum length (`KEYWORD_GATED_SEGMENTS`):
  absent keywords cost one bit test, and per present segment the word-run is
  computed once with first-match-wins inside the segment. Semantics verified
  equivalent, including the exact 200-byte window edge
  (`azure_keyword_gate_window_edge_matches_legacy_scan` test).
- **FastlyApiToken** not implemented (empty prefix would match anything);
  **GitHubSSHPrivateKey** not added as separate rule (overlaps `PrivateKeyMarker`).
- Custom byte matchers used where the generic matcher would be noisy or wrong
  (Beamer exact-44, OnePassword base64-60+, DropBox 130+, Sslmate, Azure shapes).

## Verification

- `cargo build --all-targets` / `cargo fmt --all -- --check` / `cargo clippy
  --all-targets --all-features -- -D warnings`: clean.
- `cargo test --all`: **672 passed, 0 failed** across all targets (514 lib).
- Production coverage gate (underlying `cargo-llvm-cov` invocation; the `cargo
  coverage` alias is broken in this toolchain): lines 96.24%, functions 98.86%,
  regions 97.89% — passes the ≥95/≥98/≥95 thresholds.
- Performance: see `docs/research/post-implementation-performance-2026-11-19.md`
  (written against `docs/research/baseline-performance-2026-11-19.md`); the
  flagged residual regression on the largest single-worker fixture (~+25%) is
  reported there, not hidden.
