# Secret-pattern expansion audit

Date: 2026-11-06. Status: initial audit complete; implementation design awaiting approval.

## Objective and assumptions

Audit every named platform in the proposed SDLC catalog against current sources
and Rayloc's existing rules. Recommend offline detection patterns without
mistaking public identifiers for secrets or promising credential validity.
Assume no network validation during scans, no new runtime dependencies, and no
changes to CLI or configuration contracts. Unverified formats remain deferred.

User requirement (2026-11-06): a large pattern library and high performance are
both primary goals. Preserve a same-host baseline before implementation. If the
expanded catalog measurably slows scanning, stop and ask the user before altering
the plan to include performance improvements. Do not silently accept a regression
or silently broaden the work into an engine rewrite. Report ratios and run-to-run
variation, not isolated timing samples; no slowdown tolerance has been approved.

## Research checklist

- [x] Locate Rayloc, inspect existing detector architecture and repository guidance.
- [x] Create an isolated worktree on `task/expand-secret-patterns` from `origin/main`.
- [x] Verify the worktree's unchanged test baseline: `cargo test --all --locked`
  passed, 595 tests, zero failures, at base `e4b72e4`.
- [x] Audit every platform in all 12 supplied categories with source references:
  74 named platforms, each accounted for below.
- [x] Record corrections, public identifiers, overlaps, and unresolved formats.
- [x] Prepare a focused implementation design and baseline evidence for review.
- [x] Verify all 74 platform entries/source links and the immutable baseline hash;
  scan this document with the baseline release binary: zero findings.
- [ ] Obtain explicit design approval before changing detectors.

## Evidence policy

Prefer vendor documentation/source for credential semantics and documented
prefixes. Use pinned established scanner rules only as secondary evidence for
observed lengths and alphabets; scanner heuristics are not vendor guarantees.
Do not copy working credentials or call credential-validation endpoints.

Implementation status: no production or test code has been changed.

## How to read the audit

- **Existing** means a dedicated rule exists in base `e4b72e4`, not that it
  completely or accurately recognizes every current credential format.
- **Add** recommends a provider-specific structural detector.
- **Context** requires an associated secret-bearing assignment/header or a
  credential-bearing URI. A provider name merely appearing somewhere in the
  file is insufficient. Shared bare hex, UUID, base64 and `sk_` patterns must not
  be globally attributed to a provider.
- **Defer** means evidence is insufficient for a standalone detector. The
  platform remains in the catalog with its uncertainty recorded; do not invent
  a format just to claim coverage.
- **Public** means do not introduce a provider-specific secret finding for that
  value alone. Existing generic JOSE/context policy may still report some public
  tokens; suppressing those globally is a separate policy decision, not an
  implied change in this audit.

`A` below denotes case-sensitive ASCII alphanumeric, `H` hex, `U` base64url
characters, `B` standard base64 characters, and `UUID` the full 8-4-4-4-12
structure. Lengths count the body unless stated otherwise. These are notation,
not executable regexes. Every future rule also needs complete left/right
boundaries, full-span capture and an explicit upper bound.

Secondary evidence:

- [G]: [Gitleaks configuration](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml),
  pinned at `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` (2026-10-23).
- [T]: [TruffleHog detectors](https://github.com/trufflesecurity/trufflehog/tree/f8221ca52ac51bf66228d6ec3691f3ea0782ae15/pkg/detectors),
  pinned at `f8221ca52ac51bf66228d6ec3691f3ea0782ae15` (2026-11-05).
  Detector directory names are given where relevant. Do not copy their online
  verification behavior into Rayloc, and do not confuse MoonClerk with Clerk.

Vendor pages were retrieved on the audit date. A page establishing a credential's
purpose does not establish its exact alphabet/length. Rows distinguish vendor
documentation from secondary scanner observations and remaining unknowns.

## 1. Version control, CI/CD and developer platforms (6)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| GitHub | Existing six prefix families: `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`. [G] observes 36 `A` after most classic prefixes and 82 word characters after `github_pat_`. Preserve newer installation-token framing rather than restricting every `ghs_` token to the old opaque shape. | Audit full boundaries and body shapes; current body minimum is heuristic. [Vendor token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats), [G]. |
| GitLab | Add feed `glft-` (**not `glfeed-`**), agent `glagent-`, runner `glrt-`/`glrtr-`, trigger `glptt-`, OAuth secret `gloas-`, incoming mail `glimt-`, workspace `glwt-`, SCIM `glsoat-`. Retain existing `glpat-`, `gldt-`, `glcbt-`, `glffct-`. Routable tokens have additional structure and must not be truncated at `.`. | Current 25-byte minima miss older 20-byte PAT/deploy/feature-flag bodies. [G] records per-type lengths, including agent 50, OAuth 64, trigger 40 hex; workspace and runner-registration variants need additional body evidence. [Vendor prefix table](https://docs.gitlab.com/security/tokens/#token-prefixes), [G]. |
| CircleCI | Add `(CCIPAT\|CCIPRJ)_<base58-UUID>_<40 hex>`. Vendor documents prefix, encoded UUID and hex components; [T] `circleci/v2` observes a 22-character encoded ID. Legacy 40-hex values require context. | No dedicated rule. Do not use an unconstrained `CCIPAT_` body. [Vendor format announcement](https://circleci.com/changelog/new-format-for-api-access-tokens/), [T]. |
| Bitbucket | Context for app passwords, scoped API tokens and OAuth client secrets; reuse Atlassian modern token support where verified. Base64 encoding alone identifies nothing. | App-password docs now redirect to API tokens, the long-term replacement. Public OAuth client IDs must not be treated as client secrets merely because an upstream scanner has an ID rule. [Vendor](https://support.atlassian.com/bitbucket-cloud/docs/api-tokens/), [G]. |
| Linear | Existing `lin_api_`; [G] observes 40 `A` body. Context for OAuth client secrets (32 hex observed by [G]). | Current minimum 32 is not exact validation; OAuth tokens need separately established formats. [Vendor](https://linear.app/developers/graphql), [G]. |
| Jira / Atlassian | Add modern `ATATT3` family; [G] observes a 186-character `[A-Za-z0-9_=-]` body. Context for older opaque tokens and `email:token` Basic credentials. | The supplied universal "32-character base64" claim is not supported. Basic header decoding is not part of the existing scanner contract; defer arbitrary encoded credentials. [Vendor authentication](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/), [G]. |

## 2. Cloud infrastructure, compute and serverless (8)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| AWS | Existing `AKIA`/`ASIA` access-key IDs and context-bound 40-character secret access keys. IDs are identifiers, not the secret half. `ABIA`/`ACCA` designate STS service bearer tokens in the vendor identifier table; do not blindly label every listed AWS prefix an IAM access-key ID. Context for session tokens. | Keep ID findings explicitly distinguished from secrets; evaluate additional credential families separately. [Vendor identifier table](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html), [G]. |
| GCP | Existing `AIza` family; [G] observes 35 `U` characters after the prefix, 39 total. Service-account JSON requires private-key material, not merely `"type":"service_account"`. | Current generic body minimum is not exact format validation. Existing private-key marker detection helps, but does not prove full JSON credential validation. Authorization keys and ordinary project-associated API keys have different privileges. [Vendor](https://docs.cloud.google.com/docs/authentication/api-keys), [G]. |
| Azure | Context/structure: Storage `AccountKey=` with base64 key, connection-string fields, and SAS `sig=` with Azure-specific structure; `88` base64 characters ending `==` is a Storage-key candidate, not all Azure credentials. Entra client-secret structure `...Q~...` has separate [G] evidence. | Generic management tokens have no single Azure-wide prefix. Do not globally scan all 88-character base64 strings or arbitrary `sig=` values. Emulator/development defaults need negative fixtures. [Vendor connection strings](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string), [G]. |
| DigitalOcean | Existing `dop_v1_`, `doo_v1_`, `dor_v1_`, with 64 lowercase hex characters observed by [G]. Correct the proposed OAuth prefix `do_v1_` to `doo_v1_`. | Tighten per-family alphabet/boundaries rather than broaden the prefix list. [Vendor OAuth examples](https://docs.digitalocean.com/reference/api/oauth/), [G]. |
| Vercel | Existing `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_`. Vendor currently explicitly documents `vcp_` PATs. Context for legacy unprefixed values. | "24 hex characters" is not a universal modern format. Other existing families need their own issuance evidence before tightening/removal. [Vendor access tokens](https://vercel.com/docs/accounts/access-tokens). |
| Netlify | Add `nfp_` plus 36 `[A-Za-z0-9_]` observed by [T] `netlify/v2`; legacy opaque tokens require context, not free-standing 40-hex matching. | No dedicated rule. Note [G] only covers context-bound 40–46-character opaque values; retain separate historical/current variants. [Vendor](https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/), [T], [G]. |
| Fly.io | Add validated families `fo1_`, `fm1a_`/`fm1r_`, `fm2_`; [G] observes 43 URL-safe characters for `fo1_` and long base64 bodies for macaroons. `FlyV1` is an authorization scheme, not the complete token grammar. | Must capture `+`, `/`, padding and composite forms without truncation. Vendor confirms current macaroons and `fm2_`; detailed legacy shapes rely on [G]. [Vendor](https://docs.fly.io/security/tokens/), [G]. |
| Render | Add `rnd_` family, with bounded shape to be finalized before promotion. Vendor CLI examples establish the prefix, not a fixed body length. Context for `RENDER_API_KEY`. | Prefix supported by [vendor CLI docs](https://render.com/docs/cli); [general API docs](https://render.com/docs/api) establish secret semantics. Exact body contract remains unverified. |

## 3. Database branching, storage and caching (7)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| PlanetScale | Add `pscale_tkn_`, `pscale_oauth_`, and actual password prefix `pscale_pw_`; [G] observes 32–64 `[\w=.-]` bodies. | Existing `pscale_password_` is not the established `pscale_pw_` detector; do not silently retain only the wrong prefix. Vendor confirms service-token semantics, [G] supplies observed shapes. [Vendor](https://planetscale.com/docs/api/service-tokens), [G]. |
| Neon | Context for `NEON_API_KEY` and credential-bearing `postgres://` / `postgresql://` URLs. | PostgreSQL URI rule already exists. Vendor prose calls API keys "64-bit" but does not define a usable stable byte grammar; do not turn that wording into an exact-length detector. [Vendor](https://neon.com/docs/manage/api-keys). |
| Upstash | Context for `UPSTASH_REDIS_REST_TOKEN`, read-only REST tokens, Vector/QStash signing/API credentials when separately documented; credential-bearing Redis URLs already fit the URI branch. | REST endpoint URL alone is not a secret; read-only tokens can still disclose data. No documented universal Upstash token prefix/alphabet in retrieved REST reference. [Vendor](https://upstash.com/docs/redis/features/restapi). |
| Supabase | Existing prefix matcher includes both `sb_secret_` and public `sb_publishable_`. Recommend secret-only provider detection; legacy `service_role` JWTs are sensitive, `anon` JWTs are intentionally public. Include management PATs only after separate format verification. | Generic JOSE currently catches JWT structures without knowing their purpose. Do not claim `eyJ` alone identifies a Supabase credential or promise generic JWT false positives are already resolved. [Vendor key-type table](https://supabase.com/docs/guides/getting-started/api-keys). |
| Pinecone | Add modern `pcsk_` structure; [T] `pinecone` observes `pcsk_<5–6 A>_<63 A>`. Legacy UUID-shaped credentials require `PINECONE_API_KEY` context. | UUID IDs in key-management responses are not themselves proof of secret values; vendor docs distinguish key IDs from one-time-displayed values. [Vendor](https://docs.pinecone.io/admin/projects/manage-api-keys), [T]. |
| Qdrant | Context for database/cloud API keys. Granular database keys can be JWTs starting `eyJhb`; self-hosted keys can be configured freely. | Reuse JOSE where appropriate; never treat all `eyJ` strings as Qdrant or all UUIDs as keys. Distinguish management keys from database keys. [Vendor](https://qdrant.tech/documentation/cloud/authentication/). |
| MongoDB Atlas | Existing credential-bearing `mongodb://`/`mongodb+srv://`; context for Atlas private API keys and OAuth service-account client secrets. | Public API key alone is not the private credential. Do not hardcode the supplied public/private lengths without issuance evidence. Current Atlas also supports service-account OAuth, not just legacy API-key pairs. [Vendor](https://www.mongodb.com/docs/atlas/configure-api-access/). |

## 4. AI models and search infrastructure (8)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| OpenAI | Existing broad `sk-` matcher; explicitly cover `sk-proj-`, `sk-svcacct-`, `sk-admin-` plus supported historical forms. [G] has observed lengths and `T3BlbkFJ` markers. | Do not depend solely on that internal marker forever, or attribute unrelated providers' `sk-` values to OpenAI. Exact length contracts must distinguish versions; current underscore framing can reject valid modern bodies. [Vendor authentication](https://developers.openai.com/api/reference/overview#authentication), [G]. |
| Anthropic | Existing `sk-ant-api03-`; add separately evidenced admin `sk-ant-admin01-`. [G] observes 93 `U` plus `AA` for both. | Exact body/suffix comes from [G], not a vendor guarantee. Preserve provider precedence over generic `sk-`; vendor also now documents bearer/workload-identity authentication, which has separate semantics. [Vendor](https://platform.claude.com/docs/en/api/overview), [G]. |
| Hugging Face | Existing `hf_`; [G] observes a 34-letter body. Historical `api_org_` appears in [G], but is not evidence of current issuance. | Vendor deprecates organization API tokens. Keep historical support explicitly labeled rather than assuming all tokens share arbitrary alphanumeric bodies. [Vendor](https://huggingface.co/docs/hub/security-tokens), [G]. |
| Cohere | Context `COHERE_API_KEY` / `CO_API_KEY`, observed 40 `A` and entropy gating from [G]. | No unique supported prefix; existing generic assignments may cover some contexts, but not a provider-specific rule. [Vendor](https://docs.cohere.com/docs/rate-limits), [G]. |
| Replicate | Existing `r8_`; vendor explicitly documents 40 total characters, hence 37 after the prefix. | Replace broad minimum-only acceptance with a versioned supported shape once alphabet evidence is settled. [Vendor](https://replicate.com/docs/topics/security/api-tokens). |
| Together AI | Context `TOGETHER_API_KEY`; do not add the supplied `together_` prefix without evidence. Existing `tgn-` is a separate unverified assumption to review, not proof of coverage. | Retrieved vendor quickstart specifies how to supply the credential, not a stable token grammar. Prefix-specific expansion deferred pending stronger evidence. [Vendor](https://docs.together.ai/docs/quickstart). |
| Algolia | Context specifically for admin/write API keys; [G] observes 32 alphanumeric characters case-insensitively, not exclusively hex. | Application IDs and deliberately exposed search-only keys are not standalone secrets. Identical-shaped keys require role/field context; a generic `ALGOLIA_API_KEY` remains ambiguous. [Vendor](https://www.algolia.com/doc/guides/security/api-keys), [G]. |
| Meilisearch | Context `MEILI_MASTER_KEY`, admin API keys. Master keys are user chosen, minimum 16 bytes; no universal prefix or fixed alphabet. | Default search keys differ in exposure intent; distinguish them from admin/master keys. Do not scan every 16-byte string. [Vendor](https://www.meilisearch.com/docs/resources/self_hosting/security/master_api_keys). |

## 5. Payments, billing and financial rails (6)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Stripe | Existing `sk_test_`/`sk_live_`, `rk_test_`/`rk_live_`; add webhook `whsec_` and separately documented organization `sk_org_`. Public `pk_*` excluded from new secret rules. | Shared `sk_live_`/`sk_test_` is not unique to Stripe; require context for provider attribution or describe the finding as a shared secret-key family. Existing `sk_prod_`/`rk_prod_` needs separate review. [Vendor key types](https://docs.stripe.com/keys). |
| PayPal | Context-bound client secret, OAuth bearer tokens and credential-bearing Basic authentication when actually supported. | Client IDs are not client secrets. No vendor-wide reliable client-secret prefix/length established; arbitrary base64 decoding stays deferred. [Vendor](https://developer.paypal.com/api/rest/authentication/). |
| Braintree | Context for private keys; [T] `braintreepayments` observes 32 hex private keys with other account fields. `access_token$production$...` / sandbox access-token grammar needs separate full-shape evidence before standalone support. | Do not mistake public key / merchant ID for the secret or assume that a partially recalled OAuth format is verified. [Vendor OAuth tokens](https://developer.paypal.com/braintree/docs/guides/extend/oauth/access-tokens/ruby/), [T]. |
| Lemon Squeezy | Context for API bearer keys; [T] `lemonsqueezy` observes RS256 JWTs. | Supplied `ls_` is not established. Reuse existing JOSE for structurally valid JWTs rather than copy [T]'s brittle exact JWT lengths. [Vendor](https://docs.lemonsqueezy.com/api), [T]. |
| Paddle | Add vendor-published exact grammar: `pdl_(live\|sdbx)_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3}`, total 69 characters. Context for legacy 50 lowercase alphanumeric keys. | Public client-side tokens are not backend API keys. Modern Billing is distinct from historical Paddle Classic vendor authentication. [Vendor exact regex](https://developer.paddle.com/api-reference/about/authentication/). |
| Plaid | Add/context `access-(sandbox\|development\|production)-UUID`; context for `PLAID_SECRET` (30 alphanumeric observed in [G]). | `client_id` is an identifier, not the secret. Other tokens vary in exposure intent: vendor permits `public_token` and `link_token` in frontend flows. [Vendor](https://plaid.com/docs/api/), [G]. |

## 6. Authentication, identity and access control (5)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Auth0 | Context for application client secrets, management access tokens; JWT branch can cover structurally valid JWTs. | Client IDs are public identifiers. Supplied fixed 64-character secret rule is not a universal contract. Existing `ua2_` rule needs separate primary evidence; do not expand it speculatively. [Vendor confidential/public applications](https://auth0.com/docs/get-started/applications/confidential-and-public-applications). |
| Okta | Context/authorization scheme `SSWS`; [G] observes `00` plus 40 `[\w=-]` characters. OAuth bearer tokens are a separate family. | Existing `00a` prefix is too specific for that observed SSWS format and too weak to identify Okta out of context. [Vendor](https://developer.okta.com/docs/guides/create-an-api-token/main/), [G]. |
| Clerk | `CLERK_SECRET_KEY` with documented `sk_test_` / `sk_live_`; public `pk_test_`/`pk_live_` excluded. | Already superficially matched as Stripe, so detection presence is not correct attribution. Do not introduce two identical provider matches for one span. [Vendor environment variables](https://clerk.com/docs/guides/development/clerk-environment-variables). |
| WorkOS | Context `WORKOS_API_KEY`; vendor documents `sk_`, not a universal `sk_test_`/`sk_live_` pair. `client_` IDs are not secrets. | Avoid globally matching every `sk_` value or claiming Stripe prefix matching gives complete WorkOS support. [Vendor](https://workos.com/docs/reference/api-authentication). |
| Firebase Authentication | GCP API-key family plus private service-account credentials; retain distinction between public Firebase project keys and genuinely sensitive authorized API keys. | Vendor explicitly describes Firebase service-only API keys as public by design. Reuse Google/private-key rules; no duplicate Firebase `AIza` rule. Existing broad Google key policy is not automatically changed. [Vendor](https://firebase.google.com/docs/projects/api-keys). |

## 7. Feature management and experimentation (5)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| LaunchDarkly | Add server SDK `sdk-` (UUID-shaped candidate; finalize issuance shape before promotion), context for management access tokens. | Vendor explicitly says SDK keys are secret, mobile `mob-` and client-side IDs need not be secret. Do not invent a `client-` prefix for all client-side IDs. [Vendor](https://launchdarkly.com/docs/sdk/concepts/client-side-server-side), [G]. |
| Flagsmith | Add server-side `ser.` family with bounded body to be finalized; context `FLAGSMITH_SERVER_SIDE_ENVIRONMENT_KEY`. | Client environment keys are public; `cli.` is not established as a universal client-key prefix by retrieved sources. Vendor confirms `ser.` for server-side/local evaluation. [Server keys](https://docs.flagsmith.com/integrating-with-flagsmith/sdks/server-side), [public client key](https://docs.flagsmith.com/integrating-with-flagsmith/integration-overview). |
| Unleash | Context for backend/admin tokens. Vendor grammar is `<projects>:<environment>.<secret>`; personal/service-account forms use `user:<secret>`. New secure secrets start `v2_` with selector and random components. | Frontend tokens use similar structure but are explicitly public. `*:default.` alone cannot distinguish them; add context-aware support, not a global generic token rule. [Vendor](https://docs.getunleash.io/concepts/api-tokens-and-client-keys). |
| GrowthBook | Add/context actual REST secret-key `secret_` family; public SDK connection keys/endpoints are not admin secrets. | Proposed `sdk_` is not an established REST secret prefix. Vendor authentication examples use `secret_`; exact issuance body remains to be finalized. [REST authentication](https://docs.growthbook.io/api/introduction#authentication), [SDK exposure](https://docs.growthbook.io/app/api). |
| PostHog | Add personal `phx_`; [T] `posthog` observes 43–48 `[A-Za-z0-9_]` characters. | Project tokens used by public ingestion endpoints are not personal API credentials; do not make `phc_` a standalone secret rule by default. [Vendor](https://posthog.com/docs/api), [T]. |

## 8. Observability, logging and engineering metrics (7)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Sentry | Existing `sntrys_`; add personal `sntryu_` + 64 lowercase hex. Org format is `sntrys_` + base64 payload + `_` + 43 base64 signature characters, with variable payload length. Context for legacy 64-hex auth tokens. | Vendor explicitly excludes DSNs from secrets. Existing helper cannot correctly model arbitrary org base64 payloads. `sntrya_`/`sntryi_` are reserved, not currently issued: do not count them as supported live families. [Vendor scanner guidance](https://docs.sentry.io/security-legal-pii/security/token-formats/). |
| Datadog | Context API keys (32 characters) versus application keys (40); [T] `datadogapikey` / `datadogtoken` supplies observed alphanumeric/hyphen alphabets. | Existing generic fields already include Datadog names. Do not add free-standing 32/40-hex rules or treat [G]'s application-token detector as complete API-key coverage. [Vendor](https://docs.datadoghq.com/account_management/api-app-keys/), [T], [G]. |
| New Relic | Add/context user `NRAK-` + 27 alphanumeric observed by [G]; context legacy 40-hex license keys. Distinguish browser, ingest/insert and user keys. | Supplied `NRAL-` license claim not verified by retrieved vendor docs; do not implement it from the list alone. Existing generic license fields are partial coverage. [Vendor](https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/), [G]. |
| Grafana Cloud | Add service-account `glsa_` + 32 alphanumeric + `_` + 8 hex; Cloud access-policy `glc_` base64 bodies and legacy base64 API keys are distinct. | No standalone service-account rule; existing generic context field is not full prefix support. [Vendor service accounts](https://grafana.com/docs/grafana/latest/administration/service-accounts/), [G]. |
| Axiom | Add `xaat-` API and `xapt-` personal token families. Official SDK confirms both prefixes; UUID-shaped bodies need independent issuance/fixture confirmation before making an exact contract. | No dedicated rule. [Vendor token semantics](https://axiom.co/docs/reference/tokens), [pinned official SDK](https://github.com/axiomhq/axiom-go/blob/8105e1cf18400de04646351cc59246ad0140652a/internal/config/token.go). |
| Sleuth | Context `SLEUTH_API_KEY`, organization API-key headers/assignments. | No stable standalone grammar established; defer a prefix/length detector. [Vendor](https://help.sleuth.io/sleuth-dora/sleuth-api). |
| Jellyfish | Context for API token in explicitly Jellyfish-associated configuration; vendor blog documents `Authorization` token authentication. | `docs.jellyfish.co` did not resolve; use the actual engineering-management vendor, not unrelated Jellyfish Energy or Share of Model products. No stable standalone grammar established. [Vendor integration example](https://jellyfish.co/blog/integrating-jellyfish-insights-with-grafana/). |

## 9. Communications and transactional messaging (7)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Twilio | Context for Auth Token and API-key secret. `AC` + 32 hex Account SID and `SK` + 32 hex API-key SID identify resources; neither authenticates alone. | Existing rules label both SIDs as high-severity secrets; propose explicit identifier classification rather than crediting them as secret coverage. Secret halves need context, not bare 32-hex scans. [Vendor](https://www.twilio.com/docs/iam/api-keys). |
| SendGrid | Existing `SG.` structure: two base64url segments separated by `.`, familiar 22 + 43 segment shape. | Current matcher accepts only alphanumeric segment bytes, missing `-`/`_`. [G] has broader observed bodies; vendor warns keys may exceed 69 total characters, so do not impose 69 as a universal future maximum without versioning. [Vendor](https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys), [G]. |
| Resend | Add `re_` family; [T] `resend` observes `re_<8 base58>_<24 base58>`. | Must not discard the internal underscore or confuse `re_` identifiers with keys; vendor examples confirm the prefix. [Vendor](https://resend.com/docs/api-reference/api-keys/create-api-key), [T]. |
| OneSignal | Add modern `os_v2_app_` family, exact body still to establish. Context for legacy API keys. | Vendor distinguishes private API-key values from public UUID App/Organization IDs and from key IDs. [T]'s old UUID detector is insufficient evidence to label every OneSignal UUID a secret. [Vendor](https://documentation.onesignal.com/docs/en/keys-and-ids). |
| Pusher | Context specifically for application secret, observed 20 lowercase alphanumeric in [T] `pusherchannelkey`. | App key and App ID appear in client initialization and must not be promoted as standalone secret values. No unique secret prefix. [Vendor client configuration](https://pusher.com/docs/channels/using_channels/connection/), [T]. |
| Novu | Context `NOVU_SECRET_KEY` / `NOVU_API_KEY`; API requests carry the environment secret. | `ApiKey` is an auth scheme, not necessarily a prefix inside the value. No stable standalone issuance grammar established. [Vendor](https://docs.novu.co/api-reference). |
| Courier | Context for backend auth tokens; [T] `courier` observes `pk_<alphanumeric component>_<28 alphanumeric>`. | Vendor API reference confirms bearer auth, but does not establish both proposed `pk_`/`dk_` families. Do not assume `pk_` always means public, or add a global `dk_` rule without stronger evidence. [Vendor](https://www.courier.com/docs/api-reference/send/send-a-message), [T]. |

## 10. Security scanning and secrets vaults (7)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| GitGuardian | Context `GITGUARDIAN_API_KEY` and `Authorization: Token` in vendor-associated settings. | Retrieved vendor reference does not establish `gg_api_`; do not invent support for that proposed prefix. No unauthenticated validity/health calls were made. [Vendor](https://docs.gitguardian.com/api-docs/authentication). |
| TruffleHog | Enterprise integration secret `thog-secret-` + 32 lowercase hex observed by [T] `trufflehogenterprise`; key ID `thog-key-` + 16 hex is an identifier. | Open-source TruffleHog is not itself a generic API-token issuer. Enterprise formats are historical secondary evidence, not proof of current SaaS issuance. [Vendor product docs](https://trufflesecurity.com/docs), [T]. |
| Snyk | Context for legacy UUID tokens; new personal/service-account auth needs separately verified grammar. | Existing `snyk_token` generic field is partial support. UUIDs are not unique to Snyk; current vendor distinguishes newer PATs from legacy API tokens. [Vendor](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api), [G]. |
| SonarQube | Add `squ_`/`sqp_`/`sqa_` + 40 lowercase hex; context for historical bare 40-character tokens. SonarQube Cloud `sqco_` + 59 alphanumeric is a separate optional family observed by [T]. | Existing generic `sonar_token` field does not recognize a bare prefixed value. No global SHA-1-shaped rule. [Vendor token types](https://docs.sonarsource.com/sonarqube-server/user-guide/managing-tokens), [T], [G]. |
| HashiCorp Vault | Add service `hvs.`, batch `hvb.`, recovery `hvr.`; retain legacy `s.`/`b.`/`r.` only with strong context and version-specific evidence. Vendor says random body; [G] has service/batch length heuristics. | Supplied `hvs....` omits distinct token types. Short legacy prefixes must not match prose, filenames or member access. [Vendor prefix table](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-prefixes), [G]. |
| Doppler | Correct mapping: service `dp.st.<config>.…`, personal `dp.pt.…`, CLI `dp.ct.…`; [T] also observes `dp.sa.`, `dp.scim.`, `dp.audit.` with 40–44 alphanumeric secret bodies. | Supplied service/personal labels are wrong. Preserve dotted config component, not just a fixed global `dp.pt.` detector. [Vendor service tokens](https://docs.doppler.com/docs/service-tokens), [T]. |
| Tailscale | Add independently credential-bearing `tskey-api-`, `tskey-auth-`, and separately verified OAuth/SCIM/webhook secrets. [T] observes two body components separated by `-`. | Official prefix list also includes `tskey-client`; prefix/type by itself is not enough to prove an OAuth client identifier is a client secret. Keep public identifiers separate. [Vendor key types](https://tailscale.com/docs/reference/key-prefixes), [T]. |

## 11. Network, CDN and API gateways (4)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Cloudflare | Existing `cfk_`, `cfut_`, `cfat_`; vendor documents 40 characters plus checksum. Add separately evidenced Wrangler OAuth `cfoat_`. Context for pre-2026 Global API keys and unprefixed tokens; Origin CA `v1.0-<24 hex>-<146 hex>` observed by [G]. | Vendor says legacy Global API keys can be 37–45 lowercase hex, not always 37. Do not call checksum verification implemented: current rule only scans a broad body. [Vendor exact families](https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/), [G]. |
| Fastly | Context `FASTLY_API_TOKEN` / vendor-associated token fields; [G] observes 32 `[A-Za-z0-9=_-]`. | No unique prefix; vendor distinguishes user from automation tokens. Bare 32-character scans would match unrelated IDs and hashes. [Vendor](https://www.fastly.com/documentation/reference/api/auth-tokens/), [G]. |
| Zuplo | Context for managed consumer keys and management credentials, with configurable key schemes kept distinct. | Retrieved vendor docs do not establish universal `zp_`. Defer standalone prefix until issuance contract is verified; gateway customer keys are not necessarily platform-management keys. [Vendor](https://zuplo.com/docs/articles/api-key-management). |
| Kong | Add Konnect `kpat_`/`spat_` + 49 alphanumeric observed by [T] `kong`. Context for separately configured gateway/Admin API authentication. | Gateway key-auth accepts configurable consumer credentials; there is no universal "Kong Admin key" shape. [Konnect vendor auth](https://developer.konghq.com/konnect-api/), [gateway key-auth](https://developer.konghq.com/plugins/key-auth/), [T]. |

## 12. Media processing and file pipelines (4)

| Platform | Finding and recommended detection | Rayloc gap / evidence |
| --- | --- | --- |
| Cloudinary | Existing credential-URI rule for the `cloudinary` scheme and `<api_key>:<api_secret>@host` userinfo; context specifically for `CLOUDINARY_API_SECRET`. | Numeric API key is not the secret half; don't enforce proposed 15/27 lengths as universal. URI parser must require nonempty concrete password and not consume trailing source syntax. [Vendor configuration](https://cloudinary.com/documentation/cloudinary_sdks#configuration_parameters). |
| Uploadthing | Context `UPLOADTHING_TOKEN`, v7 base64-encoded JSON containing API key/app ID/region; retain historical `UPLOADTHING_SECRET` only with versioned evidence. | Proposed shared Stripe-like `sk_live_`/`sk_test_` list is not complete current support. Do not scan all base64 JSON as Uploadthing; arbitrary decoding is deferred unless approved as a separate extension. [Vendor v7 migration](https://docs.uploadthing.com/v7). |
| APITemplate.io | Context `APITEMPLATE_API_KEY` / `X-API-KEY` request credentials; [T] `apitemplate` observes 39 alphanumeric, but retrieved vendor examples differ in presentation. | Header name is generic, not provider-unique; exact length is secondary heuristic, not vendor guarantee. Context-first; do not reject all other lengths from that observation alone. [Vendor](https://docs.apitemplate.io/reference/api-reference.html), [T]. |
| CraftMyPDF | Context `CRAFTMYPDF_API_KEY` / actual request-header secret. [T] `craftmypdf` observes 35 alphanumeric. | No stable provider-specific prefix documented; generic `X-API-KEY` must not be attributed to CraftMyPDF. Old `/apidocs.html` was unavailable; use current vendor reference. [Vendor](https://support.craftmypdf.com/rest-api-integration), [T]. |

## Corrections that must shape implementation

1. **Correct format, not just more names.** GitLab 20-byte tokens, PlanetScale
   `pscale_pw_`, SendGrid URL-safe bytes, Sentry org-token base64, and OpenAI
   multi-underscore bodies expose shortcomings in existing minimum-only/shared
   matchers. Fix the affected families with positive and near-miss fixtures.
2. **Do not copy generic regexes blindly.** UUIDs, 32/40/64 hex and base64 values
   collide with identifiers, checksums and public SDK keys. Require the secret
   field/authorization/URI association actually being scanned.
3. **Do not give shared prefixes false provider attribution.** Stripe/Clerk
   collide on `sk_live_` / `sk_test_`; WorkOS also uses `sk_`. Prefer precise
   context when available, otherwise honest shared-family wording. Preserve
   stable rule IDs/disable behavior or explicitly approve a migration.
4. **Keep issued versus reserved/historical separate.** Sentry reserved prefixes,
   old organization tokens and retired auth methods are not evidence of current
   issuance. Prefix observations without body contracts are research candidates,
   not shipped coverage claims.
5. **No credential validation calls.** All research used documentation/source
   retrieval, not credential probing. Scans must remain offline.
6. **Retain URI placeholder negatives.** Scanning the draft audit with the base
   binary reported its illustrative Cloudinary URI with angle-bracket credential
   placeholders. This was not a real credential; the document now describes the
   scheme and userinfo separately. Preserve that case as a future negative fixture
   rather than weakening scanner policy globally or claiming it is already fixed.

## Proposed bounded implementation design — awaiting approval

Extend the existing provider/context/URI branches, not CLI or configuration
interfaces. Add source-backed, versioned structural families first; then exact
secret-bearing context aliases for opaque credentials. Reuse existing JOSE,
private-key and credential-URI recognition instead of duplicating them under
each provider's name. Maintain a source/status catalog, including deliberately
public identifiers and unresolved candidates, so a large catalog does not imply
unsupported detection guarantees.

Primary files: `src/rules/builtin.rs`, `src/rules/assignment.rs`, narrowly scoped
parts of `src/rules/context.rs` if required, relevant `tests/unit/` and integration
tests, catalog documentation, and the existing benchmark/evaluation harnesses.
Avoid a general rule-loader, new dependencies or a full matcher rewrite in this
bounded pass. If measured growth makes the existing dispatcher unsuitable, stop
for approval of performance scope before proceeding.

For each supported credential variant, require synthetic positive and negative
controls: exact complete span, body length/alphabet, punctuation and adjacent
identifiers, public counterpart, references/placeholders/checksums, disabled-rule
behavior, overlaps, all relevant input split points, candidate-budget errors,
redacted scan output and stream redaction. Cover file/directory, added diff lines,
and stdin/child-command paths without reporting unchanged/deleted lines. Existing
generic public-token behavior is documented rather than silently suppressed.

No implementation approval has been given yet. The proposed design is not a
commitment to add every speculative prefix above.

## Performance baseline and approval gate

Base: `e4b72e481de0a7b3c7eebcc153bb2dbf3de3cbef`.
`cargo test --all --locked`, `cargo build --release --locked`, and
`cargo bench --locked` succeeded before detector changes.

- Immutable local baseline: `/tmp/opencode/rayloc-expansion-baseline-e4b72e4`.
- Release binary: 3,126,080 bytes, SHA-256
  `7cd7e528b0725d74d5b64daae02332f70d8a3c946ad82af14fe97bd9b31decbe`.
- Host: AMD Ryzen 9 9950X, Linux x86_64; Rust 1.88.0, Git 2.56.0.
- Warm-cache engine benchmark: 272,384 input bytes, 40 samples, one worker;
  median 7.886 ms, p95 7.952 ms, 34.54 decimal MB/s.
- Warm-cache scope, 4,096 files × 16,418 bytes, five samples:

| Workers | Median ms | p95 ms | Decimal MB/s |
| ---: | ---: | ---: | ---: |
| 1 | 2695.040 | 2760.693 | 24.95 |
| 2 | 1411.480 | 1442.144 | 47.64 |
| 8 | 369.721 | 374.845 | 181.89 |

Raw local benchmark log: `/tmp/opencode/rayloc-expansion-baseline-bench.txt`.
Benchmark output's "10 built-ins" label is historical: current `Registry` contains
more provider rules. These figures cover only the existing synthetic workloads;
five-sample scope p95 is the maximum sample, not a stable production-tail estimate.
Documentation retrieval ran during the baseline session, so these initial numbers
are orientation, not a definitive A/B regression result. Rerun both immutable
binaries paired on an otherwise idle host before deciding a regression.

Before accepting expanded rules, compare identical inputs/compiler/policy/cache
and worker counts, alternating baseline/candidate order for repeated samples:

- Existing engine/scope benchmarks plus clean, reference-heavy and token-dense
  inputs, including newly supported token families and adversarial prefix misses.
- Long physical lines crossing 256-KiB chunk and 64-KiB candidate boundaries.
- Startup-inclusive files/directories and empty/small/large staged/reference diffs.
- Stream/file/child-command redaction, measuring retained output correctness as
  well as latency, throughput, peak RSS and binary size.

Use existing `scripts/context_precision_measure.py`, `scripts/longline_measure.py`
and `scripts/measure_redaction.py` where their fixture expectations still apply;
update expectations only after reviewing intentional detection-policy changes.
Never report a faster incomplete scan or missed finding as a speed win. Preserve
fixed-scope baseline controls separately from expanded-coverage workloads, since
the old binary cannot detect newly supported credential families.

**User gate:** no slowdown allowance has been approved. If paired measurements
indicate degradation beyond run-to-run noise, present the affected workloads,
ratios, uncertainty and suspected cause, and wait for confirmation before adding
performance improvements to the plan. Existing harness tolerance thresholds do
not override this user gate. No expanded-catalog performance result exists yet.
