# Secret Pattern Implementation Design

**Date:** 2026-11-19  
**Status:** Draft  
**Worktree:** `.worktrees/secret-pattern-implementation`  
**Reference:** `docs/research/github-supported-secret-patterns.md`

## 1. Purpose

Expand `rayloc`'s detector catalog by implementing new secret patterns from the GitHub supported secret-scanning patterns catalog. All 525 provider patterns now have documented patterns (100% pattern coverage). This spec covers implementing the detectors in `src/rules/builtin.rs` for patterns that are documented but not yet implemented as Rust detection rules.

## 2. Current State

### Implemented Rules (in `RuleId` enum)
The following RuleId variants already exist in `src/rules/builtin.rs`:

| RuleId | Pattern Type | Status |
|--------|-------------|--------|
| AwsAccessKeyId | Prefix (AKIA/ASIA/ABIA/ACCA) | Implemented |
| GithubToken | Prefix (ghp_/gho_/ghu_/ghs_/ghr/github_pat_) | Implemented |
| StripeSecretKey | Prefix (sk_live_/sk_test_) | Implemented |
| StripeRestrictedKey | Prefix (rk_live_/rk_test_) | Implemented |
| SlackWebhook | URL pattern | Implemented |
| PrivateKeyMarker | Marker (-----BEGIN...) | Implemented |
| AwsSecretAccessKey | Context-bound | Implemented |
| JoseToken | JOSE structure | Implemented |
| ContextSecret | Context-based | Implemented |
| PasswordAssignment | Context-based | Implemented |
| OpenaiKey | Prefix (sk-...) | Implemented |
| OpenrouterKey | Prefix (sk-or-v1-) | Implemented |
| AnthropicKey | Prefix (sk-ant-...) | Implemented |
| GroqKey | Prefix (gsk_) | Implemented |
| PerplexityKey | Prefix (pplx-) | Implemented |
| HuggingfaceKey | Prefix (hf_) | Implemented |
| XaiKey | Prefix (xai-) | Implemented |
| GoogleApiKey | Prefix (AIza) | Implemented |
| AlibabaKey | Prefix (LTAI) | Implemented |
| BaiduKey | Prefix (bce-v3/ALTAK-) | Implemented |
| WandbKey | Prefix | Implemented |
| FirecrawlKey | Prefix | Implemented |
| LangsmithKey | Prefix | Implemented |
| VoyageKey | Prefix | Implemented |
| CartesiaKey | Prefix | Implemented |
| ReplicateKey | Prefix | Implemented |
| VercelKey | Prefix (vcp_/vci_/vca_/vcr_/vck_) | Implemented |
| SupabaseKey | Prefix (sb_secret_/sbp_) | Implemented |
| CloudflareKey | Prefix (cfk_/cfut_/cfat_) | Implemented |
| DigitalOceanPat/Oauth/Refresh | Prefix (dop_v1_/doo_v1_/dor_v1_) | Implemented |
| DockerSwarmJoin/Unlock | Prefix | Implemented |
| HerokuApiKey | Prefix (HRKU-AA) | Implemented |
| ClojarsToken | Prefix (CLOJARS_) | Implemented |
| CratesioToken | Prefix | Implemented |
| PyPiToken | Prefix (pypi-AgEI...) | Implemented |
| RubygemsApiKey | Prefix (rubygems_) | Implemented |
| SendgridApiKey | Pattern (SG....) | Implemented |
| SendinblueApiKey | Pattern (xkeysib-...) | Implemented |
| SlackBot/User/Workspace/RefreshToken | Prefix (xoxb_/xoxp_/xoxa-/xoxr-) | Implemented |
| TwilioAccountSid | Prefix (AC + 32 hex) | Implemented |
| TwilioApiKey | Prefix (SK + 32 hex) | Implemented |
| SentryOrgToken | Prefix (sntrys_eyJ...) | Implemented |
| SentryPersonalToken | Prefix (sntryu_ + 64 hex) | Implemented |
| GrafanaServiceAccountToken | Prefix | Implemented |
| AxiomToken | Prefix | Implemented |
| SonarQubeToken | Prefix | Implemented |
| SonarQubeCloudToken | Prefix | Implemented |
| KongKonnectToken | Prefix | Implemented |
| TruffleHogEnterpriseSecret | Prefix | Implemented |
| DopplerToken | Prefix (dp.pt_/dp.st_/etc.) | Implemented |
| TailscaleApiToken | Prefix (tskey-api-/etc.) | Implemented |
| TailscaleAuthToken | Prefix (tskey-auth-/etc.) | Implemented |
| ResendApiKey | Prefix (re_) | Implemented |
| LaunchDarklyServerSdkToken | Prefix | Implemented |
| FlagsmithServerToken | Prefix | Implemented |
| GrowthBookSecretKey | Prefix | Implemented |
| PostHogPersonalToken | Prefix | Implemented |
| GitLab tokens (12 variants) | Various prefixes | Implemented |
| CircleCI Personal/Project | Prefix (CCIPAT_/CCIPRJ_) | Implemented |
| AtlassianApiToken | Prefix (ATATT3...) | Implemented |
| NetlifyAccessToken | Prefix (nfp_) | Implemented |
| FlyioToken | Prefix (fo1_/fm1_/fm2_) | Implemented |
| PineconeApiKey | Prefix (pcsk_) | Implemented |
| AnthropicAdminKey | Prefix (sk-ant-admin01-) | Implemented |
| Auth0ManagementToken | Prefix | Implemented |
| OktaAccessToken | Prefix | Implemented |
| NotionApiKey | Prefix (ntn_) | Implemented |
| LinearApiKey | Prefix (lin_api_) | Implemented |
| FigmaToken | Prefix | Implemented |
| SquareAccessToken | Prefix (sq0atp-/sq0csp-) | Implemented |
| Shopify tokens (6 variants) | Prefix (shpat_/shpcc_/etc.) | Implemented |
| StripePaymentIntent | Prefix (pi_) | Implemented |
| StripeAccessToken | Prefix | Implemented |
| MistralKey | Prefix | Implemented |
| CerebrasKey | Prefix | Implemented |
| TogetheraiKey | Prefix | Implemented |
| FireworksAiKey | Prefix | Implemented |
| StabilityAiKey | Prefix | Implemented |
| DeepgramKey | Prefix | Implemented |
| RazorpayKey | Prefix | Implemented |
| Planetscale Password/Token/OAuth | Prefix (pscale_pw_/pscale_tkn_/pscale_otkn_) | Implemented |
| PaddleApiKey | Prefix | Implemented |
| PlaidAccessToken | Prefix | Implemented |
| CloudinaryUrl | URI pattern | Implemented |
| MongodbUri | URI pattern | Implemented |
| PostgresUri | URI pattern | Implemented |
| RedisUri | URI pattern | Implemented |
| SqlserverUri | URI pattern | Implemented |
| MysqlUri | URI pattern | Implemented |
| CockroachdbUri | URI pattern | Implemented |

### Patterns Documented but Not Yet Implemented

The catalog at `docs/research/github-supported-secret-patterns.md` documents patterns for all 525 providers. Many are marked `keyword-gated` meaning they don't have distinctive regex patterns yet — they rely on the secret type name appearing as a keyword near the secret value.

The following provider patterns need new `RuleId` variants and detection logic:

**Phase 1 — Prefix-based rules (distinctive prefix known):**

| Provider | Secret Type | Pattern | RuleId Name |
|----------|------------|---------|-------------|
| Adobe | adobe_client_secret | `p8e-[a-z0-9]{32}` | AdobeClientSecret |
| Adobe | adobe_device_token | `adobe` prefix | AdobeDeviceToken |
| Adobe | adobe_pac_token | `adobe` prefix | AdobePacToken |
| Adobe | adobe_refresh_token | `adobe` prefix | AdobeRefreshToken |
| Adobe | adobe_service_token | `adobe` prefix | AdobeServiceToken |
| Adobe | adobe_short_lived_access_token | `adobe` prefix | AdobeShortLivedAccessToken |
| Aikido | aikido_api_client_secret | keyword-gated | AikidoApiClientSecret |
| Aikido | aikido_ci_scanning_token | keyword-gated | AikidoCiScanningToken |
| Airtable | airtable_api_key | keyword-gated | AirtableApiKey |
| Airtable | airtable_personal_access_token | `pat[A-Za-z0-9]{14}\.[0-9a-f]{64}` | AirtablePat |
| Aiven | aiven_auth_token | `aivenv1` prefix | AivenAuthToken |
| Aiven | aiven_service_password | `aivenv1` prefix | AivenServicePassword |
| Amazon AWS | aws_api_key | keyword-gated | AwsApiKey |
| Amazon AWS | aws_session_token | keyword-gated, 40-char base64 | AwsSessionToken |
| Anthropic | anthropic_service_api_key | `sk-ant-api03-[0-9A-Za-z_-]{93}AA` | AnthropicServiceApiKey |
| Anthropic | anthropic_session_id | `sk-ant-api03-[0-9A-Za-z_-]{93}AA` | AnthropicSessionId |
| Anthropic | anthropic_user_api_key | `sk-ant-api03-[0-9A-Za-z_-]{93}AA` | AnthropicUserApiKey |
| APIclub | apiclub_api_key | keyword-gated | ApiclubApiKey |
| Apify | apify_api_token | `apify_api_[a-zA-Z-0-9]{36}` | ApifyApiToken |
| Apify | apify_actor_run_api_token | `apify_api_[a-zA-Z-0-9]{36}` | ApifyActorRunApiToken |
| Apify | apify_actor_run_proxy_password | `apify_api_[a-zA-Z-0-9]{36}` | ApifyActorRunProxyPassword |
| Apify | apify_integration_api_token | `apify_api_[a-zA-Z-0-9]{36}` | ApifyIntegrationApiToken |
| Apify | apify_proxy_password | `apify_api_[a-zA-Z-0-9]{36}` | ApifyProxyPassword |
| Apify | apify_ui_token | `apify_api_[a-zA-Z-0-9]{36}` | ApifyUiToken |
| Apify | apify_webhook_dispatch_api_token | `apify_api_[a-zA-Z-0-9]{36}` | ApifyWebhookDispatchApiToken |
| Asaas | asaas_api_token | keyword-gated | AsaasApiToken |
| Asana | asana_legacy_format_personal_access_token | keyword-gated | AsanaLegacyPat |
| Asana | asana_personal_access_token | keyword-gated | AsanaPat |
| Atlassian | atlassian_jwt | `ATATT3[A-Za-z0-9_=-]{100,}` | AtlassianJwt |
| Authress | authress_service_client_access_key | complex pattern | AuthressServiceClientAccessKey |
| Bitbucket | bitbucket_server_personal_access_token | keyword-gated | BitbucketServerPat |
| Bitrise | bitrise_personal_access_token | `bitrise_` prefix | BitrisePat |
| Bitrise | bitrise_workspace_api_token | `bitrise_` prefix | BitriseWorkspaceApiToken |
| Block Protocol | block_protocol_api_key | keyword-gated | BlockProtocolApiKey |
| Brevo | sendinblue_smtp_key | `xkeysib-[a-f0-9]{64}\-[a-z0-9]{16}` | SendinblueSmtpKey |
| Canva | canva_app_secret | `cnvca` prefix | CanvaAppSecret |
| Canva | canva_connect_api_secret | `cnvca` prefix | CanvaConnectApiSecret |
| Canva | canva_secret | `cnvca` prefix | CanvaSecret |
| Cashfree | cashfree_api_key | keyword-gated | CashfreeApiKey |
| Cfx.re | cfxre_server_key | keyword-gated | CfxreServerKey |
| Checkout.com | checkout_production_secret_key | `sk_live_` prefix | CheckoutProductionSecretKey |
| Checkout.com | checkout_test_secret_key | `sk_test_` prefix | CheckoutTestSecretKey |
| Chief Tools | chief_tools_token | keyword-gated | ChiefToolsToken |
| Clojars | clojars_deploy_token | `CLOJARS_[a-z0-9]{60}` | ClojarsDeployToken |
| Cloudsmith | cloudsmith_api_key | `cs_[a-zA-Z0-9]{32,48}` | CloudsmithApiKey |
| Cohere | cohere_api_key | keyword-gated | CohereApiKey |
| Contentful | contentful_personal_access_token | `CFPAT-` prefix | ContentfulPat |
| Contentful | contentful_web_token | keyword-gated | ContentfulWebToken |
| Contributed Systems | contributed_systems_credentials | keyword-gated | ContributedSystemsCredentials |
| Coveo | coveo_access_token | keyword-gated | CoveoAccessToken |
| Coveo | coveo_api_key | keyword-gated | CoveoApiKey |
| Databento | databento_api_key | `db-` prefix | DatabentoApiKey |
| Databricks | databricks_access_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksApiToken |
| Databricks | databricks_account_session_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksAccountSessionToken |
| Databricks | databricks_federated_account_session_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksFederatedAccountSessionToken |
| Databricks | databricks_oauth_code | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksOAuthCode |
| Databricks | databricks_oauth_refresh_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksOAuthRefreshToken |
| Databricks | databricks_oauth_secret_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksOAuthSecretToken |
| Databricks | databricks_oauth_single_use_refresh_token_child | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksOAuthSingleUseRefreshTokenChild |
| Databricks | databricks_oauth_single_use_refresh_token_parent | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksOAuthSingleUseRefreshTokenParent |
| Databricks | databricks_scoped_api_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksScopedApiToken |
| Databricks | databricks_scoped_internal_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksScopedInternalToken |
| Databricks | databricks_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksToken |
| Databricks | databricks_workspace_session_token | `dapi[0-9a-f]{32}(?:-\d)?` | DatabricksWorkspaceSessionToken |
| Datadog | datadog_api_key | keyword-gated | DatadogApiKey |
| Datadog | datadog_app_key | `datadog` keyword + 40 hex | DatadogAppKey |
| Datadog | datadog_pat | keyword-gated | DatadogPat |
| Datadog | datadog_rcm | keyword-gated | DatadogRcm |
| Datadog | datadog_sat | keyword-gated | DatadogSat |
| Datastax | datastax_astracs_token | keyword-gated | DatastaxAstraCsToken |
| DeepSeek | deepseek_api_key | keyword-gated | DeepseekApiKey |
| Defined Networking | defined_networking_nebula_api_key | `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}` | DefinedNetworkingNebulaApiKey |
| DevCycle | devcycle_client_api_key | keyword-gated | DevCycleClientApiKey |
| DevCycle | devcycle_mobile_api_key | keyword-gated | DevCycleMobileApiKey |
| DevCycle | devcycle_server_api_key | keyword-gated | DevCycleServerApiKey |
| DigitalOcean | digitalocean_system_token | `dop_v1_` prefix | DigitalOceanSystemToken |
| Discord | discord_bot_token | `[MNO][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}` | DiscordBotToken |
| Docker | docker_organization_access_token | `dckr_pat_[A-Za-z0-9_-]{27}` | DockerOrganizationPat |
| Docker | docker_personal_access_token | `dckr_pat_[A-Za-z0-9_-]{27}` | DockerPersonalPat |
| Docker | docker_swarm_join_token | keyword-gated | DockerSwarmJoinToken |
| Docker | docker_swarm_unlock_key | keyword-gated | DockerSwarmUnlockKey |
| Doppler | doppler_audit_token | `dp\.(?:pt\|st\|ct\|sa\|scim\|audit)\.[A-Za-z0-9]{40,44}` | DopplerAuditToken |
| Doppler | doppler_cli_token | `dp\.(?:pt\|st\|ct\|sa\|scim\|audit)\.[A-Za-z0-9]{40,44}` | DopplerCliToken |
| Doppler | doppler_personal_token | `dp.pt.[A-Za-z0-9]{40,44}` | DopplerPersonalToken |
| Doppler | doppler_scim_token | `dp\.(?:pt\|st\|ct\|sa\|scim\|audit)\.[A-Za-z0-9]{40,44}` | DopplerScimToken |
| Doppler | doppler_service_account_token | `dp.sa.[A-Za-z0-9]{40,44}` | DopplerServiceAccountToken |
| Doppler | doppler_service_token | `dp\.(?:pt\|st\|ct\|sa\|scim\|audit)\.[A-Za-z0-9]{40,44}` | DopplerServiceToken |
| Dropbox | dropbox_access_token | `sl\.[A-Za-z0-9\-_]{130,}` | DropboxAccessToken |
| Dropbox | dropbox_short_lived_access_token | `sl\.[a-z0-9\-=_]{130,}` | DropboxShortLivedAccessToken |
| Duffel | duffel_live_access_token | `duffel_live_[a-zA-Z0-9_-]{43}` | DuffelLiveAccessToken |
| Duffel | duffel_test_access_token | `duffel_test_[a-zA-Z0-9_-]{43}` | DuffelTestAccessToken |
| Dynatrace | dynatrace_api_token | `dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}` | DynatraceApiToken |
| Dynatrace | dynatrace_internal_token | `dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}` | DynatraceInternalToken |
| EasyPost | easypost_production_api_key | `EZAK + 54 alphanumeric` | EasypostProductionApiKey |
| EasyPost | easypost_test_api_key | `EZ[AT]K[A-Za-z0-9]{54}` | EasypostTestApiKey |
| Elastic | elastic_cloud_api_key | `essu_` prefix | ElasticCloudApiKey |
| Elastic | elastic_stack_api_key | `essu_` prefix | ElasticStackApiKey |
| Facebook | facebook_access_token | `\d{15,16}(\|%%)[0-9a-z\-_]{27,40}` | FacebookAccessToken |
| Fastly | fastly_api_token | `[a-z0-9=_\-]{32}` | FastlyApiToken |
| Fieldguide | fieldguide_api_token | keyword-gated | FieldguideApiToken |
| Figma | figma_pat | keyword-gated | FigmaPat |
| Figma | figma_scim_api_token | `fig-oauth-, figt_` | FigmaScimToken |
| Finicity | finicity_app_key | keyword-gated | FinicityAppKey |
| Firebase | firebase_cloud_messaging_server_key | keyword-gated | FirebaseCloudMessagingServerKey |
| Flickr | flickr_api_key | keyword-gated | FlickrApiKey |
| Flutterwave | flutterwave_live_api_secret_key | `FLWSECK_TEST-[a-h0-9]{32}-X` | FlutterwaveLiveApiSecretKey |
| Flutterwave | flutterwave_test_api_secret_key | `FLWSECK_TEST-[a-h0-9]{32}-X` | FlutterwaveTestApiSecretKey |
| Frame.io | frameio_developer_token | `fio-u-[a-zA-Z0-9\-_=]{64}` | FrameIoDeveloperToken |
| Frame.io | frameio_jwt | keyword-gated | FrameIoJwt |
| FullStory | fullstory_api_key | `<data center>.\<token\>` | FullStoryApiKey |
| GitHub | github_app_installation_access_token | `gh[pousr]_[A-Za-z0-9_]{36,255}` | GitHubAppInstallationToken |
| GitHub | github_oauth_access_token | `gh[pousr]_[A-Za-z0-9_]{36,255}` | GitHubOAuthToken |
| GitHub | github_personal_access_token | `gh[pousr]_[A-Za-z0-9_]{36,255}` | GitHubPersonalAccessToken |
| GitHub | github_refresh_token | `gh[pousr]_[A-Za-z0-9_]{36,255}` | GitHubRefreshToken |
| GitHub | github_test_token | `gh[pousr]_[A-Za-z0-9_]{36,255}` | GitHubTestToken |
| GitHub | github_ssh_private_key | Private key markers | GitHubSSHPrivateKey |
| GitLab | gitlab_access_token | `glpat-[0-9A-Za-z_-]{20}` | GitLabAccessToken |
| GitLab | gitlab_cicd_build_token | keyword-gated | GitLabCICDBuildToken |
| GitLab | gitlab_deploy_token | keyword-gated | GitLabDeployToken |
| GitLab | gitlab_feature_flag_client_token | keyword-gated | GitLabFeatureFlagClientToken |
| GitLab | gitlab_feed_token_v2 | keyword-gated | GitLabFeedTokenV2 |
| GitLab | gitlab_incoming_email_token | keyword-gated | GitLabIncomingEmailToken |
| GitLab | gitlab_kubernetes_agent_token | keyword-gated | GitLabKubernetesAgentToken |
| GitLab | gitlab_oauth_app_secret | keyword-gated | GitLabOAuthAppSecret |
| GitLab | gitlab_pipeline_trigger_token | keyword-gated | GitLabPipelineTriggerToken |
| GitLab | gitlab_runner_auth_token | keyword-gated | GitLabRunnerAuthToken |
| GitLab | gitlab_runner_registration_token | keyword-gated | GitLabRunnerRegistrationToken |
| GitLab | gitlab_scim_oauth_token | keyword-gated | GitLabScimOAuthToken |
| GoCardless | gocardless_live_access_token | keyword-gated | GoCardlessLiveAccessToken |
| GoCardless | gocardless_sandbox_access_token | keyword-gated | GoCardlessSandboxAccessToken |
| Google | google_api_key | `AIza[0-9A-Za-z_-]{35}` | GoogleApiKey |
| Google | google_cloud_service_account_credentials | `AIza[0-9A-Za-z_-]{35}` | GoogleCloudServiceAccountCredentials |
| Google | google_cloud_storage_access_key_secret | `AIza[0-9A-Za-z\-_]{35}` | GoogleCloudStorageAccessKeySecret |
| Google | google_cloud_storage_user_access_key_id | `AIza[0-9A-Za-z\-_]{35}` | GoogleCloudStorageUserAccessKeyId |
| Google | google_gcp_api_key_bound_service_account | `AIza[0-9A-Za-z_-]{35}` | GoogleGcpApiKeyBoundServiceAccount |
| Google | google_gemini_api_key | `AIza[0-9A-Za-z_-]{35}` | GoogleGeminiApiKey |
| Google | google_oauth_access_token | `AIza[0-9A-Za-z_-]{35}` | GoogleOAuthAccessToken |
| Google | google_oauth_client_id | `[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com` | GoogleOAuthClientId |
| Google | google_oauth_client_secret | keyword-gated | GoogleOAuthClientSecret |
| Google | google_oauth_refresh_token | `1//[0-9A-Za-z_-]{43,128}` | GoogleOAuthRefreshToken |
| Grafana | grafana_cloud_api_key | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` | GrafanaCloudApiKey |
| Grafana | grafana_cloud_api_token | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` | GrafanaCloudApiToken |
| Grafana | grafana_project_api_key | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` | GrafanaProjectApiKey |
| Grafana | grafana_project_service_account_token | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` | GrafanaProjectServiceAccountToken |
| Groq | groq_api_key | `gsk_[A-Za-z0-9]{52}` | GroqApiKey |
| GuardSquare | guardsquare_appsweep_api_key | keyword-gated | GuardsquareAppSweepApiKey |
| GuardSquare | guardsquare_cli_access_token | keyword-gated | GuardsquareCliAccessToken |
| GuardSquare | guardsquare_maven_token | keyword-gated | GuardsquareMavenToken |
| Hack Club | hackclub_ai_api_key | keyword-gated | HackClubAiKey |
| HashiCorp | hashicorp_vault_batch_token | `hvb\.[A-Za-z0-9_-]{60,}` | HashiCorpVaultBatchToken |
| HashiCorp | hashicorp_vault_root_service_token | `hvs\.[A-Za-z0-9_-]{60,}` | HashiCorpVaultRootServiceToken |
| HashiCorp | hashicorp_vault_service_token | `hvs\.[A-Za-z0-9_-]{60,}` | HashiCorpVaultServiceToken |
| HashiCorp | terraform_api_token | `[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}` | TerraformApiToken |
| Heroku | heroku_platform_api_oauth2_token | `HRKU-AA[A-Za-z0-9_-]{58}` | HerokuPlatformApiOAuth2Token |
| Heroku | heroku_postgres_connection_url | `postgres://[^:]+:[^@]+@[^/]+/[^?]+` | HerokuPostgresConnectionUrl |
| Hex | hexpm_api_key | `hex_ + 40 hex` | HexApiKey |
| Highnote | highnote_rk_live_key | `rk_live_` prefix | HighnoteRkLiveKey |
| Highnote | highnote_rk_test_key | `rk_test_` prefix | HighnoteRkTestKey |
| Highnote | highnote_sk_live_key | `sk_live_` prefix | HighnoteSkLiveKey |
| Highnote | highnote_sk_test_key | `sk_test_` prefix | HighnoteSkTestKey |
| HOP | hop_bearer | keyword-gated | HopBearer |
| HOP | hop_pat | keyword-gated | HopPat |
| HOP | hop_ptk | keyword-gated | HopPtK |
| Hubspot | hubspot_api_key | keyword-gated | HubspotApiKey |
| Hubspot | hubspot_personal_access_key | keyword-gated | HubspotPersonalAccessKey |
| Hubspot | hubspot_private_apps_user_token | keyword-gated | HubspotPrivateAppsUserToken |
| Hubspot | hubspot_smtp_credential | keyword-gated | HubspotSmtpCredential |
| Hugging Face | hf_org_api_key | `hf_[A-Za-z]{34}` | HuggingFaceOrgApiKey |
| Hugging Face | hf_user_access_token | `hf_[A-Za-z]{34}` | HuggingFaceUserAccessToken |
| IBM | ibm_cloud_iam_key | keyword-gated | IbmCloudIamKey |
| Intercom | intercom_access_token | keyword-gated | IntercomAccessToken |
| Ionic | ionic_personal_access_token | keyword-gated | IonicPersonalAccessToken |
| Ionic | ionic_refresh_token | keyword-gated | IonicRefreshToken |
| Iterative | iterative_dvc_studio_access_token | keyword-gated | IterativeDvcStudioAccessToken |
| JFrog | jfrog_platform_access_token | `jfrog/artifactory/bintray/xray keyword + 73 alphanumeric` | JFrogPlatformAccessToken |
| JFrog | jfrog_platform_api_key | `AKCp[A-Za-z0-9]{69}` | JFrogPlatformApiKey |
| JFrog | jfrog_platform_reference_token | `jfrog/artifactory/bintray/xray keyword + 64 alphanumeric` | JFrogPlatformReferenceToken |
| Langchain | langchain_api_personal_key | keyword-gated | LangChainApiPersonalKey |
| Langchain | langchain_api_server_key | keyword-gated | LangChainApiServerKey |
| Langchain | langsmith_license_key | `lsv2_pt_`, `lsv2_sk_` | LangSmithLicenseKey |
| Langchain | langsmith_scim_bearer_token | `lsv2_pt_`, `lsv2_sk_` | LangSmithScimBearerToken |
| Lark | lark_apaas_client_secret | `lark_` prefix | LarkApaasClientSecret |
| Lark | lark_app_secret | `lark_` prefix | LarkAppSecret |
| Lark | lark_mcp_grant_token | `lark_` prefix | LarkMcpGrantToken |
| Lark | lark_meego_plugin_secret | `lark_` prefix | LarkMeegoPluginSecret |
| Lark | lark_user_session | `lark_` prefix | LarkUserSession |
| LaunchDarkly | launchdarkly_access_token | keyword-gated | LaunchDarklyAccessToken |
| Lichess | lichess_oauth_access_token | keyword-gated | LichessOAuthAccessToken |
| Lichess | lichess_personal_access_token | keyword-gated | LichessPersonalAccessToken |
| Lightspeed | lightspeed_xs_pat | keyword-gated | LightspeedXsPat |
| Limbar | limbar_token | keyword-gated | LimbarToken |
| Linear | linear_oauth_access_token | `lin_api_[0-9A-Za-z]{40}` | LinearOAuthAccessToken |
| LinkedIn | linkedin_client_secret | keyword-gated | LinkedInClientSecret |
| Lob | lob_live_api_key | `live_[a-f0-9]{35}` | LobLiveApiKey |
| Lob | lob_test_api_key | `test_[a-f0-9]{35}` | LobTestApiKey |
| Localstack | localstack_api_key | keyword-gated | LocalstackApiKey |
| LogicMonitor | logicmonitor_bearer_token | keyword-gated | LogicMonitorBearerToken |
| LogicMonitor | logicmonitor_lmv1_access_key | keyword-gated | LogicMonitorLmv1AccessKey |
| Login with Amazon | amazon_oauth_client_id | keyword-gated | AmazonOAuthClientId |
| Login with Amazon | amazon_oauth_client_secret | keyword-gated | AmazonOAuthClientSecret |
| Lovable Labs | lovable_api_key | `lov_` prefix | LovableApiKey |
| Mailchimp | mailchimp_api_key | `[0-9a-f]{32}-us[0-9]+` | MailchimpApiKey |
| Mailchimp | mandrill_api_key | `[0-9a-f]{32}-us[0-9]+` | MandrillApiKey |
| Mailersend | mailersend_api_token | `mlsn.` prefix | MailersendApiToken |
| Mailersend | mailersend_smtp_password | `mlsn.` prefix | MailersendSmtpPassword |
| Mailersend | mailersend_smtp_username | `mlsn.` prefix | MailersendSmtpUsername |
| Mailgun | mailgun_api_key | `key-[0-9a-zA-Z]{32}` | MailgunApiKey |
| Mailgun | mailgun_smtp_credential | `key-[0-9a-zA-Z]{32}` | MailgunSmtpCredential |
| Mapbox | mapbox_secret_access_token | `sk.` prefix | MapboxSecretAccessToken |
| MaxMind | maxmind_license_key | keyword-gated | MaxMindLicenseKey |
| Meraki | meraki_api_key | `[0-9a-f]{40}` | MerakiApiKey |
| Mercury | mercury_non_production_api_token | `secret-token:mercury_` prefix | MercuryNonProductionApiToken |
| Mercury | mercury_production_api_token | `secret-token:mercury_production_` prefix | MercuryProductionApiToken |
| Mergify | mergify_application_key | keyword-gated | MergifyApplicationKey |
| MessageBird | messagebird_api_key | keyword-gated | MessageBirdApiKey |
| Microsoft | power_automate_webhook_sas | keyword-gated | PowerAutomateWebhookSAS |
| Midtrans | midtrans_production_server_key | `Mid-server-` prefix | MidtransProductionServerKey |
| Midtrans | midtrans_sandbox_server_key | `SB-Mid-server-` prefix | MidtransSandboxServerKey |
| Mistral AI | mistral_ai_api_key | keyword-gated | MistralAiApiKey |
| MongoDB | mongodb_atlas_db_uri_with_credentials | `mongodb://[^:]+:[^@]+@` | MongoDBAtlasDbUriWithCredentials |
| MongoDB | mongodb_atlas_service_account_secret | keyword-gated | MongoDBAtlasServiceAccountSecret |
| Naver Cloud | navercloud_gov_access_key | `navercloud_` prefix | NaverCloudGovAccessKey |
| Naver Cloud | navercloud_gov_access_key_secret | `navercloud_` prefix | NaverCloudGovAccessKeySecret |
| Naver Cloud | navercloud_gov_sts | `navercloud_` prefix | NaverCloudGovSts |
| Naver Cloud | navercloud_gov_sts_secret | `navercloud_` prefix | NaverCloudGovStsSecret |
| Naver Cloud | navercloud_pub_access_key | `navercloud_` prefix | NaverCloudPubAccessKey |
| Naver Cloud | navercloud_pub_access_key_secret | `navercloud_` prefix | NaverCloudPubAccessKeySecret |
| Naver Cloud | navercloud_pub_sts | `navercloud_` prefix | NaverCloudPubSts |
| Naver Cloud | navercloud_pub_sts_secret | `navercloud_` prefix | NaverCloudPubStsSecret |
| Neon | neon_api_key | keyword-gated | NeonApiKey |
| Neon | neon_connection_uri | `postgresql://[^:]+:[^@]+@[^/]+\.neon\.tech/[^?]+` | NeonConnectionUri |
| Netflix | netflix_netkey | keyword-gated | NetflixNetKey |
| New Relic | new_relic_insights_query_key | `NRAK-` prefix | NewRelicInsightsQueryKey |
| New Relic | new_relic_license_key | `NRAK-` prefix | NewRelicLicenseKey |
| New Relic | new_relic_personal_api_key | `NRAK-` prefix | NewRelicPersonalApiKey |
| New Relic | new_relic_rest_api_key | `NRAK-` prefix | NewRelicRestApiKey |
| Notion | notion_api_token | `ntn_[0-9]{11}[A-Za-z0-9]{35}` | NotionApiToken |
| Notion | notion_integration_token | `ntn_[0-9]{11}[A-Za-z0-9]{35}` | NotionIntegrationToken |
| Notion | notion_oauth_client_secret | `ntn_[A-Za-z0-9]{40,60}` | NotionOAuthClientSecret |
| NuGet | nuget_api_key | `oy2[a-z0-9]{43}` | NuGetApiKey |
| Octopus Deploy | octopus_deploy_api_key | `API-[A-Z0-9]{25}` | OctopusDeployApiKey |
| Oculus | oculus_access_token | keyword-gated | OculusAccessToken |
| OneChronos | onechronos_api_key | keyword-gated | OneChronosApiKey |
| OneChronos | onechronos_eb_api_key | keyword-gated | OneChronosEBApiKey |
| OneChronos | onechronos_eb_encryption_key | keyword-gated | OneChronosEBEncryptionKey |
| OneChronos | onechronos_oauth_token | keyword-gated | OneChronosOAuthToken |
| OneChronos | onechronos_refresh_token | keyword-gated | OneChronosRefreshToken |
| OneSignal | onesignal_rich_authentication_token | keyword-gated | OneSignalRichApiKey |
| Onfido | onfido_live_api_token | keyword-gated | OnfidoLiveApiToken |
| Onfido | onfido_sandbox_api_token | keyword-gated | OnfidoSandboxApiToken |
| OpenAI | openai_api_key | `sk-(?:proj-\|svcacct-\|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74}` | OpenAIApiKey |
| OpenRouter | openrouter_api_key | `sk-or-v1-[a-f0-9]{64}` | OpenRouterApiKey |
| OpenVSX | openvsx_access_token | keyword-gated | OpenVSXAccessToken |
| Openweather | openweather_api_key | keyword-gated | OpenweatherApiKey |
| Oracle | oracle_api_key | keyword-gated | OracleApiKey |
| Orbit | orbit_api_token | keyword-gated | OrbitApiToken |
| Paddle | paddle_api_key | keyword-gated | PaddleApiKey |
| Paddle | paddle_sandbox_api_key | keyword-gated | PaddleSandboxApiKey |
| PagerDuty | pagerduty_oauth_secret | keyword-gated | PagerDutyOAuthSecret |
| PagerDuty | pagerduty_oauth_token | keyword-gated | PagerDutyOAuthToken |
| Palantir | palantir_jwt | keyword-gated | PalantirJWT |
| Pangea | pangea_token | keyword-gated | PangeaToken |
| Perplexity | perplexity_api_key | `pplx-[A-Za-z0-9]{48}` | PerplexityApiKey |
| Persona Identities | persona_production_api_key | keyword-gated | PersonaProductionApiKey |
| Persona Identities | persona_sandbox_api_key | keyword-gated | PersonaSandboxApiKey |
| Pineapple Technologies Limited | pineapple_technologies_incident_api_key | keyword-gated | PineappleTechnologiesIncidentApiKey |
| Pinecone | pinecone_api_key | `pcsk_` prefix | PineconeApiKey |
| Pinterest | pinterest_access_token | keyword-gated | PinterestAccessToken |
| Pinterest | pinterest_refresh_token | keyword-gated | PinterestRefreshToken |
| PlanetScale | planetscale_database_password | `pscale_pw_[a-zA-Z0-9_-]{43}` | PlanetScaleDatabasePassword |
| PlanetScale | planetscale_oauth_token | `pscale_otkn_[a-zA-Z0-9_-]{43}` | PlanetScaleOAuthToken |
| PlanetScale | planetscale_service_token | `pscale_tkn_[a-zA-Z0-9_-]{43}` | PlanetScaleServiceToken |
| Planning Center | planning_center_oauth_access_token | keyword-gated | PlanningCenterOAuthAccessToken |
| Planning Center | planning_center_oauth_app_secret | keyword-gated | PlanningCenterOAuthAppSecret |
| Planning Center | planning_center_personal_access_token | keyword-gated | PlanningCenterPersonalAccessToken |
| Plivo | plivo_auth_id | keyword-gated | PlivoAuthID |
| Plivo | plivo_auth_token | keyword-gated | PlivoAuthToken |
| PostHog | posthog_feature_flags_secure_api_key | `phx_` prefix | PostHogFeatureFlagsSecureApiKey |
| PostHog | posthog_oauth_access_token | `phx_` prefix | PostHogOAuthAccessToken |
| PostHog | posthog_oauth_refresh_token | `phx_` prefix | PostHogOAuthRefreshToken |
| PostHog | posthog_personal_api_key | `phx_` prefix | PostHogPersonalApiKey |
| Postman | postman_api_key | `PMAK-[0-9a-f]{24}-[a-fA-F0-9]{34}` | PostmanApiKey |
| Postman | postman_collection_key | `PMAK-[0-9a-f]{24}-[a-fA-F0-9]{34}` | PostmanCollectionKey |
| Prefect | prefect_server_api_key | `pnu_[A-Za-z0-9]{36}` | PrefectServerApiKey |
| Prefect | prefect_user_api_key | `pnu_[A-Za-z0-9]{36}` | PrefectUserApiKey |
| Proctorio | proctorio_consumer_key | `[0-9a-f]{32}` | ProctorioConsumerKey |
| Proctorio | proctorio_linkage_key | `[0-9a-f]{64}` | ProctorioLinkageKey |
| Proctorio | proctorio_registration_key | `[0-9a-f]{64}` | ProctorioRegistrationKey |
| Proctorio | proctorio_secret_key | `[0-9a-f]{32}` | ProctorioSecretKey |
| Proof | proof_full_access_api_key | `prf_\|prf_test_\|prf_cli_\|prf_cli_test_` | ProofFullAccessApiKey |
| Pulumi | pulumi_access_token | `pul-` prefix | PulumiAccessToken |
| Pydantic Services Inc. | logfire_token | keyword-gated | LogfireToken |
| Pydantic Services Inc. | pydantic_ai_gateway_api_key | keyword-gated | PydanticAIGatewayApiKey |
| PyPI | pypi_api_token | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}` | PyPiApiToken |
| Rainforest Pay | rainforest_api_key | keyword-gated | RainforestApiKey |
| Rainforest Pay | rainforest_sandbox_api_key | keyword-gated | RainforestSandboxApiKey |
| Ramp | ramp_client_id | keyword-gated | RampClientID |
| Ramp | ramp_client_secret | keyword-gated | RampClientSecret |
| Ramp | ramp_oauth_token | keyword-gated | RampOAuthToken |
| Raycast | raycast_access_token | keyword-gated | RaycastAccessToken |
| ReadMe | readmeio_api_access_token | `rdme_[a-z0-9]{70}` | ReadMeApiKey |
| Replicate | replicate_api_token | keyword-gated | ReplicateApiToken |
| Resend | resend_api_key | `re_` prefix | ResendApiKey |
| Rootly | rootly_api_key | keyword-gated | RootlyApiKey |
| RubyGems | rubygems_api_key | `rubygems_[a-f0-9]{48}` | RubygemsApiKey |
| RunPod | runpod_api_key | keyword-gated | RunPodApiKey |
| Salesforce | salesforce_access_token | keyword-gated | SalesforceAccessToken |
| Salesforce | salesforce_marketing_cloud_api_oauth2_token | keyword-gated | SalesforceMarketingCloudApiOAuth2Token |
| Salesforce | salesforce_oauth2_consumer_key | `3MVG9[0-9a-zA-Z._+/=]{80,251}` | SalesforceOAuth2ConsumerKey |
| Salesforce | salesforce_oauth2_consumer_secret | keyword-gated | SalesforceOAuth2ConsumerSecret |
| Salesforce | salesforce_refresh_token | `5AEP861[a-zA-Z0-9._=]{80,}` | SalesforceRefreshToken |
| Samsara | samsara_api_token | keyword-gated | SamsaraApiToken |
| Samsara | samsara_oauth_access_token | keyword-gated | SamsaraOAuthAccessToken |
| Scalr | scalr_api_token | keyword-gated | ScalrApiToken |
| Segment | segment_public_api_token | `[a-zA-Z0-9]{32}` | SegmentPublicApiToken |
| SendGrid | sendgrid_api_key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | SendGridApiKey |
| Sentry | sentry_integration_token | `sntrys_eyJ[A-Za-z0-9+/=_]{40,}` | SentryIntegrationToken |
| Sentry | sentry_organization_token | `sntrys_eyJ[A-Za-z0-9+/=]{8,}_[A-Za-z0-9+/]{43}` | SentryOrganizationToken |
| Sentry | sentry_personal_token | `sntryu_[0-9a-f]{64}` | SentryPersonalToken |
| Sentry | sentry_user_app_auth_token | `sntryu_[a-f0-9]{64}` | SentryUserAppAuthToken |
| Shippo | shippo_live_api_token | `shippo_live_` + 40 hex | ShippoLiveApiToken |
| Shippo | shippo_test_api_token | keyword-gated | ShippoTestApiToken |
| Shopee | shopee_open_platform_partner_key | keyword-gated | ShopeeOpenPlatformPartnerKey |
| Shopify | shopify_access_token | `shp(?:at\|ca\|pa\|ss)_[a-fA-F0-9]{32}` | ShopifyAccessToken |
| Shopify | shopify_app_client_credentials | `shpca_[0-9a-fA-F]{32}` | ShopifyAppClientCredentials |
| Shopify | shopify_app_client_secret | `shpca_[0-9a-fA-F]{32}` | ShopifyAppClientSecret |
| Shopify | shopify_app_shared_secret | `shpss_[0-9a-fA-F]{32}` | ShopifyAppSharedSecret |
| Shopify | shopify_custom_app_access_token | `shp(?:at\|ca\|pa\|ss)_[a-fA-F0-9]{32}` | ShopifyCustomAppAccessToken |
| Shopify | shopify_marketplace_token | `shpat_[0-9a-fA-F]{32}` | ShopifyMarketplaceToken |
| Shopify | shopify_merchant_token | `shp(?:at\|ca\|pa\|ss)_[a-fA-F0-9]{32}` | ShopifyMerchantToken |
| Shopify | shopify_partner_api_token | `shpat_[0-9a-fA-F]{32}` | ShopifyPartnerApiToken |
| Shopify | shopify_private_app_password | `shp(?:at\|ca\|pa\|ss)_[a-fA-F0-9]{32}` | ShopifyPrivateAppPassword |
| Siemens | siemens_api_token | keyword-gated | SiemensApiToken |
| Siemens | siemens_code_token | keyword-gated | SiemensCodeToken |
| Sindri | sindri_api_key | keyword-gated | SindriApiKey |
| Slack | slack_api_token | `xox[bpe][0-9a-zA-Z_-]+` | SlackApiToken |
| Slack | slack_incoming_webhook_url | `https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{30,}` | SlackIncomingWebhookURL |
| Slack | slack_workflow_trigger_url | keyword-gated | SlackWorkflowTriggerURL |
| Slack | slack_workflow_webhook_url | keyword-gated | SlackWorkflowWebhookURL |
| Snowflake | snowflake_postgres_connection_string | keyword-gated | SnowflakePostgresConnectionString |
| Snowflake | snowflake_postgres_host | keyword-gated | SnowflakePostgresHost |
| Snowflake | snowflake_postgres_password | keyword-gated | SnowflakePostgresPassword |
| Snowflake | snowflake_programmatic_access_token | keyword-gated | SnowflakeProgrammaticAccessToken |
| Sourcegraph | sourcegraph_access_token | `sgp_` prefix | SourcegraphAccessToken |
| Sourcegraph | sourcegraph_dotcom_user_gateway | `sgph_` prefix | SourcegraphDotcomUserGateway |
| Sourcegraph | sourcegraph_instance_identifier_access_token | `sgp_` prefix | SourcegraphInstanceIdentifierAccessToken |
| Sourcegraph | sourcegraph_license_key_token | `sgp_` prefix | SourcegraphLicenseKeyToken |
| Sourcegraph | sourcegraph_product_subscription_token | `sgp_` prefix | SourcegraphProductSubscriptionToken |
| SpaceX | starlink_public_api_v2_secret | keyword-gated | StarlinkPublicAPIV2Secret |
| Square | square_access_token | `sq0atp-[A-Za-z0-9_-]{22,60}\|sq0csp-[A-Za-z0-9_-]{43}` | SquareAccessToken |
| Square | square_production_application_secret | `EAAA[0-9A-Za-z_-]{60}` | SquareProductionApplicationSecret |
| Square | square_sandbox_application_secret | `sq0atp-[0-9A-Za-z_-]{22}` | SquareSandboxApplicationSecret |
| SSLMate | sslmate_api_key | `sq0csp-` + 43 word chars | SSLMateAPIKey |
| SSLMate | sslmate_cluster_secret | `sq0csp-` + 43 word chars | SSLMateClusterSecret |
| Stripe | stripe_api_key | `rk_(?:live\|test)_[A-Za-z0-9]{24,}\|sk_prod_[A-Za-z0-9]{24,}` | StripeApiKey |
| Stripe | stripe_legacy_api_key | `(?:sk\|rk)_(?:live\|test)_[0-9A-Za-z]{24,99}` | StripeLegacyAPIKey |
| Stripe | stripe_live_restricted_key | `rk_live_[A-Za-z0-9]{24,}` | StripeLiveRestrictedKey |
| Stripe | stripe_test_restricted_key | `rk_test_[A-Za-z0-9]{24,}` | StripeTestRestrictedKey |
| Stripe | stripe_test_secret_key | `(?:sk\|rk)_(?:live\|test)_[0-9A-Za-z]{24,99}` | StripeTestAPISecretKey |
| Stripe | stripe_webhook_signing_secret | `whsec_[A-Za-z0-9]{32,64}` | StripeWebhookSigningSecret |
| Supabase | supabase_oauth_access_token | `sb_secret_[A-Za-z0-9_-]{31,}\|sbp_[a-f0-9]{40}` | SupabaseOAuthAccessToken |
| Supabase | supabase_personal_access_token | `sb_secret_` prefix | SupabasePersonalAccessToken |
| Supabase | supabase_scoped_personal_access_token | `sb_secret_[A-Za-z0-9_-]{31,}\|sbp_[a-f0-9]{40}` | SupabaseScopedPersonalAccessToken |
| Supabase | supabase_secret_key | `sb_secret_` prefix | SupabaseSecretKey |
| Tableau | tableau_personal_access_token | keyword-gated | TableauPersonalAccessToken |
| Tailscale | tailscale_api_key | `tskey-(?:api\|auth\|client\|scim\|webhook)-[A-Za-z0-9]{8,}-[A-Za-z0-9]{20,}` | TailscaleAPIKey |
| Tavily | tavily_api_key | keyword-gated | TavilyApiKey |
| Telegram | telegram_bot_token | `[0-9]{8,10}:AA[A-Za-z0-9_-]{33}` | TelegramBotToken |
| Telnyx | telnyx_api_v2_key | keyword-gated | TelnyxAPIV2Key |
| Temporal | temporal_cloud_api_key | keyword-gated | TemporalCloudApiKey |
| Tencent | tencent_cloud_intl_access_token | `AKID[0-9a-zA-Z]{32}` | TencentCloudIntlAccessToken |
| Tencent | tencent_cloud_secret_id | `AKID[0-9a-zA-Z]{32}` | TencentCloudSecretID |
| Tencent | tencent_wechat_api_app_id | keyword-gated | TencentWeChatAPIAppID |
| Tencent | tencent_wechat_pay_token | keyword-gated | TencentWeChatPayToken |
| Thunderstore | thunderstore_io_api_token | keyword-gated | ThunderstoreIOApiToken |
| Twilio | twilio_access_token | keyword-gated | TwilioAccessToken |
| Twilio | twilio_account_sid | `AC[a-zA-Z0-9]{32}` | TwilioAccountSID |
| Twilio | twilio_api_key | `SK[0-9a-fA-F]{32}` | TwilioAPIKey |
| Typeform | typeform_personal_access_token | `tfp_[a-z0-9\-_.=]{59}` | TypeformPersonalAccessToken |
| Uniwise | wiseflow_api_key | keyword-gated | WISEflowAPIKey |
| Unkey | unkey_root_key | keyword-gated | UnkeyRootKey |
| Val Town | val_town_api_token | keyword-gated | ValTownApiToken |
| Vercel | vercel_api_key | `vcp_[A-Za-z0-9]{24}` | VercelAPIKey |
| Vercel | vercel_app_refresh_token | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | VercelAppRefreshToken |
| Vercel | vercel_app_user_access_token | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | VercelAppUserAccessToken |
| Vercel | vercel_integration_access_token | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | VercelIntegrationAccessToken |
| Vercel | vercel_personal_access_token | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | VercelPersonalAccessToken |
| Vercel | vercel_support_access_token | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | VercelSupportAccessToken |
| VolcEngine | volcengine_access_key_id | keyword-gated | VolcEngineAccessKeyID |
| VolcEngine | volcengine_ark_api_key | keyword-gated | VolcEngineArkAPIKey |
| Wakatime | wakatime_api_key | `waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | WakaTimeAPIKey |
| Wakatime | wakatime_app_secret | `waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | WakaTimeAppSecret |
| Wakatime | wakatime_oauth_access_token | `waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | WakaTimeOAuthAccessToken |
| Wakatime | wakatime_oauth_refresh_token | `waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | WakaTimeOAuthRefreshToken |
| Wave Mobile Money | wave_api_prod_key | keyword-gated | WaveProductionAPIKey |
| Wave Mobile Money | wave_api_test_key | keyword-gated | WaveTestAPIKey |
| Weatherstack | weatherstack_api_key | keyword-gated | WeatherstackAPIKey |
| Weights & Biases | wandb_api_key | keyword-gated | WandbAPIKey |
| Workato | workato_developer_api_token | keyword-gated | WorkatoDeveloperAPIToken |
| WorkOS | workos_production_api_key | `sk_live_` prefix | WorkOSProductionAPIKey |
| WorkOS | workos_staging_api_key | `sk_test_` prefix | WorkOSStagingAPIKey |
| WSO2 | wso2_choreo_personal_access_token | keyword-gated | WSO2ChoreoPersonalAccessToken |
| Yandex | yandex_cloud_api_key | `AQVN[A-Za-z0-9_\-]{35,38}` | YandexCloudAPIKey |
| Yandex | yandex_cloud_iam_access_secret | `AQVN[A-Za-z0-9_\-]{35,38}` | YandexCloudIAMAccessSecret |
| Yandex | yandex_cloud_iam_cookie | keyword-gated | YandexCloudIAMCookie |
| Yandex | yandex_cloud_iam_token | `t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}` | YandexCloudIAMToken |
| Yandex | yandex_cloud_smartcaptcha_server_key | `ysc2_[a-zA-Z0-9]{40}[0-9a-f]{8}` | YandexCloudSmartcaptchaServerKey |
| Yandex | yandex_dictionary_api_key | keyword-gated | YandexDictionaryAPIKey |
| Yandex | yandex_passport_oauth_token | `y[0-6]\_[-_A-Za-z0-9]{55,199}` | YandexPassportOAuthToken |
| Yandex | yandex_predictor_api_key | keyword-gated | YandexPredictorAPIKey |
| Yandex | yandex_translate_api_key | keyword-gated | YandexTranslateAPIKey |
| ZenHub | zenhub_personal_api_key | keyword-gated | ZenHubPersonalAPIKey |
| Zuplo | zuplo_consumer_api_key | keyword-gated | ZuploConsumerAPIKey |

**Phase 2 — Generic patterns (2 remaining):**

| Secret Type | Pattern | RuleId Name |
|------------|---------|-------------|
| http_basic_authentication_header | context-based | HTTPBasicAuthHeader |
| http_bearer_authentication_header | context-based | HTTPBearerAuthHeader |

**Phase 3 — AI-detected patterns (1 row):**

| Secret Type | Pattern | RuleId Name |
|------------|---------|-------------|
| password | context-based | Password (already exists as PasswordAssignment) |

## 3. Implementation Approach

### 3.1 RuleId Enum Extension

Add new variants to the `RuleId` enum in `src/rules/builtin.rs` following the existing naming convention (PascalCase with descriptive names). Group them logically by category.

### 3.2 Metadata

Add metadata for each new rule in the `RuleId::metadata()` match arm, including:
- `id`: snake_case string identifier
- `description`: human-readable description
- `severity`: High (most are API keys/tokens)
- `confidence`: Medium (keyword-gated) or High (prefix-based)
- `reference`: URL to vendor documentation

### 3.3 Detection Logic

Two detection patterns:

**A. Prefix-based detectors** (for patterns with known prefixes):
- Add prefix bytes to the appropriate prefix constant group
- Add prefix to `PROVIDER_HEAD_LITERALS` or `PROVIDER_HEAD_EXTRA_LITERALS`
- Use existing `api_key_match`, `api_key_match_with_min`, `token_match`, or similar helper functions
- Add to `match_at` dispatch table

**B. Keyword-gated detectors** (for patterns without distinctive prefixes):
- Use the `context` module's keyword-based detection
- Match on secret type name as keyword near candidate secret value
- Follow the pattern established by `ContextSecret` and `PasswordAssignment`

### 3.4 Redaction

All matches must use `RedactedString` wrapper — never print raw secrets.

## 4. Files to Modify

- `src/rules/builtin.rs` — Add new `RuleId` variants, metadata, prefix constants, and detection logic
- `src/rules/mod.rs` — Update `BUILTIN_IDS` array if new rules should be in the default builtin set
- `tests/unit/builtin.rs` — Add unit tests for each new detector
- `tests/integration/` — Add integration tests if needed

## 5. Testing

- Every new detector must have unit tests with positive and negative samples
- Test cases must use redacted output (no raw secrets in test assertions)
- Coverage must remain >=95% lines/regions, 100% functions

## 6. Implementation Order

1. Write design spec (this document)
2. Write implementation plan (separate document)
3. Implement prefix-based detectors first (easier to verify)
4. Implement keyword-gated detectors (require context module changes)
5. Implement generic patterns (HTTP Basic/Bearer auth headers)
6. Run `cargo fmt`, `cargo clippy`, `cargo test`, `cargo coverage`
