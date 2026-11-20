# Secret Pattern Implementation — Remaining Work Queue

**Date:** 2026-11-19
**Method:** coverage diff of `docs/research/github-supported-secret-patterns.md` rows vs `src/rules/builtin.rs` (slug-id match, prefix-literal match, or keyword-rule match).
**Batches 1–5 done; batch 6 (keyword-gated, 20 variants) in progress.**

> NOTE: batch 4 task-spec listed Buildkite ×10 and Polar ×8, but neither appears in
> `builtin.rs` (`grep -ci 'buildkite\|polar'` = 0). They are back in the queue as batch 7.

## Batch 7 — prefix-based (~17 variants)

| Provider | Slug(s) | Pattern |
|---|---|---|
| 1Password | 1password_service_account_token | `ops_eyJ` + `[A-Za-z0-9+/]{60,}={0,3}` |
| Adafruit | adafruit_io_key | `aio_` + 20+ alnum |
| Beamer | beamer_api_key | `b_` + `[a-z0-9=_\-]{44}` (dedicated matcher: `b_` too generic for prefix table) |
| Cockroach Labs | ccdb_api_key | `ccdb_` prefix |
| Canadian Digital Service | cds_canada_notify_api_key | `ApiKey-v1 gcntfy` prefix |
| Contentful | contentful_personal_access_token | `CFPAT-` (variant `ContentfulPat` EXISTS but has NO dispatch/prefix wiring — wire it) |
| Docker | docker_organization_access_token, docker_personal_access_token | `dckr_pat_` + `[A-Za-z0-9_-]{27}` |
| Buildkite | 10 slugs (agent-access, agent-job, agent-registration, cluster-queue, cluster, packages-registry, packages-temporary, portal-secret, portal-token, user-access) | `bk` + `[a-zA-Z0-9]{16,40}` |

## Batch 8 — Polar + Azure structural (~13 variants)

| Provider | Slug(s) | Pattern |
|---|---|---|
| Polar | 8 slugs (access-token, authorization-code, client-registration-token, client-secret, customer-session-token, personal-access-token, refresh-token, user-session-token) | `polar_` prefix |
| Azure | azure_devops_personal_access_token | 84 chars alnum, `AZDO` signature at 76-80 |
| Azure | azure_function_key | 54 chars `[a-z0-9/+]+` ending `==` |
| Azure | azure_storage_account_key | `[A-Za-z0-9+/=]{86}` (keyword `azure`/`storage`) |
| Azure | azure_ai_services_key | `[a-zA-Z0-9]{32}` keyword-gated |
| Azure | azure_cognitive_services_key, azure_computer_vision_key | `[a-f0-9]{32}` keyword-gated |
| Azure | azure_cache_for_redis_access_key | base64 keyword-gated |
| Azure | azure_active_directory_application_secret | `[a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}` (`Q~` marker) |

## Batch 9–11 — Azure keyword-gated family (~50 variants, split ~17/batch)

Keyword `azure` (+ distinct URL markers for the identifiable/connection-string rows):
azure_anomaly_detector_ee_key, azure_anomaly_detector_key, azure_apim_direct_management_key,
azure_apim_gateway_key, azure_apim_repository_key, azure_apim_subscription_key,
azure_app_configuration_connection_string, azure_app_configuration_key,
azure_batch_key_identifiable, azure_communication_services_connection_string,
azure_communication_services_key, azure_container_registry_key_identifiable,
azure_content_moderator_key, azure_content_safety_key, azure_cosmosdb_key_identifiable,
azure_custom_vision_prediction_key, azure_custom_vision_training_key,
azure_event_grid_key_identifiable, azure_event_hub_key_identifiable,
azure_face_key, azure_fluid_relay_key, azure_form_recognizer_key,
azure_health_decision_support_key, azure_health_insights_key, azure_immersive_reader_key,
azure_internal_all_in_one_key, azure_iot_device_connection_string, azure_iot_device_key,
azure_iot_device_provisioning_key, azure_iot_hub_connection_string, azure_iot_hub_key,
azure_iot_provisioning_connection_string, azure_knowledge_key, azure_logic_apps_url,
azure_luis_authoring_key, azure_luis_key, azure_management_certificate,
azure_maps_key, azure_metrics_advisor_key, azure_mixed_reality_key,
azure_ml_inference_identifiable_key, azure_ml_internal_service_principal_identifiable_key,
azure_ml_web_service_classic_identifiable_key, azure_openai_key, azure_personalizer_key,
azure_qna_maker_key, azure_qna_maker_v2_key, azure_quantum_key,
azure_relay_key_identifiable, azure_sas_token, azure_search_admin_key,
azure_search_query_key, azure_service_bus_identifiable, azure_signalr_connection_string,
azure_signalr_key, azure_speech_services_key, azure_speech_translation_key,
azure_sql_internal_default_cloudsa_key, azure_sql_password, azure_text_analytics_key,
azure_text_translation_key, azure_video_intelligence_key, azure_web_app_bot_key,
azure_web_pub_sub_connection_string, azure_web_pub_sub_key,
microsoft_azure_entra_id_token.

## Batch 12 — remaining keyword-gated (~13 variants)

aws_api_key, aws_secret_access_key, aws_temporary_access_key_id, apiclub_api_key,
asaas_api_token, docker_swarm_join_token, docker_swarm_unlock_key,
onechronos_api_key, onechronos_eb_api_key, onechronos_eb_encryption_key,
onechronos_oauth_token, onechronos_refresh_token, onesignal_rich_authentication_token
(verify vs existing `one-signal-rich-api-key`), gitlab_ci_build_token
(verify vs `gitlab-cicd-build-token` — likely covered, skip if same),
hackclub_ai_api_key (verify vs `hack-club-ai-key` — likely covered, skip if same).

## Batch 13 — generic N rows (2 variants)

- http_basic_authentication_header — `Authorization: Basic <base64...>`
- http_bearer_authentication_header — `Authorization: Bearer <token>`

## Already covered by alias (do NOT re-implement)

github_{personal,oauth,app_installation,refresh,test}_token → `github-token` (`ghp_/gho_/ghu_/ghs_/ghr_/github_pat_`),
bitrise PAT → `bitrise-pat`, contentful PAT wiring caveat above,
digitalocean_{oauth,pat,system} → `digitalocean-*`,
hexpm → `hex-api-key`, hf_* → `huggingface-*`, readmeio → `read-me-api-key`,
stripe test/secret → `stripe-*`, wave prod/test → `wave-*`, circleci personal/project → `circleci-*`,
docker PAT/Org → pending in batch 7 (dckr_pat_ NOT present), airtable PAT → `airtable-pat`,
alibaba → `alibaba-key`, naver-cloud → `naver-cloud-*`, nuxeo/dingtalk/… fine.

## Verification protocol per batch

`cargo build` + `cargo fmt --all -- --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test --all`,
and keep `tests/unit/builtin_coverage.rs::ALL_RULE_IDS` in declaration order.
