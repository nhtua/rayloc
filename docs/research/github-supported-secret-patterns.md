# GitHub Supported Secret-Scanning Patterns — Full Catalog
Source: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
Retrieved: 2026-11-18

This catalog lists every provider pattern row from GitHub's "Supported secret"
scanning patterns" page (the **Supported provider patterns** table). It is
intended as a reference for expanding `rayloc`'s detector catalog.

## Columns
| Column | Meaning |
| ------ | ------- |
| Provider | The platform / issuer name as listed by GitHub. |
| Secret | The human-readable secret name as listed by GitHub. |
| Secret type | GitHub's internal `Secret type` identifier (used by the REST API). |
| Pattern | Detector pattern / prefix. Blank if not yet researched. |
| Implemented | **Y** if the pattern is already implemented in `rayloc`'s `src/rules/builtin.rs`; **N** if it still needs implementation. |

GitHub's page marks some rows with `[Token versions](#token-versions)`; those
link suffixes have been stripped from the `Secret type` column for clarity.
Generic patterns (e.g. `ec_private_key`, `rsa_private_key`) and AI-detected
patterns (e.g. `password`) are listed separately below the provider table.

## Provider patterns (525 rows)
| Provider | Secret | Secret type | Pattern | Implemented |
| :--- | :--- | :--- | :--- | :--- |
| 1Password | 1Password Service Account Token | 1password_service_account_token | ops_eyJ[A-Za-z0-9+/]{60,}={0,3} | Y |
| Adafruit | Adafruit IO Key | adafruit_io_key | aio_ + 20+ alphanumeric | Y |
| Adobe | Adobe Client Secret | adobe_client_secret | p8e-[a-z0-9]{32} | Y |
| Adobe | Adobe Device Token | adobe_device_token | adobe prefix | Y |
| Adobe | Adobe PAC Token | adobe_pac_token | adobe prefix | Y |
| Adobe | Adobe Refresh Token | adobe_refresh_token | adobe prefix | Y |
| Adobe | Adobe Service Token | adobe_service_token | adobe prefix | Y |
| Adobe | Adobe Short-Lived Access Token | adobe_short_lived_access_token | adobe prefix | Y |
| Aikido | Aikido API Client Secret | aikido_api_client_secret | keyword-gated | Y |
| Aikido | Aikido CI Scanning Token | aikido_ci_scanning_token | keyword-gated | Y |
| Airtable | Airtable API Key | airtable_api_key | keyword-gated | Y |
| Airtable | Airtable Personal Access Token | airtable_personal_access_token | pat[A-Za-z0-9]{14}\.[0-9a-f]{64} | Y |
| Aiven | Aiven Auth Token | aiven_auth_token | aivenv1 prefix | Y |
| Aiven | Aiven Service Password | aiven_service_password | aivenv1 prefix | Y |
| Alibaba | Alibaba Cloud AccessKey ID | alibaba_cloud_access_key_id, alibaba_cloud_access_key_secret | sk-ws- | Y |
| Amazon AWS | Amazon AWS Access Key ID | aws_access_key_id, aws_secret_access_key, | AKIA/ASIA/ABIA/ACCA + [A-Z2-7]{16} | Y |
| Amazon AWS | Amazon AWS API Key ID | aws_api_key | keyword-gated (rayloc: `amazon-aws-api-key-id`) | Y |
| Amazon AWS | Amazon AWS Session Token | aws_secret_access_key, aws_session_token, aws_temporary_access_key_id | keyword-gated, 40-char base64 body (rayloc: `amazon-aws-session-token`, `amazon-aws-temporary-access-key-id`; secret-access-key covered by context rules) | Y |
| Anthropic | Anthropic Admin API Key | anthropic_admin_api_key | sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA | Y |
| Anthropic | Anthropic API Key | anthropic_api_key, | sk-ant-api03-[a-zA-Z0-9_\-]{93}AA | Y |
| Anthropic | Anthropic Service Account API Key | anthropic_service_api_key | sk-ant-api03-[0-9A-Za-z_-]{93}AA | Y |
| Anthropic | Anthropic Session ID | anthropic_session_id | sk-ant-api03-[0-9A-Za-z_-]{93}AA | Y |
| Anthropic | Anthropic User API Key | anthropic_user_api_key | sk-ant-api03-[0-9A-Za-z_-]{93}AA | Y |
| APIclub | APIclub API Key | apiclub_api_key | keyword-gated | Y |
| Apify | Apify Actor Run API Token | apify_actor_run_api_token | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify Actor Run Proxy Password | apify_actor_run_proxy_password | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify API Token | apify_api_token | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify Integration API Token | apify_integration_api_token | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify Proxy Password | apify_proxy_password | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify UI Token | apify_ui_token | apify_api_[a-zA-Z-0-9]{36} | Y |
| Apify | Apify Webhook Dispatch API Token | apify_webhook_dispatch_api_token | apify_api_[a-zA-Z-0-9]{36} | Y |
| Asaas | Asaas API Token | asaas_api_token | keyword-gated | Y |
| Asana | Asana Legacy Format Personal Access Token | asana_legacy_format_personal_access_token | keyword-gated | Y |
| Asana | Asana Personal Access Token | asana_personal_access_token, | asana keyword + digits/digits/digits:chars | Y |
| Atlassian | Atlassian API Token | atlassian_api_token, | ATATT3[A-Za-z0-9_\-=]{186} | Y |
| Atlassian | Atlassian JSON Web Token | atlassian_jwt | ATATT3[A-Za-z0-9_=-]{100,} | Y |
| Authress | Authress Service Client Access Key | authress_service_client_access_key | (?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120} | Y |
| Azure | Azure Active Directory Application Secret | azure_active_directory_application_secret, | [a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34} with Q~ marker, keyword-gated | Y |
| Azure | Azure AI Services Key | azure_ai_services_key | [a-zA-Z0-9]{32} | Y |
| Azure | Azure Anomaly Detector EE Key | azure_anomaly_detector_ee_key | keyword-gated | Y |
| Azure | Azure Anomaly Detector Key | azure_anomaly_detector_key | keyword-gated | Y |
| Azure | Azure Apim Direct Management Key | azure_apim_direct_management_key | keyword-gated | Y |
| Azure | Azure Apim Gateway Key | azure_apim_gateway_key | keyword-gated | Y |
| Azure | Azure Apim Repository Key | azure_apim_repository_key | keyword-gated | Y |
| Azure | Azure Apim Subscription Key | azure_apim_subscription_key | keyword-gated | Y |
| Azure | Azure App Configuration Connection String | azure_app_configuration_connection_string | keyword-gated | Y |
| Azure | Azure App Configuration Key | azure_app_configuration_key | keyword-gated | Y |
| Azure | Azure Batch Key Identifiable | azure_batch_key_identifiable, | keyword-gated | Y |
| Azure | Azure Cache for Redis Access Key | azure_cache_for_redis_access_key, | base64 encoded key | Y |
| Azure | Azure Cognitive Services Key | azure_cognitive_services_key | [a-f0-9]{32} | Y |
| Azure | Azure Communication Services Connection String | azure_communication_services_connection_string | keyword-gated | Y |
| Azure | Azure Communication Services Key | azure_communication_services_key | keyword-gated | Y |
| Azure | Azure Computer Vision Key | azure_computer_vision_key | [a-f0-9]{32} | Y |
| Azure | Azure Registry Key Identifiable | azure_container_registry_key_identifiable | keyword-gated | Y |
| Azure | Azure Content Moderator Key | azure_content_moderator_key | keyword-gated | Y |
| Azure | Azure Content Safety Key | azure_content_safety_key | keyword-gated | Y |
| Azure | Azure Cosmosdb Key Identifiable | azure_cosmosdb_key_identifiable, | keyword-gated | Y |
| Azure | Azure Custom Vision Prediction Key | azure_custom_vision_prediction_key | keyword-gated | Y |
| Azure | Azure Custom Vision Training Key | azure_custom_vision_training_key | keyword-gated | Y |
| Azure | Azure DevOps Personal Access Token | azure_devops_personal_access_token, | 84 chars (a-zA-Z0-9) with AZDO signature at positions 76-80 | Y |
| Azure | Azure Event Grid Key Identifiable | azure_event_grid_key_identifiable, | keyword-gated | Y |
| Azure | Azure Event Hub Key Identifiable | azure_event_hub_key_identifiable | Endpoint=sb://<NamespaceName>.servicebus.windows.net/;SharedAccessKeyName=<KeyName>;SharedAccessKey=<KeyValue>;EntityPath=<EventHubName> | Y |
| Azure | Azure Face Key | azure_face_key | keyword-gated | Y |
| Azure | Azure Fluid Relay Key | azure_fluid_relay_key | keyword-gated | Y |
| Azure | Azure Form Recognizer Key | azure_form_recognizer_key | keyword-gated | Y |
| Azure | Azure Function Key | azure_function_key, | 54 chars (a-z, 0-9, /, +) ending with == | Y |
| Azure | Azure Health Decision Support Key | azure_health_decision_support_key | keyword-gated | Y |
| Azure | Azure Health Insights Key | azure_health_insights_key | keyword-gated | Y |
| Azure | Azure Immersive Reader Key | azure_immersive_reader_key | keyword-gated | Y |
| Azure | Azure Internal All In One Key | azure_internal_all_in_one_key | keyword-gated | Y |
| Azure | Azure IoT Device Connection String | azure_iot_device_connection_string | keyword-gated connection string | Y |
| Azure | Azure IoT Device Key | azure_iot_device_key | keyword-gated | Y |
| Azure | Azure IoT Device Provisioning Key | azure_iot_device_provisioning_key | keyword-gated | Y |
| Azure | Azure IoT Hub Connection String | azure_iot_hub_connection_string | keyword-gated connection string | Y |
| Azure | Azure IoT Hub Key | azure_iot_hub_key | keyword-gated | Y |
| Azure | Azure IoT Provisioning Connection String | azure_iot_provisioning_connection_string | keyword-gated connection string | Y |
| Azure | Azure Knowledge Key | azure_knowledge_key | keyword-gated | Y |
| Azure | Azure Logic Apps URL | azure_logic_apps_url, | keyword-gated URL | Y |
| Azure | Azure Luis Authoring Key | azure_luis_authoring_key | keyword-gated | Y |
| Azure | Azure Luis Key | azure_luis_key | keyword-gated | Y |
| Azure | Microsoft Azure Service Management Certificate | azure_management_certificate | certificate-based | Y |
| Azure | Azure Maps Key | azure_maps_key | keyword-gated | Y |
| Azure | Azure Metrics Advisor Key | azure_metrics_advisor_key | keyword-gated | Y |
| Azure | Azure Mixed Reality Key | azure_mixed_reality_key | keyword-gated | Y |
| Azure | Azure ML Inference Key | azure_ml_inference_identifiable_key | keyword-gated | Y |
| Azure | Azure ML Internal Service Principal Key | azure_ml_internal_service_principal_identifiable_key | keyword-gated | Y |
| Azure | Azure ML Studio (classic) Web Service Key | azure_ml_web_service_classic_identifiable_key | keyword-gated | Y |
| Azure | Azure OpenAI Key | azure_openai_key, | keyword-gated | Y |
| Azure | Azure Personalizer Key | azure_personalizer_key | keyword-gated | Y |
| Azure | Azure QnA Maker Key | azure_qna_maker_key | keyword-gated | Y |
| Azure | Azure QnA Maker V2 Key | azure_qna_maker_v2_key | keyword-gated | Y |
| Azure | Azure Quantum Key | azure_quantum_key | keyword-gated | Y |
| Azure | Azure Relay Key Identifiable | azure_relay_key_identifiable | keyword-gated | Y |
| Azure | Azure SAS Token | azure_sas_token | keyword-gated SAS token | Y |
| Azure | Azure Search Admin Key | azure_search_admin_key | keyword-gated | Y |
| Azure | Azure Search Query Key | azure_search_query_key | keyword-gated | Y |
| Azure | Azure Service Bus Key Identifiable | azure_service_bus_identifiable | keyword-gated | Y |
| Azure | Azure SignalR Connection String | azure_signalr_connection_string | keyword-gated connection string | Y |
| Azure | Azure SignalR Key | azure_signalr_key, | keyword-gated | Y |
| Azure | Azure Speech Services Key | azure_speech_services_key | keyword-gated | Y |
| Azure | Azure Speech Translation Key | azure_speech_translation_key | keyword-gated | Y |
| Azure | Azure SQL Internal Default CloudSA Key | azure_sql_internal_default_cloudsa_key | keyword-gated | Y |
| Azure | Azure SQL password | azure_sql_password | keyword-gated | Y |
| Azure | Azure Storage Account Access Key | azure_storage_account_key, | [A-Za-z0-9+/=]{86} | Y |
| Azure | Azure Text Analytics Key | azure_text_analytics_key | keyword-gated | Y |
| Azure | Azure Text Translation Key | azure_text_translation_key | keyword-gated | Y |
| Azure | Azure Video Intelligence Key | azure_video_intelligence_key | keyword-gated | Y |
| Azure | Microsoft Azure Web App Bot Key | azure_web_app_bot_key | keyword-gated | Y |
| Azure | Azure Web Pub Sub Connection String | azure_web_pub_sub_connection_string | keyword-gated connection string | Y |
| Azure | Azure Web Pub Sub Key | azure_web_pub_sub_key, | keyword-gated | Y |
| Azure | Microsoft Azure Entra ID Token | microsoft_azure_entra_id_token | keyword-gated | Y |
| Baidu | Baidu AI API Key | baiduai_api_key | bce-v3/ALTAK- | Y |
| Baidu | Baidu Cloud API Access Key | baiducloud_api_accesskey | bce-v3/ALTAK- | Y |
| Beamer | Beamer API Key | beamer_api_key | b_[a-z0-9=_\-]{44} | Y |
| Bitbucket | Bitbucket Server Personal Access Token | bitbucket_server_personal_access_token | keyword-gated | Y |
| Bitrise | Bitrise Personal Access Token | bitrise_personal_access_token | bitrise_ prefix | Y |
| Bitrise | Bitrise Workspace API Token | bitrise_workspace_api_token | bitrise_ prefix | Y |
| Block Protocol | Block Protocol API Key | block_protocol_api_key | keyword-gated | Y |
| Brevo | Sendinblue API Key | sendinblue_api_key, | xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16} | Y |
| Brevo | Sendinblue SMTP Key | sendinblue_smtp_key | xkeysib-[a-f0-9]{64}\-[a-z0-9]{16} | Y |
| Buildkite | Buildkite Agent Access Token | buildkite_agent_access_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Agent Job Token | buildkite_agent_job_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Agent Registration Token | buildkite_agent_registration_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Cluster Queue Token | buildkite_cluster_queue_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Cluster Token | buildkite_cluster_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Packages Registry Token | buildkite_packages_registry_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Packages Temporary Token | buildkite_packages_temporary_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Portal Secret | buildkite_portal_secret | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite Portal Token | buildkite_portal_token | bk[a-zA-Z0-9]{16,40} | Y |
| Buildkite | Buildkite User Access Token | buildkite_user_access_token | bk[a-zA-Z0-9]{16,40} | Y |
| Canadian Digital Service | Canadian Digital Service Notify API Key | cds_canada_notify_api_key | ApiKey-v1 gcntfy prefix | Y |
| Canva | Canva App Secret | canva_app_secret | cnvca prefix | Y |
| Canva | Canva Connect API Secret | canva_connect_api_secret | cnvca prefix | Y |
| Canva | Canva Secret | canva_secret | cnvca prefix | Y |
| Cashfree | Cashfree API Key | cashfree_api_key | keyword-gated | Y |
| Cfx.re | Cfx.re Server Key | cfxre_server_key | keyword-gated | Y |
| Checkout.com | Checkout.com Production Secret Key | checkout_production_secret_key, | sk_live_ prefix | Y |
| Checkout.com | Checkout.com Test Secret Key | checkout_test_secret_key, | sk_test_ prefix | Y |
| Chief Tools | Chief Tools Token | chief_tools_token | keyword-gated | Y |
| CircleCI | CircleCI Bot API Token | circleci_bot_access_token | CCIPAT_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40} | Y |
| CircleCI | CircleCI Personal Access Token | circleci_personal_access_token | CCIPAT_ or CCIPRJ_ prefix | Y |
| CircleCI | CircleCI Project Access Token | circleci_project_access_token | CCIPRJ_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40} | Y |
| CircleCI | CircleCI Release API Token | circleci_release_integration_token | CCIPRJ_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40} | Y |
| Clojars | Clojars Deploy Token | clojars_deploy_token | CLOJARS_[a-z0-9]{60} | Y |
| Cloudflare | Cloudflare Access Service Token | cloudflare_access_service_token | cfk_, cfut_, cfat_ | Y |
| Cloudflare | Cloudflare Account API Token | cloudflare_account_api_token | cfk_, cfut_, cfat_ | Y |
| Cloudflare | Cloudflare Global User API Key | cloudflare_global_user_api_key | cfk_, cfut_, cfat_ | Y |
| Cloudflare | Cloudflare User API Token | cloudflare_user_api_token | cfk_, cfut_, cfat_ | Y |
| Cloudsmith | Cloudsmith API Key | cloudsmith_api_key | cs_[a-zA-Z0-9]{32,48} | Y |
| Cockroach Labs | CockroachDB Cloud API Key | ccdb_api_key | ccdb_ prefix | Y |
| Cohere | Cohere API Key | cohere_api_key | keyword-gated | Y |
| Contentful | Contentful Personal Access Token | contentful_personal_access_token | CFPAT- prefix | Y |
| Contentful | Contentful Web Token | contentful_web_token | keyword-gated | Y |
| Contributed Systems | Contributed Systems Credentials | contributed_systems_credentials | keyword-gated | Y |
| Coveo | Coveo Access Token | coveo_access_token | keyword-gated | Y |
| Coveo | Coveo API Key | coveo_api_key | keyword-gated | Y |
| Databento | Databento API Key | databento_api_key | db- prefix | Y |
| Databricks | Databricks API Token | databricks_access_token, | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Account Session Token | databricks_account_session_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Federated Account Session Token | databricks_federated_account_session_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks OAuth Code | databricks_oauth_code | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks OAuth Refresh Token | databricks_oauth_refresh_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks OAuth Secret Token | databricks_oauth_secret_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks OAuth Single Use Refresh Token Child | databricks_oauth_single_use_refresh_token_child | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks OAuth Single Use Refresh Token Parent | databricks_oauth_single_use_refresh_token_parent | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Scoped API Token | databricks_scoped_api_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Scoped Internal Token | databricks_scoped_internal_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Token | databricks_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Databricks | Databricks Workspace Session Token | databricks_workspace_session_token | dapi[0-9a-f]{32}(?:-\d)? | Y |
| Datadog | Datadog API Key | datadog_api_key | keyword-gated | Y |
| Datadog | Datadog Application Key | datadog_app_key, | datadog keyword + 40 hex | Y |
| Datadog | Datadog Personal Access Token | datadog_pat | keyword-gated | Y |
| Datadog | Datadog RCM | datadog_rcm | keyword-gated | Y |
| Datadog | Datadog Service Account Token | datadog_sat | keyword-gated | Y |
| Datastax | Datastax AstraCS Tokens | datastax_astracs_token | keyword-gated | Y |
| DeepSeek | DeepSeek API Key | deepseek_api_key | keyword-gated | Y |
| Defined Networking | Defined Networking Managed Nebula API Key | defined_networking_nebula_api_key | dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52} | Y |
| DevCycle | DevCycle Client API Key | devcycle_client_api_key | keyword-gated | Y |
| DevCycle | DevCycle Mobile API Key | devcycle_mobile_api_key | keyword-gated | Y |
| DevCycle | DevCycle Server API Key | devcycle_server_api_key | keyword-gated | Y |
| DigitalOcean | DigitalOcean OAuth Token | digitalocean_oauth_token | doo_v1_ | Y |
| DigitalOcean | DigitalOcean Personal Access Token | digitalocean_personal_access_token | dop_v1_[0-9a-f]{64} | Y |
| DigitalOcean | DigitalOcean Refresh Token | digitalocean_refresh_token | dor_v1_[a-f0-9]{64} | Y |
| DigitalOcean | DigitalOcean System Token | digitalocean_system_token | dop_v1_ | Y |
| Discord | Discord Bot Token | discord_bot_token, | [MNO][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38} | Y |
| Docker | Docker Organization Access Token | docker_organization_access_token | dckr_pat_[A-Za-z0-9_-]{27} | Y |
| Docker | Docker Personal Access Token | docker_personal_access_token | dckr_pat_[A-Za-z0-9_-]{27} | Y |
| Docker | Docker Swarm Join Token | docker_swarm_join_token | keyword-gated | Y |
| Docker | Docker Swarm Unlock Key | docker_swarm_unlock_key | keyword-gated | Y |
| Doppler | Doppler Audit Token | doppler_audit_token | dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44} | Y |
| Doppler | Doppler CLI Token | doppler_cli_token | dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44} | Y |
| Doppler | Doppler Personal Token | doppler_personal_token | dp.pt.[A-Za-z0-9]{40,44} | Y |
| Doppler | Doppler SCIM Token | doppler_scim_token | dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44} | Y |
| Doppler | Doppler Service Account Token | doppler_service_account_token | dp.sa.[A-Za-z0-9]{40,44} | Y |
| Doppler | Doppler Service Token | doppler_service_token | dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44} | Y |
| Dropbox | Dropbox Access Token | dropbox_access_token | sl\.[A-Za-z0-9\-_]{130,} | Y |
| Dropbox | Dropbox Short-Lived Access Token | dropbox_short_lived_access_token | sl\.[a-z0-9\-=_]{130,} | Y |
| Duffel | Duffel Live Access Token | duffel_live_access_token | duffel_live_[a-zA-Z0-9_-]{43} | Y |
| Duffel | Duffel Test Access Token | duffel_test_access_token | duffel_test_[a-zA-Z0-9_-]{43} | Y |
| Dynatrace | Dynatrace API Token | dynatrace_api_token | dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64} | Y |
| Dynatrace | Dynatrace Internal Token | dynatrace_internal_token | dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64} | Y |
| EasyPost | EasyPost Production API Key | easypost_production_api_key | EZAK + 54 alphanumeric | Y |
| EasyPost | EasyPost Test API Key | easypost_test_api_key | EZ[AT]K[A-Za-z0-9]{54} | Y |
| Elastic | Elastic Cloud API Key | elastic_cloud_api_key | essu_ prefix | Y |
| Elastic | Elastic Stack API Key | elastic_stack_api_key, | essu_ prefix | Y |
| Facebook | Facebook Access Token | facebook_access_token | \d{15,16}(\||%)[0-9a-z\-_]{27,40} | Y |
| Fastly | Fastly API Token | fastly_api_token, | [a-z0-9=_\-]{32} | Y |
| Fieldguide | Fieldguide API Token | fieldguide_api_token | keyword-gated | Y |
| Figma | Figma Personal Access Token | figma_pat | keyword-gated | Y |
| Figma | Figma SCIM API Token | figma_scim_token | fig-oauth-, figt_ | Y |
| Finicity | Finicity App Key | finicity_app_key | finicity keyword + 20 alphanumeric or 32 hex | Y |
| Firebase | Firebase Cloud Messaging Server Key | firebase_cloud_messaging_server_key | keyword-gated | Y |
| Flickr | Flickr API Key | flickr_api_key | flickr keyword + 32 alphanumeric | Y |
| Flutterwave | Flutterwave Live API Secret Key | flutterwave_live_api_secret_key | FLWSECK_TEST-[a-h0-9]{32}-X | Y |
| Flutterwave | Flutterwave Test API Secret Key | flutterwave_test_api_secret_key | FLWSECK_TEST-[a-h0-9]{32}-X | Y |
| Frame.io | Frame.io Developer Token | frameio_developer_token | fio-u-[a-zA-Z0-9\-_=]{64} | Y |
| Frame.io | Frame.io JSON Web Token | frameio_jwt | keyword-gated | Y |
| FullStory | FullStory API Key | fullstory_api_key, | <data center>.<token> (3-char data center prefix) | Y |
| GitHub | GitHub App Installation Access Token | github_app_installation_access_token, | gh[pousr]_[A-Za-z0-9_]{36,255} | Y |
| GitHub | GitHub OAuth Access Token | github_oauth_access_token, | gh[pousr]_[A-Za-z0-9_]{36,255} | Y |
| GitHub | GitHub Personal Access Token | github_personal_access_token, | gh[pousr]_[A-Za-z0-9_]{36,255} | Y |
| GitHub | GitHub Refresh Token | github_refresh_token, | gh[pousr]_[A-Za-z0-9_]{36,255} | Y |
| GitHub | GitHub SSH Private Key | github_ssh_private_key | -----BEGIN ... PRIVATE KEY----- markers | Y |
| GitHub | GitHub Test Token | github_test_token | gh[pousr]_[A-Za-z0-9_]{36,255} | Y |
| GitLab | GitLab Access Token | gitlab_access_token, | glpat-[0-9A-Za-z_-]{20} | Y |
| GitLab | GitLab CI/CD Job Token | gitlab_ci_build_token | keyword-gated | Y |
| GitLab | GitLab Deploy Token | gitlab_deploy_token | keyword-gated | Y |
| GitLab | GitLab Feature Flag Client Token | gitlab_feature_flag_client_token | keyword-gated | Y |
| GitLab | GitLab Feed Token | gitlab_feed_token_v2 | keyword-gated | Y |
| GitLab | GitLab Incoming Mail Token | gitlab_incoming_email_token | keyword-gated | Y |
| GitLab | GitLab Agent for Kubernetes Token | gitlab_kubernetes_agent_token | keyword-gated | Y |
| GitLab | GitLab OAuth Application Secret | gitlab_oauth_app_secret | keyword-gated | Y |
| GitLab | GitLab Pipeline Trigger Token | gitlab_pipeline_trigger_token | keyword-gated | Y |
| GitLab | GitLab Runner Authentication Token | gitlab_runner_auth_token | keyword-gated | Y |
| GitLab | GitLab Runner Registration Token | gitlab_runner_registration_token | keyword-gated | Y |
| GitLab | GitLab SCIM Token | gitlab_scim_oauth_token | keyword-gated | Y |
| GoCardless | GoCardless Live Access Token | gocardless_live_access_token | keyword-gated | Y |
| GoCardless | GoCardless Sandbox Access Token | gocardless_sandbox_access_token | keyword-gated | Y |
| Google | Google API Key | google_api_key | AIza[0-9A-Za-z_-]{35} | Y |
| Google | Google Cloud Service Account Credentials | google_cloud_service_account_credentials | AIza[0-9A-Za-z_-]{35} | Y |
| Google | Google Cloud Storage Service Account Access Key ID | google_cloud_storage_access_key_secret, google_cloud_storage_service_account_access_key_id | AIza[0-9A-Za-z\-_]{35} | Y |
| Google | Google Cloud Storage User Access Key ID | google_cloud_storage_access_key_secret, google_cloud_storage_user_access_key_id | AIza[0-9A-Za-z\-_]{35} | Y |
| Google | GCP API Key Bound to a Service Account | google_gcp_api_key_bound_service_account | AIza[0-9A-Za-z_-]{35} | Y |
| Google | Google Gemini API Key | google_gemini_api_key | AIza[0-9A-Za-z_-]{35} | Y |
| Google | Google OAuth Access Token | google_oauth_access_token | AIza[0-9A-Za-z_-]{35} | Y |
| Google | Google OAuth Client ID | google_oauth_client_id, google_oauth_client_secret, | [0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com | Y |
| Google | Google OAuth Refresh Token | google_oauth_refresh_token, | 1//[0-9A-Za-z_-]{43,128} | Y |
| Grafana | Grafana Cloud API Key | grafana_cloud_api_key | glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8} | Y |
| Grafana | Grafana Cloud API Token | grafana_cloud_api_token | glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8} | Y |
| Grafana | Grafana Project API Key | grafana_project_api_key | glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8} | Y |
| Grafana | Grafana Project Service Account Token | grafana_project_service_account_token | glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8} | Y |
| Groq | Groq API Key | groq_api_key, | gsk_[A-Za-z0-9]{52} | Y |
| GuardSquare | GuardSquare AppSweep API Key | guardsquare_appsweep_api_key | keyword-gated | Y |
| GuardSquare | GuardSquare CLI Access Token | guardsquare_cli_access_token | keyword-gated | Y |
| GuardSquare | GuardSquare Maven Token | guardsquare_maven_token | keyword-gated | Y |
| Hack Club | Hack Club AI Key | hackclub_ai_api_key | keyword-gated | Y |
| HashiCorp | HashiCorp Vault Batch Token | hashicorp_vault_batch_token, | hvb\.[A-Za-z0-9_-]{60,} | Y |
| HashiCorp | HashiCorp Vault Root Service Token | hashicorp_vault_root_service_token | hvs\.[A-Za-z0-9_-]{60,} | Y |
| HashiCorp | HashiCorp Vault Service Token | hashicorp_vault_service_token, | hvs\.[A-Za-z0-9_-]{60,} | Y |
| HashiCorp | Terraform Cloud / Enterprise API Token | terraform_api_token | [A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70} | Y |
| Heroku | Heroku Platform API OAuth2 Token | heroku_platform_api_oauth2_token | HRKU-AA[A-Za-z0-9_-]{58} | Y |
| Heroku | Heroku Postgres Connection URL | heroku_postgres_connection_url | postgres://[^:]+:[^@]+@[^/]+/[^?]+ | Y |
| Hex | Hex API key | hexpm_api_key | hex_ + 40 hex characters | Y |
| Highnote | Highnote RK Live Key | highnote_rk_live_key | rk_live_ prefix | Y |
| Highnote | Highnote RK Test Key | highnote_rk_test_key | rk_test_ prefix | Y |
| Highnote | Highnote SK Live Key | highnote_sk_live_key | sk_live_ prefix | Y |
| Highnote | Highnote SK Test Key | highnote_sk_test_key | sk_test_ prefix | Y |
| HOP | HOP Bearer | hop_bearer | keyword-gated | Y |
| HOP | HOP PAT | hop_pat | keyword-gated | Y |
| HOP | HOP PTK | hop_ptk | keyword-gated | Y |
| Hubspot | Hubspot API Key | hubspot_api_key, | keyword-gated | Y |
| Hubspot | Hubspot Personal Access Key | hubspot_personal_access_key | keyword-gated | Y |
| Hubspot | Hubspot Private Apps User Token | hubspot_private_apps_user_token | keyword-gated | Y |
| Hubspot | Hubspot SMTP Credential | hubspot_smtp_credential, | keyword-gated | Y |
| Hugging Face | Hugging Face Organization API Token | hf_org_api_key | hf_[A-Za-z]{34} | Y |
| Hugging Face | Hugging Face User Access Token | hf_user_access_token, | hf_[A-Za-z]{34} | Y |
| IBM | IBM Cloud IAM Key | ibm_cloud_iam_key | keyword-gated | Y |
| Intercom | Intercom Access Token | intercom_access_token | keyword-gated | Y |
| Ionic | Ionic Personal Access Token | ionic_personal_access_token, | keyword-gated | Y |
| Ionic | Ionic Refresh Token | ionic_refresh_token, | keyword-gated | Y |
| Iterative | DVC Studio Access Token | iterative_dvc_studio_access_token | keyword-gated | Y |
| JFrog | JFrog Platform Access Token | jfrog_platform_access_token | jfrog/artifactory/bintray/xray keyword + 73 alphanumeric | Y |
| JFrog | JFrog Platform API Key | jfrog_platform_api_key | AKCp[A-Za-z0-9]{69} | Y |
| JFrog | JFrog Platform Reference Token | jfrog_platform_reference_token, | jfrog/artifactory/bintray/xray keyword + 64 alphanumeric | Y |
| Langchain | LangSmith Personal Access Token | langchain_api_personal_key | keyword-gated | Y |
| Langchain | LangSmith Service Key | langchain_api_server_key | keyword-gated | Y |
| Langchain | LangSmith License Key | langsmith_license_key | lsv2_pt_, lsv2_sk_ | Y |
| Langchain | LangSmith SCIM Bearer Token | langsmith_scim_bearer_token | lsv2_pt_, lsv2_sk_ | Y |
| Lark | Lark APaaS Client Secret | lark_apaas_client_secret | lark_ prefix | Y |
| Lark | Lark Application Secret | lark_app_secret | lark_ prefix | Y |
| Lark | Lark MCP Grant Token | lark_mcp_grant_token | lark_ prefix | Y |
| Lark | Lark Meego Plugin Secret | lark_meego_plugin_secret | lark_ prefix | Y |
| Lark | Lark User Session | lark_user_session | lark_ prefix | Y |
| LaunchDarkly | LaunchDarkly API Token | launchdarkly_access_token | keyword-gated | Y |
| Lichess | Lichess OAuth Access Token | lichess_oauth_access_token | keyword-gated | Y |
| Lichess | Lichess Personal Access Token | lichess_personal_access_token | keyword-gated | Y |
| Lightspeed | Lightspeed Personal Access Token | lightspeed_xs_pat | keyword-gated | Y |
| Limbar | Limbar Token | limbar_token | keyword-gated | Y |
| Linear | Linear API Key | linear_api_key | lin_api_[A-Za-z0-9]{40} | Y |
| Linear | Linear OAuth Access Token | linear_oauth_access_token | lin_api_[0-9A-Za-z]{40} | Y |
| LinkedIn | LinkedIn Client Secret | linkedin_client_secret | keyword-gated | Y |
| Lob | Lob Live API Key | lob_live_api_key | live_[a-f0-9]{35} | Y |
| Lob | Lob Test API Key | lob_test_api_key | test_[a-f0-9]{35} | Y |
| Localstack | Localstack API Key | localstack_api_key | keyword-gated | Y |
| LogicMonitor | LogicMonitor Bearer Token | logicmonitor_bearer_token | keyword-gated | Y |
| LogicMonitor | LogicMonitor LMv1 Access Key | logicmonitor_lmv1_access_key | keyword-gated | Y |
| Login with Amazon | Login with Amazon OAuth Client ID | amazon_oauth_client_id, amazon_oauth_client_secret | keyword-gated | Y |
| Lovable Labs | Lovable API Key | lovable_api_key | lov_ prefix | Y |
| Mailchimp | Mailchimp API Key | mailchimp_api_key | [0-9a-f]{32}-us[0-9]+ | Y |
| Mailchimp | Mandrill API Key | mandrill_api_key | [0-9a-f]{32}-us[0-9]+ | Y |
| Mailersend | Mailersend API Token | mailersend_api_token | mlsn\. prefix | Y |
| Mailersend | Mailersend SMTP Password | mailersend_smtp_password | mlsn\. prefix | Y |
| Mailersend | Mailersend SMTP Username | mailersend_smtp_username | mlsn\. prefix | Y |
| Mailgun | Mailgun API Key | mailgun_api_key, | key-[0-9a-zA-Z]{32} | Y |
| Mailgun | Mailgun SMTP Credential | mailgun_smtp_credential | key-[0-9a-zA-Z]{32} | Y |
| Mapbox | Mapbox Secret Access Token | mapbox_secret_access_token | sk. prefix | Y |
| MaxMind | MaxMind License Key | maxmind_license_key | keyword-gated | Y |
| Meraki | Meraki Dashboard API Key | meraki_api_key | [0-9a-f]{40} | Y |
| Mercury | Mercury Non-Production API Token | mercury_non_production_api_token | secret-token:mercury_ prefix | Y |
| Mercury | Mercury Production API Token | mercury_production_api_token | secret-token:mercury_production_ prefix | Y |
| Mergify | Mergify Application Key | mergify_application_key | keyword-gated | Y |
| MessageBird | MessageBird API Key | messagebird_api_key | keyword-gated | Y |
| Microsoft | Power Automate Webhook SAS | power_automate_webhook_sas | keyword-gated | Y |
| Midtrans | Midtrans Production Server Key | midtrans_production_server_key | Mid-server- prefix | Y |
| Midtrans | Midtrans Sandbox Server Key | midtrans_sandbox_server_key | SB-Mid-server- prefix | Y |
| Mistral AI | Mistral AI API Key | mistral_ai_api_key | keyword-gated | Y |
| MongoDB | MongoDB Atlas Database URI with credentials | mongodb_atlas_db_uri_with_credentials | mongodb://[^:]+:[^@]+@ | Y |
| MongoDB | MongoDB Atlas Service Account Secret | mongodb_atlas_service_account_secret | keyword-gated | Y |
| Naver Cloud | Naver Cloud Gov Access Key ID | navercloud_gov_access_key | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Gov Secret Key | navercloud_gov_access_key_secret | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Gov Secure Token Service | navercloud_gov_sts | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Gov Secure Token Service Secret | navercloud_gov_sts_secret | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Access Key ID | navercloud_pub_access_key | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Secret Key | navercloud_pub_access_key_secret | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Secure Token Service | navercloud_pub_sts | navercloud_ prefix | Y |
| Naver Cloud | Naver Cloud Secure Token Service Secret | navercloud_pub_sts_secret | navercloud_ prefix | Y |
| Neon | Neon API Key | neon_api_key | keyword-gated | Y |
| Neon | Neon Connection URI | neon_connection_uri | postgresql://[^:]+:[^@]+@[^/]+\.neon\.tech/[^?]+ | Y |
| Netflix | Netflix NetKey | netflix_netkey | keyword-gated | Y |
| New Relic | New Relic Insights Query Key | new_relic_insights_query_key | NRAK- prefix | Y |
| New Relic | New Relic License Key | new_relic_license_key | NRAK- prefix | Y |
| New Relic | New Relic Personal API Key | new_relic_personal_api_key | NRAK- prefix | Y |
| New Relic | New Relic REST API Key | new_relic_rest_api_key | NRAK- prefix | Y |
| Notion | Notion API Token | notion_api_token | ntn_[0-9]{11}[A-Za-z0-9]{35} | Y |
| Notion | Notion Integration Token | notion_integration_token | ntn_[0-9]{11}[A-Za-z0-9]{35} | Y |
| Notion | Notion OAuth Client Secret | notion_oauth_client_secret | ntn_[A-Za-z0-9]{40,60} | Y |
| NuGet | NuGet API Key | nuget_api_key, | oy2[a-z0-9]{43} | Y |
| Octopus Deploy | Octopus Deploy API Key | octopus_deploy_api_key | API-[A-Z0-9]{25} | Y |
| Oculus | Oculus Access Token | oculus_access_token | keyword-gated | Y |
| OneChronos | OneChronos API Token | onechronos_api_key | keyword-gated | Y |
| OneChronos | OneChronos Expressive Bidding API Key | onechronos_eb_api_key | keyword-gated | Y |
| OneChronos | OneChronos Expressive Bidding Encryption Key | onechronos_eb_encryption_key | keyword-gated | Y |
| OneChronos | OneChronos OAuth Token | onechronos_oauth_token | keyword-gated | Y |
| OneChronos | OneChronos Refresh Token | onechronos_refresh_token | keyword-gated | Y |
| OneSignal | OneSignal Rich API Key | onesignal_rich_authentication_token | keyword-gated | Y |
| Onfido | Onfido Live API Token | onfido_live_api_token | keyword-gated | Y |
| Onfido | Onfido Sandbox API Token | onfido_sandbox_api_token | keyword-gated | Y |
| OpenAI | OpenAI API Key | openai_api_key, | sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74} | Y |
| OpenRouter | OpenRouter API Key | openrouter_api_key | sk-or-v1-[a-f0-9]{64} | Y |
| OpenVSX | OpenVSX Access Token | openvsx_access_token, | keyword-gated | Y |
| Openweather | Openweather API Key | openweather_api_key | keyword-gated | Y |
| Oracle | Oracle API Key | oracle_api_key | keyword-gated | Y |
| Orbit | Orbit API Token | orbit_api_token | keyword-gated | Y |
| Paddle | Paddle API Key | paddle_api_key | keyword-gated | Y |
| Paddle | Paddle Sandbox API Key | paddle_sandbox_api_key | keyword-gated | Y |
| PagerDuty | PagerDuty OAuth Secret | pagerduty_oauth_secret | keyword-gated | Y |
| PagerDuty | PagerDuty OAuth Token | pagerduty_oauth_token | keyword-gated | Y |
| Palantir | Palantir JSON Web Token | palantir_jwt | keyword-gated | Y |
| Pangea | Pangea Token | pangea_token | keyword-gated | Y |
| Perplexity | Perplexity API Key | perplexity_api_key | pplx-[A-Za-z0-9]{48} | Y |
| Persona  Identities | Persona Production Api Key | persona_production_api_key | keyword-gated | Y |
| Persona  Identities | Persona Sandbox Api Key | persona_sandbox_api_key | keyword-gated | Y |
| Pineapple Technologies Limited | Pineapple Technologies Incident API Key | pineapple_technologies_incident_api_key | keyword-gated | Y |
| Pinecone | Pinecone API Key | pinecone_api_key | pcsk_ (head literal) | Y |
| Pinterest | Pinterest Access Token | pinterest_access_token | keyword-gated | Y |
| Pinterest | Pinterest Refresh Token | pinterest_refresh_token | keyword-gated | Y |
| PlanetScale | PlanetScale Database Password | planetscale_database_password | pscale_pw_[a-zA-Z0-9_-]{43} | Y |
| PlanetScale | PlanetScale OAuth Token | planetscale_oauth_token | pscale_otkn_[a-zA-Z0-9_-]{43} | Y |
| PlanetScale | PlanetScale Service Token | planetscale_service_token | pscale_tkn_[a-zA-Z0-9_-]{43} | Y |
| Planning Center | Planning Center OAuth Access Token | planning_center_oauth_access_token | keyword-gated | Y |
| Planning Center | Planning Center OAuth Application Secret | planning_center_oauth_app_secret | keyword-gated | Y |
| Planning Center | Planning Center Personal Access Token | planning_center_personal_access_token | keyword-gated | Y |
| Plivo | Plivo Auth ID | plivo_auth_id, plivo_auth_token | keyword-gated | Y |
| Polar | Polar Access Token | polar_access_token, | polar_ prefix | Y |
| Polar | Polar Authorization Code | polar_authorization_code, | polar_ prefix | Y |
| Polar | Polar Client Registration Token | polar_client_registration_token, | polar_ prefix | Y |
| Polar | Polar Client Secret | polar_client_secret, | polar_ prefix | Y |
| Polar | Polar Customer Session Token | polar_customer_session_token | polar_ prefix | Y |
| Polar | Polar Personal Access Token | polar_personal_access_token, | polar_ prefix | Y |
| Polar | Polar Refresh Token | polar_refresh_token, | polar_ prefix | Y |
| Polar | Polar User Session Token | polar_user_session_token | polar_ prefix | Y |
| PostHog | PostHog Project Secret API Key | posthog_feature_flags_secure_api_key | phx_ | Y |
| PostHog | PostHog OAuth Access Token | posthog_oauth_access_token | phx_ | Y |
| PostHog | PostHog OAuth Refresh Token | posthog_oauth_refresh_token | phx_ | Y |
| PostHog | PostHog Personal API Key | posthog_personal_api_key | phx_ | Y |
| Postman | Postman API Key | postman_api_key | PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34} | Y |
| Postman | Postman Collection Key | postman_collection_key | PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34} | Y |
| Prefect | Prefect Server API Key | prefect_server_api_key | pnu_[A-Za-z0-9]{36} | Y |
| Prefect | Prefect User API Key | prefect_user_api_key | pnu_[A-Za-z0-9]{36} | Y |
| Proctorio | Proctorio Consumer Key | proctorio_consumer_key | [0-9a-f]{32} | Y |
| Proctorio | Proctorio Linkage Key | proctorio_linkage_key | [0-9a-f]{64} | Y |
| Proctorio | Proctorio Registration Key | proctorio_registration_key | [0-9a-f]{64} | Y |
| Proctorio | Proctorio Secret Key | proctorio_secret_key, | [0-9a-f]{32} | Y |
| Proof | Proof Full Access API Key | proof_full_access_api_key | prf_|prf_test_|prf_cli_|prf_cli_test_ | Y |
| Pulumi | Pulumi Access Token | pulumi_access_token | pul- prefix | Y |
| Pydantic Services Inc. | Logfire Token | logfire_token | keyword-gated | Y |
| Pydantic Services Inc. | Pydantic AI Gateway API Key | pydantic_ai_gateway_api_key | keyword-gated | Y |
| PyPI | PyPI API Token | pypi_api_token | pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,} | Y |
| Rainforest Pay | Rainforest API Key | rainforest_api_key | keyword-gated | Y |
| Rainforest Pay | Rainforest Sandbox API Key | rainforest_sandbox_api_key | keyword-gated | Y |
| Ramp | Ramp OAuth Client ID | ramp_client_id | keyword-gated | Y |
| Ramp | Ramp OAuth Client Secret | ramp_client_secret | keyword-gated | Y |
| Ramp | Ramp OAuth Access or Refresh Token | ramp_oauth_token | keyword-gated | Y |
| Raycast | Raycast Access Token | raycast_access_token | keyword-gated | Y |
| ReadMe | ReadMe API Key | readmeio_api_access_token | rdme_[a-z0-9]{70} | Y |
| Replicate | Replicate API Token | replicate_api_token | keyword-gated | Y |
| Resend | Resend API Key | resend_api_key | re_ | Y |
| Rootly | Rootly API Key | rootly_api_key | keyword-gated | Y |
| RubyGems | RubyGems API Key | rubygems_api_key | rubygems_[a-f0-9]{48} | Y |
| RunPod | RunPod API Key | runpod_api_key | keyword-gated | Y |
| Salesforce | Salesforce Access Token | salesforce_access_token | keyword-gated | Y |
| Salesforce | Salesforce Marketing Cloud API OAuth2 Token | salesforce_marketing_cloud_api_oauth2_token | keyword-gated | Y |
| Salesforce | Salesforce OAuth2 Consumer Key | salesforce_oauth2_consumer_key, salesforce_oauth2_consumer_secret | 3MVG9[0-9a-zA-Z._+/=]{80,251} | Y |
| Salesforce | Salesforce Refresh Token | salesforce_refresh_token | 5AEP861[a-zA-Z0-9._=]{80,} | Y |
| Samsara | Samsara API Token | samsara_api_token | keyword-gated | Y |
| Samsara | Samsara OAuth Access Token | samsara_oauth_access_token | keyword-gated | Y |
| Scalr | Scalr API Token | scalr_api_token | keyword-gated | Y |
| Segment | Segment Public API Token | segment_public_api_token | [a-zA-Z0-9]{32} | Y |
| SendGrid | SendGrid API Key | sendgrid_api_key | SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43} | Y |
| Sentry | Sentry Integration Token | sentry_integration_token | sntrys_eyJ[A-Za-z0-9+/=_]{40,} | Y |
| Sentry | Sentry Organization Token | sentry_organization_token | sntrys_eyJ[A-Za-z0-9+/=]{8,}_[A-Za-z0-9+/]{43} | Y |
| Sentry | Sentry Personal Token | sentry_personal_token | sntryu_[0-9a-f]{64} | Y |
| Sentry | Sentry User App Auth Token | sentry_user_app_auth_token | sntryu_[a-f0-9]{64} | Y |
| Shippo | Shippo Live API Token | shippo_live_api_token | shippo_live_ + 40 hex | Y |
| Shippo | Shippo Test API Token | shippo_test_api_token | keyword-gated | Y |
| Shopee | Shopee Open Platform Partner Key | shopee_open_platform_partner_key | keyword-gated | Y |
| Shopify | Shopify Access Token | shopify_access_token | shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32} | Y |
| Shopify | Shopify App Client Credentials | shopify_app_client_credentials | shpca_[0-9a-fA-F]{32} | Y |
| Shopify | Shopify App Client Secret | shopify_app_client_secret | shpca_[0-9a-fA-F]{32} | Y |
| Shopify | Shopify App Shared Secret | shopify_app_shared_secret | shpss_[0-9a-fA-F]{32} | Y |
| Shopify | Shopify Custom App Access Token | shopify_custom_app_access_token | shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32} | Y |
| Shopify | Shopify Marketplace Token | shopify_marketplace_token | shpat_[0-9a-fA-F]{32} | Y |
| Shopify | Shopify Merchant Token | shopify_merchant_token | shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32} | Y |
| Shopify | Shopify Partner API Token | shopify_partner_api_token | shpat_[0-9a-fA-F]{32} | Y |
| Shopify | Shopify Private App Password | shopify_private_app_password | shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32} | Y |
| Siemens | Siemens API Token | siemens_api_token | keyword-gated | Y |
| Siemens | Siemens Code Token | siemens_code_token | keyword-gated | Y |
| Sindri | Sindri API Key | sindri_api_key, | keyword-gated | Y |
| Slack | Slack API Token | slack_api_token, | xox[bpe][0-9a-zA-Z_-]+ | Y |
| Slack | Slack Incoming Webhook URL | slack_incoming_webhook_url | https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{30,} | Y |
| Slack | Slack Workflow Trigger URL | slack_workflow_trigger_url | keyword-gated | Y |
| Slack | Slack Workflow Webhook URL | slack_workflow_webhook_url | keyword-gated | Y |
| Snowflake | SFPG Connection String | snowflake_postgres_connection_string | keyword-gated | Y |
| Snowflake | SFPG Host | snowflake_postgres_host, snowflake_postgres_password | keyword-gated | Y |
| Snowflake | Snowflake Programmatic Access Token | snowflake_programmatic_access_token | keyword-gated | Y |
| Sourcegraph | Sourcegraph Access Token | sourcegraph_access_token | sgp_ prefix | Y |
| Sourcegraph | Sourcegraph Dotcom User Gateway Access Token | sourcegraph_dotcom_user_gateway | sgph_ prefix | Y |
| Sourcegraph | Sourcegraph Access Token with Instance Identifier | sourcegraph_instance_identifier_access_token | sgp_ prefix | Y |
| Sourcegraph | Sourcegraph License Key Token | sourcegraph_license_key_token | sgp_ prefix | Y |
| Sourcegraph | Sourcegraph Product Subscription Token | sourcegraph_product_subscription_token | sgp_ prefix | Y |
| SpaceX | Starlink Public API V2 Client Secret | starlink_public_api_v2_secret | keyword-gated | Y |
| Square | Square Access Token | square_access_token, | sq0atp-[A-Za-z0-9_-]{22,60}|sq0csp-[A-Za-z0-9_-]{43} | Y |
| Square | Square Production Application Secret | square_production_application_secret | EAAA[0-9A-Za-z_-]{60} | Y |
| Square | Square Sandbox Application Secret | square_sandbox_application_secret | sq0atp-[0-9A-Za-z_-]{22} | Y |
| SSLMate | SSLMate API Key | sslmate_api_key, | sq0csp- + 43 word chars | Y |
| SSLMate | SSLMate Cluster Secret | sslmate_cluster_secret | sq0csp- + 43 word chars | Y |
| Stripe | Stripe API Key | stripe_api_key | rk_(?:live|test)_[A-Za-z0-9]{24,}|sk_prod_[A-Za-z0-9]{24,} | Y |
| Stripe | Stripe Legacy API Key | stripe_legacy_api_key | (?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99} | Y |
| Stripe | Stripe Live API Restricted Key | stripe_live_restricted_key | rk_live_[A-Za-z0-9]{24,} | Y |
| Stripe | Stripe Test API Restricted Key | stripe_test_restricted_key | rk_test_[A-Za-z0-9]{24,} | Y |
| Stripe | Stripe Test API Secret Key | stripe_test_secret_key | (?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99} | Y |
| Stripe | Stripe Webhook Signing Secret | stripe_webhook_signing_secret | whsec_[A-Za-z0-9]{32,64} | Y |
| Supabase | Supabase OAuth Access Token | supabase_oauth_access_token | sb_secret_[A-Za-z0-9_-]{31,}|sbp_[a-f0-9]{40} | Y |
| Supabase | Supabase Personal Access Token | supabase_personal_access_token | sb_secret_ | Y |
| Supabase | Supabase Personal Access Token (scoped) | supabase_scoped_personal_access_token | sb_secret_[A-Za-z0-9_-]{31,}|sbp_[a-f0-9]{40} | Y |
| Supabase | Supabase Secret Key | supabase_secret_key | sb_secret_ | Y |
| Tableau | Tableau Personal Access Token | tableau_personal_access_token | keyword-gated | Y |
| Tailscale | Tailscale API Key | tailscale_api_key | tskey-(?:api|auth|client|scim|webhook)-[A-Za-z0-9]{8,}-[A-Za-z0-9]{20,} | Y |
| Tavily | Tavily API Key | tavily_api_key | keyword-gated | Y |
| Telegram | Telegram Bot Token | telegram_bot_token | [0-9]{8,10}:AA[A-Za-z0-9_-]{33} | Y |
| Telnyx | Telnyx API V2 Key | telnyx_api_v2_key | keyword-gated | Y |
| Temporal | Temporal Cloud API Key | temporal_cloud_api_key | keyword-gated | Y |
| Tencent | Tencent Cloud International Access Token | tencent_cloud_intl_access_token | AKID[0-9a-zA-Z]{32} | Y |
| Tencent | Tencent Cloud Secret ID | tencent_cloud_secret_id | AKID[0-9a-zA-Z]{32} | Y |
| Tencent | Tencent WeChat API App ID | tencent_wechat_api_app_id | keyword-gated | Y |
| Tencent | Tencent WeChat Pay Token | tencent_wechat_pay_token | keyword-gated | Y |
| Thunderstore | Thunderstore IO API Token | thunderstore_io_api_token | keyword-gated | Y |
| Twilio | Twilio Access Token | twilio_access_token | keyword-gated | Y |
| Twilio | Twilio Account String Identifier | twilio_account_sid, | AC[a-zA-Z0-9]{32} | Y |
| Twilio | Twilio API Key | twilio_api_key | SK[0-9a-fA-F]{32} | Y |
| Typeform | Typeform Personal Access Token | typeform_personal_access_token | tfp_[a-z0-9\-_.=]{59} | Y |
| Uniwise | WISEflow API Key | wiseflow_api_key | keyword-gated | Y |
| Unkey | Unkey Root Key | unkey_root_key | keyword-gated | Y |
| Val Town | Val Town API Token | val_town_api_token | keyword-gated | Y |
| Vercel | Vercel API Key | vercel_api_key | vcp_[A-Za-z0-9]{24} | Y |
| Vercel | Vercel App Refresh Token | vercel_app_refresh_token | vcp_, vci_, vca_, vcr_, vck_ | Y |
| Vercel | Vercel App User Access Token | vercel_app_user_access_token | vcp_, vci_, vca_, vcr_, vck_ | Y |
| Vercel | Vercel Integration Access Token | vercel_integration_access_token | vcp_, vci_, vca_, vcr_, vck_ | Y |
| Vercel | Vercel Personal Access Token | vercel_personal_access_token | vcp_, vci_, vca_, vcr_, vck_ | Y |
| Vercel | Vercel Support Access Token | vercel_support_access_token | vcp_, vci_, vca_, vcr_, vck_ | Y |
| VolcEngine | VolcEngine Access Key ID | volcengine_access_key_id | keyword-gated | Y |
| VolcEngine | VolcEngine Ark API Key | volcengine_ark_api_key | keyword-gated | Y |
| Wakatime | WakaTime API Key | wakatime_api_key | waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} | Y |
| Wakatime | WakaTime App Secret | wakatime_app_secret | waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} | Y |
| Wakatime | WakaTime OAuth Access Token | wakatime_oauth_access_token | waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} | Y |
| Wakatime | WakaTime OAuth Refresh Token | wakatime_oauth_refresh_token | waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} | Y |
| Wave Mobile Money Inc. | Wave Production API Key | wave_api_prod_key | keyword-gated | Y |
| Wave Mobile Money Inc. | Wave Test API Key | wave_api_test_key | keyword-gated | Y |
| Weatherstack | Weatherstack API Key | weatherstack_api_key | keyword-gated | Y |
| Weights & Biases | Weights & Biases API Key | wandb_api_key | keyword-gated | Y |
| Workato | Workato Developer API Token | workato_developer_api_token, | keyword-gated | Y |
| WorkOS | WorkOS Production API Key | workos_production_api_key, | sk_live_ prefix | Y |
| WorkOS | WorkOS Staging API Key | workos_staging_api_key, | sk_test_ prefix | Y |
| WSO2 | WSO2 Choreo Personal Access Token | wso2_choreo_personal_access_token | keyword-gated | Y |
| Yandex | Yandex.Cloud API Key | yandex_cloud_api_key | AQVN[A-Za-z0-9_\-]{35,38} | Y |
| Yandex | Yandex.Cloud Access Secret | yandex_cloud_iam_access_secret | AQVN[A-Za-z0-9_\-]{35,38} | Y |
| Yandex | Yandex.Cloud IAM Cookie | yandex_cloud_iam_cookie | keyword-gated | Y |
| Yandex | Yandex.Cloud IAM Token | yandex_cloud_iam_token | t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2} | Y |
| Yandex | Yandex.Cloud Smartchapta Server Key | yandex_cloud_smartcaptcha_server_key | ysc2_[a-zA-Z0-9]{40}[0-9a-f]{8} | Y |
| Yandex | Yandex.Dictionary API Key | yandex_dictionary_api_key | keyword-gated | Y |
| Yandex | Yandex.Passport OAuth Token | yandex_passport_oauth_token | y[0-6]_[-_A-Za-z0-9]{55,199} | Y |
| Yandex | Yandex.Predictor API Key | yandex_predictor_api_key | keyword-gated | Y |
| Yandex | Yandex.Translate API Key | yandex_translate_api_key | keyword-gated | Y |
| ZenHub | ZenHub Personal API Key | zenhub_personal_api_key | keyword-gated | Y |
| Zuplo | Zuplo Consumer API Key | zuplo_consumer_api_key | keyword-gated | Y |

## Generic patterns (10 rows)
Not tied to a specific provider. Regex-based. No partner notifications, no
validity checks.
| Provider | Secret type | Description | Precision | Pattern | Implemented |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Generic | ec_private_key | Elliptic Curve (EC) private keys used for cryptographic operations | High | `-----BEGIN ... PRIVATE KEY-----` markers (private-key-marker rule) | Y |
| Generic | generic_private_key | Cryptographic private keys with `-----BEGIN PRIVATE KEY-----` header | High | `-----BEGIN ... PRIVATE KEY-----` markers (private-key-marker rule) | Y |
| Generic | http_basic_authentication_header | HTTP Basic Authentication credentials in request headers | Medium | `Authorization: Basic <base64>` request-header credential (rayloc: `http-basic-authentication-header`) | Y |
| Generic | http_bearer_authentication_header | HTTP Bearer tokens used for API authentication | Medium | `Authorization: Bearer <token>` request-header credential (rayloc: `http-bearer-authentication-header`) | Y |
| Generic | mongodb_connection_string | Connection strings for MongoDB databases containing credentials | High | `mongodb://`, `mongodb+srv://` (mongodb-uri rule) | Y |
| Generic | mysql_connection_url | Connection strings for MySQL databases containing credentials | High | `mysql://` (mysql-uri rule) | Y |
| Generic | openssh_private_key | OpenSSH format private keys used for SSH authentication | High | `-----BEGIN ... PRIVATE KEY-----` markers (private-key-marker rule) | Y |
| Generic | pgp_private_key | PGP (Pretty Good Privacy) private keys used for encryption and signing | High | `-----BEGIN ... PRIVATE KEY-----` markers (private-key-marker rule) | Y |
| Generic | postgres_connection_string | Connection strings for PostgreSQL databases containing credentials | High | `postgres://`, `postgresql://` (postgres-uri rule) | Y |
| Generic | rsa_private_key | RSA private keys used for cryptographic operations | High | `-----BEGIN ... PRIVATE KEY-----` markers (private-key-marker rule) | Y |

## AI-detected patterns (1 row)
Detected using GitHub Copilot AI models. No validity checks.
| Provider | Secret type | Pattern | Implemented |
| :--- | :--- | :--- | :--- |
| Generic | password | context-based (password-assignment / context-secret rules) | Y |

## Summary
| Category | Rows | Implemented (Y) | Pending (N) |
| :--- | :--- | :--- | :--- |
| Provider patterns | 525 | 525 | 0 |
| Generic patterns | 10 | 10 | 0 |
| AI-detected patterns | 1 | 1 | 0 |
| **Total** | **536** | **536** | **0** |

## Notes
- **525 provider rows** all have patterns merged from rayloc's existing
  detector code (`src/rules/builtin.rs`) and research: prefix tables (e.g. `ghp_`, `sk_live_`,
  `gsk_`, `hf_`, `r8_`) and special matchers (e.g. `AKIA`/`ASIA`, `SG.`, `AC`/`SK`,
  `-----BEGIN ... PRIVATE KEY-----` markers). These are marked `Y` in the
  `Implemented` column.
- **0 provider rows** remain pending (N): every provider pattern from GitHub's supported secret scanning patterns page now has a corresponding pattern entry.
- **0 generic patterns** remain pending (N): `http_basic_authentication_header` and `http_bearer_authentication_header` are implemented as header-trigger detectors (`http-basic-authentication-header` / `http-bearer-authentication-header` rules) that require an `authorization` marker within 30 bytes and the `Basic `/`Bearer ` scheme within 20 bytes of the candidate value.
- **Keyword-gated patterns:** Rows marked `keyword-gated` in the `Pattern` column have no distinctive prefix or regex. When implementing detectors for these, rayloc should match on the **secret type name** as a keyword (e.g. `ionic`, `openvsx`, `workos`, `hop`, `onechronos`) near candidate secret values, since users commonly name their config variables using the provider's secret type (e.g. `IONIC_API_KEY`, `OPENV SX_TOKEN`, `WORKOS_PRODUCTION_API_KEY`). This follows Gitleaks' `GenerateSemiGenericRegex` approach with provider-specific keywords as pre-filters.
- Rows marked `[Token versions]` on GitHub's page have had that link suffix
  removed from the `Secret type` column here.
- Provider prefixes in GitHub's table are indicative only; exact alphabets,
  lengths and boundaries must be established from vendor documentation before
  introducing a detector in `rayloc`.
- This catalog does not imply `rayloc` will detect every listed secret type.
  Detection requires a rule, boundary framing, and (for provider patterns)
  evidence of issuance format.
