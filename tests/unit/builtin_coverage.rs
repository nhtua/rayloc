use super::*;

const CHUNK: usize = crate::scanner::chunk::CHUNK_BYTES;
const LOOKAHEAD: usize = MAX_CANDIDATE_BYTES;

/// Every variant listed in `pub enum RuleId`, kept in declaration order.
const ALL_RULE_IDS: &[RuleId] = &[
    RuleId::AwsAccessKeyId,
    RuleId::GithubToken,
    RuleId::StripeSecretKey,
    RuleId::StripeRestrictedKey,
    RuleId::SlackWebhook,
    RuleId::PrivateKeyMarker,
    RuleId::AwsSecretAccessKey,
    RuleId::JoseToken,
    RuleId::ContextSecret,
    RuleId::PasswordAssignment,
    RuleId::OpenaiKey,
    RuleId::OpenrouterKey,
    RuleId::AnthropicKey,
    RuleId::GroqKey,
    RuleId::PerplexityKey,
    RuleId::HuggingfaceKey,
    RuleId::XaiKey,
    RuleId::GoogleApiKey,
    RuleId::AlibabaKey,
    RuleId::BaiduKey,
    RuleId::WandbKey,
    RuleId::FirecrawlKey,
    RuleId::LangsmithKey,
    RuleId::VoyageKey,
    RuleId::CartesiaKey,
    RuleId::ReplicateKey,
    RuleId::VercelKey,
    RuleId::SupabaseKey,
    RuleId::CloudflareKey,
    RuleId::DigitalOceanPat,
    RuleId::DigitalOceanOauth,
    RuleId::DigitalOceanRefresh,
    RuleId::DockerSwarmJoin,
    RuleId::DockerSwarmUnlock,
    RuleId::HerokuApiKey,
    RuleId::ClojarsToken,
    RuleId::CratesioToken,
    RuleId::PyPiToken,
    RuleId::RubygemsApiKey,
    RuleId::SendgridApiKey,
    RuleId::SendinblueApiKey,
    RuleId::SlackBotToken,
    RuleId::SlackUserToken,
    RuleId::SlackWorkspaceToken,
    RuleId::SlackRefreshToken,
    RuleId::TwilioAccountSid,
    RuleId::TwilioApiKey,
    RuleId::SentryOrgToken,
    RuleId::SentryPersonalToken,
    RuleId::GrafanaServiceAccountToken,
    RuleId::AxiomToken,
    RuleId::SonarQubeToken,
    RuleId::SonarQubeCloudToken,
    RuleId::KongKonnectToken,
    RuleId::TruffleHogEnterpriseSecret,
    RuleId::DopplerToken,
    RuleId::TailscaleApiToken,
    RuleId::TailscaleAuthToken,
    RuleId::ResendApiKey,
    RuleId::LaunchDarklyServerSdkToken,
    RuleId::FlagsmithServerToken,
    RuleId::GrowthBookSecretKey,
    RuleId::PostHogPersonalToken,
    RuleId::GitlabCicdJobToken,
    RuleId::GitlabDeployToken,
    RuleId::GitlabFeatureFlagToken,
    RuleId::GitlabPersonalAccessToken,
    RuleId::GitlabRunnerToken,
    RuleId::GitlabRunnerRegistrationToken,
    RuleId::GitlabFeedToken,
    RuleId::GitlabIncomingMailToken,
    RuleId::GitlabScimToken,
    RuleId::GitlabAgentToken,
    RuleId::GitlabOauthAppSecret,
    RuleId::GitlabTriggerToken,
    RuleId::CircleCiPersonalToken,
    RuleId::CircleCiProjectToken,
    RuleId::AtlassianApiToken,
    RuleId::NetlifyAccessToken,
    RuleId::FlyioToken,
    RuleId::PineconeApiKey,
    RuleId::AnthropicAdminKey,
    RuleId::Auth0ManagementToken,
    RuleId::OktaAccessToken,
    RuleId::NotionApiKey,
    RuleId::LinearApiKey,
    RuleId::FigmaToken,
    RuleId::SquareAccessToken,
    RuleId::ShopifyAccessToken,
    RuleId::ShopifyCustomToken,
    RuleId::ShopifySharedSecret,
    RuleId::ShopifyAppPassword,
    RuleId::StripePaymentIntent,
    RuleId::StripeAccessToken,
    RuleId::MistralKey,
    RuleId::CerebrasKey,
    RuleId::TogetheraiKey,
    RuleId::FireworksAiKey,
    RuleId::StabilityAiKey,
    RuleId::DeepgramKey,
    RuleId::TelegramBotToken,
    RuleId::RazorpayKey,
    RuleId::FlutterwaveKey,
    RuleId::PlanetscalePassword,
    RuleId::PlanetscaleToken,
    RuleId::PlanetscaleOauthToken,
    RuleId::PaddleApiKey,
    RuleId::PlaidAccessToken,
    RuleId::CloudinaryUrl,
    RuleId::AdafruitIoKey,
    RuleId::AdobeClientSecret,
    RuleId::AdobeDeviceToken,
    RuleId::AdobePacToken,
    RuleId::AdobeRefreshToken,
    RuleId::AdobeServiceToken,
    RuleId::AdobeShortLivedAccessToken,
    RuleId::AivenAuthToken,
    RuleId::AivenServicePassword,
    RuleId::ApiclubApiKey,
    RuleId::ApifyApiToken,
    RuleId::AsaasApiToken,
    RuleId::CanvaAppSecret,
    RuleId::CloudsmithApiKey,
    RuleId::DatabentoApiKey,
    RuleId::DopplerAuditToken,
    RuleId::GitHubSSHPrivateKey,
    RuleId::HashiCorpVaultServiceToken,
    RuleId::AirtablePat,
    RuleId::AikidoApiClientSecret,
    RuleId::AikidoCiScanningToken,
    RuleId::AirtableApiKey,
    RuleId::BeamerApiKey,
    RuleId::BitbucketServerPat,
    RuleId::BitrisePat,
    RuleId::BitriseWorkspaceApiToken,
    RuleId::BuildkiteUserAccessToken,
    RuleId::BuildkiteAgentAccessToken,
    RuleId::BuildkiteAgentJobToken,
    RuleId::BuildkiteAgentRegistrationToken,
    RuleId::BuildkiteClusterToken,
    RuleId::BuildkiteClusterQueueToken,
    RuleId::BuildkitePackagesRegistryToken,
    RuleId::BuildkitePackagesTemporaryToken,
    RuleId::BuildkitePortalToken,
    RuleId::BuildkitePortalSecret,
    RuleId::BlockProtocolApiKey,
    RuleId::SendinblueSmtpKey,
    RuleId::CanvaConnectApiSecret,
    RuleId::CanvaSecret,
    RuleId::CashfreeApiKey,
    RuleId::CcdbApiKey,
    RuleId::CdsCanadaNotifyApiKey,
    RuleId::CfxreServerKey,
    RuleId::CheckoutProductionSecretKey,
    RuleId::CheckoutTestSecretKey,
    RuleId::ChiefToolsToken,
    RuleId::ClojarsDeployToken,
    RuleId::CohereApiKey,
    RuleId::ContentfulPat,
    RuleId::ContentfulWebToken,
    RuleId::ContributedSystemsCredentials,
    RuleId::CoveoAccessToken,
    RuleId::CoveoApiKey,
    RuleId::DatabricksApiToken,
    RuleId::DatabricksAccountSessionToken,
    RuleId::DatabricksFederatedAccountSessionToken,
    RuleId::DatabricksOAuthCode,
    RuleId::DatabricksOAuthRefreshToken,
    RuleId::DatabricksOAuthSecretToken,
    RuleId::DatabricksOAuthSingleUseRefreshTokenChild,
    RuleId::DatabricksOAuthSingleUseRefreshTokenParent,
    RuleId::DatabricksScopedApiToken,
    RuleId::DatabricksScopedInternalToken,
    RuleId::DatabricksToken,
    RuleId::DatabricksWorkspaceSessionToken,
    RuleId::DatadogApiKey,
    RuleId::DatadogAppKey,
    RuleId::DatadogPat,
    RuleId::DatadogRcm,
    RuleId::DatadogSat,
    RuleId::DatastaxAstraCsToken,
    RuleId::DeepseekApiKey,
    RuleId::AmazonAwsApiKeyId,
    RuleId::AmazonAwsSessionToken,
    RuleId::AmazonAwsTemporaryAccessKeyId,
    RuleId::AsanaLegacyFormatPersonalAccessToken,
    RuleId::AsanaPersonalAccessToken,
    RuleId::AtlassianJwt,
    RuleId::AuthressServiceClientAccessKey,
    RuleId::AzureDevopsPersonalAccessToken,
    RuleId::AzureFunctionKey,
    RuleId::AzureStorageAccountKey,
    RuleId::AzureCognitiveServicesKey,
    RuleId::AzureComputerVisionKey,
    RuleId::AzureAiServicesKey,
    RuleId::AzureCacheForRedisAccessKey,
    RuleId::AzureActiveDirectoryApplicationSecret,
    RuleId::AzureAnomalyDetectorKey,
    RuleId::AzureAnomalyDetectorEeKey,
    RuleId::AzureApimDirectManagementKey,
    RuleId::AzureApimGatewayKey,
    RuleId::AzureApimRepositoryKey,
    RuleId::AzureApimSubscriptionKey,
    RuleId::AzureAppConfigurationKey,
    RuleId::AzureAppConfigurationConnectionString,
    RuleId::AzureBatchKeyIdentifiable,
    RuleId::AzureCommunicationServicesKey,
    RuleId::AzureCommunicationServicesConnectionString,
    RuleId::AzureContainerRegistryKeyIdentifiable,
    RuleId::AzureContentModeratorKey,
    RuleId::AzureContentSafetyKey,
    RuleId::AzureCosmosdbKeyIdentifiable,
    RuleId::AzureCustomVisionPredictionKey,
    RuleId::AzureCustomVisionTrainingKey,
    RuleId::AzureEventGridKeyIdentifiable,
    RuleId::AzureEventHubKeyIdentifiable,
    RuleId::AzureFaceKey,
    RuleId::AzureFluidRelayKey,
    RuleId::AzureFormRecognizerKey,
    RuleId::AzureHealthDecisionSupportKey,
    RuleId::AzureHealthInsightsKey,
    RuleId::AzureImmersiveReaderKey,
    RuleId::AzureInternalAllInOneKey,
    RuleId::AzureIotDeviceConnectionString,
    RuleId::AzureIotDeviceKey,
    RuleId::AzureIotDeviceProvisioningKey,
    RuleId::AzureIotHubConnectionString,
    RuleId::AzureIotHubKey,
    RuleId::AzureIotProvisioningConnectionString,
    RuleId::AzureKnowledgeKey,
    RuleId::AzureLogicAppsUrl,
    RuleId::AzureLuisAuthoringKey,
    RuleId::AzureLuisKey,
    RuleId::AzureManagementCertificate,
    RuleId::AzureMapsKey,
    RuleId::AzureMetricsAdvisorKey,
    RuleId::AzureMixedRealityKey,
    RuleId::AzureMlInferenceIdentifiableKey,
    RuleId::AzureMlInternalServicePrincipalIdentifiableKey,
    RuleId::AzureMlWebServiceClassicIdentifiableKey,
    RuleId::AzureOpenAIKey,
    RuleId::AzurePersonalizerKey,
    RuleId::AzureQnaMakerKey,
    RuleId::AzureQnaMakerV2Key,
    RuleId::AzureQuantumKey,
    RuleId::AzureRelayKeyIdentifiable,
    RuleId::AzureSasToken,
    RuleId::AzureSearchAdminKey,
    RuleId::AzureSearchQueryKey,
    RuleId::AzureServiceBusIdentifiable,
    RuleId::AzureSignalrConnectionString,
    RuleId::AzureSignalrKey,
    RuleId::AzureSpeechServicesKey,
    RuleId::AzureSpeechTranslationKey,
    RuleId::AzureSqlInternalDefaultCloudSaKey,
    RuleId::AzureSqlPassword,
    RuleId::AzureTextAnalyticsKey,
    RuleId::AzureTextTranslationKey,
    RuleId::AzureVideoIntelligenceKey,
    RuleId::AzureWebAppBotKey,
    RuleId::AzureWebPubSubConnectionString,
    RuleId::AzureWebPubSubKey,
    RuleId::MicrosoftAzureEntraIdToken,
    RuleId::BitbucketServerPersonalAccessToken,
    RuleId::DefinedNetworkingNebulaApiKey,
    RuleId::DevCycleClientApiKey,
    RuleId::DevCycleMobileApiKey,
    RuleId::DevCycleServerApiKey,
    RuleId::DiscordBotToken,
    RuleId::DockerOrganizationPat,
    RuleId::DockerPersonalPat,
    RuleId::DockerSwarmJoinToken,
    RuleId::DockerSwarmUnlockKey,
    RuleId::DopplerCliToken,
    RuleId::DopplerPersonalToken,
    RuleId::DopplerScimToken,
    RuleId::DopplerServiceAccountToken,
    RuleId::DopplerServiceToken,
    RuleId::DropboxAccessToken,
    RuleId::DropboxShortLivedAccessToken,
    RuleId::DuffelLiveAccessToken,
    RuleId::DuffelTestAccessToken,
    RuleId::DynatraceApiToken,
    RuleId::DynatraceInternalToken,
    RuleId::EasypostProductionApiKey,
    RuleId::EasypostTestApiKey,
    RuleId::ElasticCloudApiKey,
    RuleId::ElasticStackApiKey,
    RuleId::FacebookAccessToken,
    RuleId::FastlyApiToken,
    RuleId::FieldguideApiToken,
    RuleId::FigmaPat,
    RuleId::FigmaScimToken,
    RuleId::FinicityAppKey,
    RuleId::FirebaseCloudMessagingServerKey,
    RuleId::FlickrApiKey,
    RuleId::FlutterwaveLiveApiSecretKey,
    RuleId::FlutterwaveTestApiSecretKey,
    RuleId::FrameIoDeveloperToken,
    RuleId::FrameIoJwt,
    RuleId::FullStoryApiKey,
    RuleId::GitLabAccessToken,
    RuleId::GitLabCICDBuildToken,
    RuleId::GitLabDeployToken,
    RuleId::GitLabFeatureFlagClientToken,
    RuleId::GitLabFeedTokenV2,
    RuleId::GitLabIncomingEmailToken,
    RuleId::GitLabKubernetesAgentToken,
    RuleId::GitLabOAuthAppSecret,
    RuleId::GitLabPipelineTriggerToken,
    RuleId::GitLabRunnerAuthToken,
    RuleId::GitLabRunnerRegistrationToken,
    RuleId::GitLabScimOAuthToken,
    RuleId::GoCardlessLiveAccessToken,
    RuleId::GoCardlessSandboxAccessToken,
    RuleId::GoogleCloudServiceAccountCredentials,
    RuleId::GoogleCloudStorageAccessKeySecret,
    RuleId::GoogleCloudStorageUserAccessKeyId,
    RuleId::GoogleGcpApiKeyBoundServiceAccount,
    RuleId::GoogleGeminiApiKey,
    RuleId::GoogleOAuthAccessToken,
    RuleId::GoogleOAuthClientId,
    RuleId::GoogleOAuthClientSecret,
    RuleId::GoogleOAuthRefreshToken,
    RuleId::GrafanaCloudApiKey,
    RuleId::GrafanaCloudApiToken,
    RuleId::GrafanaProjectApiKey,
    RuleId::GrafanaProjectServiceAccountToken,
    RuleId::GroqApiKey,
    RuleId::GuardsquareAppSweepApiKey,
    RuleId::GuardsquareCliAccessToken,
    RuleId::GuardsquareMavenToken,
    RuleId::HackClubAiKey,
    RuleId::HashiCorpVaultBatchToken,
    RuleId::HashiCorpVaultRootServiceToken,
    RuleId::TerraformApiToken,
    RuleId::HerokuPlatformApiOAuth2Token,
    RuleId::HerokuPostgresConnectionUrl,
    RuleId::HexApiKey,
    RuleId::HighnoteRkLiveKey,
    RuleId::HighnoteRkTestKey,
    RuleId::HighnoteSkLiveKey,
    RuleId::HighnoteSkTestKey,
    RuleId::HopBearer,
    RuleId::HopPat,
    RuleId::HopPtK,
    RuleId::HttpBasicAuthenticationHeader,
    RuleId::HttpBearerAuthenticationHeader,
    RuleId::HubspotApiKey,
    RuleId::HubspotPersonalAccessKey,
    RuleId::HubspotPrivateAppsUserToken,
    RuleId::HubspotSmtpCredential,
    RuleId::HuggingFaceOrgApiKey,
    RuleId::HuggingFaceUserAccessToken,
    RuleId::IbmCloudIamKey,
    RuleId::IntercomAccessToken,
    RuleId::IonicPersonalAccessToken,
    RuleId::IonicRefreshToken,
    RuleId::IterativeDvcStudioAccessToken,
    RuleId::JFrogPlatformAccessToken,
    RuleId::JFrogPlatformApiKey,
    RuleId::JFrogPlatformReferenceToken,
    RuleId::LangChainApiPersonalKey,
    RuleId::LangChainApiServerKey,
    RuleId::LangSmithLicenseKey,
    RuleId::LangSmithScimBearerToken,
    RuleId::LarkApaasClientSecret,
    RuleId::LarkAppSecret,
    RuleId::LarkMcpGrantToken,
    RuleId::LarkMeegoPluginSecret,
    RuleId::LarkUserSession,
    RuleId::LaunchDarklyAccessToken,
    RuleId::LichessOAuthAccessToken,
    RuleId::LichessPersonalAccessToken,
    RuleId::LightspeedXsPat,
    RuleId::LimbarToken,
    RuleId::LinearOAuthAccessToken,
    RuleId::LinkedInClientSecret,
    RuleId::LobLiveApiKey,
    RuleId::LobTestApiKey,
    RuleId::LocalstackApiKey,
    RuleId::LogicMonitorBearerToken,
    RuleId::LogicMonitorLmv1AccessKey,
    RuleId::AmazonOAuthClientId,
    RuleId::AmazonOAuthClientSecret,
    RuleId::LovableApiKey,
    RuleId::MailchimpApiKey,
    RuleId::MandrillApiKey,
    RuleId::MailersendApiToken,
    RuleId::MailersendSmtpPassword,
    RuleId::MailersendSmtpUsername,
    RuleId::MailgunApiKey,
    RuleId::MailgunSmtpCredential,
    RuleId::MapboxSecretAccessToken,
    RuleId::MaxMindLicenseKey,
    RuleId::MerakiApiKey,
    RuleId::MercuryNonProductionApiToken,
    RuleId::MercuryProductionApiToken,
    RuleId::MergifyApplicationKey,
    RuleId::MessageBirdApiKey,
    RuleId::PowerAutomateWebhookSAS,
    RuleId::MidtransProductionServerKey,
    RuleId::MidtransSandboxServerKey,
    RuleId::MistralAiApiKey,
    RuleId::MongoDBAtlasDbUriWithCredentials,
    RuleId::MongoDBAtlasServiceAccountSecret,
    RuleId::NaverCloudGovAccessKey,
    RuleId::NaverCloudGovAccessKeySecret,
    RuleId::NaverCloudGovSts,
    RuleId::NaverCloudGovStsSecret,
    RuleId::NaverCloudPubAccessKey,
    RuleId::NaverCloudPubAccessKeySecret,
    RuleId::NaverCloudPubSts,
    RuleId::NaverCloudPubStsSecret,
    RuleId::NeonApiKey,
    RuleId::NeonConnectionUri,
    RuleId::NetflixNetKey,
    RuleId::NewRelicInsightsQueryKey,
    RuleId::NewRelicLicenseKey,
    RuleId::NewRelicPersonalApiKey,
    RuleId::NewRelicRestApiKey,
    RuleId::NotionApiToken,
    RuleId::NotionIntegrationToken,
    RuleId::NotionOAuthClientSecret,
    RuleId::NuGetApiKey,
    RuleId::OctopusDeployApiKey,
    RuleId::OculusAccessToken,
    RuleId::OneChronosApiKey,
    RuleId::OneChronosEbApiKey,
    RuleId::OneChronosEbEncryptionKey,
    RuleId::OneChronosOauthToken,
    RuleId::OneChronosRefreshToken,
    RuleId::OnePasswordServiceAccountToken,
    RuleId::OneSignalRichApiKey,
    RuleId::OneSignalRichAuthenticationToken,
    RuleId::OnfidoLiveApiToken,
    RuleId::OnfidoSandboxApiToken,
    RuleId::OpenAIApiKey,
    RuleId::OpenRouterApiKey,
    RuleId::OpenVSXAccessToken,
    RuleId::OpenweatherApiKey,
    RuleId::OracleApiKey,
    RuleId::OrbitApiToken,
    RuleId::PaddleSandboxApiKey,
    RuleId::PagerDutyOAuthSecret,
    RuleId::PagerDutyOAuthToken,
    RuleId::PalantirJWT,
    RuleId::PangeaToken,
    RuleId::PerplexityApiKey,
    RuleId::PersonaProductionApiKey,
    RuleId::PersonaSandboxApiKey,
    RuleId::PineappleTechnologiesIncidentApiKey,
    RuleId::PinterestAccessToken,
    RuleId::PinterestRefreshToken,
    RuleId::PlanetScaleDatabasePassword,
    RuleId::PlanetScaleOAuthToken,
    RuleId::PlanetScaleServiceToken,
    RuleId::PlanningCenterOAuthAccessToken,
    RuleId::PlanningCenterOAuthAppSecret,
    RuleId::PlanningCenterPersonalAccessToken,
    RuleId::PlivoAuthID,
    RuleId::PlivoAuthToken,
    RuleId::PolarPersonalAccessToken,
    RuleId::PolarAccessToken,
    RuleId::PolarRefreshToken,
    RuleId::PolarAuthorizationCode,
    RuleId::PolarClientRegistrationToken,
    RuleId::PolarClientSecret,
    RuleId::PolarCustomerSessionToken,
    RuleId::PolarUserSessionToken,
    RuleId::PostHogFeatureFlagsSecureApiKey,
    RuleId::PostHogOAuthAccessToken,
    RuleId::PostHogOAuthRefreshToken,
    RuleId::PostHogPersonalApiKey,
    RuleId::PostmanApiKey,
    RuleId::PostmanCollectionKey,
    RuleId::PrefectServerApiKey,
    RuleId::PrefectUserApiKey,
    RuleId::ProctorioConsumerKey,
    RuleId::ProctorioLinkageKey,
    RuleId::ProctorioRegistrationKey,
    RuleId::ProctorioSecretKey,
    RuleId::ProofFullAccessApiKey,
    RuleId::PulumiAccessToken,
    RuleId::LogfireToken,
    RuleId::PydanticAIGatewayApiKey,
    RuleId::PyPiApiToken,
    RuleId::RainforestApiKey,
    RuleId::RainforestSandboxApiKey,
    RuleId::RampClientID,
    RuleId::RampClientSecret,
    RuleId::RampOAuthToken,
    RuleId::RaycastAccessToken,
    RuleId::ReadMeApiKey,
    RuleId::ReplicateApiToken,
    RuleId::RootlyApiKey,
    RuleId::RunPodApiKey,
    RuleId::SalesforceAccessToken,
    RuleId::SalesforceMarketingCloudApiOAuth2Token,
    RuleId::SalesforceOAuth2ConsumerKey,
    RuleId::SalesforceOAuth2ConsumerSecret,
    RuleId::SalesforceRefreshToken,
    RuleId::SamsaraApiToken,
    RuleId::SamsaraOAuthAccessToken,
    RuleId::ScalrApiToken,
    RuleId::SegmentPublicApiToken,
    RuleId::SendGridApiKey,
    RuleId::SentryIntegrationToken,
    RuleId::SentryOrganizationToken,
    RuleId::SentryUserAppAuthToken,
    RuleId::ShippoLiveApiToken,
    RuleId::ShippoTestApiToken,
    RuleId::ShopeeOpenPlatformPartnerKey,
    RuleId::ShopifyAppClientCredentials,
    RuleId::ShopifyAppClientSecret,
    RuleId::ShopifyAppSharedSecret,
    RuleId::ShopifyCustomAppAccessToken,
    RuleId::ShopifyMarketplaceToken,
    RuleId::ShopifyMerchantToken,
    RuleId::ShopifyPartnerApiToken,
    RuleId::ShopifyPrivateAppPassword,
    RuleId::SiemensApiToken,
    RuleId::SiemensCodeToken,
    RuleId::SindriApiKey,
    RuleId::SlackApiToken,
    RuleId::SlackIncomingWebhookURL,
    RuleId::SlackWorkflowTriggerURL,
    RuleId::SlackWorkflowWebhookURL,
    RuleId::SnowflakePostgresConnectionString,
    RuleId::SnowflakePostgresHost,
    RuleId::SnowflakePostgresPassword,
    RuleId::SnowflakeProgrammaticAccessToken,
    RuleId::SourcegraphAccessToken,
    RuleId::SourcegraphDotcomUserGateway,
    RuleId::SourcegraphInstanceIdentifierAccessToken,
    RuleId::SourcegraphLicenseKeyToken,
    RuleId::SourcegraphProductSubscriptionToken,
    RuleId::StarlinkPublicAPIV2Secret,
    RuleId::SquareProductionApplicationSecret,
    RuleId::SquareSandboxApplicationSecret,
    RuleId::SSLMateAPIKey,
    RuleId::SSLMateClusterSecret,
    RuleId::StripeApiKey,
    RuleId::StripeLegacyAPIKey,
    RuleId::StripeLiveRestrictedKey,
    RuleId::StripeTestRestrictedKey,
    RuleId::StripeTestAPISecretKey,
    RuleId::StripeWebhookSigningSecret,
    RuleId::SupabaseOAuthAccessToken,
    RuleId::SupabasePersonalAccessToken,
    RuleId::SupabaseScopedPersonalAccessToken,
    RuleId::SupabaseSecretKey,
    RuleId::TableauPersonalAccessToken,
    RuleId::TailscaleAPIKey,
    RuleId::TavilyApiKey,
    RuleId::TelnyxAPIV2Key,
    RuleId::TemporalCloudApiKey,
    RuleId::TencentCloudIntlAccessToken,
    RuleId::TencentCloudSecretID,
    RuleId::TencentWeChatAPIAppID,
    RuleId::TencentWeChatPayToken,
    RuleId::ThunderstoreIOApiToken,
    RuleId::TwilioAccessToken,
    RuleId::TwilioAccountSID,
    RuleId::TwilioAPIKey,
    RuleId::TypeformPersonalAccessToken,
    RuleId::WISEflowAPIKey,
    RuleId::UnkeyRootKey,
    RuleId::ValTownApiToken,
    RuleId::VercelAPIKey,
    RuleId::VercelAppRefreshToken,
    RuleId::VercelAppUserAccessToken,
    RuleId::VercelIntegrationAccessToken,
    RuleId::VercelPersonalAccessToken,
    RuleId::VercelSupportAccessToken,
    RuleId::VolcEngineAccessKeyID,
    RuleId::VolcEngineArkAPIKey,
    RuleId::WakaTimeAPIKey,
    RuleId::WakaTimeAppSecret,
    RuleId::WakaTimeOAuthAccessToken,
    RuleId::WakaTimeOAuthRefreshToken,
    RuleId::WaveProductionAPIKey,
    RuleId::WaveTestAPIKey,
    RuleId::WeatherstackAPIKey,
    RuleId::WandbAPIKey,
    RuleId::WorkatoDeveloperAPIToken,
    RuleId::WorkOSProductionAPIKey,
    RuleId::WorkOSStagingAPIKey,
    RuleId::WSO2ChoreoPersonalAccessToken,
    RuleId::YandexCloudAPIKey,
    RuleId::YandexCloudIAMAccessSecret,
    RuleId::YandexCloudIAMCookie,
    RuleId::YandexCloudIAMToken,
    RuleId::YandexCloudSmartcaptchaServerKey,
    RuleId::YandexDictionaryAPIKey,
    RuleId::YandexPassportOAuthToken,
    RuleId::YandexPredictorAPIKey,
    RuleId::YandexTranslateAPIKey,
    RuleId::ZenHubPersonalAPIKey,
    RuleId::ZuploConsumerAPIKey,
    RuleId::MongodbUri,
    RuleId::PostgresUri,
    RuleId::RedisUri,
    RuleId::SqlserverUri,
    RuleId::MysqlUri,
    RuleId::CockroachdbUri,
];

#[test]
fn every_rule_variant_metadata_is_populated_and_valid() {
    // Context, password-context, and user-defined rules carry no provider URL.
    let reference_free = |id: &RuleId| {
        matches!(
            id,
            RuleId::ContextSecret | RuleId::PasswordAssignment | RuleId::Custom(_, _)
        )
    };
    for &id in ALL_RULE_IDS {
        let metadata = id.metadata();
        assert!(!metadata.id.is_empty(), "{id:?} id");
        assert!(!metadata.description.is_empty(), "{id:?} description");
        assert!(
            matches!(
                metadata.severity.to_string().as_str(),
                "Low" | "Medium" | "High" | "Critical"
            ),
            "{id:?} severity"
        );
        assert!(
            matches!(
                metadata.confidence.to_string().as_str(),
                "Medium confidence" | "High confidence"
            ),
            "{id:?} confidence"
        );
        assert_eq!(metadata.reviewed_on, "2026-10-06", "{id:?} reviewed_on");
        if reference_free(&id) {
            assert!(metadata.reference.is_empty(), "{id:?} reference");
        } else {
            assert!(
                metadata.reference.starts_with("https://"),
                "{id:?} reference"
            );
        }
    }
}

#[test]
fn custom_rule_metadata_carries_severity_and_defaults() {
    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let id = RuleId::Custom(1000 + severity as u16, severity);
        let metadata = id.metadata();
        assert_eq!(metadata.id, "custom-rule");
        assert_eq!(metadata.description, "Custom rule");
        assert_eq!(metadata.severity, severity);
        assert_eq!(metadata.confidence, Confidence::Medium);
        assert!(metadata.reference.is_empty());
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
    let edge = RuleId::Custom(u16::MAX, Severity::Critical).metadata();
    assert_eq!(edge.severity, Severity::Critical);
    let zero = RuleId::Custom(0, Severity::Low).metadata();
    assert_eq!(zero.severity, Severity::Low);
}

#[test]
fn severity_and_confidence_display_arms() {
    assert_eq!(Severity::Low.to_string(), "Low");
    assert_eq!(Severity::Medium.to_string(), "Medium");
    assert_eq!(Severity::High.to_string(), "High");
    assert_eq!(Severity::Critical.to_string(), "Critical");
    assert_eq!(Confidence::Medium.to_string(), "Medium confidence");
    assert_eq!(Confidence::High.to_string(), "High confidence");
}

fn synthetic_stream() -> Vec<u8> {
    let mut input = vec![b'a'; 3 * CHUNK - LOOKAHEAD];
    let token = b"AKIA1234567890ABCDEF "; // rayloc:ignore
    for absolute in [150_000usize, 262_144 + 66_000, 700_000] {
        input[absolute..absolute + token.len()].copy_from_slice(token);
    }
    input
}

fn stream_candidates(
    input: &[u8],
    registry: &Registry,
) -> Result<Vec<(RuleId, Range<u64>)>, ScanError> {
    let mut state = ProviderState::new();
    let mut found = Vec::new();
    for fragment in input.chunks(CHUNK) {
        state.push(fragment, registry, |candidate| {
            found.push((candidate.rule, candidate.span));
        })?;
    }
    state.finish(registry, |candidate| {
        found.push((candidate.rule, candidate.span));
    })?;
    Ok(found)
}

#[test]
fn stream_window_drain_skips_owned_and_lookahead_spans() {
    let registry = &crate::rules::BUILTINS;
    let input = vec![b'a'; 3 * CHUNK];
    let found = stream_candidates(&input, registry).unwrap();
    assert!(found.is_empty());
}

#[test]
fn stream_finish_returns_cleanly_when_the_window_is_fully_scanned() {
    let registry = &crate::rules::BUILTINS;
    let mut state = ProviderState::new();
    let mut found = Vec::new();
    // A full chunk triggers a mid-stream scan that drains the window down to
    // the kept lookahead; the following finish then observes cutoff <= owned
    // and returns without a second scan.
    state
        .push(&vec![b'a'; CHUNK], registry, |candidate| {
            found.push(candidate.rule);
        })
        .unwrap();
    state
        .finish(registry, |candidate| found.push(candidate.rule))
        .unwrap();
    assert!(found.is_empty());
}

#[test]
fn stream_candidate_limit_and_disabled_rules_survive_window_drain() {
    let config =
        crate::config::parse(b"version: '1'\ndisabled_rules: [aws-access-key-id]").unwrap();
    let disabled = Registry::compile(config).unwrap();
    // rayloc:ignore
    let mut input = synthetic_stream();
    input.extend_from_slice(b"ghp_");
    input.resize(MAX_CANDIDATE_BYTES + 1, b'a');
    input.push(b' ');
    let found = stream_candidates(&input, &disabled).unwrap();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn api_key_body_framing_rejects_dotted_and_multi_underscore_bodies() {
    // Prefix ends with an underscore: dots mark module paths, extra underscores
    // mark larger identifiers, so neither is a standalone key.
    assert_eq!(
        api_key_match(b"hf_Synthetic.Key.12345678901234567", &[b"hf_"]),
        Ok(None)
    );
    assert_eq!(
        api_key_match(b"gsk_A_B_C_12345678901234567890", &[b"gsk_"]),
        Ok(None)
    );
    assert_eq!(
        api_key_match(b"lin_api_A_B_C_12345678901234567890", &[b"lin_api_"]),
        Ok(None)
    );
    // No prefix match at all.
    assert_eq!(api_key_match(b"plain-value", &[b"hf_"]), Ok(None));
    // Trailing identifier-safe punctuation (not a word byte) keeps the match.
    assert_eq!(
        api_key_match(b"hf_SyntheticKey1234567890123456789@", &[b"hf_"]),
        Ok(Some(34))
    );
}

#[test]
fn token_match_padded_installation_tokens_and_min_body() {
    // rayloc:ignore
    let base = b"ghs_1234567890123456_abcdefghijklmnop"; // rayloc:ignore
    assert_eq!(
        token_match(base, &[b"ghs_"]).unwrap(),
        Some(base.len()) // rayloc:ignore
    );
    let padded = [base.as_slice(), b"="].concat();
    assert_eq!(
        token_match(&padded, &[b"ghs_"]).unwrap(),
        Some(padded.len())
    );
    // Too short to be a token body.
    assert_eq!(
        token_match(b"ghs_Short12345", GITHUB_PREFIXES).unwrap(),
        None
    );
    // Padding is only framed for installation prefixes.
    assert_eq!(
        token_match(b"ghp_1234567890123456=", &[b"ghp_"]).unwrap(),
        Some(20)
    );
}

#[test]
fn uri_match_stops_at_delimiters_and_requires_credentials() {
    let redis: &[&[u8]] = &[b"redis://", b"rediss://"];
    for delimiter in *b", ;)\t\n" {
        let input = [
            b"redis://user:pass123@host:6379/db".as_slice(), // rayloc:ignore
            &[delimiter][..],
            b"trailing",
        ]
        .concat();
        assert_eq!(
            uri_match(&input, redis, RuleId::RedisUri),
            Some((RuleId::RedisUri, 33)),
            "delimiter {delimiter:?}"
        );
    }
    // No credentials at all, and credentials without a password separator.
    assert_eq!(
        uri_match(b"redis://host:6379/db", redis, RuleId::RedisUri),
        None
    );
    assert_eq!(
        uri_match(b"redis://user@host:6379/db", redis, RuleId::RedisUri), // rayloc:ignore
        None
    );
    // Unsupported scheme.
    assert_eq!(uri_match(b"ftp://u:p@host", redis, RuleId::RedisUri), None);
}

#[test]
fn match_at_respects_a_fully_disabled_registry() {
    let all_disabled: Vec<RuleId> = ALL_RULE_IDS
        .iter()
        .copied()
        .chain([RuleId::Custom(1, Severity::Low)])
        .collect();
    let fixtures: Vec<(RuleId, Vec<u8>)> = vec![
        (RuleId::AwsAccessKeyId, b"AKIA1234567890ABCDEF".to_vec()), // rayloc:ignore
        (
            RuleId::GithubToken,
            b"ghp_Synthetic0123456789ABCDEF".to_vec(), // rayloc:ignore
        ),
        (
            RuleId::SlackWebhook,
            b"https://hooks.slack.com/services/T1/B2/SyntheticSecret".to_vec(), // rayloc:ignore
        ),
        (
            RuleId::SendgridApiKey,
            concat!(
                "SG.",
                "a2b3c4d5e6f7g8h9i0j1k2",
                ".",
                "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u"
            )
            .as_bytes()
            .to_vec(), // rayloc:ignore
        ),
        (
            RuleId::SendinblueApiKey,
            [b"xkeysib-".as_slice(), vec![b'a'; 81].as_slice()].concat(),
        ),
        (
            RuleId::DockerSwarmJoin,
            [b"SWMTKN-1-a-".as_slice(), vec![b'a'; 24].as_slice()].concat(),
        ),
        (
            RuleId::TwilioApiKey,
            [b"SK".as_slice(), vec![b'a'; 32].as_slice()].concat(),
        ),
        (
            RuleId::TelegramBotToken,
            [b"12345:A".as_slice(), vec![b'a'; 34].as_slice()].concat(),
        ),
        (
            RuleId::StripePaymentIntent,
            b"pi_live_secret_Synthetic1".to_vec(), // rayloc:ignore
        ),
        (
            RuleId::FlutterwaveKey,
            [b"FLWSECK-".as_slice(), vec![b'a'; 32].as_slice()].concat(),
        ),
        (
            RuleId::GitlabPersonalAccessToken,
            b"glpat-SyntheticGitlabPAT12".to_vec(), // rayloc:ignore
        ),
        (
            RuleId::MongodbUri,
            b"mongodb://user:pass123@cluster.example.com/db".to_vec(), // rayloc:ignore
        ),
        (
            RuleId::PrivateKeyMarker,
            b"-----BEGIN PRIVATE KEY-----".to_vec(), // rayloc:ignore
        ),
    ];
    for (rule, fixture) in fixtures {
        assert_eq!(
            match_at(&fixture, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "{rule:?} enabled"
        );
        assert_eq!(
            match_at(&fixture, &all_disabled).unwrap(),
            None,
            "{rule:?} disabled"
        );
    }
}

#[test]
fn specialized_matchers_cover_valid_and_near_miss_boundaries() {
    let api_key = [b"hf_".as_slice(), b"abcdefghijklmnopqrst", b"."].concat(); // rayloc:ignore
    assert_eq!(api_key_match(&api_key, &[b"hf_"]), Ok(None));

    let account_sid = [b"AC".as_slice(), b"a1".repeat(16).as_slice()].concat(); // rayloc:ignore
    assert_eq!(
        twilio_match(&account_sid),
        Some((RuleId::TwilioAccountSid, 34))
    );

    assert!(docker_swarm_match(b"SWMTKN-1-").is_none());
    assert!(docker_swarm_match(b"SWMTKN-1-a-short").is_none());
    assert!(
        docker_swarm_match(&[b"SWMKEY-1-".as_slice(), vec![b'a'; 39].as_slice()].concat())
            .is_none()
    );

    let sendgrid = [
        b"SG.".as_slice(),
        b"a".repeat(20).as_slice(),
        b".",
        b"b".repeat(39).as_slice(),
    ]
    .concat(); // rayloc:ignore
    assert_eq!(sendgrid_match(&sendgrid), Ok(Some(sendgrid.len())));
    assert_eq!(sendgrid_match(b"SG.short.body"), Ok(None));

    let sendinblue = [b"xkeysib-".as_slice(), vec![b'a'; 81].as_slice()].concat(); // rayloc:ignore
    assert_eq!(sendinblue_match(&sendinblue), Ok(Some(sendinblue.len())));
    assert_eq!(sendinblue_match(b"xkeysib-short"), Ok(None));

    let telegram = [b"12345:A".as_slice(), b"a".repeat(34).as_slice()].concat(); // rayloc:ignore
    assert_eq!(
        telegram_match(&telegram),
        Some((RuleId::TelegramBotToken, telegram.len()))
    );
    assert!(telegram_match(b"12345678901234567:Axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").is_none());

    let payment_intent = b"pi_live_secret_Synthetic1"; // rayloc:ignore
    assert_eq!(
        stripe_payment_intent_match(payment_intent),
        Some((RuleId::StripePaymentIntent, payment_intent.len()))
    );
    assert!(stripe_payment_intent_match(b"pi_live_public_Synthetic1").is_none());

    let flutterwave = [b"FLWSECK-".as_slice(), b"a1".repeat(16).as_slice()].concat(); // rayloc:ignore
    assert_eq!(
        flutterwave_match(&flutterwave),
        Some((RuleId::FlutterwaveKey, flutterwave.len()))
    );
}
