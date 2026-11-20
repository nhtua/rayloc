//! Small byte-oriented provider signatures, without regex/runtime dependencies.
//!
//! Body minima are scanner heuristics, not provider validity guarantees. Context,
//! custom regex rules, and JOSE validation belong to later implementation slices.

use std::{fmt, ops::Range};

use super::{Registry, stream::Candidate};
use crate::scanner::ScanError;

pub const MAX_CANDIDATE_BYTES: usize = 64 * 1024;
#[allow(dead_code)] // Consumed by the line session in Task 5.
const PROVIDER_LOOKAHEAD_BYTES: usize = MAX_CANDIDATE_BYTES;

/// Sliding bounded history keeps detector boundaries real across input fragments.
#[allow(dead_code)] // Consumed by the line session in Task 5.
pub(crate) struct ProviderState {
    window: Vec<u8>,
    base: u64,
    next_start: u64,
    bytes_since_scan: usize,
}

#[allow(dead_code)] // Consumed by the line session in Task 5.
impl ProviderState {
    pub(crate) fn new() -> Self {
        Self {
            window: Vec::with_capacity(2 * PROVIDER_LOOKAHEAD_BYTES + 1),
            base: 0,
            next_start: 0,
            bytes_since_scan: 0,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.window.clear();
        self.base = 0;
        self.next_start = 0;
        self.bytes_since_scan = 0;
    }

    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        registry: &Registry,
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        for fragment in bytes.chunks(crate::scanner::chunk::CHUNK_BYTES) {
            self.window.extend_from_slice(fragment);
            self.bytes_since_scan = self.bytes_since_scan.saturating_add(fragment.len());
            if self.bytes_since_scan >= crate::scanner::chunk::CHUNK_BYTES {
                self.scan(registry, false, &mut emit)?;
                self.bytes_since_scan = 0;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        registry: &Registry,
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        self.scan(registry, true, &mut emit)?;
        self.reset();
        Ok(())
    }

    fn scan(
        &mut self,
        registry: &Registry,
        final_fragment: bool,
        emit: &mut impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        let cutoff = if final_fragment {
            self.window.len()
        } else {
            self.window.len().saturating_sub(PROVIDER_LOOKAHEAD_BYTES)
        };
        let owned_start = usize::try_from(self.next_start.saturating_sub(self.base))
            .map_err(|_| ScanError::CounterOverflow)?;
        if cutoff <= owned_start {
            return Ok(());
        }
        let window = &self.window;
        let base = self.base;
        let mut location_error = false;
        registry.detect_provider_line(window, |rule, span| {
            if span.start < owned_start || span.start >= cutoff {
                return;
            }
            let Some(start) = u64::try_from(span.start)
                .ok()
                .and_then(|value| base.checked_add(value))
            else {
                location_error = true;
                return;
            };
            let Some(end) = u64::try_from(span.end)
                .ok()
                .and_then(|value| base.checked_add(value))
            else {
                location_error = true;
                return;
            };
            emit(Candidate {
                rule,
                span: start..end,
                value: &window[span],
                priority: 0,
            });
        })?;
        if location_error {
            return Err(ScanError::CounterOverflow);
        }
        let cutoff_bytes = u64::try_from(cutoff).map_err(|_| ScanError::CounterOverflow)?;
        let next_start = base
            .checked_add(cutoff_bytes)
            .ok_or(ScanError::CounterOverflow)?;
        if !final_fragment {
            let keep_from = cutoff.saturating_sub(PROVIDER_LOOKAHEAD_BYTES + 1);
            if keep_from > 0 {
                let keep_bytes =
                    u64::try_from(keep_from).map_err(|_| ScanError::CounterOverflow)?;
                self.base = base
                    .checked_add(keep_bytes)
                    .ok_or(ScanError::CounterOverflow)?;
                self.window.drain(..keep_from);
            }
        }
        self.next_start = next_start;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confidence {
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Medium => "Medium confidence",
            Self::High => "High confidence",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuleId {
    AwsAccessKeyId,
    GithubToken,
    StripeSecretKey,
    StripeRestrictedKey,
    SlackWebhook,
    PrivateKeyMarker,
    AwsSecretAccessKey,
    JoseToken,
    ContextSecret,
    PasswordAssignment,
    OpenaiKey,
    OpenrouterKey,
    AnthropicKey,
    GroqKey,
    PerplexityKey,
    HuggingfaceKey,
    XaiKey,
    GoogleApiKey,
    AlibabaKey,
    BaiduKey,
    WandbKey,
    FirecrawlKey,
    LangsmithKey,
    VoyageKey,
    CartesiaKey,
    ReplicateKey,
    VercelKey,
    SupabaseKey,
    CloudflareKey,
    // Phase 1: Prefix-based rules
    DigitalOceanPat,
    DigitalOceanOauth,
    DigitalOceanRefresh,
    DockerSwarmJoin,
    DockerSwarmUnlock,
    HerokuApiKey,
    ClojarsToken,
    CratesioToken,
    PyPiToken,
    RubygemsApiKey,
    SendgridApiKey,
    SendinblueApiKey,
    SlackBotToken,
    SlackUserToken,
    SlackWorkspaceToken,
    SlackRefreshToken,
    TwilioAccountSid,
    TwilioApiKey,
    SentryOrgToken,
    SentryPersonalToken,
    GrafanaServiceAccountToken,
    AxiomToken,
    SonarQubeToken,
    SonarQubeCloudToken,
    KongKonnectToken,
    TruffleHogEnterpriseSecret,
    DopplerToken,
    TailscaleApiToken,
    TailscaleAuthToken,
    ResendApiKey,
    LaunchDarklyServerSdkToken,
    FlagsmithServerToken,
    GrowthBookSecretKey,
    PostHogPersonalToken,
    GitlabCicdJobToken,
    GitlabDeployToken,
    GitlabFeatureFlagToken,
    GitlabPersonalAccessToken,
    GitlabRunnerToken,
    GitlabRunnerRegistrationToken,
    GitlabFeedToken,
    GitlabIncomingMailToken,
    GitlabScimToken,
    GitlabAgentToken,
    GitlabOauthAppSecret,
    GitlabTriggerToken,
    CircleCiPersonalToken,
    CircleCiProjectToken,
    AtlassianApiToken,
    NetlifyAccessToken,
    FlyioToken,
    PineconeApiKey,
    AnthropicAdminKey,
    Auth0ManagementToken,
    OktaAccessToken,
    NotionApiKey,
    LinearApiKey,
    FigmaToken,
    SquareAccessToken,
    ShopifyAccessToken,
    ShopifyCustomToken,
    ShopifySharedSecret,
    ShopifyAppPassword,
    StripePaymentIntent,
    StripeAccessToken,
    MistralKey,
    CerebrasKey,
    TogetheraiKey,
    FireworksAiKey,
    StabilityAiKey,
    DeepgramKey,
    TelegramBotToken,
    RazorpayKey,
    FlutterwaveKey,
    PlanetscalePassword,
    PlanetscaleToken,
    PlanetscaleOauthToken,
    PaddleApiKey,
    PlaidAccessToken,
    CloudinaryUrl,
    // Phase 2: Additional provider patterns from GitHub catalog
    AdafruitIoKey,
    AdobeClientSecret,
    AdobeDeviceToken,
    AdobePacToken,
    AdobeRefreshToken,
    AdobeServiceToken,
    AdobeShortLivedAccessToken,
    AivenAuthToken,
    AivenServicePassword,
    ApiclubApiKey,
    ApifyApiToken,
    AsaasApiToken,
    CanvaAppSecret,
    CloudsmithApiKey,
    DatabentoApiKey,
    DopplerAuditToken,
    GitHubSSHPrivateKey,
    HashiCorpVaultServiceToken,
    AirtablePat,
    AikidoApiClientSecret,
    AikidoCiScanningToken,
    AirtableApiKey,
    BeamerApiKey,
    BitbucketServerPat,
    BitrisePat,
    BitriseWorkspaceApiToken,
    BuildkiteUserAccessToken,
    BuildkiteAgentAccessToken,
    BuildkiteAgentJobToken,
    BuildkiteAgentRegistrationToken,
    BuildkiteClusterToken,
    BuildkiteClusterQueueToken,
    BuildkitePackagesRegistryToken,
    BuildkitePackagesTemporaryToken,
    BuildkitePortalToken,
    BuildkitePortalSecret,
    BlockProtocolApiKey,
    SendinblueSmtpKey,
    CanvaConnectApiSecret,
    CanvaSecret,
    CashfreeApiKey,
    CcdbApiKey,
    CdsCanadaNotifyApiKey,
    CfxreServerKey,
    CheckoutProductionSecretKey,
    CheckoutTestSecretKey,
    ChiefToolsToken,
    ClojarsDeployToken,
    CohereApiKey,
    ContentfulPat,
    ContentfulWebToken,
    ContributedSystemsCredentials,
    CoveoAccessToken,
    CoveoApiKey,
    DatabricksApiToken,
    DatabricksAccountSessionToken,
    DatabricksFederatedAccountSessionToken,
    DatabricksOAuthCode,
    DatabricksOAuthRefreshToken,
    DatabricksOAuthSecretToken,
    DatabricksOAuthSingleUseRefreshTokenChild,
    DatabricksOAuthSingleUseRefreshTokenParent,
    DatabricksScopedApiToken,
    DatabricksScopedInternalToken,
    DatabricksToken,
    DatabricksWorkspaceSessionToken,
    DatadogApiKey,
    DatadogAppKey,
    DatadogPat,
    DatadogRcm,
    DatadogSat,
    DatastaxAstraCsToken,
    DeepseekApiKey,
    AmazonAwsApiKeyId,
    AmazonAwsSessionToken,
    // Batch 9 (part 4): one more generic `aws` keyword-gated sibling, sitting
    // after the two existing `aws` rows so the earlier rules keep winning.
    AmazonAwsTemporaryAccessKeyId,
    AsanaLegacyFormatPersonalAccessToken,
    AsanaPersonalAccessToken,
    AtlassianJwt,
    AuthressServiceClientAccessKey,
    // Batch 8: Azure structural keyword-gated rules. These come before the
    // generic-keyword Azure rules (a later batch), so documented shapes win
    // over any future generic `azure` keyword match.
    AzureDevopsPersonalAccessToken,
    AzureFunctionKey,
    AzureStorageAccountKey,
    AzureCognitiveServicesKey,
    AzureComputerVisionKey,
    AzureAiServicesKey,
    AzureCacheForRedisAccessKey,
    AzureActiveDirectoryApplicationSecret,
    // Batch 9 (part 1): generic `azure` keyword-gated rules. These share the
    // generic keyword table (keyword `azure`, 20-byte minimum value) and run
    // after the structural Azure family, so only undocumentable shapes reach
    // them. Table order is the order declared here: first match wins.
    AzureAnomalyDetectorKey,
    AzureAnomalyDetectorEeKey,
    AzureApimDirectManagementKey,
    AzureApimGatewayKey,
    AzureApimRepositoryKey,
    AzureApimSubscriptionKey,
    AzureAppConfigurationKey,
    AzureAppConfigurationConnectionString,
    AzureBatchKeyIdentifiable,
    AzureCommunicationServicesKey,
    AzureCommunicationServicesConnectionString,
    AzureContainerRegistryKeyIdentifiable,
    AzureContentModeratorKey,
    AzureContentSafetyKey,
    AzureCosmosdbKeyIdentifiable,
    AzureCustomVisionPredictionKey,
    AzureCustomVisionTrainingKey,
    // Batch 9 (part 2): the rest of the generic `azure` keyword-gated family,
    // sharing part 1's keyword gate and 20-byte minimum value length.
    AzureEventGridKeyIdentifiable,
    AzureEventHubKeyIdentifiable,
    AzureFaceKey,
    AzureFluidRelayKey,
    AzureFormRecognizerKey,
    AzureHealthDecisionSupportKey,
    AzureHealthInsightsKey,
    AzureImmersiveReaderKey,
    AzureInternalAllInOneKey,
    AzureIotDeviceConnectionString,
    AzureIotDeviceKey,
    AzureIotDeviceProvisioningKey,
    AzureIotHubConnectionString,
    AzureIotHubKey,
    AzureIotProvisioningConnectionString,
    AzureKnowledgeKey,
    // Batch 14: gap-closing rows from the final coverage diff.
    AzureLogicAppsUrl,
    AzureLuisAuthoringKey,
    // Batch 9 (part 3): the third wave of generic `azure` keyword-gated rules,
    // sharing the `azure` keyword gate and 20-byte minimum value length used by
    // parts 1 and 2. Table order is the order declared here: first match wins.
    AzureLuisKey,
    AzureManagementCertificate,
    AzureMapsKey,
    AzureMetricsAdvisorKey,
    AzureMixedRealityKey,
    AzureMlInferenceIdentifiableKey,
    AzureMlInternalServicePrincipalIdentifiableKey,
    AzureMlWebServiceClassicIdentifiableKey,
    AzureOpenAIKey,
    AzurePersonalizerKey,
    AzureQnaMakerKey,
    AzureQnaMakerV2Key,
    AzureQuantumKey,
    AzureRelayKeyIdentifiable,
    AzureSasToken,
    AzureSearchAdminKey,
    AzureSearchQueryKey,
    AzureServiceBusIdentifiable,
    // Batch 9 (part 4): the fourth wave of generic `azure` keyword-gated rules,
    // sharing the `azure` keyword gate and 20-byte minimum value length used by
    // parts 1-3. Table order is the order declared here: first match wins.
    AzureSignalrConnectionString,
    AzureSignalrKey,
    AzureSpeechServicesKey,
    AzureSpeechTranslationKey,
    AzureSqlInternalDefaultCloudSaKey,
    AzureSqlPassword,
    AzureTextAnalyticsKey,
    AzureTextTranslationKey,
    AzureVideoIntelligenceKey,
    AzureWebAppBotKey,
    AzureWebPubSubConnectionString,
    AzureWebPubSubKey,
    MicrosoftAzureEntraIdToken,
    BitbucketServerPersonalAccessToken,
    DefinedNetworkingNebulaApiKey,
    DevCycleClientApiKey,
    DevCycleMobileApiKey,
    DevCycleServerApiKey,
    DiscordBotToken,
    DockerOrganizationPat,
    DockerPersonalPat,
    DockerSwarmJoinToken,
    DockerSwarmUnlockKey,
    DopplerCliToken,
    DopplerPersonalToken,
    DopplerScimToken,
    DopplerServiceAccountToken,
    DopplerServiceToken,
    DropboxAccessToken,
    DropboxShortLivedAccessToken,
    DuffelLiveAccessToken,
    DuffelTestAccessToken,
    DynatraceApiToken,
    DynatraceInternalToken,
    EasypostProductionApiKey,
    EasypostTestApiKey,
    ElasticCloudApiKey,
    ElasticStackApiKey,
    FacebookAccessToken,
    FastlyApiToken,
    FieldguideApiToken,
    FigmaPat,
    FigmaScimToken,
    FinicityAppKey,
    FirebaseCloudMessagingServerKey,
    FlickrApiKey,
    FlutterwaveLiveApiSecretKey,
    FlutterwaveTestApiSecretKey,
    FrameIoDeveloperToken,
    FrameIoJwt,
    FullStoryApiKey,
    GitLabAccessToken,
    GitLabCICDBuildToken,
    GitLabDeployToken,
    GitLabFeatureFlagClientToken,
    GitLabFeedTokenV2,
    GitLabIncomingEmailToken,
    GitLabKubernetesAgentToken,
    GitLabOAuthAppSecret,
    GitLabPipelineTriggerToken,
    GitLabRunnerAuthToken,
    GitLabRunnerRegistrationToken,
    GitLabScimOAuthToken,
    GoCardlessLiveAccessToken,
    GoCardlessSandboxAccessToken,
    GoogleCloudServiceAccountCredentials,
    GoogleCloudStorageAccessKeySecret,
    GoogleCloudStorageUserAccessKeyId,
    GoogleGcpApiKeyBoundServiceAccount,
    GoogleGeminiApiKey,
    GoogleOAuthAccessToken,
    GoogleOAuthClientId,
    GoogleOAuthClientSecret,
    GoogleOAuthRefreshToken,
    GrafanaCloudApiKey,
    GrafanaCloudApiToken,
    GrafanaProjectApiKey,
    GrafanaProjectServiceAccountToken,
    GroqApiKey,
    GuardsquareAppSweepApiKey,
    GuardsquareCliAccessToken,
    GuardsquareMavenToken,
    HackClubAiKey,
    HashiCorpVaultBatchToken,
    HashiCorpVaultRootServiceToken,
    TerraformApiToken,
    HerokuPlatformApiOAuth2Token,
    HerokuPostgresConnectionUrl,
    HexApiKey,
    HighnoteRkLiveKey,
    HighnoteRkTestKey,
    HighnoteSkLiveKey,
    HighnoteSkTestKey,
    HopBearer,
    HopPat,
    HopPtK,
    HttpBasicAuthenticationHeader,
    HttpBearerAuthenticationHeader,
    HubspotApiKey,
    HubspotPersonalAccessKey,
    HubspotPrivateAppsUserToken,
    HubspotSmtpCredential,
    HuggingFaceOrgApiKey,
    HuggingFaceUserAccessToken,
    IbmCloudIamKey,
    IntercomAccessToken,
    IonicPersonalAccessToken,
    IonicRefreshToken,
    IterativeDvcStudioAccessToken,
    JFrogPlatformAccessToken,
    JFrogPlatformApiKey,
    JFrogPlatformReferenceToken,
    LangChainApiPersonalKey,
    LangChainApiServerKey,
    LangSmithLicenseKey,
    LangSmithScimBearerToken,
    LarkApaasClientSecret,
    LarkAppSecret,
    LarkMcpGrantToken,
    LarkMeegoPluginSecret,
    LarkUserSession,
    LaunchDarklyAccessToken,
    LichessOAuthAccessToken,
    LichessPersonalAccessToken,
    LightspeedXsPat,
    LimbarToken,
    LinearOAuthAccessToken,
    LinkedInClientSecret,
    LobLiveApiKey,
    LobTestApiKey,
    LocalstackApiKey,
    LogicMonitorBearerToken,
    LogicMonitorLmv1AccessKey,
    AmazonOAuthClientId,
    AmazonOAuthClientSecret,
    LovableApiKey,
    MailchimpApiKey,
    MandrillApiKey,
    MailersendApiToken,
    MailersendSmtpPassword,
    MailersendSmtpUsername,
    MailgunApiKey,
    MailgunSmtpCredential,
    MapboxSecretAccessToken,
    MaxMindLicenseKey,
    MerakiApiKey,
    MercuryNonProductionApiToken,
    MercuryProductionApiToken,
    MergifyApplicationKey,
    MessageBirdApiKey,
    PowerAutomateWebhookSAS,
    MidtransProductionServerKey,
    MidtransSandboxServerKey,
    MistralAiApiKey,
    MongoDBAtlasDbUriWithCredentials,
    MongoDBAtlasServiceAccountSecret,
    NaverCloudGovAccessKey,
    NaverCloudGovAccessKeySecret,
    NaverCloudGovSts,
    NaverCloudGovStsSecret,
    NaverCloudPubAccessKey,
    NaverCloudPubAccessKeySecret,
    NaverCloudPubSts,
    NaverCloudPubStsSecret,
    NeonApiKey,
    NeonConnectionUri,
    NetflixNetKey,
    NewRelicInsightsQueryKey,
    NewRelicLicenseKey,
    NewRelicPersonalApiKey,
    NewRelicRestApiKey,
    NotionApiToken,
    NotionIntegrationToken,
    NotionOAuthClientSecret,
    NuGetApiKey,
    OctopusDeployApiKey,
    OculusAccessToken,
    OneChronosApiKey,
    OneChronosEbApiKey,
    OneChronosEbEncryptionKey,
    OneChronosOauthToken,
    OneChronosRefreshToken,
    OnePasswordServiceAccountToken,
    OneSignalRichApiKey,
    OneSignalRichAuthenticationToken,
    OnfidoLiveApiToken,
    OnfidoSandboxApiToken,
    OpenAIApiKey,
    OpenRouterApiKey,
    OpenVSXAccessToken,
    OpenweatherApiKey,
    OracleApiKey,
    OrbitApiToken,
    PaddleSandboxApiKey,
    PagerDutyOAuthSecret,
    PagerDutyOAuthToken,
    PalantirJWT,
    PangeaToken,
    PerplexityApiKey,
    PersonaProductionApiKey,
    PersonaSandboxApiKey,
    PineappleTechnologiesIncidentApiKey,
    PinterestAccessToken,
    PinterestRefreshToken,
    PlanetScaleDatabasePassword,
    PlanetScaleOAuthToken,
    PlanetScaleServiceToken,
    PlanningCenterOAuthAccessToken,
    PlanningCenterOAuthAppSecret,
    PlanningCenterPersonalAccessToken,
    PlivoAuthID,
    PlivoAuthToken,
    // Batch 8: Polar prefix rules (all share the `polar_` prefix; the first
    // enabled entry in dispatch order wins).
    PolarPersonalAccessToken,
    PolarAccessToken,
    PolarRefreshToken,
    PolarAuthorizationCode,
    PolarClientRegistrationToken,
    PolarClientSecret,
    PolarCustomerSessionToken,
    PolarUserSessionToken,
    PostHogFeatureFlagsSecureApiKey,
    PostHogOAuthAccessToken,
    PostHogOAuthRefreshToken,
    PostHogPersonalApiKey,
    PostmanApiKey,
    PostmanCollectionKey,
    PrefectServerApiKey,
    PrefectUserApiKey,
    ProctorioConsumerKey,
    ProctorioLinkageKey,
    ProctorioRegistrationKey,
    ProctorioSecretKey,
    ProofFullAccessApiKey,
    PulumiAccessToken,
    LogfireToken,
    PydanticAIGatewayApiKey,
    PyPiApiToken,
    RainforestApiKey,
    RainforestSandboxApiKey,
    RampClientID,
    RampClientSecret,
    RampOAuthToken,
    RaycastAccessToken,
    ReadMeApiKey,
    ReplicateApiToken,
    RootlyApiKey,
    RunPodApiKey,
    SalesforceAccessToken,
    SalesforceMarketingCloudApiOAuth2Token,
    SalesforceOAuth2ConsumerKey,
    SalesforceOAuth2ConsumerSecret,
    SalesforceRefreshToken,
    SamsaraApiToken,
    SamsaraOAuthAccessToken,
    ScalrApiToken,
    SegmentPublicApiToken,
    SendGridApiKey,
    SentryIntegrationToken,
    SentryOrganizationToken,
    SentryUserAppAuthToken,
    ShippoLiveApiToken,
    ShippoTestApiToken,
    ShopeeOpenPlatformPartnerKey,
    ShopifyAppClientCredentials,
    ShopifyAppClientSecret,
    ShopifyAppSharedSecret,
    ShopifyCustomAppAccessToken,
    ShopifyMarketplaceToken,
    ShopifyMerchantToken,
    ShopifyPartnerApiToken,
    ShopifyPrivateAppPassword,
    SiemensApiToken,
    SiemensCodeToken,
    SindriApiKey,
    SlackApiToken,
    SlackIncomingWebhookURL,
    SlackWorkflowTriggerURL,
    SlackWorkflowWebhookURL,
    SnowflakePostgresConnectionString,
    SnowflakePostgresHost,
    SnowflakePostgresPassword,
    SnowflakeProgrammaticAccessToken,
    SourcegraphAccessToken,
    SourcegraphDotcomUserGateway,
    SourcegraphInstanceIdentifierAccessToken,
    SourcegraphLicenseKeyToken,
    SourcegraphProductSubscriptionToken,
    StarlinkPublicAPIV2Secret,
    SquareProductionApplicationSecret,
    SquareSandboxApplicationSecret,
    SSLMateAPIKey,
    SSLMateClusterSecret,
    StripeApiKey,
    StripeLegacyAPIKey,
    StripeLiveRestrictedKey,
    StripeTestRestrictedKey,
    StripeTestAPISecretKey,
    StripeWebhookSigningSecret,
    SupabaseOAuthAccessToken,
    SupabasePersonalAccessToken,
    SupabaseScopedPersonalAccessToken,
    SupabaseSecretKey,
    TableauPersonalAccessToken,
    TailscaleAPIKey,
    TavilyApiKey,
    TelnyxAPIV2Key,
    TemporalCloudApiKey,
    TencentCloudIntlAccessToken,
    TencentCloudSecretID,
    TencentWeChatAPIAppID,
    TencentWeChatPayToken,
    ThunderstoreIOApiToken,
    TwilioAccessToken,
    TwilioAccountSID,
    TwilioAPIKey,
    TypeformPersonalAccessToken,
    WISEflowAPIKey,
    UnkeyRootKey,
    ValTownApiToken,
    VercelAPIKey,
    VercelAppRefreshToken,
    VercelAppUserAccessToken,
    VercelIntegrationAccessToken,
    VercelPersonalAccessToken,
    VercelSupportAccessToken,
    VolcEngineAccessKeyID,
    VolcEngineArkAPIKey,
    WakaTimeAPIKey,
    WakaTimeAppSecret,
    WakaTimeOAuthAccessToken,
    WakaTimeOAuthRefreshToken,
    WaveProductionAPIKey,
    WaveTestAPIKey,
    WeatherstackAPIKey,
    WandbAPIKey,
    WorkatoDeveloperAPIToken,
    WorkOSProductionAPIKey,
    WorkOSStagingAPIKey,
    WSO2ChoreoPersonalAccessToken,
    YandexCloudAPIKey,
    YandexCloudIAMAccessSecret,
    YandexCloudIAMCookie,
    YandexCloudIAMToken,
    YandexCloudSmartcaptchaServerKey,
    YandexDictionaryAPIKey,
    YandexPassportOAuthToken,
    YandexPredictorAPIKey,
    YandexTranslateAPIKey,
    ZenHubPersonalAPIKey,
    ZuploConsumerAPIKey,
    // Phase 3: URI-based rules
    MongodbUri,
    PostgresUri,
    RedisUri,
    SqlserverUri,
    MysqlUri,
    CockroachdbUri,
    Custom(u16, Severity),
}

pub struct RuleMetadata {
    pub id: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reference: &'static str,
    pub reviewed_on: &'static str,
}

impl RuleId {
    pub fn metadata(self) -> RuleMetadata {
        let (id, description, severity, confidence, reference) = match self {
            Self::AwsSecretAccessKey => (
                "aws-secret-access-key",
                "AWS secret access key assignment",
                Severity::High,
                Confidence::Medium,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            ),
            Self::JoseToken => (
                "jose-token",
                "Compact JOSE structure (not verified)",
                Severity::High,
                Confidence::Medium,
                "https://www.rfc-editor.org/rfc/rfc7515.html",
            ),
            Self::ContextSecret => (
                "context-secret",
                "Context-associated secret",
                Severity::High,
                Confidence::Medium,
                "",
            ),
            Self::PasswordAssignment => (
                "password-assignment",
                "Concrete password assignment",
                Severity::High,
                Confidence::Medium,
                "",
            ),
            Self::AmazonAwsApiKeyId => (
                "amazon-aws-api-key-id",
                "Amazon AWS API key ID",
                Severity::High,
                Confidence::Medium,
                "https://aws.amazon.com/",
            ),
            Self::AmazonAwsSessionToken => (
                "amazon-aws-session-token",
                "Amazon AWS session token",
                Severity::High,
                Confidence::Medium,
                "https://aws.amazon.com/",
            ),
            Self::AmazonAwsTemporaryAccessKeyId => (
                "amazon-aws-temporary-access-key-id",
                "Amazon AWS temporary access key id",
                Severity::High,
                Confidence::Medium,
                "https://aws.amazon.com/",
            ),
            Self::AsanaLegacyFormatPersonalAccessToken => (
                "asana-legacy-format-personal-access-token",
                "Asana legacy format personal access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.asana.com/",
            ),
            Self::AsanaPersonalAccessToken => (
                "asana-personal-access-token",
                "Asana personal access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.asana.com/",
            ),
            Self::AtlassianJwt => (
                "atlassian-jwt",
                "Atlassian JWT",
                Severity::High,
                Confidence::Medium,
                "https://developer.atlassian.com/",
            ),
            Self::AuthressServiceClientAccessKey => (
                "authress-service-client-access-key",
                "Authress service client access key",
                Severity::High,
                Confidence::Medium,
                "https://authress.io/",
            ),
            Self::AzureDevopsPersonalAccessToken => (
                "azure-devops-personal-access-token",
                "Azure DevOps personal access token",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureFunctionKey => (
                "azure-function-key",
                "Azure function key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureStorageAccountKey => (
                "azure-storage-account-key",
                "Azure storage account key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCognitiveServicesKey => (
                "azure-cognitive-services-key",
                "Azure cognitive services key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureComputerVisionKey => (
                "azure-computer-vision-key",
                "Azure computer vision key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureAiServicesKey => (
                "azure-ai-services-key",
                "Azure AI services key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCacheForRedisAccessKey => (
                "azure-cache-for-redis-access-key",
                "Azure cache for Redis access key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureActiveDirectoryApplicationSecret => (
                "azure-active-directory-application-secret",
                "Azure Active Directory application secret",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureAnomalyDetectorKey => (
                "azure-anomaly-detector-key",
                "Azure anomaly detector key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureAnomalyDetectorEeKey => (
                "azure-anomaly-detector-ee-key",
                "Azure anomaly detector enterprise edition key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureApimDirectManagementKey => (
                "azure-apim-direct-management-key",
                "Azure APIM direct management key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureApimGatewayKey => (
                "azure-apim-gateway-key",
                "Azure APIM gateway key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureApimRepositoryKey => (
                "azure-apim-repository-key",
                "Azure APIM repository key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureApimSubscriptionKey => (
                "azure-apim-subscription-key",
                "Azure APIM subscription key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureAppConfigurationKey => (
                "azure-app-configuration-key",
                "Azure App Configuration key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureAppConfigurationConnectionString => (
                "azure-app-configuration-connection-string",
                "Azure App Configuration connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureBatchKeyIdentifiable => (
                "azure-batch-key-identifiable",
                "Azure batch key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCommunicationServicesKey => (
                "azure-communication-services-key",
                "Azure communication services key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCommunicationServicesConnectionString => (
                "azure-communication-services-connection-string",
                "Azure communication services connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureContainerRegistryKeyIdentifiable => (
                "azure-container-registry-key-identifiable",
                "Azure container registry key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureContentModeratorKey => (
                "azure-content-moderator-key",
                "Azure content moderator key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureContentSafetyKey => (
                "azure-content-safety-key",
                "Azure content safety key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCosmosdbKeyIdentifiable => (
                "azure-cosmosdb-key-identifiable",
                "Azure Cosmos DB key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCustomVisionPredictionKey => (
                "azure-custom-vision-prediction-key",
                "Azure custom vision prediction key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureCustomVisionTrainingKey => (
                "azure-custom-vision-training-key",
                "Azure custom vision training key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureEventGridKeyIdentifiable => (
                "azure-event-grid-key-identifiable",
                "Azure Event Grid key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureEventHubKeyIdentifiable => (
                "azure-event-hub-key-identifiable",
                "Azure Event Hub key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureFaceKey => (
                "azure-face-key",
                "Azure face key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureFluidRelayKey => (
                "azure-fluid-relay-key",
                "Azure Fluid Relay key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureFormRecognizerKey => (
                "azure-form-recognizer-key",
                "Azure Form Recognizer key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureHealthDecisionSupportKey => (
                "azure-health-decision-support-key",
                "Azure Health Decision Support key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureHealthInsightsKey => (
                "azure-health-insights-key",
                "Azure Health Insights key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureImmersiveReaderKey => (
                "azure-immersive-reader-key",
                "Azure Immersive Reader key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureInternalAllInOneKey => (
                "azure-internal-all-in-one-key",
                "Azure internal all-in-one key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotDeviceConnectionString => (
                "azure-iot-device-connection-string",
                "Azure IoT device connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotDeviceKey => (
                "azure-iot-device-key",
                "Azure IoT device key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotDeviceProvisioningKey => (
                "azure-iot-device-provisioning-key",
                "Azure IoT device provisioning key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotHubConnectionString => (
                "azure-iot-hub-connection-string",
                "Azure IoT hub connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotHubKey => (
                "azure-iot-hub-key",
                "Azure IoT hub key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureIotProvisioningConnectionString => (
                "azure-iot-provisioning-connection-string",
                "Azure IoT provisioning connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureKnowledgeKey => (
                "azure-knowledge-key",
                "Azure knowledge key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureLuisAuthoringKey => (
                "azure-luis-authoring-key",
                "Azure Luis authoring key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureLuisKey => (
                "azure-luis-key",
                "Azure Luis key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMapsKey => (
                "azure-maps-key",
                "Azure Maps key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMetricsAdvisorKey => (
                "azure-metrics-advisor-key",
                "Azure Metrics Advisor key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMixedRealityKey => (
                "azure-mixed-reality-key",
                "Azure Mixed Reality key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMlInferenceIdentifiableKey => (
                "azure-ml-inference-identifiable-key",
                "Azure ML inference key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMlInternalServicePrincipalIdentifiableKey => (
                "azure-ml-internal-service-principal-identifiable-key",
                "Azure ML internal service principal key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureMlWebServiceClassicIdentifiableKey => (
                "azure-ml-web-service-classic-identifiable-key",
                "Azure ML web service classic key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureOpenAIKey => (
                "azure-openai-key",
                "Azure OpenAI key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzurePersonalizerKey => (
                "azure-personalizer-key",
                "Azure Personalizer key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureQnaMakerKey => (
                "azure-qna-maker-key",
                "Azure QnA Maker key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureQnaMakerV2Key => (
                "azure-qna-maker-v2-key",
                "Azure QnA Maker v2 key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureQuantumKey => (
                "azure-quantum-key",
                "Azure Quantum key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureRelayKeyIdentifiable => (
                "azure-relay-key-identifiable",
                "Azure Relay key (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSasToken => (
                "azure-sas-token",
                "Azure SAS token",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSearchAdminKey => (
                "azure-search-admin-key",
                "Azure Search admin key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSearchQueryKey => (
                "azure-search-query-key",
                "Azure Search query key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureServiceBusIdentifiable => (
                "azure-service-bus-identifiable",
                "Azure Service Bus credential (identifiable)",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSignalrConnectionString => (
                "azure-signalr-connection-string",
                "Azure SignalR connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSignalrKey => (
                "azure-signalr-key",
                "Azure SignalR key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSpeechServicesKey => (
                "azure-speech-services-key",
                "Azure Speech Services key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSpeechTranslationKey => (
                "azure-speech-translation-key",
                "Azure Speech Translation key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSqlInternalDefaultCloudSaKey => (
                "azure-sql-internal-default-cloudsa-key",
                "Azure SQL internal default CloudSA key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureSqlPassword => (
                "azure-sql-password",
                "Azure SQL password",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureTextAnalyticsKey => (
                "azure-text-analytics-key",
                "Azure Text Analytics key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureTextTranslationKey => (
                "azure-text-translation-key",
                "Azure Text Translation key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureVideoIntelligenceKey => (
                "azure-video-intelligence-key",
                "Azure Video Intelligence key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureWebAppBotKey => (
                "azure-web-app-bot-key",
                "Azure Web App Bot key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureWebPubSubConnectionString => (
                "azure-web-pub-sub-connection-string",
                "Azure Web PubSub connection string",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureWebPubSubKey => (
                "azure-web-pub-sub-key",
                "Azure Web PubSub key",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::MicrosoftAzureEntraIdToken => (
                "microsoft-azure-entra-id-token",
                "Microsoft Azure Entra ID token",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureLogicAppsUrl => (
                "azure-logic-apps-url",
                "Azure Logic Apps URL",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::AzureManagementCertificate => (
                "azure-management-certificate",
                "Azure management certificate",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/azure/",
            ),
            Self::BitbucketServerPersonalAccessToken => (
                "bitbucket-server-personal-access-token",
                "Bitbucket Server personal access token",
                Severity::High,
                Confidence::Medium,
                "https://bitbucket.org/",
            ),
            Self::Custom(_, severity) => (
                "custom-rule",
                "Custom rule",
                severity,
                Confidence::Medium,
                "",
            ),
            Self::AwsAccessKeyId => (
                "aws-access-key-id",
                "AWS access key ID (not a secret access key)",
                Severity::Medium,
                Confidence::High,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
            ),
            Self::GithubToken => (
                "github-token",
                "GitHub token signature",
                Severity::High,
                Confidence::Medium,
                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
            ),
            Self::StripeSecretKey => (
                "stripe-secret-key",
                "Stripe secret key signature",
                Severity::High,
                Confidence::Medium,
                "https://docs.stripe.com/keys",
            ),
            Self::StripeRestrictedKey => (
                "stripe-restricted-key",
                "Stripe restricted key signature",
                Severity::High,
                Confidence::Medium,
                "https://docs.stripe.com/keys",
            ),
            Self::SlackWebhook => (
                "slack-webhook",
                "Slack incoming webhook URL",
                Severity::High,
                Confidence::Medium,
                "https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/",
            ),
            Self::PrivateKeyMarker => (
                "private-key-marker",
                "Private key header (marker only)",
                Severity::Critical,
                Confidence::Medium,
                "https://www.rfc-editor.org/rfc/rfc7468.html",
            ),
            Self::OpenaiKey => (
                "openai-key",
                "OpenAI API key",
                Severity::High,
                Confidence::Medium,
                "https://platform.openai.com/api-keys",
            ),
            Self::OpenrouterKey => (
                "openrouter-key",
                "OpenRouter API key",
                Severity::High,
                Confidence::Medium,
                "https://openrouter.ai/docs/api_reference/authentication",
            ),
            Self::AnthropicKey => (
                "anthropic-key",
                "Anthropic API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.anthropic.com/en/api/getting-started-with-the-api",
            ),
            Self::GroqKey => (
                "groq-key",
                "Groq API key",
                Severity::High,
                Confidence::Medium,
                "https://console.groq.com/docs/api-reference",
            ),
            Self::PerplexityKey => (
                "perplexity-key",
                "Perplexity API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.perplexity.ai/docs/getting-started",
            ),
            Self::HuggingfaceKey => (
                "huggingface-key",
                "Hugging Face API token",
                Severity::High,
                Confidence::Medium,
                "https://huggingface.co/docs/hub/security-tokens",
            ),
            Self::XaiKey => (
                "xai-key",
                "xAI/Grok API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.x.ai/developers/quickstart",
            ),
            Self::GoogleApiKey => (
                "google-api-key",
                "Google API key (Gemini)",
                Severity::High,
                Confidence::Medium,
                "https://ai.google.dev/gemini-api/docs/api-key",
            ),
            Self::AlibabaKey => (
                "alibaba-key",
                "Alibaba Cloud API key (Tongyi/Qwen)",
                Severity::High,
                Confidence::Medium,
                "https://www.alibabacloud.com/help/en/model-studio/get-api-key",
            ),
            Self::BaiduKey => (
                "baidu-key",
                "Baidu API key (Ernie Bot)",
                Severity::High,
                Confidence::Medium,
                "https://cloud.baidu.com/doc/QIANFAN/s/Yl4i8xj2y",
            ),
            Self::WandbKey => (
                "wandb-key",
                "Weights & Biases API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.wandb.ai/models/articles/how-do-i-find-my-api-key",
            ),
            Self::FirecrawlKey => (
                "firecrawl-key",
                "Firecrawl API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.firecrawl.dev/introduction",
            ),
            Self::LangsmithKey => (
                "langsmith-key",
                "LangSmith API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.langchain.com/langsmith/create-account-api-key",
            ),
            Self::VoyageKey => (
                "voyage-key",
                "Voyage AI API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.voyageai.com/docs/faq",
            ),
            Self::CartesiaKey => (
                "cartesia-key",
                "Cartesia AI API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.cartesia.ai/use-the-api/api-conventions",
            ),
            Self::ReplicateKey => (
                "replicate-key",
                "Replicate API key",
                Severity::High,
                Confidence::Medium,
                "https://replicate.com/docs/topics/security/api-tokens",
            ),
            Self::VercelKey => (
                "vercel-key",
                "Vercel API token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/docs/accounts/access-tokens",
            ),
            Self::SupabaseKey => (
                "supabase-key",
                "Supabase API key",
                Severity::High,
                Confidence::Medium,
                "https://supabase.com/docs/guides/getting-started/api-keys",
            ),
            Self::CloudflareKey => (
                "cloudflare-key",
                "Cloudflare API token",
                Severity::High,
                Confidence::Medium,
                "https://developers.cloudflare.com/fundamentals/api/get-started/token-formats",
            ),
            // Phase 2: Additional provider patterns from GitHub catalog
            Self::AdafruitIoKey => (
                "adafruit-io-key",
                "Adafruit.IO key",
                Severity::High,
                Confidence::Medium,
                "https://www.adafruit.com/make",
            ),
            Self::AdobeClientSecret => (
                "adobe-client-secret",
                "Adobe OAuth Web Client Secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.adobe.com/developer-console/docs/guides/authentication/",
            ),
            Self::AdobeDeviceToken => (
                "adobe-device-token",
                "Adobe device token",
                Severity::High,
                Confidence::Medium,
                "https://helpx.adobe.com/",
            ),
            Self::AdobePacToken => (
                "adobe-pac-token",
                "Adobe PAC token",
                Severity::High,
                Confidence::Medium,
                "https://helpx.adobe.com/",
            ),
            Self::AdobeRefreshToken => (
                "adobe-refresh-token",
                "Adobe refresh token",
                Severity::High,
                Confidence::Medium,
                "https://helpx.adobe.com/",
            ),
            Self::AdobeServiceToken => (
                "adobe-service-token",
                "Adobe service token",
                Severity::High,
                Confidence::Medium,
                "https://helpx.adobe.com/",
            ),
            Self::AdobeShortLivedAccessToken => (
                "adobe-short-lived-access-token",
                "Adobe short-lived access token",
                Severity::High,
                Confidence::Medium,
                "https://helpx.adobe.com/",
            ),
            Self::AivenAuthToken => (
                "aiven-auth-token",
                "Aiven authentication token",
                Severity::High,
                Confidence::Medium,
                "https://aiven.io/docs/",
            ),
            Self::AivenServicePassword => (
                "aiven-service-password",
                "Aiven service password",
                Severity::High,
                Confidence::Medium,
                "https://aiven.io/docs/",
            ),
            Self::ApifyApiToken => (
                "apify-api-token",
                "Apify API token",
                Severity::High,
                Confidence::Medium,
                "https://docs.apify.com/",
            ),
            Self::ApiclubApiKey => (
                "apiclub-api-key",
                "APIclub API key",
                Severity::High,
                Confidence::Medium,
                "https://api.club/",
            ),
            Self::AsaasApiToken => (
                "asaas-api-token",
                "Asaas API token",
                Severity::High,
                Confidence::Medium,
                "https://asaas.com/",
            ),
            Self::CanvaAppSecret => (
                "canva-app-secret",
                "Canva app secret",
                Severity::High,
                Confidence::Medium,
                "https://www.canva.dev/docs/",
            ),
            Self::CloudsmithApiKey => (
                "cloudsmith-api-key",
                "Cloudsmith API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.cloudsmith.com/",
            ),
            Self::DatabentoApiKey => (
                "databento-api-key",
                "Databento API key",
                Severity::High,
                Confidence::Medium,
                "https://databento.com/",
            ),
            Self::DopplerAuditToken => (
                "doppler-audit-token",
                "Doppler audit token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::GitHubSSHPrivateKey => (
                "github-ssh-private-key",
                "GitHub SSH private key",
                Severity::Critical,
                Confidence::Medium,
                "https://docs.github.com/",
            ),
            Self::HashiCorpVaultServiceToken => (
                "hashicorp-vault-service-token",
                "HashiCorp Vault service token",
                Severity::High,
                Confidence::Medium,
                "https://developer.hashicorp.com/vault/docs/",
            ),
            Self::AirtablePat => (
                "airtable-pat",
                "Airtable personal access token",
                Severity::High,
                Confidence::Medium,
                "https://airtable.com/developers/web/api/authentication",
            ),
            Self::AikidoApiClientSecret => (
                "aikido-api-client-secret",
                "Aikido API client secret",
                Severity::High,
                Confidence::Medium,
                "https://aikido.dev/",
            ),
            Self::AikidoCiScanningToken => (
                "aikido-ci-scanning-token",
                "Aikido CI scanning token",
                Severity::High,
                Confidence::Medium,
                "https://aikido.dev/",
            ),
            Self::AirtableApiKey => (
                "airtable-api-key",
                "Airtable API key",
                Severity::High,
                Confidence::Medium,
                "https://airtable.com/developers/web/api/authentication",
            ),
            Self::BitbucketServerPat => (
                "bitbucket-server-pat",
                "Bitbucket Server personal access token",
                Severity::High,
                Confidence::Medium,
                "https://confluence.atlassian.com/bitbucketserver/",
            ),
            Self::BitrisePat => (
                "bitrise-pat",
                "Bitrise personal access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.bitrise.io/",
            ),
            Self::BitriseWorkspaceApiToken => (
                "bitrise-workspace-api-token",
                "Bitrise workspace API token",
                Severity::High,
                Confidence::Medium,
                "https://docs.bitrise.io/",
            ),
            Self::BeamerApiKey => (
                "beamer-api-key",
                "Beamer API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.beamer.shop/",
            ),
            Self::BuildkiteUserAccessToken => (
                "buildkite-user-access-token",
                "Buildkite user access token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkiteAgentAccessToken => (
                "buildkite-agent-access-token",
                "Buildkite agent access token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkiteAgentJobToken => (
                "buildkite-agent-job-token",
                "Buildkite agent job token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkiteAgentRegistrationToken => (
                "buildkite-agent-registration-token",
                "Buildkite agent registration token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkiteClusterToken => (
                "buildkite-cluster-token",
                "Buildkite cluster token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkiteClusterQueueToken => (
                "buildkite-cluster-queue-token",
                "Buildkite cluster queue token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkitePackagesRegistryToken => (
                "buildkite-packages-registry-token",
                "Buildkite packages registry token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkitePackagesTemporaryToken => (
                "buildkite-packages-temporary-token",
                "Buildkite packages temporary token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkitePortalToken => (
                "buildkite-portal-token",
                "Buildkite portal token",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BuildkitePortalSecret => (
                "buildkite-portal-secret",
                "Buildkite portal secret",
                Severity::High,
                Confidence::Medium,
                "https://registrydocs.buildkite.com/",
            ),
            Self::BlockProtocolApiKey => (
                "block-protocol-api-key",
                "Block Protocol API key",
                Severity::High,
                Confidence::Medium,
                "https://blockprotocol.org/",
            ),
            Self::SendinblueSmtpKey => (
                "sendinblue-smtp-key",
                "Sendinblue (Brevo) SMTP key",
                Severity::High,
                Confidence::Medium,
                "https://developers.brevo.com/",
            ),
            Self::CanvaConnectApiSecret => (
                "canva-connect-api-secret",
                "Canva Connect API secret",
                Severity::High,
                Confidence::Medium,
                "https://www.canva.dev/docs/",
            ),
            Self::CanvaSecret => (
                "canva-secret",
                "Canva secret",
                Severity::High,
                Confidence::Medium,
                "https://www.canva.dev/docs/",
            ),
            Self::CashfreeApiKey => (
                "cashfree-api-key",
                "Cashfree API key",
                Severity::High,
                Confidence::Medium,
                "https://cashfree.com/",
            ),
            Self::CcdbApiKey => (
                "ccdb-api-key",
                "Cockroach Labs API key",
                Severity::High,
                Confidence::Medium,
                "https://www.cockroachlabs.com/docs/",
            ),
            Self::CdsCanadaNotifyApiKey => (
                "cds-canada-notify-api-key",
                "CDS Canada Notify API key",
                Severity::High,
                Confidence::Medium,
                "https://www.cds.canada.ca/",
            ),
            Self::CfxreServerKey => (
                "cfxre-server-key",
                "Cfx.re server key",
                Severity::High,
                Confidence::Medium,
                "https://www.cfx.re/",
            ),
            Self::CheckoutProductionSecretKey => (
                "checkout-production-secret-key",
                "Checkout.com production secret key",
                Severity::High,
                Confidence::Medium,
                "https://docs.checkout.com/",
            ),
            Self::CheckoutTestSecretKey => (
                "checkout-test-secret-key",
                "Checkout.com test secret key",
                Severity::High,
                Confidence::Medium,
                "https://docs.checkout.com/",
            ),
            Self::ChiefToolsToken => (
                "chief-tools-token",
                "Chief Tools token",
                Severity::High,
                Confidence::Medium,
                "https://chieflive.com/",
            ),
            Self::ClojarsDeployToken => (
                "clojars-deploy-token",
                "Clojars deploy token",
                Severity::High,
                Confidence::Medium,
                "https://clojars.org/",
            ),
            Self::CohereApiKey => (
                "cohere-api-key",
                "Cohere API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.cohere.com/",
            ),
            Self::ContentfulPat => (
                "contentful-pat",
                "Contentful personal access token",
                Severity::High,
                Confidence::Medium,
                "https://www.contentful.com/developers/docs/",
            ),
            Self::ContentfulWebToken => (
                "contentful-web-token",
                "Contentful web token",
                Severity::High,
                Confidence::Medium,
                "https://www.contentful.com/developers/docs/",
            ),
            Self::ContributedSystemsCredentials => (
                "contributed-systems-credentials",
                "Contributed Systems credentials",
                Severity::High,
                Confidence::Medium,
                "https://contributed.io/",
            ),
            Self::CoveoAccessToken => (
                "coveo-access-token",
                "Coveo access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.coveo.com/",
            ),
            Self::CoveoApiKey => (
                "coveo-api-key",
                "Coveo API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.coveo.com/",
            ),
            Self::DatabricksApiToken => (
                "databricks-api-token",
                "Databricks API token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksAccountSessionToken => (
                "databricks-account-session-token",
                "Databricks account session token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksFederatedAccountSessionToken => (
                "databricks-federated-account-session-token",
                "Databricks federated account session token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksOAuthCode => (
                "databricks-oauth-code",
                "Databricks OAuth code",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksOAuthRefreshToken => (
                "databricks-oauth-refresh-token",
                "Databricks OAuth refresh token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksOAuthSecretToken => (
                "databricks-oauth-secret-token",
                "Databricks OAuth secret token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksOAuthSingleUseRefreshTokenChild => (
                "databricks-oauth-single-use-refresh-token-child",
                "Databricks OAuth single use refresh token child",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksOAuthSingleUseRefreshTokenParent => (
                "databricks-oauth-single-use-refresh-token-parent",
                "Databricks OAuth single use refresh token parent",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksScopedApiToken => (
                "databricks-scoped-api-token",
                "Databricks scoped API token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksScopedInternalToken => (
                "databricks-scoped-internal-token",
                "Databricks scoped internal token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksToken => (
                "databricks-token",
                "Databricks token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatabricksWorkspaceSessionToken => (
                "databricks-workspace-session-token",
                "Databricks workspace session token",
                Severity::High,
                Confidence::Medium,
                "https://docs.databricks.com/",
            ),
            Self::DatadogApiKey => (
                "datadog-api-key",
                "Datadog API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.datadoghq.com/",
            ),
            Self::DatadogAppKey => (
                "datadog-app-key",
                "Datadog application key",
                Severity::High,
                Confidence::Medium,
                "https://docs.datadoghq.com/",
            ),
            Self::DatadogPat => (
                "datadog-pat",
                "Datadog personal access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.datadoghq.com/",
            ),
            Self::DatadogRcm => (
                "datadog-rcm",
                "Datadog RCM",
                Severity::High,
                Confidence::Medium,
                "https://docs.datadoghq.com/",
            ),
            Self::DatadogSat => (
                "datadog-sat",
                "Datadog service account token",
                Severity::High,
                Confidence::Medium,
                "https://docs.datadoghq.com/",
            ),
            Self::DatastaxAstraCsToken => (
                "datastax-astracs-token",
                "DataStax AstraCS token",
                Severity::High,
                Confidence::Medium,
                "https://docs.datastax.com/",
            ),
            Self::DeepseekApiKey => (
                "deepseek-api-key",
                "DeepSeek API key",
                Severity::High,
                Confidence::Medium,
                "https://deepseek.com/",
            ),
            Self::DefinedNetworkingNebulaApiKey => (
                "defined-networking-nebula-api-key",
                "Defined Networking Nebula API key",
                Severity::High,
                Confidence::Medium,
                "https://definednetworking.com/",
            ),
            Self::DevCycleClientApiKey => (
                "devcycle-client-api-key",
                "DevCycle client API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.devcycle.com/",
            ),
            Self::DevCycleMobileApiKey => (
                "devcycle-mobile-api-key",
                "DevCycle mobile API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.devcycle.com/",
            ),
            Self::DevCycleServerApiKey => (
                "devcycle-server-api-key",
                "DevCycle server API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.devcycle.com/",
            ),
            Self::DiscordBotToken => (
                "discord-bot-token",
                "Discord bot token",
                Severity::High,
                Confidence::Medium,
                "https://discord.com/developers/docs/",
            ),
            Self::DockerOrganizationPat => (
                "docker-organization-pat",
                "Docker organization access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.docker.com/",
            ),
            Self::DockerPersonalPat => (
                "docker-personal-pat",
                "Docker personal access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.docker.com/",
            ),
            Self::DockerSwarmJoinToken => (
                "docker-swarm-join-token",
                "Docker Swarm join token",
                Severity::High,
                Confidence::Medium,
                "https://docs.docker.com/",
            ),
            Self::DockerSwarmUnlockKey => (
                "docker-swarm-unlock-key",
                "Docker Swarm unlock key",
                Severity::Critical,
                Confidence::Medium,
                "https://docs.docker.com/",
            ),
            Self::DopplerCliToken => (
                "doppler-cli-token",
                "Doppler CLI token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::DopplerPersonalToken => (
                "doppler-personal-token",
                "Doppler personal token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::DopplerScimToken => (
                "doppler-scim-token",
                "Doppler SCIM token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::DopplerServiceAccountToken => (
                "doppler-service-account-token",
                "Doppler service account token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::DopplerServiceToken => (
                "doppler-service-token",
                "Doppler service token",
                Severity::High,
                Confidence::Medium,
                "https://docs.doppler.com/",
            ),
            Self::DropboxAccessToken => (
                "dropbox-access-token",
                "Dropbox access token",
                Severity::High,
                Confidence::Medium,
                "https://www.dropbox.com/developers/",
            ),
            Self::DropboxShortLivedAccessToken => (
                "dropbox-short-lived-access-token",
                "Dropbox short-lived access token",
                Severity::High,
                Confidence::Medium,
                "https://www.dropbox.com/developers/",
            ),
            Self::DuffelLiveAccessToken => (
                "duffel-live-access-token",
                "Duffel live access token",
                Severity::High,
                Confidence::Medium,
                "https://duffel.com/",
            ),
            Self::DuffelTestAccessToken => (
                "duffel-test-access-token",
                "Duffel test access token",
                Severity::High,
                Confidence::Medium,
                "https://duffel.com/",
            ),
            Self::DynatraceApiToken => (
                "dynatrace-api-token",
                "Dynatrace API token",
                Severity::High,
                Confidence::Medium,
                "https://www.dynatrace.com/",
            ),
            Self::DynatraceInternalToken => (
                "dynatrace-internal-token",
                "Dynatrace internal token",
                Severity::High,
                Confidence::Medium,
                "https://www.dynatrace.com/",
            ),
            Self::EasypostProductionApiKey => (
                "easypost-production-api-key",
                "EasyPost production API key",
                Severity::High,
                Confidence::Medium,
                "https://www.easypost.com/",
            ),
            Self::EasypostTestApiKey => (
                "easypost-test-api-key",
                "EasyPost test API key",
                Severity::High,
                Confidence::Medium,
                "https://www.easypost.com/",
            ),
            Self::ElasticCloudApiKey => (
                "elastic-cloud-api-key",
                "Elastic Cloud API key",
                Severity::High,
                Confidence::Medium,
                "https://www.elastic.co/",
            ),
            Self::ElasticStackApiKey => (
                "elastic-stack-api-key",
                "Elastic Stack API key",
                Severity::High,
                Confidence::Medium,
                "https://www.elastic.co/",
            ),
            Self::FacebookAccessToken => (
                "facebook-access-token",
                "Facebook access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.facebook.com/",
            ),
            Self::FastlyApiToken => (
                "fastly-api-token",
                "Fastly API token",
                Severity::High,
                Confidence::Medium,
                "https://developer.fastly.com/",
            ),
            Self::FieldguideApiToken => (
                "fieldguide-api-token",
                "Fieldguide API token",
                Severity::High,
                Confidence::Medium,
                "https://fieldguide.io/",
            ),
            Self::FigmaPat => (
                "figma-pat",
                "Figma personal access token",
                Severity::High,
                Confidence::Medium,
                "https://www.figma.com/developers/",
            ),
            Self::FigmaScimToken => (
                "figma-scim-token",
                "Figma SCIM API token",
                Severity::High,
                Confidence::Medium,
                "https://www.figma.com/developers/",
            ),
            Self::FinicityAppKey => (
                "finicity-app-key",
                "Finicity app key",
                Severity::High,
                Confidence::Medium,
                "https://finicity.com/",
            ),
            Self::FirebaseCloudMessagingServerKey => (
                "firebase-cloud-messaging-server-key",
                "Firebase Cloud Messaging server key",
                Severity::High,
                Confidence::Medium,
                "https://firebase.google.com/",
            ),
            Self::FlickrApiKey => (
                "flickr-api-key",
                "Flickr API key",
                Severity::High,
                Confidence::Medium,
                "https://www.flickr.com/services/api/",
            ),
            Self::FlutterwaveLiveApiSecretKey => (
                "flutterwave-live-api-secret-key",
                "Flutterwave live API secret key",
                Severity::High,
                Confidence::Medium,
                "https://developer.flutterwave.com/",
            ),
            Self::FlutterwaveTestApiSecretKey => (
                "flutterwave-test-api-secret-key",
                "Flutterwave test API secret key",
                Severity::High,
                Confidence::Medium,
                "https://developer.flutterwave.com/",
            ),
            Self::FrameIoDeveloperToken => (
                "frame-io-developer-token",
                "Frame.io developer token",
                Severity::High,
                Confidence::Medium,
                "https://frame.io/",
            ),
            Self::FrameIoJwt => (
                "frame-io-jwt",
                "Frame.io JSON Web Token",
                Severity::High,
                Confidence::Medium,
                "https://frame.io/",
            ),
            Self::FullStoryApiKey => (
                "fullstory-api-key",
                "FullStory API key",
                Severity::High,
                Confidence::Medium,
                "https://www.fullstory.com/",
            ),
            Self::GitLabAccessToken => (
                "gitlab-access-token",
                "GitLab access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabCICDBuildToken => (
                "gitlab-cicd-build-token",
                "GitLab CI/CD build token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabDeployToken => (
                "gitlab-deploy-token",
                "GitLab deploy token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabFeatureFlagClientToken => (
                "gitlab-feature-flag-client-token",
                "GitLab feature flag client token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabFeedTokenV2 => (
                "gitlab-feed-token-v2",
                "GitLab feed token v2",
                Severity::Medium,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabIncomingEmailToken => (
                "gitlab-incoming-email-token",
                "GitLab incoming email token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabKubernetesAgentToken => (
                "gitlab-kubernetes-agent-token",
                "GitLab Kubernetes agent token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabOAuthAppSecret => (
                "gitlab-oauth-app-secret",
                "GitLab OAuth application secret",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabPipelineTriggerToken => (
                "gitlab-pipeline-trigger-token",
                "GitLab pipeline trigger token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabRunnerAuthToken => (
                "gitlab-runner-auth-token",
                "GitLab runner authentication token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabRunnerRegistrationToken => (
                "gitlab-runner-registration-token",
                "GitLab runner registration token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GitLabScimOAuthToken => (
                "gitlab-scim-oauth-token",
                "GitLab SCIM OAuth token",
                Severity::High,
                Confidence::Medium,
                "https://docs.gitlab.com/",
            ),
            Self::GoCardlessLiveAccessToken => (
                "gocardless-live-access-token",
                "GoCardless live access token",
                Severity::High,
                Confidence::Medium,
                "https://gocardless.com/",
            ),
            Self::GoCardlessSandboxAccessToken => (
                "gocardless-sandbox-access-token",
                "GoCardless sandbox access token",
                Severity::High,
                Confidence::Medium,
                "https://gocardless.com/",
            ),
            Self::GoogleCloudServiceAccountCredentials => (
                "google-cloud-service-account-credentials",
                "Google Cloud service account credentials",
                Severity::High,
                Confidence::Medium,
                "https://cloud.google.com/",
            ),
            Self::GoogleCloudStorageAccessKeySecret => (
                "google-cloud-storage-access-key-secret",
                "Google Cloud Storage access key secret",
                Severity::High,
                Confidence::Medium,
                "https://cloud.google.com/storage/",
            ),
            Self::GoogleCloudStorageUserAccessKeyId => (
                "google-cloud-storage-user-access-key-id",
                "Google Cloud Storage user access key ID",
                Severity::High,
                Confidence::Medium,
                "https://cloud.google.com/storage/",
            ),
            Self::GoogleGcpApiKeyBoundServiceAccount => (
                "google-gcp-api-key-bound-service-account",
                "Google GCP API key bound to service account",
                Severity::High,
                Confidence::Medium,
                "https://cloud.google.com/",
            ),
            Self::GoogleGeminiApiKey => (
                "google-gemini-api-key",
                "Google Gemini API key",
                Severity::High,
                Confidence::Medium,
                "https://ai.google.dev/",
            ),
            Self::GoogleOAuthAccessToken => (
                "google-oauth-access-token",
                "Google OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.google.com/",
            ),
            Self::GoogleOAuthClientId => (
                "google-oauth-client-id",
                "Google OAuth client ID",
                Severity::High,
                Confidence::Medium,
                "https://developers.google.com/",
            ),
            Self::GoogleOAuthClientSecret => (
                "google-oauth-client-secret",
                "Google OAuth client secret",
                Severity::High,
                Confidence::Medium,
                "https://developers.google.com/",
            ),
            Self::GoogleOAuthRefreshToken => (
                "google-oauth-refresh-token",
                "Google OAuth refresh token",
                Severity::High,
                Confidence::Medium,
                "https://developers.google.com/",
            ),
            Self::GrafanaCloudApiKey => (
                "grafana-cloud-api-key",
                "Grafana Cloud API key",
                Severity::High,
                Confidence::Medium,
                "https://grafana.com/",
            ),
            Self::GrafanaCloudApiToken => (
                "grafana-cloud-api-token",
                "Grafana Cloud API token",
                Severity::High,
                Confidence::Medium,
                "https://grafana.com/",
            ),
            Self::GrafanaProjectApiKey => (
                "grafana-project-api-key",
                "Grafana project API key",
                Severity::High,
                Confidence::Medium,
                "https://grafana.com/",
            ),
            Self::GrafanaProjectServiceAccountToken => (
                "grafana-project-service-account-token",
                "Grafana project service account token",
                Severity::High,
                Confidence::Medium,
                "https://grafana.com/",
            ),
            Self::GroqApiKey => (
                "groq-api-key",
                "Groq API key",
                Severity::High,
                Confidence::Medium,
                "https://console.groq.com/",
            ),
            Self::GuardsquareAppSweepApiKey => (
                "guardsquare-appsweep-api-key",
                "GuardSquare AppSweep API key",
                Severity::High,
                Confidence::Medium,
                "https://www.guardsquare.com/",
            ),
            Self::GuardsquareCliAccessToken => (
                "guardsquare-cli-access-token",
                "GuardSquare CLI access token",
                Severity::High,
                Confidence::Medium,
                "https://www.guardsquare.com/",
            ),
            Self::GuardsquareMavenToken => (
                "guardsquare-maven-token",
                "GuardSquare Maven token",
                Severity::High,
                Confidence::Medium,
                "https://www.guardsquare.com/",
            ),
            Self::HackClubAiKey => (
                "hack-club-ai-key",
                "Hack Club AI key",
                Severity::High,
                Confidence::Medium,
                "https://hackclub.com/",
            ),
            Self::HashiCorpVaultBatchToken => (
                "hashicorp-vault-batch-token",
                "HashiCorp Vault batch token",
                Severity::High,
                Confidence::Medium,
                "https://developer.hashicorp.com/vault/docs/",
            ),
            Self::HashiCorpVaultRootServiceToken => (
                "hashicorp-vault-root-service-token",
                "HashiCorp Vault root service token",
                Severity::High,
                Confidence::Medium,
                "https://developer.hashicorp.com/vault/docs/",
            ),
            Self::TerraformApiToken => (
                "terraform-api-token",
                "Terraform Cloud/Enterprise API token",
                Severity::High,
                Confidence::Medium,
                "https://developer.hashicorp.com/terraform/cloud-docs/",
            ),
            Self::HerokuPlatformApiOAuth2Token => (
                "heroku-platform-api-oauth2-token",
                "Heroku platform API OAuth2 token",
                Severity::High,
                Confidence::Medium,
                "https://devcenter.heroku.com/",
            ),
            Self::HerokuPostgresConnectionUrl => (
                "heroku-postgres-connection-url",
                "Heroku Postgres connection URL",
                Severity::High,
                Confidence::Medium,
                "https://devcenter.heroku.com/",
            ),
            Self::HexApiKey => (
                "hex-api-key",
                "Hex API key",
                Severity::High,
                Confidence::Medium,
                "https://hex.pm/",
            ),
            Self::HighnoteRkLiveKey => (
                "highnote-rk-live-key",
                "Highnote RK live key",
                Severity::High,
                Confidence::Medium,
                "https://highnote.com/",
            ),
            Self::HighnoteRkTestKey => (
                "highnote-rk-test-key",
                "Highnote RK test key",
                Severity::High,
                Confidence::Medium,
                "https://highnote.com/",
            ),
            Self::HighnoteSkLiveKey => (
                "highnote-sk-live-key",
                "Highnote SK live key",
                Severity::High,
                Confidence::Medium,
                "https://highnote.com/",
            ),
            Self::HighnoteSkTestKey => (
                "highnote-sk-test-key",
                "Highnote SK test key",
                Severity::High,
                Confidence::Medium,
                "https://highnote.com/",
            ),
            Self::HopBearer => (
                "hop-bearer",
                "HOP bearer token",
                Severity::High,
                Confidence::Medium,
                "https://hop.dev/",
            ),
            Self::HopPat => (
                "hop-pat",
                "HOP PAT",
                Severity::High,
                Confidence::Medium,
                "https://hop.dev/",
            ),
            Self::HopPtK => (
                "hop-ptk",
                "HOP PTK",
                Severity::High,
                Confidence::Medium,
                "https://hop.dev/",
            ),
            Self::HttpBasicAuthenticationHeader => (
                "http-basic-authentication-header",
                "HTTP Basic authentication header credentials",
                Severity::Medium,
                Confidence::Medium,
                "https://datatracker.ietf.org/doc/html/rfc7617/",
            ),
            Self::HttpBearerAuthenticationHeader => (
                "http-bearer-authentication-header",
                "HTTP Bearer authentication header token",
                Severity::Medium,
                Confidence::Medium,
                "https://datatracker.ietf.org/doc/html/rfc6750/",
            ),
            Self::HubspotApiKey => (
                "hubspot-api-key",
                "HubSpot API key",
                Severity::High,
                Confidence::Medium,
                "https://developers.hubspot.com/",
            ),
            Self::HubspotPersonalAccessKey => (
                "hubspot-personal-access-key",
                "HubSpot personal access key",
                Severity::High,
                Confidence::Medium,
                "https://developers.hubspot.com/",
            ),
            Self::HubspotPrivateAppsUserToken => (
                "hubspot-private-apps-user-token",
                "HubSpot private apps user token",
                Severity::High,
                Confidence::Medium,
                "https://developers.hubspot.com/",
            ),
            Self::HubspotSmtpCredential => (
                "hubspot-smtp-credential",
                "HubSpot SMTP credential",
                Severity::High,
                Confidence::Medium,
                "https://developers.hubspot.com/",
            ),
            Self::HuggingFaceOrgApiKey => (
                "huggingface-org-api-key",
                "Hugging Face organization API key",
                Severity::High,
                Confidence::Medium,
                "https://huggingface.co/",
            ),
            Self::HuggingFaceUserAccessToken => (
                "huggingface-user-access-token",
                "Hugging Face user access token",
                Severity::High,
                Confidence::Medium,
                "https://huggingface.co/",
            ),
            Self::IbmCloudIamKey => (
                "ibm-cloud-iam-key",
                "IBM Cloud IAM key",
                Severity::High,
                Confidence::Medium,
                "https://cloud.ibm.com/",
            ),
            Self::IntercomAccessToken => (
                "intercom-access-token",
                "Intercom access token",
                Severity::High,
                Confidence::Medium,
                "https://www.intercom.com/",
            ),
            Self::IonicPersonalAccessToken => (
                "ionic-personal-access-token",
                "Ionic personal access token",
                Severity::High,
                Confidence::Medium,
                "https://ionic.io/",
            ),
            Self::IonicRefreshToken => (
                "ionic-refresh-token",
                "Ionic refresh token",
                Severity::High,
                Confidence::Medium,
                "https://ionic.io/",
            ),
            Self::IterativeDvcStudioAccessToken => (
                "iterative-dvc-studio-access-token",
                "Iterative DVC Studio access token",
                Severity::High,
                Confidence::Medium,
                "https://iterative.ai/",
            ),
            Self::JFrogPlatformAccessToken => (
                "jfrog-platform-access-token",
                "JFrog platform access token",
                Severity::High,
                Confidence::Medium,
                "https://jfrog.com/",
            ),
            Self::JFrogPlatformApiKey => (
                "jfrog-platform-api-key",
                "JFrog platform API key",
                Severity::High,
                Confidence::Medium,
                "https://jfrog.com/",
            ),
            Self::JFrogPlatformReferenceToken => (
                "jfrog-platform-reference-token",
                "JFrog platform reference token",
                Severity::High,
                Confidence::Medium,
                "https://jfrog.com/",
            ),
            Self::LangChainApiPersonalKey => (
                "lang-chain-api-personal-key",
                "LangChain API personal key",
                Severity::High,
                Confidence::Medium,
                "https://langchain.com/",
            ),
            Self::LangChainApiServerKey => (
                "lang-chain-api-server-key",
                "LangChain API server key",
                Severity::High,
                Confidence::Medium,
                "https://langchain.com/",
            ),
            Self::LangSmithLicenseKey => (
                "lang-smith-license-key",
                "LangSmith license key",
                Severity::High,
                Confidence::Medium,
                "https://docs.langchain.com/langsmith/",
            ),
            Self::LangSmithScimBearerToken => (
                "lang-smith-scim-bearer-token",
                "LangSmith SCIM bearer token",
                Severity::High,
                Confidence::Medium,
                "https://docs.langchain.com/langsmith/",
            ),
            Self::LarkApaasClientSecret => (
                "lark-apaas-client-secret",
                "Lark APaaS client secret",
                Severity::High,
                Confidence::Medium,
                "https://open.larksuite.com/",
            ),
            Self::LarkAppSecret => (
                "lark-app-secret",
                "Lark app secret",
                Severity::High,
                Confidence::Medium,
                "https://open.larksuite.com/",
            ),
            Self::LarkMcpGrantToken => (
                "lark-mcp-grant-token",
                "Lark MCP grant token",
                Severity::High,
                Confidence::Medium,
                "https://open.larksuite.com/",
            ),
            Self::LarkMeegoPluginSecret => (
                "lark-meego-plugin-secret",
                "Lark Meego plugin secret",
                Severity::High,
                Confidence::Medium,
                "https://open.larksuite.com/",
            ),
            Self::LarkUserSession => (
                "lark-user-session",
                "Lark user session",
                Severity::High,
                Confidence::Medium,
                "https://open.larksuite.com/",
            ),
            Self::LaunchDarklyAccessToken => (
                "launch-darkly-access-token",
                "LaunchDarkly access token",
                Severity::High,
                Confidence::Medium,
                "https://launchdarkly.com/",
            ),
            Self::LichessOAuthAccessToken => (
                "lichess-oauth-access-token",
                "Lichess OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://lichess.org/",
            ),
            Self::LichessPersonalAccessToken => (
                "lichess-personal-access-token",
                "Lichess personal access token",
                Severity::High,
                Confidence::Medium,
                "https://lichess.org/",
            ),
            Self::LightspeedXsPat => (
                "lightspeed-xs-pat",
                "Lightspeed XS PAT",
                Severity::High,
                Confidence::Medium,
                "https://developer.lightspeedhq.com/",
            ),
            Self::LimbarToken => (
                "limbar-token",
                "Limbar token",
                Severity::High,
                Confidence::Medium,
                "https://limbar.dev/",
            ),
            Self::LinearOAuthAccessToken => (
                "linear-oauth-access-token",
                "Linear OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://linear.app/",
            ),
            Self::LinkedInClientSecret => (
                "linkedin-client-secret",
                "LinkedIn client secret",
                Severity::High,
                Confidence::Medium,
                "https://docs.microsoft.com/linkedin/",
            ),
            Self::LobLiveApiKey => (
                "lob-live-api-key",
                "Lob live API key",
                Severity::High,
                Confidence::Medium,
                "https://lob.com/",
            ),
            Self::LobTestApiKey => (
                "lob-test-api-key",
                "Lob test API key",
                Severity::High,
                Confidence::Medium,
                "https://lob.com/",
            ),
            Self::LocalstackApiKey => (
                "localstack-api-key",
                "LocalStack API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.localstack.cloud/",
            ),
            Self::LogicMonitorBearerToken => (
                "logicmonitor-bearer-token",
                "LogicMonitor bearer token",
                Severity::High,
                Confidence::Medium,
                "https://www.logicmonitor.com/",
            ),
            Self::LogicMonitorLmv1AccessKey => (
                "logicmonitor-lmv1-access-key",
                "LogicMonitor LMv1 access key",
                Severity::High,
                Confidence::Medium,
                "https://www.logicmonitor.com/",
            ),
            Self::AmazonOAuthClientId => (
                "amazon-oauth-client-id",
                "Login with Amazon OAuth client ID",
                Severity::High,
                Confidence::Medium,
                "https://developer.amazon.com/",
            ),
            Self::AmazonOAuthClientSecret => (
                "amazon-oauth-client-secret",
                "Login with Amazon OAuth client secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.amazon.com/",
            ),
            Self::LovableApiKey => (
                "lovable-api-key",
                "Lovable API key",
                Severity::High,
                Confidence::Medium,
                "https://lovable.dev/",
            ),
            Self::MailchimpApiKey => (
                "mailchimp-api-key",
                "Mailchimp API key",
                Severity::High,
                Confidence::Medium,
                "https://mailchimp.com/",
            ),
            Self::MandrillApiKey => (
                "mandrill-api-key",
                "Mandrill API key",
                Severity::High,
                Confidence::Medium,
                "https://mailchimp.com/",
            ),
            Self::MailersendApiToken => (
                "mailersend-api-token",
                "MailerSend API token",
                Severity::High,
                Confidence::Medium,
                "https://www.mailersend.com/",
            ),
            Self::MailersendSmtpPassword => (
                "mailersend-smtp-password",
                "MailerSend SMTP password",
                Severity::High,
                Confidence::Medium,
                "https://www.mailersend.com/",
            ),
            Self::MailersendSmtpUsername => (
                "mailersend-smtp-username",
                "MailerSend SMTP username",
                Severity::High,
                Confidence::Medium,
                "https://www.mailersend.com/",
            ),
            Self::MailgunApiKey => (
                "mailgun-api-key",
                "Mailgun API key",
                Severity::High,
                Confidence::Medium,
                "https://www.mailgun.com/",
            ),
            Self::MailgunSmtpCredential => (
                "mailgun-smtp-credential",
                "Mailgun SMTP credential",
                Severity::High,
                Confidence::Medium,
                "https://www.mailgun.com/",
            ),
            Self::MapboxSecretAccessToken => (
                "mapbox-secret-access-token",
                "Mapbox secret access token",
                Severity::High,
                Confidence::Medium,
                "https://www.mapbox.com/",
            ),
            Self::MaxMindLicenseKey => (
                "maxmind-license-key",
                "MaxMind license key",
                Severity::High,
                Confidence::Medium,
                "https://www.maxmind.com/",
            ),
            Self::MerakiApiKey => (
                "meraki-api-key",
                "Meraki dashboard API key",
                Severity::High,
                Confidence::Medium,
                "https://documentation.meraki.com/",
            ),
            Self::MercuryNonProductionApiToken => (
                "mercury-non-production-api-token",
                "Mercury non-production API token",
                Severity::High,
                Confidence::Medium,
                "https://mercury.com/",
            ),
            Self::MercuryProductionApiToken => (
                "mercury-production-api-token",
                "Mercury production API token",
                Severity::High,
                Confidence::Medium,
                "https://mercury.com/",
            ),
            Self::MergifyApplicationKey => (
                "mergify-application-key",
                "Mergify application key",
                Severity::High,
                Confidence::Medium,
                "https://mergify.com/",
            ),
            Self::MessageBirdApiKey => (
                "messagebird-api-key",
                "MessageBird API key",
                Severity::High,
                Confidence::Medium,
                "https://messagebird.com/",
            ),
            Self::PowerAutomateWebhookSAS => (
                "power-automate-webhook-sas",
                "Microsoft Power Automate webhook SAS",
                Severity::High,
                Confidence::Medium,
                "https://learn.microsoft.com/power-automate/",
            ),
            Self::MidtransProductionServerKey => (
                "midtrans-production-server-key",
                "Midtrans production server key",
                Severity::High,
                Confidence::Medium,
                "https://midtrans.com/",
            ),
            Self::MidtransSandboxServerKey => (
                "midtrans-sandbox-server-key",
                "Midtrans sandbox server key",
                Severity::High,
                Confidence::Medium,
                "https://midtrans.com/",
            ),
            Self::MistralAiApiKey => (
                "mistral-ai-api-key",
                "Mistral AI API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.mistral.ai/",
            ),
            Self::MongoDBAtlasDbUriWithCredentials => (
                "mongodb-atlas-db-uri-with-credentials",
                "MongoDB Atlas DB URI with credentials",
                Severity::High,
                Confidence::Medium,
                "https://www.mongodb.com/",
            ),
            Self::MongoDBAtlasServiceAccountSecret => (
                "mongodb-atlas-service-account-secret",
                "MongoDB Atlas service account secret",
                Severity::High,
                Confidence::Medium,
                "https://www.mongodb.com/",
            ),
            Self::NaverCloudGovAccessKey => (
                "naver-cloud-gov-access-key",
                "Naver Cloud Gov access key",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudGovAccessKeySecret => (
                "naver-cloud-gov-access-key-secret",
                "Naver Cloud Gov access key secret",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudGovSts => (
                "naver-cloud-gov-sts",
                "Naver Cloud Gov STS",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudGovStsSecret => (
                "naver-cloud-gov-sts-secret",
                "Naver Cloud Gov STS secret",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudPubAccessKey => (
                "naver-cloud-pub-access-key",
                "Naver Cloud pub access key",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudPubAccessKeySecret => (
                "naver-cloud-pub-access-key-secret",
                "Naver Cloud pub access key secret",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudPubSts => (
                "naver-cloud-pub-sts",
                "Naver Cloud pub STS",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NaverCloudPubStsSecret => (
                "naver-cloud-pub-sts-secret",
                "Naver Cloud pub STS secret",
                Severity::High,
                Confidence::Medium,
                "https://www.ncloud.com/",
            ),
            Self::NeonApiKey => (
                "neon-api-key",
                "Neon API key",
                Severity::High,
                Confidence::Medium,
                "https://neon.tech/",
            ),
            Self::NeonConnectionUri => (
                "neon-connection-uri",
                "Neon connection URI",
                Severity::High,
                Confidence::Medium,
                "https://neon.tech/",
            ),
            Self::NetflixNetKey => (
                "netflix-netkey",
                "Netflix NetKey",
                Severity::High,
                Confidence::Medium,
                "https://www.netflix.com/",
            ),
            Self::NewRelicInsightsQueryKey => (
                "new-relic-insights-query-key",
                "New Relic insights query key",
                Severity::High,
                Confidence::Medium,
                "https://docs.newrelic.com/",
            ),
            Self::NewRelicLicenseKey => (
                "new-relic-license-key",
                "New Relic license key",
                Severity::High,
                Confidence::Medium,
                "https://docs.newrelic.com/",
            ),
            Self::NewRelicPersonalApiKey => (
                "new-relic-personal-api-key",
                "New Relic personal API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.newrelic.com/",
            ),
            Self::NewRelicRestApiKey => (
                "new-relic-rest-api-key",
                "New Relic REST API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.newrelic.com/",
            ),
            Self::NotionApiToken => (
                "notion-api-token",
                "Notion API token",
                Severity::High,
                Confidence::Medium,
                "https://developers.notion.com/",
            ),
            Self::NotionIntegrationToken => (
                "notion-integration-token",
                "Notion integration token",
                Severity::High,
                Confidence::Medium,
                "https://developers.notion.com/",
            ),
            Self::NotionOAuthClientSecret => (
                "notion-oauth-client-secret",
                "Notion OAuth client secret",
                Severity::High,
                Confidence::Medium,
                "https://developers.notion.com/",
            ),
            Self::NuGetApiKey => (
                "nuget-api-key",
                "NuGet API key",
                Severity::High,
                Confidence::Medium,
                "https://www.nuget.org/",
            ),
            Self::OctopusDeployApiKey => (
                "octopus-deploy-api-key",
                "Octopus Deploy API key",
                Severity::High,
                Confidence::Medium,
                "https://octopus.com/",
            ),
            Self::OculusAccessToken => (
                "oculus-access-token",
                "Oculus access token",
                Severity::High,
                Confidence::Medium,
                "https://developer.oculus.com/",
            ),
            Self::OneChronosApiKey => (
                "onechronos-api-key",
                "OneChronos API key",
                Severity::High,
                Confidence::Medium,
                "https://onechronos.com/",
            ),
            Self::OneChronosEbApiKey => (
                "onechronos-eb-api-key",
                "OneChronos EB API key",
                Severity::High,
                Confidence::Medium,
                "https://onechronos.com/",
            ),
            Self::OneChronosEbEncryptionKey => (
                "onechronos-eb-encryption-key",
                "OneChronos EB encryption key",
                Severity::High,
                Confidence::Medium,
                "https://onechronos.com/",
            ),
            Self::OneChronosOauthToken => (
                "onechronos-oauth-token",
                "OneChronos OAuth token",
                Severity::High,
                Confidence::Medium,
                "https://onechronos.com/",
            ),
            Self::OneChronosRefreshToken => (
                "onechronos-refresh-token",
                "OneChronos refresh token",
                Severity::High,
                Confidence::Medium,
                "https://onechronos.com/",
            ),
            Self::OnePasswordServiceAccountToken => (
                "one-password-service-account-token",
                "1Password service account token",
                Severity::High,
                Confidence::Medium,
                "https://support.1password.com/service-account/",
            ),
            Self::OneSignalRichApiKey => (
                "one-signal-rich-api-key",
                "OneSignal rich API key",
                Severity::High,
                Confidence::Medium,
                "https://documentation.onesignal.com/",
            ),
            Self::OneSignalRichAuthenticationToken => (
                "onesignal-rich-authentication-token",
                "OneSignal rich authentication token",
                Severity::High,
                Confidence::Medium,
                "https://onesignal.com/",
            ),
            Self::OnfidoLiveApiToken => (
                "onfido-live-api-token",
                "Onfido live API token",
                Severity::High,
                Confidence::Medium,
                "https://onfido.com/",
            ),
            Self::OnfidoSandboxApiToken => (
                "onfido-sandbox-api-token",
                "Onfido sandbox API token",
                Severity::High,
                Confidence::Medium,
                "https://onfido.com/",
            ),
            Self::OpenAIApiKey => (
                "openai-api-key",
                "OpenAI API key",
                Severity::High,
                Confidence::Medium,
                "https://platform.openai.com/",
            ),
            Self::OpenRouterApiKey => (
                "openrouter-api-key",
                "OpenRouter API key",
                Severity::High,
                Confidence::Medium,
                "https://openrouter.ai/",
            ),
            Self::OpenVSXAccessToken => (
                "openvsx-access-token",
                "OpenVSX access token",
                Severity::High,
                Confidence::Medium,
                "https://open-vsx.org/",
            ),
            Self::OpenweatherApiKey => (
                "openweather-api-key",
                "OpenWeather API key",
                Severity::High,
                Confidence::Medium,
                "https://openweathermap.org/",
            ),
            Self::OracleApiKey => (
                "oracle-api-key",
                "Oracle API key",
                Severity::High,
                Confidence::Medium,
                "https://www.oracle.com/",
            ),
            Self::OrbitApiToken => (
                "orbit-api-token",
                "Orbit API token",
                Severity::High,
                Confidence::Medium,
                "https://orbit.love/",
            ),
            Self::PaddleApiKey => (
                "paddle-api-key",
                "Paddle API key",
                Severity::High,
                Confidence::Medium,
                "https://developer.paddle.com/",
            ),
            Self::PaddleSandboxApiKey => (
                "paddle-sandbox-api-key",
                "Paddle sandbox API key",
                Severity::High,
                Confidence::Medium,
                "https://developer.paddle.com/",
            ),
            Self::PagerDutyOAuthSecret => (
                "pagerduty-oauth-secret",
                "PagerDuty OAuth secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.pagerduty.com/",
            ),
            Self::PagerDutyOAuthToken => (
                "pagerduty-oauth-token",
                "PagerDuty OAuth token",
                Severity::High,
                Confidence::Medium,
                "https://developer.pagerduty.com/",
            ),
            Self::PalantirJWT => (
                "palantir-jwt",
                "Palantir JSON Web Token",
                Severity::High,
                Confidence::Medium,
                "https://www.palantir.com/",
            ),
            Self::PangeaToken => (
                "pangea-token",
                "Pangea token",
                Severity::High,
                Confidence::Medium,
                "https://pangea.cloud/",
            ),
            Self::PerplexityApiKey => (
                "perplexity-api-key",
                "Perplexity API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.perplexity.ai/",
            ),
            Self::PersonaProductionApiKey => (
                "persona-production-api-key",
                "Persona production API key",
                Severity::High,
                Confidence::Medium,
                "https://withpersona.com/",
            ),
            Self::PersonaSandboxApiKey => (
                "persona-sandbox-api-key",
                "Persona sandbox API key",
                Severity::High,
                Confidence::Medium,
                "https://withpersona.com/",
            ),
            Self::PineappleTechnologiesIncidentApiKey => (
                "pineapple-technologies-incident-api-key",
                "Pineapple Technologies incident API key",
                Severity::High,
                Confidence::Medium,
                "https://pineappletechnologies.com/",
            ),
            Self::PinterestAccessToken => (
                "pinterest-access-token",
                "Pinterest access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.pinterest.com/",
            ),
            Self::PinterestRefreshToken => (
                "pinterest-refresh-token",
                "Pinterest refresh token",
                Severity::High,
                Confidence::Medium,
                "https://developers.pinterest.com/",
            ),
            Self::PlanetScaleDatabasePassword => (
                "planet-scale-database-password",
                "PlanetScale database password",
                Severity::High,
                Confidence::Medium,
                "https://planetscale.com/",
            ),
            Self::PlanetScaleOAuthToken => (
                "planet-scale-oauth-token",
                "PlanetScale OAuth token",
                Severity::High,
                Confidence::Medium,
                "https://planetscale.com/",
            ),
            Self::PlanetScaleServiceToken => (
                "planet-scale-service-token",
                "PlanetScale service token",
                Severity::High,
                Confidence::Medium,
                "https://planetscale.com/",
            ),
            Self::PlanningCenterOAuthAccessToken => (
                "planning-center-oauth-access-token",
                "Planning Center OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://planningcenter.com/",
            ),
            Self::PlanningCenterOAuthAppSecret => (
                "planning-center-oauth-app-secret",
                "Planning Center OAuth app secret",
                Severity::High,
                Confidence::Medium,
                "https://planningcenter.com/",
            ),
            Self::PlanningCenterPersonalAccessToken => (
                "planning-center-personal-access-token",
                "Planning Center personal access token",
                Severity::High,
                Confidence::Medium,
                "https://planningcenter.com/",
            ),
            Self::PlivoAuthID => (
                "plivo-auth-id",
                "Plivo Auth ID",
                Severity::High,
                Confidence::Medium,
                "https://www.plivo.com/",
            ),
            Self::PlivoAuthToken => (
                "plivo-auth-token",
                "Plivo auth token",
                Severity::High,
                Confidence::Medium,
                "https://www.plivo.com/",
            ),
            Self::PolarPersonalAccessToken => (
                "polar-personal-access-token",
                "Polar personal access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarAccessToken => (
                "polar-access-token",
                "Polar access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarRefreshToken => (
                "polar-refresh-token",
                "Polar refresh token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarAuthorizationCode => (
                "polar-authorization-code",
                "Polar authorization code",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarClientRegistrationToken => (
                "polar-client-registration-token",
                "Polar client registration token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarClientSecret => (
                "polar-client-secret",
                "Polar client secret",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarCustomerSessionToken => (
                "polar-customer-session-token",
                "Polar customer session token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PolarUserSessionToken => (
                "polar-user-session-token",
                "Polar user session token",
                Severity::High,
                Confidence::Medium,
                "https://docs.polar.sh/",
            ),
            Self::PostHogFeatureFlagsSecureApiKey => (
                "posthog-feature-flags-secure-api-key",
                "PostHog feature flags secure API key",
                Severity::High,
                Confidence::Medium,
                "https://posthog.com/",
            ),
            Self::PostHogOAuthAccessToken => (
                "posthog-oauth-access-token",
                "PostHog OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://posthog.com/",
            ),
            Self::PostHogOAuthRefreshToken => (
                "posthog-oauth-refresh-token",
                "PostHog OAuth refresh token",
                Severity::High,
                Confidence::Medium,
                "https://posthog.com/",
            ),
            Self::PostHogPersonalApiKey => (
                "posthog-personal-api-key",
                "PostHog personal API key",
                Severity::High,
                Confidence::Medium,
                "https://posthog.com/",
            ),
            Self::PostmanApiKey => (
                "postman-api-key",
                "Postman API key",
                Severity::High,
                Confidence::Medium,
                "https://www.postman.com/",
            ),
            Self::PostmanCollectionKey => (
                "postman-collection-key",
                "Postman collection key",
                Severity::High,
                Confidence::Medium,
                "https://www.postman.com/",
            ),
            Self::PrefectServerApiKey => (
                "prefect-server-api-key",
                "Prefect server API key",
                Severity::High,
                Confidence::Medium,
                "https://www.prefect.io/",
            ),
            Self::PrefectUserApiKey => (
                "prefect-user-api-key",
                "Prefect user API key",
                Severity::High,
                Confidence::Medium,
                "https://www.prefect.io/",
            ),
            Self::ProctorioConsumerKey => (
                "proctorio-consumer-key",
                "Proctorio consumer key",
                Severity::High,
                Confidence::Medium,
                "https://proctorio.com/",
            ),
            Self::ProctorioLinkageKey => (
                "proctorio-linkage-key",
                "Proctorio linkage key",
                Severity::High,
                Confidence::Medium,
                "https://proctorio.com/",
            ),
            Self::ProctorioRegistrationKey => (
                "proctorio-registration-key",
                "Proctorio registration key",
                Severity::High,
                Confidence::Medium,
                "https://proctorio.com/",
            ),
            Self::ProctorioSecretKey => (
                "proctorio-secret-key",
                "Proctorio secret key",
                Severity::High,
                Confidence::Medium,
                "https://proctorio.com/",
            ),
            Self::ProofFullAccessApiKey => (
                "proof-full-access-api-key",
                "Proof full access API key",
                Severity::High,
                Confidence::Medium,
                "https://dev.proof.com/",
            ),
            Self::PulumiAccessToken => (
                "pulumi-access-token",
                "Pulumi access token",
                Severity::High,
                Confidence::Medium,
                "https://www.pulumi.com/",
            ),
            Self::LogfireToken => (
                "logfire-token",
                "Pydantic Logfire token",
                Severity::High,
                Confidence::Medium,
                "https://logfire.pydantic.dev/",
            ),
            Self::PydanticAIGatewayApiKey => (
                "pydantic-ai-gateway-api-key",
                "Pydantic AI Gateway API key",
                Severity::High,
                Confidence::Medium,
                "https://pydantic.dev/",
            ),
            Self::PyPiApiToken => (
                "pypi-api-token",
                "PyPI API token",
                Severity::High,
                Confidence::Medium,
                "https://pypi.org/",
            ),
            Self::RainforestApiKey => (
                "rainforest-api-key",
                "Rainforest Pay API key",
                Severity::High,
                Confidence::Medium,
                "https://rainforestpay.com/",
            ),
            Self::RainforestSandboxApiKey => (
                "rainforest-sandbox-api-key",
                "Rainforest Pay sandbox API key",
                Severity::High,
                Confidence::Medium,
                "https://rainforestpay.com/",
            ),
            Self::RampClientID => (
                "ramp-client-id",
                "Ramp OAuth client ID",
                Severity::High,
                Confidence::Medium,
                "https://ramp.com/",
            ),
            Self::RampClientSecret => (
                "ramp-client-secret",
                "Ramp OAuth client secret",
                Severity::High,
                Confidence::Medium,
                "https://ramp.com/",
            ),
            Self::RampOAuthToken => (
                "ramp-oauth-token",
                "Ramp OAuth access or refresh token",
                Severity::High,
                Confidence::Medium,
                "https://ramp.com/",
            ),
            Self::RaycastAccessToken => (
                "raycast-access-token",
                "Raycast access token",
                Severity::High,
                Confidence::Medium,
                "https://www.raycast.com/",
            ),
            Self::ReadMeApiKey => (
                "read-me-api-key",
                "ReadMe API key",
                Severity::High,
                Confidence::Medium,
                "https://readme.com/",
            ),
            Self::ReplicateApiToken => (
                "replicate-api-token",
                "Replicate API token",
                Severity::High,
                Confidence::Medium,
                "https://replicate.com/",
            ),
            Self::ResendApiKey => (
                "resend-api-key",
                "Resend API key",
                Severity::High,
                Confidence::Medium,
                "https://resend.com/",
            ),
            Self::RootlyApiKey => (
                "rootly-api-key",
                "Rootly API key",
                Severity::High,
                Confidence::Medium,
                "https://rootly.com/",
            ),
            Self::RubygemsApiKey => (
                "rubygems-api-key",
                "RubyGems API key",
                Severity::High,
                Confidence::Medium,
                "https://rubygems.org/",
            ),
            Self::RunPodApiKey => (
                "run-pod-api-key",
                "RunPod API key",
                Severity::High,
                Confidence::Medium,
                "https://docs.runpod.io/",
            ),
            Self::SalesforceAccessToken => (
                "salesforce-access-token",
                "Salesforce access token",
                Severity::High,
                Confidence::Medium,
                "https://developer.salesforce.com/",
            ),
            Self::SalesforceMarketingCloudApiOAuth2Token => (
                "salesforce-marketing-cloud-api-oauth2-token",
                "Salesforce Marketing Cloud API OAuth2 token",
                Severity::High,
                Confidence::Medium,
                "https://developer.salesforce.com/",
            ),
            Self::SalesforceOAuth2ConsumerKey => (
                "salesforce-oauth2-consumer-key",
                "Salesforce OAuth2 consumer key",
                Severity::High,
                Confidence::Medium,
                "https://developer.salesforce.com/",
            ),
            Self::SalesforceOAuth2ConsumerSecret => (
                "salesforce-oauth2-consumer-secret",
                "Salesforce OAuth2 consumer secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.salesforce.com/",
            ),
            Self::SalesforceRefreshToken => (
                "salesforce-refresh-token",
                "Salesforce refresh token",
                Severity::High,
                Confidence::Medium,
                "https://developer.salesforce.com/",
            ),
            Self::SamsaraApiToken => (
                "samsara-api-token",
                "Samsara API token",
                Severity::High,
                Confidence::Medium,
                "https://developers.samsara.com/",
            ),
            Self::SamsaraOAuthAccessToken => (
                "samsara-oauth-access-token",
                "Samsara OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://developers.samsara.com/",
            ),
            Self::ScalrApiToken => (
                "scalr-api-token",
                "Scalr API token",
                Severity::High,
                Confidence::Medium,
                "https://www.scalr.com/",
            ),
            Self::SegmentPublicApiToken => (
                "segment-public-api-token",
                "Segment public API token",
                Severity::High,
                Confidence::Medium,
                "https://segment.com/",
            ),
            Self::SendGridApiKey => (
                "send-grid-api-key",
                "SendGrid API key",
                Severity::High,
                Confidence::Medium,
                "https://sendgrid.com/",
            ),
            Self::SentryIntegrationToken => (
                "sentry-integration-token",
                "Sentry integration token",
                Severity::High,
                Confidence::Medium,
                "https://docs.sentry.io/",
            ),
            Self::SentryOrganizationToken => (
                "sentry-organization-token",
                "Sentry organization token",
                Severity::High,
                Confidence::Medium,
                "https://docs.sentry.io/",
            ),
            Self::SentryUserAppAuthToken => (
                "sentry-user-app-auth-token",
                "Sentry user app auth token",
                Severity::High,
                Confidence::Medium,
                "https://docs.sentry.io/",
            ),
            Self::ShippoLiveApiToken => (
                "shippo-live-api-token",
                "Shippo live API token",
                Severity::High,
                Confidence::Medium,
                "https://goshippo.com/",
            ),
            Self::ShippoTestApiToken => (
                "shippo-test-api-token",
                "Shippo test API token",
                Severity::High,
                Confidence::Medium,
                "https://goshippo.com/",
            ),
            Self::ShopeeOpenPlatformPartnerKey => (
                "shopee-open-platform-partner-key",
                "Shopee open platform partner key",
                Severity::High,
                Confidence::Medium,
                "https://shopee.com/",
            ),
            Self::ShopifyAccessToken => (
                "shopify-access-token",
                "Shopify access token",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyAppClientCredentials => (
                "shopify-app-client-credentials",
                "Shopify app client credentials",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyAppClientSecret => (
                "shopify-app-client-secret",
                "Shopify app client secret",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyAppSharedSecret => (
                "shopify-app-shared-secret",
                "Shopify app shared secret",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyCustomAppAccessToken => (
                "shopify-custom-app-access-token",
                "Shopify custom app access token",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyMarketplaceToken => (
                "shopify-marketplace-token",
                "Shopify marketplace token",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyMerchantToken => (
                "shopify-merchant-token",
                "Shopify merchant token",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyPartnerApiToken => (
                "shopify-partner-api-token",
                "Shopify partner API token",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::ShopifyPrivateAppPassword => (
                "shopify-private-app-password",
                "Shopify private app password",
                Severity::High,
                Confidence::Medium,
                "https://shopify.dev/",
            ),
            Self::SiemensApiToken => (
                "siemens-api-token",
                "Siemens API token",
                Severity::High,
                Confidence::Medium,
                "https://developer.siemens.com/",
            ),
            Self::SiemensCodeToken => (
                "siemens-code-token",
                "Siemens code token",
                Severity::High,
                Confidence::Medium,
                "https://developer.siemens.com/",
            ),
            Self::SindriApiKey => (
                "sindri-api-key",
                "Sindri API key",
                Severity::High,
                Confidence::Medium,
                "https://sindri.ai/",
            ),
            Self::SlackApiToken => (
                "slack-api-token",
                "Slack API token",
                Severity::High,
                Confidence::Medium,
                "https://api.slack.com/",
            ),
            Self::SlackIncomingWebhookURL => (
                "slack-incoming-webhook-url",
                "Slack incoming webhook URL",
                Severity::High,
                Confidence::Medium,
                "https://api.slack.com/",
            ),
            Self::SlackWorkflowTriggerURL => (
                "slack-workflow-trigger-url",
                "Slack workflow trigger URL",
                Severity::High,
                Confidence::Medium,
                "https://api.slack.com/",
            ),
            Self::SlackWorkflowWebhookURL => (
                "slack-workflow-webhook-url",
                "Slack workflow webhook URL",
                Severity::High,
                Confidence::Medium,
                "https://api.slack.com/",
            ),
            Self::SnowflakePostgresConnectionString => (
                "snowflake-postgres-connection-string",
                "Snowflake SFPG connection string",
                Severity::High,
                Confidence::Medium,
                "https://docs.snowflake.com/",
            ),
            Self::SnowflakePostgresHost => (
                "snowflake-postgres-host",
                "Snowflake SFPG host",
                Severity::High,
                Confidence::Medium,
                "https://docs.snowflake.com/",
            ),
            Self::SnowflakePostgresPassword => (
                "snowflake-postgres-password",
                "Snowflake SFPG password",
                Severity::High,
                Confidence::Medium,
                "https://docs.snowflake.com/",
            ),
            Self::SnowflakeProgrammaticAccessToken => (
                "snowflake-programmatic-access-token",
                "Snowflake programmatic access token",
                Severity::High,
                Confidence::Medium,
                "https://docs.snowflake.com/",
            ),
            Self::SourcegraphAccessToken => (
                "sourcegraph-access-token",
                "Sourcegraph access token",
                Severity::High,
                Confidence::Medium,
                "https://about.sourcegraph.com/",
            ),
            Self::SourcegraphDotcomUserGateway => (
                "sourcegraph-dotcom-user-gateway",
                "Sourcegraph dotcom user gateway",
                Severity::High,
                Confidence::Medium,
                "https://about.sourcegraph.com/",
            ),
            Self::SourcegraphInstanceIdentifierAccessToken => (
                "sourcegraph-instance-identifier-access-token",
                "Sourcegraph instance identifier access token",
                Severity::High,
                Confidence::Medium,
                "https://about.sourcegraph.com/",
            ),
            Self::SourcegraphLicenseKeyToken => (
                "sourcegraph-license-key-token",
                "Sourcegraph license key token",
                Severity::High,
                Confidence::Medium,
                "https://about.sourcegraph.com/",
            ),
            Self::SourcegraphProductSubscriptionToken => (
                "sourcegraph-product-subscription-token",
                "Sourcegraph product subscription token",
                Severity::High,
                Confidence::Medium,
                "https://about.sourcegraph.com/",
            ),
            Self::StarlinkPublicAPIV2Secret => (
                "starlink-public-api-v2-secret",
                "Starlink public API v2 client secret",
                Severity::High,
                Confidence::Medium,
                "https://www.starlink.com/",
            ),
            Self::SquareAccessToken => (
                "square-access-token",
                "Square access token",
                Severity::High,
                Confidence::Medium,
                "https://developer.squareup.com/",
            ),
            Self::SquareProductionApplicationSecret => (
                "square-production-application-secret",
                "Square production application secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.squareup.com/",
            ),
            Self::SquareSandboxApplicationSecret => (
                "square-sandbox-application-secret",
                "Square sandbox application secret",
                Severity::High,
                Confidence::Medium,
                "https://developer.squareup.com/",
            ),
            Self::SSLMateAPIKey => (
                "sslmate-api-key",
                "SSLMate API key",
                Severity::High,
                Confidence::Medium,
                "https://sslmate.com/",
            ),
            Self::SSLMateClusterSecret => (
                "sslmate-cluster-secret",
                "SSLMate cluster secret",
                Severity::High,
                Confidence::Medium,
                "https://sslmate.com/",
            ),
            Self::StripeApiKey => (
                "stripe-api-key",
                "Stripe API key",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::StripeLegacyAPIKey => (
                "stripe-legacy-api-key",
                "Stripe legacy API key",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::StripeLiveRestrictedKey => (
                "stripe-live-restricted-key",
                "Stripe live restricted key",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::StripeTestRestrictedKey => (
                "stripe-test-restricted-key",
                "Stripe test restricted key",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::StripeTestAPISecretKey => (
                "stripe-test-api-secret-key",
                "Stripe test API secret key",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::StripeWebhookSigningSecret => (
                "stripe-webhook-signing-secret",
                "Stripe webhook signing secret",
                Severity::High,
                Confidence::Medium,
                "https://stripe.com/",
            ),
            Self::SupabaseOAuthAccessToken => (
                "supabase-oauth-access-token",
                "Supabase OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://supabase.com/",
            ),
            Self::SupabasePersonalAccessToken => (
                "supabase-personal-access-token",
                "Supabase personal access token",
                Severity::High,
                Confidence::Medium,
                "https://supabase.com/",
            ),
            Self::SupabaseScopedPersonalAccessToken => (
                "supabase-scoped-personal-access-token",
                "Supabase scoped personal access token",
                Severity::High,
                Confidence::Medium,
                "https://supabase.com/",
            ),
            Self::SupabaseSecretKey => (
                "supabase-secret-key",
                "Supabase secret key",
                Severity::High,
                Confidence::Medium,
                "https://supabase.com/",
            ),
            Self::TableauPersonalAccessToken => (
                "tableau-personal-access-token",
                "Tableau personal access token",
                Severity::High,
                Confidence::Medium,
                "https://www.tableau.com/",
            ),
            Self::TailscaleAPIKey => (
                "tailscale-api-key",
                "Tailscale API key",
                Severity::High,
                Confidence::Medium,
                "https://tailscale.com/",
            ),
            Self::TavilyApiKey => (
                "tavily-api-key",
                "Tavily API key",
                Severity::High,
                Confidence::Medium,
                "https://tavily.com/",
            ),
            Self::TelegramBotToken => (
                "telegram-bot-token",
                "Telegram bot token",
                Severity::High,
                Confidence::Medium,
                "https://core.telegram.org/",
            ),
            Self::TelnyxAPIV2Key => (
                "telnyx-api-v2-key",
                "Telnyx API V2 key",
                Severity::High,
                Confidence::Medium,
                "https://telnyx.com/",
            ),
            Self::TemporalCloudApiKey => (
                "temporal-cloud-api-key",
                "Temporal Cloud API key",
                Severity::High,
                Confidence::Medium,
                "https://temporal.io/",
            ),
            Self::TencentCloudIntlAccessToken => (
                "tencent-cloud-intl-access-token",
                "Tencent Cloud international access token",
                Severity::High,
                Confidence::Medium,
                "https://cloud.tencent.com/",
            ),
            Self::TencentCloudSecretID => (
                "tencent-cloud-secret-id",
                "Tencent Cloud secret ID",
                Severity::High,
                Confidence::Medium,
                "https://cloud.tencent.com/",
            ),
            Self::TencentWeChatAPIAppID => (
                "tencent-we-chat-api-app-id",
                "Tencent WeChat API app ID",
                Severity::High,
                Confidence::Medium,
                "https://cloud.tencent.com/",
            ),
            Self::TencentWeChatPayToken => (
                "tencent-we-chat-pay-token",
                "Tencent WeChat Pay token",
                Severity::High,
                Confidence::Medium,
                "https://cloud.tencent.com/",
            ),
            Self::ThunderstoreIOApiToken => (
                "thunderstore-io-api-token",
                "Thunderstore IO API token",
                Severity::High,
                Confidence::Medium,
                "https://thunderstore.io/",
            ),
            Self::TwilioAccessToken => (
                "twilio-access-token",
                "Twilio access token",
                Severity::High,
                Confidence::Medium,
                "https://www.twilio.com/",
            ),
            Self::TwilioAccountSID => (
                "twilio-account-sid",
                "Twilio account SID",
                Severity::High,
                Confidence::Medium,
                "https://www.twilio.com/",
            ),
            Self::TwilioAPIKey => (
                "twilio-api-key",
                "Twilio API key",
                Severity::High,
                Confidence::Medium,
                "https://www.twilio.com/",
            ),
            Self::TypeformPersonalAccessToken => (
                "typeform-personal-access-token",
                "Typeform personal access token",
                Severity::High,
                Confidence::Medium,
                "https://developer.typeform.com/",
            ),
            Self::WISEflowAPIKey => (
                "wiseflow-api-key",
                "Uniwise WISEflow API key",
                Severity::High,
                Confidence::Medium,
                "https://wiseflow.com/",
            ),
            Self::UnkeyRootKey => (
                "unkey-root-key",
                "Unkey root key",
                Severity::High,
                Confidence::Medium,
                "https://unkey.dev/",
            ),
            Self::ValTownApiToken => (
                "val-town-api-token",
                "Val Town API token",
                Severity::High,
                Confidence::Medium,
                "https://val.town/",
            ),
            Self::VercelAPIKey => (
                "vercel-api-key",
                "Vercel API key",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VercelAppRefreshToken => (
                "vercel-app-refresh-token",
                "Vercel app refresh token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VercelAppUserAccessToken => (
                "vercel-app-user-access-token",
                "Vercel app user access token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VercelIntegrationAccessToken => (
                "vercel-integration-access-token",
                "Vercel integration access token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VercelPersonalAccessToken => (
                "vercel-personal-access-token",
                "Vercel personal access token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VercelSupportAccessToken => (
                "vercel-support-access-token",
                "Vercel support access token",
                Severity::High,
                Confidence::Medium,
                "https://vercel.com/",
            ),
            Self::VolcEngineAccessKeyID => (
                "volc-engine-access-key-id",
                "VolcEngine access key ID",
                Severity::High,
                Confidence::Medium,
                "https://www.volcengine.com/",
            ),
            Self::VolcEngineArkAPIKey => (
                "volc-engine-ark-api-key",
                "VolcEngine Ark API key",
                Severity::High,
                Confidence::Medium,
                "https://www.volcengine.com/",
            ),
            Self::WakaTimeAPIKey => (
                "waka-time-api-key",
                "WakaTime API key",
                Severity::High,
                Confidence::Medium,
                "https://wakatime.com/",
            ),
            Self::WakaTimeAppSecret => (
                "waka-time-app-secret",
                "WakaTime app secret",
                Severity::High,
                Confidence::Medium,
                "https://wakatime.com/",
            ),
            Self::WakaTimeOAuthAccessToken => (
                "waka-time-oauth-access-token",
                "WakaTime OAuth access token",
                Severity::High,
                Confidence::Medium,
                "https://wakatime.com/",
            ),
            Self::WakaTimeOAuthRefreshToken => (
                "waka-time-oauth-refresh-token",
                "WakaTime OAuth refresh token",
                Severity::High,
                Confidence::Medium,
                "https://wakatime.com/",
            ),
            Self::WaveProductionAPIKey => (
                "wave-production-api-key",
                "Wave production API key",
                Severity::High,
                Confidence::Medium,
                "https://waveapps.com/",
            ),
            Self::WaveTestAPIKey => (
                "wave-test-api-key",
                "Wave test API key",
                Severity::High,
                Confidence::Medium,
                "https://waveapps.com/",
            ),
            Self::WeatherstackAPIKey => (
                "weatherstack-api-key",
                "Weatherstack API key",
                Severity::High,
                Confidence::Medium,
                "https://weatherstack.com/",
            ),
            Self::WandbAPIKey => (
                "wandb-api-key",
                "Weights & Biases API key",
                Severity::High,
                Confidence::Medium,
                "https://wandb.ai/",
            ),
            Self::WorkatoDeveloperAPIToken => (
                "workato-developer-api-token",
                "Workato developer API token",
                Severity::High,
                Confidence::Medium,
                "https://workato.com/",
            ),
            Self::WorkOSProductionAPIKey => (
                "work-os-production-api-key",
                "WorkOS production API key",
                Severity::High,
                Confidence::Medium,
                "https://workos.com/",
            ),
            Self::WorkOSStagingAPIKey => (
                "work-os-staging-api-key",
                "WorkOS staging API key",
                Severity::High,
                Confidence::Medium,
                "https://workos.com/",
            ),
            Self::WSO2ChoreoPersonalAccessToken => (
                "wso-2-choreo-personal-access-token",
                "WSO2 Choreo personal access token",
                Severity::High,
                Confidence::Medium,
                "https://wso2.com/",
            ),
            Self::YandexCloudAPIKey => (
                "yandex-cloud-api-key",
                "Yandex.Cloud API key",
                Severity::High,
                Confidence::Medium,
                "https://cloud.yandex.com/",
            ),
            Self::YandexCloudIAMAccessSecret => (
                "yandex-cloud-iam-access-secret",
                "Yandex.Cloud IAM access secret",
                Severity::High,
                Confidence::Medium,
                "https://cloud.yandex.com/",
            ),
            Self::YandexCloudIAMCookie => (
                "yandex-cloud-iam-cookie",
                "Yandex.Cloud IAM cookie",
                Severity::High,
                Confidence::Medium,
                "https://cloud.yandex.com/",
            ),
            Self::YandexCloudIAMToken => (
                "yandex-cloud-iam-token",
                "Yandex.Cloud IAM token",
                Severity::High,
                Confidence::Medium,
                "https://cloud.yandex.com/",
            ),
            Self::YandexCloudSmartcaptchaServerKey => (
                "yandex-cloud-smartcaptcha-server-key",
                "Yandex.Cloud Smartcaptcha server key",
                Severity::High,
                Confidence::Medium,
                "https://cloud.yandex.com/",
            ),
            Self::YandexDictionaryAPIKey => (
                "yandex-dictionary-api-key",
                "Yandex Dictionary API key",
                Severity::High,
                Confidence::Medium,
                "https://yandex.com/",
            ),
            Self::YandexPassportOAuthToken => (
                "yandex-passport-oauth-token",
                "Yandex Passport OAuth token",
                Severity::High,
                Confidence::Medium,
                "https://yandex.com/",
            ),
            Self::YandexPredictorAPIKey => (
                "yandex-predictor-api-key",
                "Yandex Predictor API key",
                Severity::High,
                Confidence::Medium,
                "https://yandex.com/",
            ),
            Self::YandexTranslateAPIKey => (
                "yandex-translate-api-key",
                "Yandex Translate API key",
                Severity::High,
                Confidence::Medium,
                "https://yandex.com/",
            ),
            Self::ZenHubPersonalAPIKey => (
                "zen-hub-personal-api-key",
                "ZenHub personal API key",
                Severity::High,
                Confidence::Medium,
                "https://www.zenhub.com/",
            ),
            Self::ZuploConsumerAPIKey => (
                "zuplo-consumer-api-key",
                "Zuplo consumer API key",
                Severity::High,
                Confidence::Medium,
                "https://zuplo.com/",
            ),
            // Phase 1: Cloud & Infrastructure
            Self::DigitalOceanPat => (
                "digitalocean-pat",
                "DigitalOcean personal access token",
                Severity::High,
                Confidence::High,
                "https://docs.digitalocean.com/reference/api/api-reference/",
            ),
            Self::DigitalOceanOauth => (
                "digitalocean-oauth",
                "DigitalOcean OAuth token",
                Severity::High,
                Confidence::High,
                "https://docs.digitalocean.com/reference/api/api-reference/",
            ),
            Self::DigitalOceanRefresh => (
                "digitalocean-refresh-token",
                "DigitalOcean refresh token",
                Severity::High,
                Confidence::High,
                "https://docs.digitalocean.com/reference/api/api-reference/",
            ),
            Self::DockerSwarmJoin => (
                "docker-swarm-join-token",
                "Docker Swarm join token",
                Severity::High,
                Confidence::High,
                "https://docs.docker.com/engine/swarm/join-nodes/",
            ),
            Self::DockerSwarmUnlock => (
                "docker-swarm-unlock-key",
                "Docker Swarm unlock key",
                Severity::Critical,
                Confidence::High,
                "https://docs.docker.com/engine/swarm/join-nodes/",
            ),
            Self::HerokuApiKey => (
                "heroku-api-key",
                "Heroku API key",
                Severity::High,
                Confidence::High,
                "https://devcenter.heroku.com/articles/authentication",
            ),
            // Phase 1: Package Managers
            Self::ClojarsToken => (
                "clojars-token",
                "Clojars API token",
                Severity::High,
                Confidence::High,
                "https://clojars.org/about/tokens",
            ),
            Self::CratesioToken => (
                "cratesio-token",
                "Crates.io API token",
                Severity::High,
                Confidence::High,
                "https://doc.rust-lang.org/cargo/reference/registering-on-crates-io.html",
            ),
            Self::PyPiToken => (
                "pypi-token",
                "PyPI upload token",
                Severity::High,
                Confidence::High,
                "https://pypi.org/help/#apitoken",
            ),
            // Phase 1: Communication & Messaging
            Self::SendgridApiKey => (
                "sendgrid-api-key",
                "SendGrid API key",
                Severity::High,
                Confidence::High,
                "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
            ),
            Self::SendinblueApiKey => (
                "sendinblue-api-key",
                "Sendinblue (Brevo) API key",
                Severity::High,
                Confidence::High,
                "https://developers.brevo.com/docs/api-reference/authentication",
            ),
            Self::SlackBotToken => (
                "slack-bot-token",
                "Slack bot token",
                Severity::High,
                Confidence::High,
                "https://api.slack.com/authentication/token-types",
            ),
            Self::SlackUserToken => (
                "slack-user-token",
                "Slack user token",
                Severity::High,
                Confidence::High,
                "https://api.slack.com/authentication/token-types",
            ),
            Self::SlackWorkspaceToken => (
                "slack-workspace-token",
                "Slack workspace token",
                Severity::High,
                Confidence::High,
                "https://api.slack.com/authentication/token-types",
            ),
            Self::SlackRefreshToken => (
                "slack-refresh-token",
                "Slack refresh token",
                Severity::High,
                Confidence::High,
                "https://api.slack.com/authentication/token-types",
            ),
            // Phase 1: Databases & Storage
            Self::TwilioAccountSid => (
                "twilio-account-sid",
                "Twilio Account SID",
                Severity::High,
                Confidence::High,
                "https://www.twilio.com/docs/sms/api",
            ),
            Self::TwilioApiKey => (
                "twilio-api-key",
                "Twilio API key",
                Severity::High,
                Confidence::High,
                "https://www.twilio.com/docs/sms/api",
            ),
            // Phase 1: SaaS & Dev Tools
            Self::SentryOrgToken => (
                "sentry-org-token",
                "Sentry organization token",
                Severity::High,
                Confidence::High,
                "https://docs.sentry.io/meta/sso-and-orgs.html",
            ),
            Self::SentryPersonalToken => (
                "sentry-personal-token",
                "Sentry personal API token",
                Severity::High,
                Confidence::High,
                "https://docs.sentry.io/security-legal-pii/security/token-formats/",
            ),
            Self::GrafanaServiceAccountToken => (
                "grafana-service-account-token",
                "Grafana service account token",
                Severity::High,
                Confidence::High,
                "https://grafana.com/docs/grafana/latest/administration/service-accounts/",
            ),
            Self::AxiomToken => (
                "axiom-token",
                "Axiom API or personal token",
                Severity::High,
                Confidence::High,
                "https://axiom.co/docs/reference/tokens",
            ),
            Self::SonarQubeToken => (
                "sonarqube-token",
                "SonarQube access token",
                Severity::High,
                Confidence::High,
                "https://docs.sonarsource.com/sonarqube-server/user-guide/managing-tokens",
            ),
            Self::SonarQubeCloudToken => (
                "sonarqube-cloud-token",
                "SonarQube Cloud access token",
                Severity::High,
                Confidence::High,
                "https://docs.sonarsource.com/sonarqube-server/user-guide/managing-tokens",
            ),
            Self::KongKonnectToken => (
                "kong-konnect-token",
                "Kong Konnect personal access token",
                Severity::High,
                Confidence::High,
                "https://developer.konghq.com/konnect-api/",
            ),
            Self::TruffleHogEnterpriseSecret => (
                "trufflehog-enterprise-secret",
                "TruffleHog Enterprise integration secret",
                Severity::High,
                Confidence::High,
                "https://trufflesecurity.com/docs",
            ),
            Self::DopplerToken => (
                "doppler-token",
                "Doppler service, personal, CLI, or scope token",
                Severity::High,
                Confidence::High,
                "https://docs.doppler.com/docs/service-tokens",
            ),
            Self::TailscaleApiToken => (
                "tailscale-api-token",
                "Tailscale API access token",
                Severity::High,
                Confidence::High,
                "https://tailscale.com/docs/reference/key-prefixes",
            ),
            Self::TailscaleAuthToken => (
                "tailscale-auth-token",
                "Tailscale pre-authentication key",
                Severity::High,
                Confidence::High,
                "https://tailscale.com/docs/reference/key-prefixes",
            ),
            Self::LaunchDarklyServerSdkToken => (
                "launch-darkly-server-sdk-token",
                "LaunchDarkly server-side SDK secret",
                Severity::High,
                Confidence::High,
                "https://launchdarkly.com/docs/sdk/concepts/client-side-server-side",
            ),
            Self::FlagsmithServerToken => (
                "flagsmith-server-token",
                "Flagsmith server-side environment key",
                Severity::High,
                Confidence::High,
                "https://docs.flagsmith.com/integrating-with-flagsmith/sdks/server-side",
            ),
            Self::GrowthBookSecretKey => (
                "growth-book-secret-key",
                "GrowthBook REST secret key",
                Severity::High,
                Confidence::High,
                "https://docs.growthbook.io/api/introduction",
            ),
            Self::PostHogPersonalToken => (
                "post-hog-personal-token",
                "PostHog personal API token",
                Severity::High,
                Confidence::High,
                "https://posthog.com/docs/api",
            ),
            Self::GitlabCicdJobToken => (
                "gitlab-cicd-job-token",
                "GitLab CI/CD job token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/ee/ci/secrets/",
            ),
            Self::GitlabDeployToken => (
                "gitlab-deploy-token",
                "GitLab deploy token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/ee/user/project/deploy_tokens/",
            ),
            Self::GitlabFeatureFlagToken => (
                "gitlab-feature-flag-token",
                "GitLab feature flag token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/ee/user/project/merge_requests/feature_flags/",
            ),
            Self::GitlabPersonalAccessToken => (
                "gitlab-personal-access-token",
                "GitLab personal access token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/ee/user/profile/personal_access_tokens/",
            ),
            Self::GitlabRunnerToken => (
                "gitlab-runner-token",
                "GitLab runner token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabRunnerRegistrationToken => (
                "gitlab-runner-registration-token",
                "GitLab runner registration token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabFeedToken => (
                "gitlab-feed-token",
                "GitLab feed token",
                Severity::Medium,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabIncomingMailToken => (
                "gitlab-incoming-mail-token",
                "GitLab incoming mail token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabScimToken => (
                "gitlab-scim-token",
                "GitLab SCIM token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabAgentToken => (
                "gitlab-agent-token",
                "GitLab agent token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabOauthAppSecret => (
                "gitlab-oauth-app-secret",
                "GitLab OAuth application secret",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::GitlabTriggerToken => (
                "gitlab-trigger-token",
                "GitLab trigger token",
                Severity::High,
                Confidence::High,
                "https://docs.gitlab.com/security/tokens/",
            ),
            Self::CircleCiPersonalToken => (
                "circleci-personal-token",
                "CircleCI personal access token",
                Severity::High,
                Confidence::High,
                "https://circleci.com/changelog/new-format-for-api-access-tokens/",
            ),
            Self::CircleCiProjectToken => (
                "circleci-project-token",
                "CircleCI project context token",
                Severity::High,
                Confidence::High,
                "https://circleci.com/changelog/new-format-for-api-access-tokens/",
            ),
            Self::AtlassianApiToken => (
                "atlassian-api-token",
                "Atlassian modern API token",
                Severity::High,
                Confidence::High,
                "https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/",
            ),
            Self::NetlifyAccessToken => (
                "netlify-access-token",
                "Netlify access token",
                Severity::High,
                Confidence::High,
                "https://docs.netlify.com/configure-sites/manage-deploy/manage-site-access-tokens/",
            ),
            Self::FlyioToken => (
                "flyio-token",
                "Fly.io API or management token",
                Severity::High,
                Confidence::High,
                "https://docs.fly.io/en/latest/fly101/apps/security",
            ),
            Self::PineconeApiKey => (
                "pinecone-api-key",
                "Pinecone API key",
                Severity::High,
                Confidence::High,
                "https://docs.pinecone.io/troubleshooting/retrieval-and-interaction-options",
            ),
            Self::AnthropicAdminKey => (
                "anthropic-admin-key",
                "Anthropic admin API key",
                Severity::Critical,
                Confidence::High,
                "https://docs.anthropic.com/en/docs/keys",
            ),
            Self::Auth0ManagementToken => (
                "auth0-management-token",
                "Auth0 management API token",
                Severity::High,
                Confidence::High,
                "https://auth0.com/docs/api-management",
            ),
            Self::OktaAccessToken => (
                "okta-access-token",
                "Okta access token",
                Severity::High,
                Confidence::High,
                "https://developer.okta.com/docs/api/openapi/okta-management/overview",
            ),
            Self::NotionApiKey => (
                "notion-api-key",
                "Notion integration token",
                Severity::High,
                Confidence::High,
                "https://developers.notion.com/docs/authorization",
            ),
            Self::LinearApiKey => (
                "linear-api-key",
                "Linear API key",
                Severity::High,
                Confidence::High,
                "https://developers.linear.app/docs/oauth-setup",
            ),
            Self::FigmaToken => (
                "figma-token",
                "Figma personal access token",
                Severity::High,
                Confidence::High,
                "https://www.figma.com/developers/api#access-tokens",
            ),
            Self::ShopifyCustomToken => (
                "shopify-custom-token",
                "Shopify custom token",
                Severity::High,
                Confidence::High,
                "https://shopify.dev/docs/api/development",
            ),
            Self::ShopifySharedSecret => (
                "shopify-shared-secret",
                "Shopify shared secret",
                Severity::High,
                Confidence::High,
                "https://shopify.dev/docs/api/development",
            ),
            Self::ShopifyAppPassword => (
                "shopify-app-password",
                "Shopify app password",
                Severity::High,
                Confidence::High,
                "https://shopify.dev/docs/api/development",
            ),
            Self::StripePaymentIntent => (
                "stripe-payment-intent",
                "Stripe payment intent secret",
                Severity::High,
                Confidence::High,
                "https://docs.stripe.com/checkout/sequential-payment-intents",
            ),
            Self::StripeAccessToken => (
                "stripe-access-token",
                "Stripe restricted production access token",
                Severity::High,
                Confidence::High,
                "https://docs.stripe.com/keys",
            ),
            // Phase 1: AI / ML Providers
            Self::MistralKey => (
                "mistral-key",
                "Mistral AI API key",
                Severity::High,
                Confidence::High,
                "https://docs.mistral.ai/",
            ),
            Self::CerebrasKey => (
                "cerebras-key",
                "Cerebras API key",
                Severity::High,
                Confidence::High,
                "https://docs.cerebras.ai/",
            ),
            Self::TogetheraiKey => (
                "togetherai-key",
                "Together AI API key",
                Severity::High,
                Confidence::High,
                "https://docs.together.ai/docs/quickstart",
            ),
            Self::FireworksAiKey => (
                "fireworks-ai-key",
                "Fireworks AI API key",
                Severity::High,
                Confidence::High,
                "https://docs.fireworks.com/",
            ),
            Self::StabilityAiKey => (
                "stability-ai-key",
                "Stability AI API key",
                Severity::High,
                Confidence::High,
                "https://platform.stability.ai/",
            ),
            Self::DeepgramKey => (
                "deepgram-key",
                "Deepgram API key",
                Severity::High,
                Confidence::High,
                "https://developers.deepgram.com/reference/authentication",
            ),
            Self::RazorpayKey => (
                "razorpay-key",
                "Razorpay API key",
                Severity::High,
                Confidence::High,
                "https://razorpay.com/docs/payments/api/",
            ),
            Self::FlutterwaveKey => (
                "flutterwave-key",
                "Flutterwave API key",
                Severity::High,
                Confidence::High,
                "https://developer.flutterwave.com/docs/reference",
            ),
            Self::PlanetscalePassword => (
                "planetscale-password",
                "PlanetScale database password",
                Severity::High,
                Confidence::High,
                "https://planetscale.com/docs/reference/api-overview",
            ),
            Self::PlanetscaleToken => (
                "planetscale-token",
                "PlanetScale service token",
                Severity::High,
                Confidence::High,
                "https://planetscale.com/docs/reference/api-overview",
            ),
            Self::PlanetscaleOauthToken => (
                "planetscale-oauth-token",
                "PlanetScale OAuth token",
                Severity::High,
                Confidence::High,
                "https://planetscale.com/docs/reference/api-overview",
            ),
            Self::PlaidAccessToken => (
                "plaid-access-token",
                "Plaid access token",
                Severity::High,
                Confidence::High,
                "https://plaid.com/docs/api/",
            ),
            Self::CloudinaryUrl => (
                "cloudinary-url",
                "Cloudinary cloud URL with credentials",
                Severity::High,
                Confidence::High,
                "https://cloudinary.com/documentation/user_authentication",
            ),
            // Phase 3: URI-based rules
            Self::MongodbUri => (
                "mongodb-uri",
                "MongoDB connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://www.mongodb.com/docs/manual/reference/connection-string/",
            ),
            Self::PostgresUri => (
                "postgres-uri",
                "PostgreSQL connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING",
            ),
            Self::RedisUri => (
                "redis-uri",
                "Redis connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://redis.io/docs/latest/develop/connect/",
            ),
            Self::SqlserverUri => (
                "sqlserver-uri",
                "SQL Server connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/connection-string",
            ),
            Self::MysqlUri => (
                "mysql-uri",
                "MySQL connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://dev.mysql.com/doc/refman/8.0/en/connection-strings.html",
            ),
            Self::CockroachdbUri => (
                "cockroachdb-uri",
                "CockroachDB connection string with credentials",
                Severity::High,
                Confidence::High,
                "https://www.cockroachlabs.com/docs/stable/connection-params",
            ),
        };
        RuleMetadata {
            id,
            description,
            severity,
            confidence,
            reference,
            reviewed_on: "2026-10-06",
        }
    }
}

const GITHUB_PREFIXES: &[&[u8]] = &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_", b"github_pat_"];
const STRIPE_SECRET_PREFIXES: &[&[u8]] = &[b"sk_live_", b"sk_test_"];
const STRIPE_RESTRICTED_PREFIXES: &[&[u8]] = &[b"rk_live_", b"rk_test_"];
const SLACK_PREFIXES: &[&[u8]] = &[
    b"https://hooks.slack.com/services/",
    b"https://hooks.slack-gov.com/services/",
];
pub(crate) const PRIVATE_KEY_MARKERS: &[&[u8]] = &[
    b"-----BEGIN PRIVATE KEY-----",           // rayloc:ignore
    b"-----BEGIN RSA PRIVATE KEY-----",       // rayloc:ignore
    b"-----BEGIN EC PRIVATE KEY-----",        // rayloc:ignore
    b"-----BEGIN DSA PRIVATE KEY-----",       // rayloc:ignore
    b"-----BEGIN OPENSSH PRIVATE KEY-----",   // rayloc:ignore
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----", // rayloc:ignore
];

// LLM provider API key prefixes
const OPENAI_PREFIXES: &[&[u8]] = &[b"sk-"];
const OPENROUTER_PREFIXES: &[&[u8]] = &[b"sk-or-v1-"];
const ANTHROPIC_PREFIXES: &[&[u8]] = &[b"sk-ant-api03-"];
const GROQ_PREFIXES: &[&[u8]] = &[b"gsk_"];
const PERPLEXITY_PREFIXES: &[&[u8]] = &[b"pplx-"];
const HUGGINGFACE_PREFIXES: &[&[u8]] = &[b"hf_"];
const XAI_PREFIXES: &[&[u8]] = &[b"xai-"];
const GOOGLE_API_PREFIXES: &[&[u8]] = &[b"AIza", b"AQ."];
const ALIBABA_PREFIXES: &[&[u8]] = &[b"sk-ws-"];
const BAIDU_PREFIXES: &[&[u8]] = &[b"bce-v3/ALTAK-"];
const WANDB_PREFIXES: &[&[u8]] = &[b"wandb_"];
const FIRECRAWL_PREFIXES: &[&[u8]] = &[b"fc-"];
const LANGSMITH_PREFIXES: &[&[u8]] = &[b"lsv2_pt_", b"lsv2_sk_"];
const VOYAGE_PREFIXES: &[&[u8]] = &[b"al-", b"pa-"];
const CARTESIA_PREFIXES: &[&[u8]] = &[b"sk_car_"];
const REPLICATE_PREFIXES: &[&[u8]] = &[b"r8_"];
const VERCEL_PREFIXES: &[&[u8]] = &[b"vcp_", b"vci_", b"vca_", b"vcr_", b"vck_"];
const SUPABASE_PREFIXES: &[&[u8]] = &[b"sb_secret_"];
const CLOUDFLARE_PREFIXES: &[&[u8]] = &[b"cfk_", b"cfut_", b"cfat_"];

// Phase 1: Cloud & Infrastructure
const DIGITALOCEAN_PAT_PREFIXES: &[&[u8]] = &[b"dop_v1_"];
const DIGITALOCEAN_OAUTH_PREFIXES: &[&[u8]] = &[b"doo_v1_"];
const DIGITALOCEAN_REFRESH_PREFIXES: &[&[u8]] = &[b"dor_v1_"];
const HEROKU_API_KEY_PREFIXES: &[&[u8]] = &[b"HRKU-AA"];
const CLOUDINARY_URL_PREFIXES: &[&[u8]] = &[b"cloudinary://"];
// Phase 1: Package Managers
const CLOJARS_TOKEN_PREFIXES: &[&[u8]] = &[b"CLOJARS_"];
const CRATESIO_TOKEN_PREFIXES: &[&[u8]] = &[b"cratesio_", b"cratesioplus_"];
const PYPY_TOKEN_PREFIXES: &[&[u8]] = &[b"pypi-AgEI", b"pypi-Agkv"];
const RUBYGENS_API_KEY_PREFIXES: &[&[u8]] = &[b"rubygems_"];
// Phase 1: Communication & Messaging
const SLACK_BOT_TOKEN_PREFIXES: &[&[u8]] = &[b"xoxb-"];
const SLACK_USER_TOKEN_PREFIXES: &[&[u8]] = &[b"xoxp-"];
const SLACK_WORKSPACE_TOKEN_PREFIXES: &[&[u8]] = &[b"xoxa-"];
const SLACK_REFRESH_TOKEN_PREFIXES: &[&[u8]] = &[b"xoxr-"];
// Phase 1: SaaS & Dev Tools
const SENTRY_ORG_TOKEN_PREFIXES: &[&[u8]] = &[b"sntrys_"];
const SENTRY_PERSONAL_TOKEN_PREFIXES: &[&[u8]] = &[b"sntryu_"];
const GRAFANA_SERVICE_ACCOUNT_TOKEN_PREFIXES: &[&[u8]] = &[b"glsa_"];
const AXIOM_TOKEN_PREFIXES: &[&[u8]] = &[b"xaat-", b"xapt-"];
const SONARQUBE_TOKEN_PREFIXES: &[&[u8]] = &[b"squ_", b"sqp_", b"sqa_"];
const SONARQUBE_CLOUD_TOKEN_PREFIXES: &[&[u8]] = &[b"sqco_"];
const KONG_KONNECT_TOKEN_PREFIXES: &[&[u8]] = &[b"kpat_", b"spat_"];
const TRUFFLEHOG_ENTERPRISE_SECRET_PREFIXES: &[&[u8]] = &[b"thog-secret-"];
const TAILSCALE_API_TOKEN_PREFIXES: &[&[u8]] = &[b"tskey-api-"];
const TAILSCALE_AUTH_TOKEN_PREFIXES: &[&[u8]] = &[b"tskey-auth-"];
const RESEND_API_KEY_PREFIXES: &[&[u8]] = &[b"re_"];
const LAUNCH_DARKLY_SERVER_SDK_TOKEN_PREFIXES: &[&[u8]] = &[b"sdk-"];
const FLAGSMITH_SERVER_TOKEN_PREFIXES: &[&[u8]] = &[b"ser."];
const GROWTHBOOK_SECRET_KEY_PREFIXES: &[&[u8]] = &[b"secret_"];
const POSTHOG_PERSONAL_TOKEN_PREFIXES: &[&[u8]] = &[b"phx_"];
const GITLAB_CICD_JOB_TOKEN_PREFIXES: &[&[u8]] = &[b"glcbt-"];
const GITLAB_DEPLOY_TOKEN_PREFIXES: &[&[u8]] = &[b"gldt-"];
const GITLAB_FEATURE_FLAG_TOKEN_PREFIXES: &[&[u8]] = &[b"glffct-"];
const GITLAB_PERSONAL_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"glpat-"];
const GITLAB_RUNNER_TOKEN_PREFIXES: &[&[u8]] = &[b"glrt-"];
const GITLAB_RUNNER_REGISTRATION_TOKEN_PREFIXES: &[&[u8]] = &[b"glrtr-"];
const GITLAB_FEED_TOKEN_PREFIXES: &[&[u8]] = &[b"glft-"];
const GITLAB_INCOMING_MAIL_TOKEN_PREFIXES: &[&[u8]] = &[b"glimt-"];
const GITLAB_SCIM_TOKEN_PREFIXES: &[&[u8]] = &[b"glsoat-"];
const GITLAB_AGENT_TOKEN_PREFIXES: &[&[u8]] = &[b"glagent-"];
const GITLAB_OAUTH_APP_SECRET_PREFIXES: &[&[u8]] = &[b"gloas-"];
const GITLAB_TRIGGER_TOKEN_PREFIXES: &[&[u8]] = &[b"glptt-"];
const CIRCLECI_PERSONAL_TOKEN_PREFIXES: &[&[u8]] = &[b"CCIPAT_"];
const CIRCLECI_PROJECT_TOKEN_PREFIXES: &[&[u8]] = &[b"CCIPRJ_"];
const ATLASSIAN_API_TOKEN_PREFIXES: &[&[u8]] = &[b"ATATT3"];
const NETLIFY_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"nfp_"];
const FLYIO_API_TOKEN_PREFIXES: &[&[u8]] = &[b"fo1_"];
const FLYIO_MANAGEMENT_TOKEN_PREFIXES: &[&[u8]] = &[b"fm1a_", b"fm1r_", b"fm2_"];
const AUTH0_MANAGEMENT_TOKEN_PREFIXES: &[&[u8]] = &[b"ua2_"];
const OKTA_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"00a"];
const NOTION_API_KEY_PREFIXES: &[&[u8]] = &[b"nt_"];
const LINEAR_API_KEY_PREFIXES: &[&[u8]] = &[b"lin_api_"];
const FIGMA_TOKEN_PREFIXES: &[&[u8]] = &[b"fig-oauth-", b"figt_"];
const SQUARE_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"sq0atp-"];
const SHOPIFY_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"shpat_"];
const SHOPIFY_CUSTOM_TOKEN_PREFIXES: &[&[u8]] = &[b"shpcc_"];
const SHOPIFY_SHARED_SECRET_PREFIXES: &[&[u8]] = &[b"shpss_"];
const SHOPIFY_APP_PASSWORD_PREFIXES: &[&[u8]] = &[b"shppa_"];
const STRIPE_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"sk_prod_", b"rk_prod_"];
const PLANETSCALE_PASSWORD_PREFIXES: &[&[u8]] = &[b"pscale_pw_"];
const PLANETSCALE_TOKEN_PREFIXES: &[&[u8]] = &[b"pscale_tkn_"];
const PLANETSCALE_OAUTH_TOKEN_PREFIXES: &[&[u8]] = &[b"pscale_oauth_"];
const PADDLE_API_KEY_PREFIXES: &[&[u8]] = &[b"pdl_live_apikey_", b"pdl_sdbx_apikey_"];
const PLAID_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[
    b"access-sandbox-",
    b"access-development-",
    b"access-production-",
];
// Phase 1: AI / ML Providers
const MISTRAL_KEY_PREFIXES: &[&[u8]] = &[b"mv4-"];
const CEREBRAS_KEY_PREFIXES: &[&[u8]] = &[b"csk_"];
const TOGETHERAI_KEY_PREFIXES: &[&[u8]] = &[b"tgn-"];
const FIREWORKS_AI_KEY_PREFIXES: &[&[u8]] = &[b"fw_"];
const STABILITY_AI_KEY_PREFIXES: &[&[u8]] = &[b"sk-stability"];
const DEEPGRAM_KEY_PREFIXES: &[&[u8]] = &[b"dg_"];
const RAZORPAY_KEY_PREFIXES: &[&[u8]] = &[b"rzpj_", b"rzp_"];
// Phase 3: URI-based
const MONGODB_URI_PREFIXES: &[&[u8]] = &[b"mongodb://", b"mongodb+srv://"];
const POSTGRES_URI_PREFIXES: &[&[u8]] = &[b"postgres://", b"postgresql://"];
const REDIS_URI_PREFIXES: &[&[u8]] = &[b"redis://", b"rediss://"];
const SQLSERVER_URI_PREFIXES: &[&[u8]] = &[b"mssql://", b"sqlserver://"];
const MYSQL_URI_PREFIXES: &[&[u8]] = &[b"mysql://"];
const COCKROACHDB_URI_PREFIXES: &[&[u8]] = &[b"cockroachdb://", b"cockroach+srv://"];
// Phase 2: Additional provider prefix constants
const ADOBE_CLIENT_SECRET_PREFIXES: &[&[u8]] = &[b"p8e-"];
const AIVEN_AUTH_TOKEN_PREFIXES: &[&[u8]] = &[b"aivenv1"];
const AIVEN_SERVICE_PASSWORD_PREFIXES: &[&[u8]] = &[b"aivenv1"];
const APIFY_API_TOKEN_PREFIXES: &[&[u8]] = &[b"apify_api_"];
const CANVA_APP_SECRET_PREFIXES: &[&[u8]] = &[b"cnvca"];
const CANVA_CONNECT_API_SECRET_PREFIXES: &[&[u8]] = &[b"cnvca"];
const CANVA_SECRET_PREFIXES: &[&[u8]] = &[b"cnvca"];
const CLOUDSMITH_API_KEY_PREFIXES: &[&[u8]] = &[b"cs_"];
const DATABENTO_API_KEY_PREFIXES: &[&[u8]] = &[b"db-"];
const DOPPLER_AUDIT_TOKEN_PREFIXES: &[&[u8]] = &[b"dp."];
const GITHUB_SSH_PRIVATE_KEY_PREFIXES: &[&[u8]] = &[b"-----BEGIN "];
const HASHICORP_VAULT_SERVICE_TOKEN_PREFIXES: &[&[u8]] = &[b"hvs."];
const LOB_LIVE_API_KEY_PREFIXES: &[&[u8]] = &[b"live_"];
const LOB_TEST_API_KEY_PREFIXES: &[&[u8]] = &[b"test_"];
const MAILERSEND_API_TOKEN_PREFIXES: &[&[u8]] = &[b"mlsn."];
const MAILERSEND_SMTP_PASSWORD_PREFIXES: &[&[u8]] = &[b"mlsn."];
const MAILERSEND_SMTP_USERNAME_PREFIXES: &[&[u8]] = &[b"mlsn."];
const MAILGUN_API_KEY_PREFIXES: &[&[u8]] = &[b"key-"];
const MAILGUN_SMTP_CREDENTIAL_PREFIXES: &[&[u8]] = &[b"key-"];
const MAPBOX_SECRET_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"sk."];
const MERCURY_NON_PRODUCTION_API_TOKEN_PREFIXES: &[&[u8]] = &[b"secret-token:mercury_"];
const MERCURY_PRODUCTION_API_TOKEN_PREFIXES: &[&[u8]] = &[b"secret-token:mercury_production_"];
const MIDTRANS_PRODUCTION_SERVER_KEY_PREFIXES: &[&[u8]] = &[b"Mid-server-"];
const MIDTRANS_SANDBOX_SERVER_KEY_PREFIXES: &[&[u8]] = &[b"SB-Mid-server-"];
const NAVERCLOUD_GOV_ACCESS_KEY_ID_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_GOV_ACCESS_KEY_SECRET_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_GOV_STS_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_GOV_STS_SECRET_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_PUB_ACCESS_KEY_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_PUB_ACCESS_KEY_SECRET_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_PUB_STS_PREFIXES: &[&[u8]] = &[b"navercloud_"];
const NAVERCLOUD_PUB_STS_SECRET_PREFIXES: &[&[u8]] = &[b"navercloud_"];
// Batch 8: Polar prefix constants (one family, shared `polar_` prefix)
const POLAR_PERSONAL_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_REFRESH_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_AUTHORIZATION_CODE_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_CLIENT_REGISTRATION_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_CLIENT_SECRET_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_CUSTOMER_SESSION_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
const POLAR_USER_SESSION_TOKEN_PREFIXES: &[&[u8]] = &[b"polar_"];
// Phase 2: Additional provider prefix constants
const AIRTABLE_PAT_PREFIXES: &[&[u8]] = &[b"pat"];
const BITRISE_PAT_PREFIXES: &[&[u8]] = &[b"bitrise"];
const DUFFEL_LIVE_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"duffel_live_"];
const DUFFEL_TEST_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"duffel_test_"];
const DYNATRACE_API_TOKEN_PREFIXES: &[&[u8]] = &[b"dt0c01."];
const EASYPOST_PRODUCTION_API_KEY_PREFIXES: &[&[u8]] = &[b"EZAK"];
const EASYPOST_TEST_API_KEY_PREFIXES: &[&[u8]] = &[b"EZAK", b"EZTK"];
const ELASTIC_CLOUD_API_KEY_PREFIXES: &[&[u8]] = &[b"essu_"];
const ELASTIC_STACK_API_KEY_PREFIXES: &[&[u8]] = &[b"essu_"];
const FLUTTERWAVE_LIVE_API_SECRET_KEY_PREFIXES: &[&[u8]] = &[b"FLWSECK_TEST-"];
const FLUTTERWAVE_TEST_API_SECRET_KEY_PREFIXES: &[&[u8]] = &[b"FLWSECK_TEST-"];
const FRAME_IO_DEVELOPER_TOKEN_PREFIXES: &[&[u8]] = &[b"fio-u-"];
const HASHICORP_VAULT_BATCH_TOKEN_PREFIXES: &[&[u8]] = &[b"hvb."];
const HEROKU_PLATFORM_API_OAUTH2_TOKEN_PREFIXES: &[&[u8]] = &[b"HRKU-AA"];
const HEX_API_KEY_PREFIXES: &[&[u8]] = &[b"hex_"];
const HIGHNOTE_RK_LIVE_KEY_PREFIXES: &[&[u8]] = &[b"rk_live_"];
const HIGHNOTE_RK_TEST_KEY_PREFIXES: &[&[u8]] = &[b"rk_test_"];
const HIGHNOTE_SK_LIVE_KEY_PREFIXES: &[&[u8]] = &[b"sk_live_"];
const HIGHNOTE_SK_TEST_KEY_PREFIXES: &[&[u8]] = &[b"sk_test_"];
const DATABRICKS_API_TOKEN_PREFIXES: &[&[u8]] = &[b"dapi"];
const DOPPLER_CLI_TOKEN_PREFIXES: &[&[u8]] = &[b"dp."];
const DOPPLER_PERSONAL_TOKEN_PREFIXES: &[&[u8]] = &[b"dp."];
const DROPBOX_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"sl."];

// Task-target prefix constants (prefix-based detectors)
const NEW_RELIC_INSIGHTS_QUERY_KEY_PREFIXES: &[&[u8]] = &[b"NRAK-"];
const NEW_RELIC_LICENSE_KEY_PREFIXES: &[&[u8]] = &[b"NRAK-"];
const NEW_RELIC_PERSONAL_API_KEY_PREFIXES: &[&[u8]] = &[b"NRAK-"];
const NEW_RELIC_REST_API_KEY_PREFIXES: &[&[u8]] = &[b"NRAK-"];
const NUGET_API_KEY_PREFIXES: &[&[u8]] = &[b"oy2"];
const OCTOPUS_DEPLOY_API_KEY_PREFIXES: &[&[u8]] = &[b"API-"];
const PULUMI_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"pul-"];
const POSTMAN_API_KEY_PREFIXES: &[&[u8]] = &[b"PMAK-"];
const POSTMAN_COLLECTION_KEY_PREFIXES: &[&[u8]] = &[b"PMAK-"];
const READ_ME_API_KEY_PREFIXES: &[&[u8]] = &[b"rdme_"];
const SALESFORCE_OAUTH2_CONSUMER_KEY_PREFIXES: &[&[u8]] = &[b"3MVG9"];
const SALESFORCE_REFRESH_TOKEN_PREFIXES: &[&[u8]] = &[b"5AEP861"];
const TYPEFORM_PERSONAL_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"tfp_"];
const VERCEL_API_KEY_PREFIXES: &[&[u8]] = &[b"vcp_"];
const WAKATIME_API_KEY_PREFIXES: &[&[u8]] = &[b"waka_"];
const YANDEX_CLOUD_API_KEY_PREFIXES: &[&[u8]] = &[b"AQVN"];
const YANDEX_CLOUD_ACCESS_SECRET_PREFIXES: &[&[u8]] = &[b"AQVN"];
const YANDEX_CLOUD_IAM_TOKEN_PREFIXES: &[&[u8]] = &[b"t1."];
const YANDEX_CLOUD_SMARTCAPTCHA_SERVER_KEY_PREFIXES: &[&[u8]] = &[b"ysc2_"];
const YANDEX_PASSPORT_OAUTH_TOKEN_PREFIXES: &[&[u8]] =
    &[b"y0_", b"y1_", b"y2_", b"y3_", b"y4_", b"y5_", b"y6_"];

// Batch 5: additional prefix-based detectors from the GitHub catalog.
const ONE_PASSWORD_SERVICE_ACCOUNT_TOKEN_PREFIXES: &[&[u8]] = &[b"ops_eyJ"];
const ADAFRUIT_IO_KEY_PREFIXES: &[&[u8]] = &[b"aio_"];
const BEAMER_API_KEY_PREFIXES: &[&[u8]] = &[b"b_"];
const CCDB_API_KEY_PREFIXES: &[&[u8]] = &[b"ccdb_"];
const CDS_CANADA_NOTIFY_API_KEY_PREFIXES: &[&[u8]] = &[b"ApiKey-v1 gcntfy"];
const CONTENTFUL_PAT_PREFIXES: &[&[u8]] = &[b"CFPAT-"];
const DOCKER_PERSONAL_PAT_PREFIXES: &[&[u8]] = &[b"dckr_pat_"];
const DOCKER_ORGANIZATION_PAT_PREFIXES: &[&[u8]] = &[b"dckr_pat_"];
const BUILDKITE_USER_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_AGENT_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_AGENT_JOB_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_AGENT_REGISTRATION_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_CLUSTER_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_CLUSTER_QUEUE_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_PACKAGES_REGISTRY_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_PACKAGES_TEMPORARY_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_PORTAL_TOKEN_PREFIXES: &[&[u8]] = &[b"bk"];
const BUILDKITE_PORTAL_SECRET_PREFIXES: &[&[u8]] = &[b"bk"];

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn aws_match(bytes: &[u8]) -> Option<usize> {
    if !(bytes.starts_with(b"AKIA") || bytes.starts_with(b"ASIA")) {
        return None;
    }
    let body = bytes.get(4..20)?;
    if body
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && !bytes.get(20).is_some_and(|&b| is_word(b))
    {
        Some(20)
    } else {
        None
    }
}

fn token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Result<Option<usize>, ScanError> {
    let Some(prefix) = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix)) else {
        return Ok(None);
    };
    // Frame the complete compact installation form, including forbidden padding,
    // so JOSE validation cannot accept a valid prefix of a malformed token.
    let allow_dot = *prefix == b"ghs_";
    let allow_padding = allow_dot && {
        let body = &bytes[prefix.len()..];
        let id_length = body
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .take(MAX_CANDIDATE_BYTES + 1)
            .count();
        id_length != 0 && body.get(id_length) == Some(&b'_')
    };
    let body_length = bytes[prefix.len()..]
        .iter()
        .take_while(|&&byte| {
            is_word(byte)
                || (allow_dot && matches!(byte, b'.' | b'-'))
                || (allow_padding && byte == b'=')
        })
        .take(MAX_CANDIDATE_BYTES + 1)
        .count();
    let length = prefix.len() + body_length;
    if length > MAX_CANDIDATE_BYTES {
        return Err(ScanError::CandidateLimit);
    }
    if allow_dot && bytes[..length].contains(&b'.') {
        let body = &bytes[prefix.len()..length];
        let Some(separator) = body.iter().position(|b| *b == b'_') else {
            return Ok(None);
        };
        if separator == 0
            || !body[..separator].iter().all(u8::is_ascii_digit)
            || !super::jose::valid(&body[separator + 1..])?
        {
            return Ok(None);
        }
    }
    Ok((body_length >= 16).then_some(length))
}

fn slack_match(bytes: &[u8]) -> Result<Option<usize>, ScanError> {
    let Some(prefix) = SLACK_PREFIXES
        .iter()
        .find(|&&prefix| bytes.starts_with(prefix))
    else {
        return Ok(None);
    };
    let mut end = prefix.len();
    for segment in 0..3 {
        let start = end;
        while bytes
            .get(end)
            .is_some_and(|&byte| is_word(byte) || byte == b'-')
        {
            end += 1;
            if end > MAX_CANDIDATE_BYTES {
                return Err(ScanError::CandidateLimit);
            }
        }
        if start == end {
            return Ok(None);
        }
        if segment < 2 {
            if bytes.get(end) != Some(&b'/') {
                return Ok(None);
            }
            end += 1;
        }
    }
    // A longer path is not the supported three-segment credential URL.
    Ok((bytes.get(end) != Some(&b'/')).then_some(end))
}

fn api_key_match(bytes: &[u8], prefixes: &[&[u8]]) -> Result<Option<usize>, ScanError> {
    api_key_match_with_min(bytes, prefixes, 20)
}

fn api_key_match_with_min(
    bytes: &[u8],
    prefixes: &[&[u8]],
    min_body_length: usize,
) -> Result<Option<usize>, ScanError> {
    let Some(prefix) = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix)) else {
        return Ok(None);
    };
    let body = &bytes[prefix.len()..];
    let body_length = body
        .iter()
        .take_while(|&&byte| is_word(byte) || byte == b'-' || byte == b'.')
        .take(MAX_CANDIDATE_BYTES + 1)
        .count();
    let length = prefix.len() + body_length;
    if length > MAX_CANDIDATE_BYTES {
        return Err(ScanError::CandidateLimit);
    }
    if body_length < min_body_length {
        return Ok(None);
    }
    // For prefixes ending with underscore (e.g., hf_, gsk_), the body should not
    // contain dots or multiple underscores. Dots indicate the match is part of a
    // larger identifier (e.g., module.attr). A single underscore is allowed for
    // separator formats like github_pat_xxx_yyy.
    if prefix.ends_with(b"_") {
        let body_bytes = &body[..body_length];
        let underscore_count = body_bytes.iter().filter(|&&b| b == b'_').count();
        if body_bytes.contains(&b'.') || underscore_count > 1 {
            return Ok(None);
        }
    }
    // Word boundary check: if the character after the match is an identifier
    // character, the match is part of a larger identifier and should not be
    // treated as a standalone secret.
    if length < bytes.len() {
        let next_byte = bytes[length];
        if is_word(next_byte) || next_byte == b'-' || next_byte == b'.' || next_byte == b'_' {
            return Ok(None);
        }
    }
    Ok(Some(length))
}

fn sendgrid_match(bytes: &[u8]) -> Result<Option<usize>, ScanError> {
    if !bytes.starts_with(b"SG.") {
        return Ok(None);
    }
    let mut end = 3;
    let mut seg1_len = 0;
    while bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric()) {
        end += 1;
        seg1_len += 1;
        if end > MAX_CANDIDATE_BYTES {
            return Err(ScanError::CandidateLimit);
        }
    }
    if !(20..=24).contains(&seg1_len) || bytes.get(end) != Some(&b'.') {
        return Ok(None);
    }
    end += 1;
    let mut seg2_len = 0;
    while bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric()) {
        end += 1;
        seg2_len += 1;
        if end > MAX_CANDIDATE_BYTES {
            return Err(ScanError::CandidateLimit);
        }
    }
    Ok((39..=50).contains(&seg2_len).then_some(end))
}

fn sendinblue_match(bytes: &[u8]) -> Result<Option<usize>, ScanError> {
    if !bytes.starts_with(b"xkeysib-") {
        return Ok(None);
    }
    let body = &bytes[8..];
    let body_len = body
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        .take(MAX_CANDIDATE_BYTES + 1)
        .count();
    Ok((body_len == 81).then_some(8 + body_len))
}

fn twilio_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    for &(prefix, rule, hex_len) in &[
        (b"AC" as &[u8], RuleId::TwilioAccountSid, 32),
        (b"SK", RuleId::TwilioApiKey, 32),
    ] {
        if !bytes.starts_with(prefix) {
            continue;
        }
        let body = bytes.get(prefix.len()..prefix.len() + hex_len)?;
        if body.iter().all(|b| b.is_ascii_hexdigit())
            && !bytes
                .get(prefix.len() + hex_len)
                .is_some_and(|&b| b.is_ascii_hexdigit())
        {
            return Some((rule, prefix.len() + hex_len));
        }
    }
    None
}

fn docker_swarm_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    if bytes.starts_with(b"SWMTKN-1-") {
        let mut end = 9;
        while bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric()) {
            end += 1;
            if end > MAX_CANDIDATE_BYTES {
                return None;
            }
        }
        if end == 9 || bytes.get(end) != Some(&b'-') {
            return None;
        }
        end += 1;
        let part2_start = end;
        while bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric()) {
            end += 1;
            if end > MAX_CANDIDATE_BYTES {
                return None;
            }
        }
        let part2_len = end - part2_start;
        if (24..=30).contains(&part2_len) {
            return Some((RuleId::DockerSwarmJoin, end));
        }
    }
    if bytes.starts_with(b"SWMKEY-1-") {
        let mut end = 9;
        while bytes
            .get(end)
            .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            end += 1;
            if end > MAX_CANDIDATE_BYTES {
                return None;
            }
        }
        let key_len = end - 9;
        if (40..=50).contains(&key_len) {
            return Some((RuleId::DockerSwarmUnlock, end));
        }
    }
    None
}

fn telegram_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    let mut digits_len = 0;
    while bytes.get(digits_len).is_some_and(|&b| b.is_ascii_digit()) {
        digits_len += 1;
        if digits_len > 16 {
            return None;
        }
    }
    if !(5..=16).contains(&digits_len) {
        return None;
    }
    if bytes.get(digits_len) != Some(&b':') {
        return None;
    }
    if bytes.get(digits_len + 1) != Some(&b'A') {
        return None;
    }
    let mut end = digits_len + 2;
    while bytes
        .get(end)
        .is_some_and(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        end += 1;
        if end > MAX_CANDIDATE_BYTES {
            return None;
        }
    }
    let body_len = end - (digits_len + 2);
    if body_len >= 34 {
        Some((RuleId::TelegramBotToken, end))
    } else {
        None
    }
}

fn stripe_payment_intent_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    if !bytes.starts_with(b"pi_") {
        return None;
    }
    let mut i = 3;
    while bytes
        .get(i)
        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'-')
    {
        i += 1;
        if i > MAX_CANDIDATE_BYTES {
            return None;
        }
    }
    if bytes.get(i) != Some(&b'_') {
        return None;
    }
    if bytes.get(i + 1..i + 7) != Some(b"secret") {
        return None;
    }
    if bytes.get(i + 7) != Some(&b'_') {
        return None;
    }
    i += 8;
    let mut end = i;
    while bytes
        .get(end)
        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'-')
    {
        end += 1;
        if end > MAX_CANDIDATE_BYTES {
            return None;
        }
    }
    if end > i {
        Some((RuleId::StripePaymentIntent, end))
    } else {
        None
    }
}

fn flutterwave_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    for prefix in &[b"FLWSECK-" as &[u8], b"FLWTESTCK-"] {
        if !bytes.starts_with(prefix) {
            continue;
        }
        let body = bytes.get(prefix.len()..prefix.len() + 32)?;
        if body.iter().all(|b| b.is_ascii_hexdigit())
            && !bytes
                .get(prefix.len() + 32)
                .is_some_and(|&b| b.is_ascii_hexdigit())
        {
            return Some((RuleId::FlutterwaveKey, prefix.len() + 32));
        }
    }
    None
}

/// Dropbox access token: `sl.` prefix followed by 130+ body chars over
/// `[A-Za-z0-9\-_]` (dots are not part of the body, unlike api_key_match_with_min).
fn dropbox_access_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let is_body = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    let mut end = start;
    while end - start < MAX_CANDIDATE_BYTES && bytes.get(end).is_some_and(|&b| is_body(b)) {
        end += 1;
    }
    if end - start < 130 {
        return None;
    }
    if bytes.get(end).is_some_and(|&b| is_body(b)) {
        return None;
    }
    Some(end)
}

/// GitLab documents per-type token families with an exact body length over
/// `[A-Za-z0-9_-]`; a longer run is a different identifier, not this family.
fn gitlab_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Atlassian's modern API token format: `ATATT3` plus 186 `[A-Za-z0-9_=-]` bytes.
/// A longer run is another identifier; a shorter run is a near miss.
fn atlassian_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b'-'))
    {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-' || next == b'=')
    {
        return None;
    }
    Some(end)
}

/// Netlify access token: `nfp_` plus exactly 36 `[A-Za-z0-9_]` bytes.
fn netlify_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Pinecone keys are `pcsk_`, a five- or six-byte alphanumeric group, `_`, then 63
/// alphanumeric body bytes.
fn pinecone_key_match(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"pcsk_") {
        return None;
    }
    for group_len in [5, 6] {
        let group_end = 5 + group_len;
        let body_start = group_end + 1;
        let body_end = body_start + 63;
        if bytes.get(group_end) != Some(&b'_') || bytes.len() < body_end {
            continue;
        }
        let group = &bytes[5..group_end];
        let body = &bytes[body_start..body_end];
        if !group.iter().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        if !body.iter().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        if bytes
            .get(body_end)
            .is_some_and(|&next| is_word(next) || next == b'-')
        {
            continue;
        }
        return Some(body_end);
    }
    None
}

/// Anthropic admin keys are `sk-ant-admin01-` plus 93 `[A-Za-z0-9_-]` bytes ending in
/// `AA`. Ordinary `sk-ant-` keys stay with the existing opaque rule.
fn anthropic_admin_key_match(bytes: &[u8]) -> Option<usize> {
    let prefix_len = b"sk-ant-admin01-".len();
    if !bytes.starts_with(b"sk-ant-admin01-") {
        return None;
    }
    let end = prefix_len + 93;
    if bytes.len() < end {
        return None;
    }
    let body = &bytes[prefix_len..end];
    if !body
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-'))
    {
        return None;
    }
    if bytes.get(end - 2) != Some(&b'A') || bytes.get(end - 1) != Some(&b'A') {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// PlanetScale publishes three credential prefixes with 32-64 byte bodies over
/// `[A-Za-z0-9_.=-]`; the older `pscale_password_` spelling is not current.
fn planetscale_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let is_body = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'=' | b'-');
    let mut end = start;
    while end - start < 64 && bytes.get(end).is_some_and(|&b| is_body(b)) {
        end += 1;
    }
    if end - start < 32 {
        return None;
    }
    if bytes.get(end).is_some_and(|&b| is_body(b)) {
        return None;
    }
    Some(end)
}

/// Paddle publishes an exact backend API key grammar: a live or sandbox prefix,
/// 26 lowercase alphanumeric bytes, `_`, 22 alphanumeric bytes, `_`, and three
/// alphanumeric bytes.
fn paddle_api_key_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    if bytes.len() < start + 53 {
        return None;
    }
    if bytes.get(start + 26) != Some(&b'_') || bytes.get(start + 49) != Some(&b'_') {
        return None;
    }
    let groups_ok = bytes[start..start + 26]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes[start + 27..start + 49]
            .iter()
            .all(|b| b.is_ascii_alphanumeric())
        && bytes[start + 50..start + 53]
            .iter()
            .all(|b| b.is_ascii_alphanumeric());
    if !groups_ok {
        return None;
    }
    let end = start + 53;
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Fly.io API tokens (`fo1_` + 43) and Flagsmith server tokens (`ser.` + 43) use
/// exact-length bodies over `[A-Za-z0-9_-]`; a longer run is a different identifier.
fn alnum_dash_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Resend keys are `re_`, an 8-byte base58 component, `_`, and a 24-byte base58
/// component; the base58 alphabet excludes `0`, `O`, `I`, and `l`.
fn resend_api_key_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let is_base58 = |b: u8| {
        (b'1'..=b'9').contains(&b)
            || (b'A'..=b'H').contains(&b)
            || (b'J'..=b'N').contains(&b)
            || (b'P'..=b'Z').contains(&b)
            || (b'a'..=b'k').contains(&b)
            || (b'm'..=b'z').contains(&b)
    };
    let start = prefix.len();
    if bytes.len() < start + 33 {
        return None;
    }
    let first = &bytes[start..start + 8];
    let second = &bytes[start + 9..start + 33];
    if !first.iter().all(|&b| is_base58(b)) || bytes.get(start + 8) != Some(&b'_') {
        return None;
    }
    if !second.iter().all(|&b| is_base58(b)) {
        return None;
    }
    let end = start + 33;
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// GrowthBook REST secret keys are `secret_` plus 16-64 `[A-Za-z0-9_-]` bytes.
fn growthbook_secret_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let is_body = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
    let mut end = start;
    while end - start < 64 && bytes.get(end).is_some_and(|&b| is_body(b)) {
        end += 1;
    }
    if end - start < 16 {
        return None;
    }
    if bytes.get(end).is_some_and(|&b| is_body(b)) {
        return None;
    }
    Some(end)
}

/// PostHog personal tokens are `phx_` plus 43-48 `[A-Za-z0-9_]` bytes; public
/// `phc_` project tokens stay out of this rule.
fn posthog_personal_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let is_body = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut end = start;
    while end - start < 48 && bytes.get(end).is_some_and(|&b| is_body(b)) {
        end += 1;
    }
    if end - start < 43 {
        return None;
    }
    if bytes.get(end).is_some_and(|&b| is_body(b)) {
        return None;
    }
    Some(end)
}

/// Grafana service-account tokens are `glsa_` plus 32 alphanumeric bytes, `_`, and
/// eight lowercase hex bytes.
fn grafana_service_account_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    if bytes.len() < start + 41 {
        return None;
    }
    let body = &bytes[start..start + 41];
    if !body[..32].iter().all(|b| b.is_ascii_alphanumeric()) || body[32] != b'_' {
        return None;
    }
    if !body[33..41]
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let end = start + 41;
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Axiom (`xaat-`/`xapt-`), Plaid access tokens, and LaunchDarkly server SDK tokens
/// (`sdk-`) carry a lowercase-hex UUID in the 8-4-4-4-12 grouping.
fn hyphen_hex_uuid_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    if bytes.len() < start + 36 {
        return None;
    }
    let body = &bytes[start..start + 36];
    if body[8] != b'-' || body[13] != b'-' || body[18] != b'-' || body[23] != b'-' {
        return None;
    }
    let is_hex_lower = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    for (from, to) in [(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)] {
        if !body[from..to].iter().all(|&b| is_hex_lower(b)) {
            return None;
        }
    }
    let end = start + 36;
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Fly.io management tokens are `fm1a_`, `fm1r_`, or `fm2_` plus 100-512 base64
/// characters and up to three `=` padding bytes.
fn flyio_management_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let mut end = start;
    while end - start < 512
        && bytes
            .get(end)
            .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        end += 1;
    }
    let body_len = end - start;
    if body_len < 100 {
        return None;
    }
    let mut padding = 0;
    while padding < 2 && bytes.get(end).is_some_and(|&b| b == b'=') {
        end += 1;
        padding += 1;
    }
    if bytes.get(end).is_some_and(|&next| {
        is_word(next) || next == b'/' || next == b'+' || next == b'-' || next == b'='
    }) {
        return None;
    }
    Some(end)
}

/// GitLab trigger tokens (`glptt-`) and Sentry personal tokens (`sntryu_`) use exact
/// lowercase-hex bodies of 40 and 64 bytes respectively.
fn lower_hex_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// SonarQube Cloud (`sqco_`) and Kong Konnect (`kpat_`/`spat_`) publish exact-length
/// alphanumeric bodies; a longer run is a different identifier.
fn alnum_token_match(bytes: &[u8], prefixes: &[&[u8]], body_len: usize) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + body_len;
    let body = bytes.get(start..end)?;
    if !body.iter().all(|&b| b.is_ascii_alphanumeric()) {
        return None;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// Doppler tokens are `dp.` plus a type segment and a 40-44 byte alphanumeric
/// secret. `st` may carry an optional dotted lowercase config segment; the other
/// segments take `_`.
fn doppler_token_match(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"dp.") {
        return None;
    }
    let secret_end = |start: usize| -> Option<usize> {
        let mut end = start;
        while end - start < 44 && bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric()) {
            end += 1;
        }
        if end - start < 40 {
            return None;
        }
        if bytes
            .get(end)
            .is_some_and(|&next| is_word(next) || next == b'-')
        {
            return None;
        }
        Some(end)
    };
    if bytes.starts_with(b"dp.ct_") || bytes.starts_with(b"dp.pt_") || bytes.starts_with(b"dp.sa_")
    {
        return secret_end(6);
    }
    if bytes.starts_with(b"dp.scim_") {
        return secret_end(8);
    }
    if bytes.starts_with(b"dp.audit_") {
        return secret_end(9);
    }
    if !bytes.starts_with(b"dp.st.") {
        return None;
    }
    let is_scope = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-');
    let mut scope_end = 6;
    while scope_end - 6 < 35 && bytes.get(scope_end).is_some_and(|&b| is_scope(b)) {
        scope_end += 1;
    }
    if scope_end - 6 >= 2 && bytes.get(scope_end) == Some(&b'.') {
        return secret_end(scope_end + 1);
    }
    secret_end(6)
}

/// Tailscale credential families carry a type prefix, a nonempty alphanumeric
/// or `_` component, `-`, and a second nonempty component. Public `tskey-client`
/// identifiers stay out of these rules.
fn tailscale_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let is_part = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let start = prefix.len();
    if !bytes.get(start).is_some_and(|&b| is_part(b)) {
        return None;
    }
    let mut end = start;
    while bytes.get(end).is_some_and(|&b| is_part(b)) {
        end += 1;
    }
    if bytes.get(end) != Some(&b'-') {
        return None;
    }
    let second = end + 1;
    if !bytes.get(second).is_some_and(|&b| is_part(b)) {
        return None;
    }
    end = second;
    while bytes.get(end).is_some_and(|&b| is_part(b)) {
        end += 1;
    }
    if bytes
        .get(end)
        .is_some_and(|&next| is_word(next) || next == b'-')
    {
        return None;
    }
    Some(end)
}

/// CircleCI announced format: prefix, 22-byte base58 encoded UUID, `_`, 40 hex.
/// Legacy 40-hex-only values require context and stay out of this rule.
fn circleci_match(bytes: &[u8]) -> Option<(RuleId, usize)> {
    for (prefixes, rule) in [
        (
            CIRCLECI_PERSONAL_TOKEN_PREFIXES,
            RuleId::CircleCiPersonalToken,
        ),
        (
            CIRCLECI_PROJECT_TOKEN_PREFIXES,
            RuleId::CircleCiProjectToken,
        ),
    ] {
        let Some(prefix) = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix)) else {
            continue;
        };
        let id_start = prefix.len();
        let id_end = id_start + 22;
        let hex_start = id_end + 1;
        let hex_end = hex_start + 40;
        let Some(id_part) = bytes.get(id_start..id_end) else {
            continue;
        };
        // Base58 excludes the confusable 0, O, I, and l characters.
        if !id_part
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
        {
            continue;
        }
        if bytes.get(id_end) != Some(&b'_') {
            continue;
        }
        let Some(hex_part) = bytes.get(hex_start..hex_end) else {
            continue;
        };
        if !hex_part.iter().all(|&b| b.is_ascii_hexdigit()) {
            continue;
        }
        if bytes
            .get(hex_end)
            .is_some_and(|&next| is_word(next) || next == b'-')
        {
            continue;
        }
        return Some((rule, hex_end));
    }
    None
}

fn uri_match(bytes: &[u8], prefixes: &[&[u8]], rule: RuleId) -> Option<(RuleId, usize)> {
    let prefix = prefixes.iter().find(|&&p| bytes.starts_with(p))?;
    let after_scheme = &bytes[prefix.len()..];
    // Must have user:pass@ for credentials
    let slash_pos = after_scheme.iter().position(|&b| b == b'/');
    let authority = match slash_pos {
        Some(pos) => &after_scheme[..pos],
        None => after_scheme,
    };
    if !authority.contains(&b'@') {
        return None;
    }
    let at_pos = authority.iter().position(|&b| b == b'@')?;
    let credentials = &authority[..at_pos];
    if !credentials.contains(&b':') {
        return None;
    }
    // Find end: stop at whitespace or common delimiters
    let mut end = prefix.len();
    while end < bytes.len() {
        if bytes[end].is_ascii_whitespace()
            || matches!(bytes[end], b'"' | b'\'' | b')' | b',' | b';')
        {
            break;
        }
        end += 1;
    }
    Some((rule, end))
}

/// 1Password service-account token: `ops_eyJ` followed by 60+ base64 body bytes
/// (`[A-Za-z0-9+/]`) and an optional up-to-three `=` padding run. A longer run
/// than this is a different identifier, not the supported token format.
fn one_password_service_token_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let is_body = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let mut end = start;
    while end - start < MAX_CANDIDATE_BYTES && bytes.get(end).is_some_and(|&b| is_body(b)) {
        end += 1;
    }
    if end - start < 60 {
        return None;
    }
    let mut pad = 0;
    while pad < 3 && bytes.get(end + pad) == Some(&b'=') {
        pad += 1;
    }
    let length = end + pad;
    if let Some(next) = bytes.get(length) {
        if is_body(*next) || *next == b'=' {
            return None;
        }
    }
    Some(length)
}

/// Beamer API key: `b_` followed by EXACTLY 44 chars of `[a-z0-9=_-]`. A longer
/// or shorter body is a different identifier, not this family.
fn beamer_api_key_match(bytes: &[u8], prefixes: &[&[u8]]) -> Option<usize> {
    let prefix = prefixes.iter().find(|&&prefix| bytes.starts_with(prefix))?;
    let start = prefix.len();
    let end = start + 44;
    let body = bytes.get(start..end)?;
    let is_body = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'=' | b'_');
    if !body.iter().all(|&b| is_body(b)) {
        return None;
    }
    if bytes.get(end).is_some_and(|&next| is_body(next)) {
        return None;
    }
    Some(end)
}

/// Two-byte head prefilter for the provider chain. Every structural match (and
/// its candidate-limit error) is reachable only after one of the registered
/// literals starts at the position, so a position whose first two bytes head no
/// literal returns `Ok(None)` without walking the chain. Kept as data next to
/// the prefix tables so adding a rule cannot silently disable the prefilter.
const PROVIDER_HEAD_LITERALS: &[&[&[u8]]] = &[
    GITHUB_PREFIXES,
    STRIPE_SECRET_PREFIXES,
    STRIPE_RESTRICTED_PREFIXES,
    SLACK_PREFIXES,
    OPENAI_PREFIXES,
    OPENROUTER_PREFIXES,
    ANTHROPIC_PREFIXES,
    GROQ_PREFIXES,
    PERPLEXITY_PREFIXES,
    HUGGINGFACE_PREFIXES,
    XAI_PREFIXES,
    GOOGLE_API_PREFIXES,
    ALIBABA_PREFIXES,
    BAIDU_PREFIXES,
    WANDB_PREFIXES,
    FIRECRAWL_PREFIXES,
    LANGSMITH_PREFIXES,
    VOYAGE_PREFIXES,
    CARTESIA_PREFIXES,
    REPLICATE_PREFIXES,
    VERCEL_PREFIXES,
    SUPABASE_PREFIXES,
    CLOUDFLARE_PREFIXES,
    DIGITALOCEAN_PAT_PREFIXES,
    DIGITALOCEAN_OAUTH_PREFIXES,
    DIGITALOCEAN_REFRESH_PREFIXES,
    HEROKU_API_KEY_PREFIXES,
    CLOUDINARY_URL_PREFIXES,
    CLOJARS_TOKEN_PREFIXES,
    CRATESIO_TOKEN_PREFIXES,
    PYPY_TOKEN_PREFIXES,
    RUBYGENS_API_KEY_PREFIXES,
    SLACK_BOT_TOKEN_PREFIXES,
    SLACK_USER_TOKEN_PREFIXES,
    SLACK_WORKSPACE_TOKEN_PREFIXES,
    SLACK_REFRESH_TOKEN_PREFIXES,
    SENTRY_ORG_TOKEN_PREFIXES,
    SENTRY_PERSONAL_TOKEN_PREFIXES,
    GRAFANA_SERVICE_ACCOUNT_TOKEN_PREFIXES,
    AXIOM_TOKEN_PREFIXES,
    SONARQUBE_TOKEN_PREFIXES,
    SONARQUBE_CLOUD_TOKEN_PREFIXES,
    KONG_KONNECT_TOKEN_PREFIXES,
    TRUFFLEHOG_ENTERPRISE_SECRET_PREFIXES,
    TAILSCALE_API_TOKEN_PREFIXES,
    TAILSCALE_AUTH_TOKEN_PREFIXES,
    RESEND_API_KEY_PREFIXES,
    LAUNCH_DARKLY_SERVER_SDK_TOKEN_PREFIXES,
    FLAGSMITH_SERVER_TOKEN_PREFIXES,
    GROWTHBOOK_SECRET_KEY_PREFIXES,
    POSTHOG_PERSONAL_TOKEN_PREFIXES,
    GITLAB_CICD_JOB_TOKEN_PREFIXES,
    GITLAB_DEPLOY_TOKEN_PREFIXES,
    GITLAB_FEATURE_FLAG_TOKEN_PREFIXES,
    GITLAB_PERSONAL_ACCESS_TOKEN_PREFIXES,
    GITLAB_RUNNER_TOKEN_PREFIXES,
    GITLAB_RUNNER_REGISTRATION_TOKEN_PREFIXES,
    GITLAB_FEED_TOKEN_PREFIXES,
    GITLAB_INCOMING_MAIL_TOKEN_PREFIXES,
    GITLAB_SCIM_TOKEN_PREFIXES,
    GITLAB_AGENT_TOKEN_PREFIXES,
    GITLAB_OAUTH_APP_SECRET_PREFIXES,
    GITLAB_TRIGGER_TOKEN_PREFIXES,
    CIRCLECI_PERSONAL_TOKEN_PREFIXES,
    CIRCLECI_PROJECT_TOKEN_PREFIXES,
    ATLASSIAN_API_TOKEN_PREFIXES,
    NETLIFY_ACCESS_TOKEN_PREFIXES,
    FLYIO_API_TOKEN_PREFIXES,
    FLYIO_MANAGEMENT_TOKEN_PREFIXES,
    AUTH0_MANAGEMENT_TOKEN_PREFIXES,
    OKTA_ACCESS_TOKEN_PREFIXES,
    NOTION_API_KEY_PREFIXES,
    LINEAR_API_KEY_PREFIXES,
    FIGMA_TOKEN_PREFIXES,
    SQUARE_ACCESS_TOKEN_PREFIXES,
    SHOPIFY_ACCESS_TOKEN_PREFIXES,
    SHOPIFY_CUSTOM_TOKEN_PREFIXES,
    SHOPIFY_SHARED_SECRET_PREFIXES,
    SHOPIFY_APP_PASSWORD_PREFIXES,
    STRIPE_ACCESS_TOKEN_PREFIXES,
    PLANETSCALE_PASSWORD_PREFIXES,
    PLANETSCALE_TOKEN_PREFIXES,
    PLANETSCALE_OAUTH_TOKEN_PREFIXES,
    PADDLE_API_KEY_PREFIXES,
    PLAID_ACCESS_TOKEN_PREFIXES,
    MISTRAL_KEY_PREFIXES,
    CEREBRAS_KEY_PREFIXES,
    TOGETHERAI_KEY_PREFIXES,
    FIREWORKS_AI_KEY_PREFIXES,
    STABILITY_AI_KEY_PREFIXES,
    DEEPGRAM_KEY_PREFIXES,
    RAZORPAY_KEY_PREFIXES,
    MONGODB_URI_PREFIXES,
    POSTGRES_URI_PREFIXES,
    REDIS_URI_PREFIXES,
    SQLSERVER_URI_PREFIXES,
    MYSQL_URI_PREFIXES,
    COCKROACHDB_URI_PREFIXES,
    ADOBE_CLIENT_SECRET_PREFIXES,
    AIVEN_AUTH_TOKEN_PREFIXES,
    AIVEN_SERVICE_PASSWORD_PREFIXES,
    APIFY_API_TOKEN_PREFIXES,
    CANVA_APP_SECRET_PREFIXES,
    CANVA_CONNECT_API_SECRET_PREFIXES,
    CANVA_SECRET_PREFIXES,
    CLOUDSMITH_API_KEY_PREFIXES,
    DATABENTO_API_KEY_PREFIXES,
    DOPPLER_AUDIT_TOKEN_PREFIXES,
    GITHUB_SSH_PRIVATE_KEY_PREFIXES,
    HASHICORP_VAULT_SERVICE_TOKEN_PREFIXES,
    LOB_LIVE_API_KEY_PREFIXES,
    LOB_TEST_API_KEY_PREFIXES,
    MAILERSEND_API_TOKEN_PREFIXES,
    MAILERSEND_SMTP_PASSWORD_PREFIXES,
    MAILERSEND_SMTP_USERNAME_PREFIXES,
    MAILGUN_API_KEY_PREFIXES,
    MAILGUN_SMTP_CREDENTIAL_PREFIXES,
    MAPBOX_SECRET_ACCESS_TOKEN_PREFIXES,
    MERCURY_NON_PRODUCTION_API_TOKEN_PREFIXES,
    MERCURY_PRODUCTION_API_TOKEN_PREFIXES,
    MIDTRANS_PRODUCTION_SERVER_KEY_PREFIXES,
    MIDTRANS_SANDBOX_SERVER_KEY_PREFIXES,
    NAVERCLOUD_GOV_ACCESS_KEY_ID_PREFIXES,
    NAVERCLOUD_GOV_ACCESS_KEY_SECRET_PREFIXES,
    NAVERCLOUD_GOV_STS_PREFIXES,
    NAVERCLOUD_GOV_STS_SECRET_PREFIXES,
    NAVERCLOUD_PUB_ACCESS_KEY_PREFIXES,
    NAVERCLOUD_PUB_ACCESS_KEY_SECRET_PREFIXES,
    NAVERCLOUD_PUB_STS_PREFIXES,
    NAVERCLOUD_PUB_STS_SECRET_PREFIXES,
    POLAR_PERSONAL_ACCESS_TOKEN_PREFIXES,
    POLAR_ACCESS_TOKEN_PREFIXES,
    POLAR_REFRESH_TOKEN_PREFIXES,
    POLAR_AUTHORIZATION_CODE_PREFIXES,
    POLAR_CLIENT_REGISTRATION_TOKEN_PREFIXES,
    POLAR_CLIENT_SECRET_PREFIXES,
    POLAR_CUSTOMER_SESSION_TOKEN_PREFIXES,
    POLAR_USER_SESSION_TOKEN_PREFIXES,
    AIRTABLE_PAT_PREFIXES,
    BITRISE_PAT_PREFIXES,
    DUFFEL_LIVE_ACCESS_TOKEN_PREFIXES,
    DUFFEL_TEST_ACCESS_TOKEN_PREFIXES,
    DYNATRACE_API_TOKEN_PREFIXES,
    EASYPOST_PRODUCTION_API_KEY_PREFIXES,
    EASYPOST_TEST_API_KEY_PREFIXES,
    ELASTIC_CLOUD_API_KEY_PREFIXES,
    ELASTIC_STACK_API_KEY_PREFIXES,
    FLUTTERWAVE_LIVE_API_SECRET_KEY_PREFIXES,
    FLUTTERWAVE_TEST_API_SECRET_KEY_PREFIXES,
    FRAME_IO_DEVELOPER_TOKEN_PREFIXES,
    HASHICORP_VAULT_BATCH_TOKEN_PREFIXES,
    HEROKU_PLATFORM_API_OAUTH2_TOKEN_PREFIXES,
    HEX_API_KEY_PREFIXES,
    HIGHNOTE_RK_LIVE_KEY_PREFIXES,
    HIGHNOTE_RK_TEST_KEY_PREFIXES,
    HIGHNOTE_SK_LIVE_KEY_PREFIXES,
    HIGHNOTE_SK_TEST_KEY_PREFIXES,
    DATABRICKS_API_TOKEN_PREFIXES,
    DOPPLER_CLI_TOKEN_PREFIXES,
    DOPPLER_PERSONAL_TOKEN_PREFIXES,
    DROPBOX_ACCESS_TOKEN_PREFIXES,
    NEW_RELIC_INSIGHTS_QUERY_KEY_PREFIXES,
    NEW_RELIC_LICENSE_KEY_PREFIXES,
    NEW_RELIC_PERSONAL_API_KEY_PREFIXES,
    NEW_RELIC_REST_API_KEY_PREFIXES,
    NUGET_API_KEY_PREFIXES,
    OCTOPUS_DEPLOY_API_KEY_PREFIXES,
    PULUMI_ACCESS_TOKEN_PREFIXES,
    POSTMAN_API_KEY_PREFIXES,
    POSTMAN_COLLECTION_KEY_PREFIXES,
    READ_ME_API_KEY_PREFIXES,
    SALESFORCE_OAUTH2_CONSUMER_KEY_PREFIXES,
    SALESFORCE_REFRESH_TOKEN_PREFIXES,
    TYPEFORM_PERSONAL_ACCESS_TOKEN_PREFIXES,
    VERCEL_API_KEY_PREFIXES,
    WAKATIME_API_KEY_PREFIXES,
    YANDEX_CLOUD_API_KEY_PREFIXES,
    YANDEX_CLOUD_ACCESS_SECRET_PREFIXES,
    YANDEX_CLOUD_IAM_TOKEN_PREFIXES,
    YANDEX_CLOUD_SMARTCAPTCHA_SERVER_KEY_PREFIXES,
    YANDEX_PASSPORT_OAUTH_TOKEN_PREFIXES,
    ONE_PASSWORD_SERVICE_ACCOUNT_TOKEN_PREFIXES,
    ADAFRUIT_IO_KEY_PREFIXES,
    BEAMER_API_KEY_PREFIXES,
    CCDB_API_KEY_PREFIXES,
    CDS_CANADA_NOTIFY_API_KEY_PREFIXES,
    CONTENTFUL_PAT_PREFIXES,
    DOCKER_PERSONAL_PAT_PREFIXES,
    DOCKER_ORGANIZATION_PAT_PREFIXES,
    BUILDKITE_USER_ACCESS_TOKEN_PREFIXES,
    BUILDKITE_AGENT_ACCESS_TOKEN_PREFIXES,
    BUILDKITE_AGENT_JOB_TOKEN_PREFIXES,
    BUILDKITE_AGENT_REGISTRATION_TOKEN_PREFIXES,
    BUILDKITE_CLUSTER_TOKEN_PREFIXES,
    BUILDKITE_CLUSTER_QUEUE_TOKEN_PREFIXES,
    BUILDKITE_PACKAGES_REGISTRY_TOKEN_PREFIXES,
    BUILDKITE_PACKAGES_TEMPORARY_TOKEN_PREFIXES,
    BUILDKITE_PORTAL_TOKEN_PREFIXES,
    BUILDKITE_PORTAL_SECRET_PREFIXES,
    PRIVATE_KEY_MARKERS,
];
const PROVIDER_HEAD_EXTRA_LITERALS: [&[u8]; 13] = [
    b"AKIA",            // aws_match
    b"ASIA",            // aws_match
    b"AC",              // twilio_match
    b"SK",              // twilio_match
    b"SG.",             // sendgrid_match
    b"SWMKEY-1-",       // docker_swarm_match
    b"SWMTKN-1-",       // docker_swarm_match
    b"FLWSECK-",        // flutterwave_match (FLWTESTCK- shares this head)
    b"xkeysib-",        // sendinblue_match
    b"pi_",             // stripe_payment_intent_match
    b"dp.",             // doppler_token_match (all dp.<type> literals share this head)
    b"pcsk_",           // pinecone_key_match
    b"sk-ant-admin01-", // anthropic_admin_key_match
];

/// Build the 256x256 head-byte bitmap at compile time. A one-byte prefix (none
/// today) opens every second byte for its head; telegram digits do the same.
const fn provider_head_bits() -> [bool; 65536] {
    let mut bits = [false; 65536];
    let mut any_second = [false; 256];
    let mut group_index = 0;
    while group_index < PROVIDER_HEAD_LITERALS.len() {
        let group = PROVIDER_HEAD_LITERALS[group_index];
        let mut prefix_index = 0;
        while prefix_index < group.len() {
            let prefix = group[prefix_index];
            if prefix.len() == 1 {
                any_second[prefix[0] as usize] = true;
            } else if prefix.len() >= 2 {
                bits[(((prefix[0] as u16) << 8) | prefix[1] as u16) as usize] = true;
            }
            prefix_index += 1;
        }
        group_index += 1;
    }
    let mut extra_index = 0;
    while extra_index < PROVIDER_HEAD_EXTRA_LITERALS.len() {
        let literal = PROVIDER_HEAD_EXTRA_LITERALS[extra_index];
        bits[(((literal[0] as u16) << 8) | literal[1] as u16) as usize] = true;
        extra_index += 1;
    }
    let mut digit = b'0';
    while digit <= b'9' {
        any_second[digit as usize] = true;
        digit += 1;
    }
    let mut head = 0;
    while head < 256 {
        if any_second[head] {
            let mut slot = head * 256;
            while slot < head * 256 + 256 {
                bits[slot] = true;
                slot += 1;
            }
        }
        head += 1;
    }
    bits
}
const PROVIDER_HEAD_BITS: &[bool; 65536] = &provider_head_bits();

/// Distinct context keywords used by the generic `keyword_gated` dispatch
/// table (deterministic order; `azure` gates both the structural family and
/// the 66-row generic tail). The line scanner feeds occurrences of these
/// words incrementally so each candidate only tests a bitmask.
const KEYWORD_GATE_WORDS: [&[u8]; 23] = [
    b"aikido",
    b"airtable",
    b"aws",
    b"asana",
    b"asaas",
    b"atlassian",
    b"authress",
    b"azure",
    b"bitbucket",
    b"block",
    b"cashfree",
    b"cfx",
    b"chief",
    b"cohere",
    b"contentful",
    b"contributed",
    b"coveo",
    b"datadog",
    b"docker",
    b"onechronos",
    b"onesignal",
    b"apiclub",
    b"adobe",
];
const KEYWORD_GATE_WINDOW: usize = 200;
const KEYWORD_GATE_MIN_LEN: usize = 3;
const KEYWORD_GATE_MAX_LEN: usize = 11;
const KEYWORD_GATE_RING_LEN: usize = KEYWORD_GATE_MAX_LEN + 1;

/// Bitmask of keyword indices whose first byte matches a given byte
/// (case-insensitive), so the incremental feed compares only plausible
/// keywords at each position.
const fn keyword_first_bits() -> [u32; 256] {
    let mut bits = [0u32; 256];
    let mut index = 0;
    while index < KEYWORD_GATE_WORDS.len() {
        let first = KEYWORD_GATE_WORDS[index][0];
        bits[first as usize] |= 1 << index;
        bits[((first as u16) & 0xDF) as usize] |= 1 << index;
        index += 1;
    }
    bits
}
const KEYWORD_GATE_FIRST_BITS: &[u32; 256] = &keyword_first_bits();

/// Case-insensitive two-byte prefix gate: true for every pair of bytes that
/// can start a gate keyword in any letter case. Queueing keyword comparisons
/// only for matching pairs keeps common English bigrams from triggering whole
/// keyword scans (the per-completion verification already rejects misses, so
/// the gate only trims work).
const fn keyword_pair_hits() -> [bool; 65536] {
    let mut hits = [false; 65536];
    let mut index = 0;
    while index < KEYWORD_GATE_WORDS.len() {
        let word = KEYWORD_GATE_WORDS[index];
        let first = word[0];
        let second = word[1];
        let upper_first = (first as u16) & 0xDF;
        let upper_second = (second as u16) & 0xDF;
        hits[(((first as u16) << 8) | second as u16) as usize] = true;
        hits[((upper_first << 8) | second as u16) as usize] = true;
        hits[(((first as u16) << 8) | upper_second) as usize] = true;
        hits[((upper_first << 8) | upper_second) as usize] = true;
        index += 1;
    }
    hits
}
const KEYWORD_GATE_PAIR_HITS: &[bool; 65536] = &keyword_pair_hits();

/// Bit whose keyword entry equals `azure`, shared by the structural family
/// gate (resolved at compile time so the table order can change safely).
const KEYWORD_AZURE_BIT: u32 = 1u32 << keyword_index(b"azure");
const fn keyword_index(word: &[u8]) -> usize {
    let mut index = 0;
    while index < KEYWORD_GATE_WORDS.len() {
        let candidate = KEYWORD_GATE_WORDS[index];
        if candidate.len() == word.len() {
            let mut at = 0;
            let mut same = true;
            while at < word.len() {
                if candidate[at] != word[at] {
                    same = false;
                    break;
                }
                at += 1;
            }
            if same {
                return index;
            }
        }
        index += 1;
    }
    0
}

/// Generic keyword-gated dispatch rows: (rule, keyword index into
/// `KEYWORD_GATE_WORDS`, minimum value length). Order is first-match-wins
/// and alphabetical by rule id with the azure family contiguous.
const KEYWORD_GATED_ROWS: &[(RuleId, u8, usize)] = &[
    (RuleId::AikidoApiClientSecret, 0, 20),
    (RuleId::AikidoCiScanningToken, 0, 20),
    (RuleId::AirtableApiKey, 1, 20),
    (RuleId::AdobeDeviceToken, 22, 20),
    (RuleId::AdobePacToken, 22, 20),
    (RuleId::AdobeRefreshToken, 22, 20),
    (RuleId::AdobeServiceToken, 22, 20),
    (RuleId::AdobeShortLivedAccessToken, 22, 20),
    (RuleId::ApiclubApiKey, 21, 20),
    (RuleId::AmazonAwsApiKeyId, 2, 20),
    (RuleId::AmazonAwsSessionToken, 2, 20),
    (RuleId::AmazonAwsTemporaryAccessKeyId, 2, 20),
    (RuleId::AsanaLegacyFormatPersonalAccessToken, 3, 20),
    (RuleId::AsanaPersonalAccessToken, 3, 20),
    (RuleId::AsaasApiToken, 4, 20),
    (RuleId::AtlassianJwt, 5, 20),
    (RuleId::AuthressServiceClientAccessKey, 6, 20),
    (RuleId::AzureAnomalyDetectorKey, 7, 20),
    (RuleId::AzureAnomalyDetectorEeKey, 7, 20),
    (RuleId::AzureApimDirectManagementKey, 7, 20),
    (RuleId::AzureApimGatewayKey, 7, 20),
    (RuleId::AzureApimRepositoryKey, 7, 20),
    (RuleId::AzureApimSubscriptionKey, 7, 20),
    (RuleId::AzureAppConfigurationKey, 7, 20),
    (RuleId::AzureAppConfigurationConnectionString, 7, 20),
    (RuleId::AzureBatchKeyIdentifiable, 7, 20),
    (RuleId::AzureCommunicationServicesKey, 7, 20),
    (RuleId::AzureCommunicationServicesConnectionString, 7, 20),
    (RuleId::AzureContainerRegistryKeyIdentifiable, 7, 20),
    (RuleId::AzureContentModeratorKey, 7, 20),
    (RuleId::AzureContentSafetyKey, 7, 20),
    (RuleId::AzureCosmosdbKeyIdentifiable, 7, 20),
    (RuleId::AzureCustomVisionPredictionKey, 7, 20),
    (RuleId::AzureCustomVisionTrainingKey, 7, 20),
    (RuleId::AzureEventGridKeyIdentifiable, 7, 20),
    (RuleId::AzureEventHubKeyIdentifiable, 7, 20),
    (RuleId::AzureFaceKey, 7, 20),
    (RuleId::AzureFluidRelayKey, 7, 20),
    (RuleId::AzureFormRecognizerKey, 7, 20),
    (RuleId::AzureHealthDecisionSupportKey, 7, 20),
    (RuleId::AzureHealthInsightsKey, 7, 20),
    (RuleId::AzureImmersiveReaderKey, 7, 20),
    (RuleId::AzureInternalAllInOneKey, 7, 20),
    (RuleId::AzureIotDeviceConnectionString, 7, 20),
    (RuleId::AzureIotDeviceKey, 7, 20),
    (RuleId::AzureIotDeviceProvisioningKey, 7, 20),
    (RuleId::AzureIotHubConnectionString, 7, 20),
    (RuleId::AzureIotHubKey, 7, 20),
    (RuleId::AzureIotProvisioningConnectionString, 7, 20),
    (RuleId::AzureKnowledgeKey, 7, 20),
    (RuleId::AzureLuisAuthoringKey, 7, 20),
    (RuleId::AzureLuisKey, 7, 20),
    (RuleId::AzureMapsKey, 7, 20),
    (RuleId::AzureMetricsAdvisorKey, 7, 20),
    (RuleId::AzureMixedRealityKey, 7, 20),
    (RuleId::AzureMlInferenceIdentifiableKey, 7, 20),
    (
        RuleId::AzureMlInternalServicePrincipalIdentifiableKey,
        7,
        20,
    ),
    (RuleId::AzureMlWebServiceClassicIdentifiableKey, 7, 20),
    (RuleId::AzureOpenAIKey, 7, 20),
    (RuleId::AzurePersonalizerKey, 7, 20),
    (RuleId::AzureQnaMakerKey, 7, 20),
    (RuleId::AzureQnaMakerV2Key, 7, 20),
    (RuleId::AzureQuantumKey, 7, 20),
    (RuleId::AzureRelayKeyIdentifiable, 7, 20),
    (RuleId::AzureSasToken, 7, 20),
    (RuleId::AzureSearchAdminKey, 7, 20),
    (RuleId::AzureSearchQueryKey, 7, 20),
    (RuleId::AzureServiceBusIdentifiable, 7, 20),
    (RuleId::AzureSignalrConnectionString, 7, 20),
    (RuleId::AzureSignalrKey, 7, 20),
    (RuleId::AzureSpeechServicesKey, 7, 20),
    (RuleId::AzureSpeechTranslationKey, 7, 20),
    (RuleId::AzureSqlInternalDefaultCloudSaKey, 7, 20),
    (RuleId::AzureSqlPassword, 7, 20),
    (RuleId::AzureTextAnalyticsKey, 7, 20),
    (RuleId::AzureTextTranslationKey, 7, 20),
    (RuleId::AzureVideoIntelligenceKey, 7, 20),
    (RuleId::AzureWebAppBotKey, 7, 20),
    (RuleId::AzureWebPubSubConnectionString, 7, 20),
    (RuleId::AzureWebPubSubKey, 7, 20),
    (RuleId::MicrosoftAzureEntraIdToken, 7, 20),
    (RuleId::AzureLogicAppsUrl, 7, 20),
    (RuleId::AzureManagementCertificate, 7, 20),
    (RuleId::BitbucketServerPersonalAccessToken, 8, 20),
    (RuleId::BlockProtocolApiKey, 9, 20),
    (RuleId::CashfreeApiKey, 10, 20),
    (RuleId::CfxreServerKey, 11, 20),
    (RuleId::ChiefToolsToken, 12, 20),
    (RuleId::CohereApiKey, 13, 20),
    (RuleId::ContentfulWebToken, 14, 20),
    (RuleId::ContributedSystemsCredentials, 15, 20),
    (RuleId::CoveoAccessToken, 16, 20),
    (RuleId::CoveoApiKey, 16, 20),
    (RuleId::DatadogApiKey, 17, 20),
    // Batch 12 tails: keyword families continue alphabetically after
    // `datadog`. `docker` gates only the two generic Swarm rows; the
    // `dckr_pat_` PAT rules and the `SWMTKN`/`SWMKEY` prefix rules are
    // separate detectors elsewhere in the pipeline.
    (RuleId::DockerSwarmJoinToken, 18, 20),
    (RuleId::DockerSwarmUnlockKey, 18, 20),
    (RuleId::OneChronosApiKey, 19, 20),
    (RuleId::OneChronosEbApiKey, 19, 20),
    (RuleId::OneChronosEbEncryptionKey, 19, 20),
    (RuleId::OneChronosOauthToken, 19, 20),
    (RuleId::OneChronosRefreshToken, 19, 20),
    (RuleId::OneSignalRichAuthenticationToken, 20, 20),
];

/// Consecutive rows sharing one keyword and one minimum length share the
/// same context gate and the same value shape, so the line loop can test
/// the keyword bit and compute the word-run once per segment, then emit
/// the first non-disabled rule inside the segment.
const KEYWORD_GATED_MAX_SEGMENTS: usize = 24;
const fn keyword_segment_build() -> [(usize, usize, u8, usize); KEYWORD_GATED_MAX_SEGMENTS] {
    // The table is a compile-time constant with at least one row.
    let mut segments = [(0usize, 0usize, 0u8, 0usize); KEYWORD_GATED_MAX_SEGMENTS];
    let mut out = 0;
    let mut start = 0;
    let mut index = 1;
    while index <= KEYWORD_GATED_ROWS.len() {
        if index == KEYWORD_GATED_ROWS.len()
            || KEYWORD_GATED_ROWS[index].1 != KEYWORD_GATED_ROWS[start].1
            || KEYWORD_GATED_ROWS[index].2 != KEYWORD_GATED_ROWS[start].2
        {
            segments[out] = (
                start,
                index - start,
                KEYWORD_GATED_ROWS[start].1,
                KEYWORD_GATED_ROWS[start].2,
            );
            out += 1;
            start = index;
        }
        index += 1;
    }
    segments
}
const fn keyword_segment_count() -> usize {
    let mut count = 1;
    let mut index = 1;
    while index < KEYWORD_GATED_ROWS.len() {
        if KEYWORD_GATED_ROWS[index].1 != KEYWORD_GATED_ROWS[index - 1].1
            || KEYWORD_GATED_ROWS[index].2 != KEYWORD_GATED_ROWS[index - 1].2
        {
            count += 1;
        }
        index += 1;
    }
    count
}
const KEYWORD_GATED_SEGMENT_COUNT: usize = keyword_segment_count();
const KEYWORD_GATED_SEGMENT_TABLE: [(usize, usize, u8, usize); KEYWORD_GATED_MAX_SEGMENTS] =
    keyword_segment_build();

/// Word-run matcher for keyword-gated rules: the keyword context is checked
/// by the line's incremental feed (see `detect_line_with_disabled`), so this
/// only validates the value shape and length at the candidate offset.
fn keyword_value_match(bytes: &[u8], min_val_len: usize) -> Option<usize> {
    let mut end = 0;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric()
            || bytes[end] == b'-'
            || bytes[end] == b'_'
            || bytes[end] == b'.')
        && end < MAX_CANDIDATE_BYTES
    {
        end += 1;
    }
    if end >= min_val_len { Some(end) } else { None }
}

// Batch 13: HTTP authentication header rules (the catalog's generic `N` rows).
// The header text itself is the trigger — no provider keyword — so these run
// outside the keyword table, on their own two-tier cheap gate (see
// `detect_line_with_disabled`): a first-tier check on the one byte preceding
// the candidate plus the byte completing a `basic `/`bearer ` window (one
// extra tier inside the matcher), and the full comparison only on gate hits.
const fn http_basic_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

const fn http_bearer_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
}

// Full header check for one candidate: the `basic `/`bearer ` marker must end
// immediately before the candidate (optionally one quote back), the word
// `authorization` must appear within 30 bytes before the marker, and the body
// class/length must fit the rule. No allocations: bounded byte windows
// compared case-insensitively. Returns the emitted length from the candidate
// start (the body plus at most three `=` padding bytes for Basic).
fn http_auth_header_match(bytes: &[u8], offset: usize) -> Option<(RuleId, usize)> {
    if offset == 0 {
        return None;
    }
    // Second-tier gate: the marker ends right at the candidate, or one quote
    // earlier.
    let quoted = bytes[offset - 1] == b'"' || bytes[offset - 1] == b'\'';
    let marker_end = if quoted {
        if offset < 2 {
            return None;
        }
        offset - 1
    } else {
        offset
    };
    // `basic ` spans six bytes, `bearer ` seven, both ending at the marker.
    let basic =
        marker_end >= 6 && bytes[marker_end - 6..marker_end].eq_ignore_ascii_case(b"basic ");
    let bearer =
        marker_end >= 7 && bytes[marker_end - 7..marker_end].eq_ignore_ascii_case(b"bearer ");
    if !basic && !bearer {
        return None;
    }
    // The header word must sit within 30 bytes before the marker.
    let marker_start = marker_end - (if basic { 6 } else { 7 });
    let window_start = marker_start.saturating_sub(30);
    let window = &bytes[window_start..marker_start];
    if !window
        .windows(13)
        .any(|w| w.eq_ignore_ascii_case(b"authorization"))
    {
        return None;
    }
    // Body: Basic takes `[A-Za-z0-9+/]{12,128}` with at most three `=` padding
    // (four or more tail bytes are rejected); Bearer takes
    // `[A-Za-z0-9._-]{10,256}`. Over-long runs are rejected rather than
    // truncated so a near miss stays quiet.
    let end_cap = offset + (if basic { 128 } else { 256 });
    let body_class = if basic {
        http_basic_body_byte
    } else {
        http_bearer_body_byte
    };
    let mut end = offset;
    while end <= end_cap && bytes.get(end).is_some_and(|byte| body_class(*byte)) {
        end += 1;
    }
    let body_len = end - offset;
    if body_len < (if basic { 12 } else { 10 }) || body_len > (if basic { 128 } else { 256 }) {
        return None;
    }
    let mut pad_end = end;
    while pad_end < end + 3 && bytes.get(pad_end) == Some(&b'=') {
        pad_end += 1;
    }
    if bytes.get(pad_end) == Some(&b'=') {
        return None;
    }
    Some((
        if basic {
            RuleId::HttpBasicAuthenticationHeader
        } else {
            RuleId::HttpBearerAuthenticationHeader
        },
        pad_end - offset,
    ))
}

type AzureValidator = fn(&[u8]) -> Option<usize>;

// Batch 8: Azure structural family. These bodies have documented shapes the
// generic word-run matcher cannot express (padding, separators, embedded
// signatures), so each variant carries a small validator over the candidate
// slice. The family shares the `azure` keyword gate inside the context
// window (KEYWORD_AZURE_BIT), and the validators only report exact
// documented lengths so near misses stay quiet.
//
// Union of every structural validator's byte class (alnum plus `_ ~ . - + =
// /`) and the family's shortest documented length (32): one shared run at a
// candidate gates all eight shape validators, since each validator's class is
// a subset of the union and a shorter run cannot reach any documented length.
const fn azure_union_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'~' | b'.' | b'-' | b'+' | b'=' | b'/')
}
const AZURE_STRUCTURAL_MIN_BYTES: usize = 32;
const AZURE_STRUCTURAL_MAX_BYTES: usize = 256;

fn azure_union_run(bytes: &[u8]) -> usize {
    let mut end = 0;
    while end < AZURE_STRUCTURAL_MAX_BYTES
        && bytes.get(end).is_some_and(|&byte| azure_union_byte(byte))
    {
        end += 1;
    }
    end
}

fn azure_devops_pat_match(bytes: &[u8]) -> Option<usize> {
    // Exactly 84 alphanumeric bytes with the literal `AZDO` signature at
    // relative offsets 76..80, terminated by a non-alphanumeric boundary.
    let mut end = 0;
    while end <= 84
        && bytes
            .get(end)
            .is_some_and(|&byte| byte.is_ascii_alphanumeric())
    {
        end += 1;
    }
    if end != 84 || bytes.get(76..80) != Some(b"AZDO") {
        return None;
    }
    Some(84)
}

const fn azure_function_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'/' || byte == b'+'
}

fn azure_function_key_match(bytes: &[u8]) -> Option<usize> {
    // 52 bytes from `[a-z0-9/+]` then the literal `==` padding: 54 total.
    let mut end = 0;
    while end <= 52
        && bytes
            .get(end)
            .is_some_and(|&byte| azure_function_byte(byte))
    {
        end += 1;
    }
    if end != 52
        || bytes.get(52) != Some(&b'=')
        || bytes.get(53) != Some(&b'=')
        || bytes
            .get(54)
            .is_some_and(|&byte| azure_function_byte(byte) || byte == b'=')
    {
        return None;
    }
    Some(54)
}

const fn azure_storage_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
}

fn azure_storage_account_key_match(bytes: &[u8]) -> Option<usize> {
    // Exactly 86 bytes from `[A-Za-z0-9+/=]`, conventionally ending in `=`.
    let mut end = 0;
    while end <= 86 && bytes.get(end).is_some_and(|&byte| azure_storage_byte(byte)) {
        end += 1;
    }
    (end == 86).then_some(86)
}

const fn azure_hex_lower_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

fn azure_hex32_match(bytes: &[u8]) -> Option<usize> {
    // Exactly 32 lowercase hex bytes (`[a-f0-9]`).
    let mut end = 0;
    while end <= 32
        && bytes
            .get(end)
            .is_some_and(|&byte| azure_hex_lower_byte(byte))
    {
        end += 1;
    }
    (end == 32).then_some(32)
}

fn azure_ai_services_key_match(bytes: &[u8]) -> Option<usize> {
    // Exactly 32 alphanumeric bytes (`[a-zA-Z0-9]`).
    let mut end = 0;
    while end <= 32
        && bytes
            .get(end)
            .is_some_and(|&byte| byte.is_ascii_alphanumeric())
    {
        end += 1;
    }
    (end == 32).then_some(32)
}

const fn azure_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn azure_redis_access_key_match(bytes: &[u8]) -> Option<usize> {
    // A base64 run of 32..256 bytes with an optional `=` padding tail.
    let mut end = 0;
    while end <= 256 && bytes.get(end).is_some_and(|&byte| azure_base64_byte(byte)) {
        end += 1;
    }
    if !(32..=256).contains(&end) {
        return None;
    }
    let mut tail = end;
    while tail < end + 2 && bytes.get(tail) == Some(&b'=') {
        tail += 1;
    }
    if bytes
        .get(tail)
        .is_some_and(|&byte| azure_base64_byte(byte) || byte == b'=')
    {
        return None;
    }
    Some(tail)
}

const fn azure_ad_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'~' | b'.' | b'-')
}

fn azure_ad_application_secret_match(bytes: &[u8]) -> Option<usize> {
    // 36..38 bytes from `[a-zA-Z0-9_~.-]` carrying the `Q~` marker at offset 4
    // (three class bytes, one digit, then `Q~`).
    let mut end = 0;
    while end <= 38 && bytes.get(end).is_some_and(|&byte| azure_ad_byte(byte)) {
        end += 1;
    }
    if !(36..=38).contains(&end) || !bytes[3].is_ascii_digit() || bytes.get(4..6) != Some(b"Q~") {
        return None;
    }
    Some(end)
}

fn match_at(bytes: &[u8], disabled: &[RuleId]) -> Result<Option<(RuleId, usize)>, ScanError> {
    if bytes.len() >= 2
        && !PROVIDER_HEAD_BITS[(((bytes[0] as u16) << 8) | bytes[1] as u16) as usize]
    {
        return Ok(None);
    }
    if let Some(end) = (!disabled.contains(&RuleId::AwsAccessKeyId))
        .then(|| aws_match(bytes))
        .flatten()
    {
        return Ok(Some((RuleId::AwsAccessKeyId, end)));
    }
    for (rule, prefixes) in [
        (RuleId::GithubToken, GITHUB_PREFIXES),
        (RuleId::StripeSecretKey, STRIPE_SECRET_PREFIXES),
        (RuleId::StripeRestrictedKey, STRIPE_RESTRICTED_PREFIXES),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = token_match(bytes, prefixes)? {
            return Ok(Some((rule, end)));
        }
    }
    if !disabled.contains(&RuleId::SlackWebhook) {
        if let Some(end) = slack_match(bytes)? {
            return Ok(Some((RuleId::SlackWebhook, end)));
        }
    }
    if !disabled.contains(&RuleId::AnthropicAdminKey) {
        if let Some(end) = anthropic_admin_key_match(bytes) {
            return Ok(Some((RuleId::AnthropicAdminKey, end)));
        }
    }
    // LLM provider and AI infrastructure API keys (more specific prefixes first)
    for (rule, prefixes) in [
        (RuleId::OpenrouterKey, OPENROUTER_PREFIXES),
        (RuleId::AnthropicKey, ANTHROPIC_PREFIXES),
        (RuleId::AlibabaKey, ALIBABA_PREFIXES),
        (RuleId::BaiduKey, BAIDU_PREFIXES),
        (RuleId::LangsmithKey, LANGSMITH_PREFIXES),
        (RuleId::CartesiaKey, CARTESIA_PREFIXES),
        (RuleId::WandbKey, WANDB_PREFIXES),
        (RuleId::FirecrawlKey, FIRECRAWL_PREFIXES),
        (RuleId::ReplicateKey, REPLICATE_PREFIXES),
        (RuleId::VercelKey, VERCEL_PREFIXES),
        (RuleId::SupabaseKey, SUPABASE_PREFIXES),
        (RuleId::CloudflareKey, CLOUDFLARE_PREFIXES),
        (RuleId::VoyageKey, VOYAGE_PREFIXES),
        (RuleId::StabilityAiKey, STABILITY_AI_KEY_PREFIXES),
        (RuleId::OpenaiKey, OPENAI_PREFIXES),
        (RuleId::GroqKey, GROQ_PREFIXES),
        (RuleId::PerplexityKey, PERPLEXITY_PREFIXES),
        (RuleId::HuggingfaceKey, HUGGINGFACE_PREFIXES),
        (RuleId::XaiKey, XAI_PREFIXES),
        (RuleId::GoogleApiKey, GOOGLE_API_PREFIXES),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = api_key_match(bytes, prefixes)? {
            return Ok(Some((rule, end)));
        }
    }
    // Docker Swarm tokens
    if !disabled.contains(&RuleId::DockerSwarmJoin)
        || !disabled.contains(&RuleId::DockerSwarmUnlock)
    {
        if let Some((rule, end)) = docker_swarm_match(bytes) {
            if !disabled.contains(&rule) {
                return Ok(Some((rule, end)));
            }
        }
    }
    // Sendgrid API key (two-segment dot pattern)
    if !disabled.contains(&RuleId::SendgridApiKey) {
        if let Some(end) = sendgrid_match(bytes)? {
            return Ok(Some((RuleId::SendgridApiKey, end)));
        }
    }
    // Sendinblue API key
    if !disabled.contains(&RuleId::SendinblueApiKey) {
        if let Some(end) = sendinblue_match(bytes)? {
            return Ok(Some((RuleId::SendinblueApiKey, end)));
        }
    }
    // Twilio Account SID / API Key
    if !disabled.contains(&RuleId::TwilioAccountSid) || !disabled.contains(&RuleId::TwilioApiKey) {
        if let Some((rule, end)) = twilio_match(bytes) {
            if !disabled.contains(&rule) {
                return Ok(Some((rule, end)));
            }
        }
    }
    // Telegram bot token
    if !disabled.contains(&RuleId::TelegramBotToken) {
        if let Some((rule, end)) = telegram_match(bytes) {
            return Ok(Some((rule, end)));
        }
    }
    // Stripe Payment Intent
    if !disabled.contains(&RuleId::StripePaymentIntent) {
        if let Some((rule, end)) = stripe_payment_intent_match(bytes) {
            return Ok(Some((rule, end)));
        }
    }
    // Flutterwave API key
    if !disabled.contains(&RuleId::FlutterwaveKey) {
        if let Some((rule, end)) = flutterwave_match(bytes) {
            return Ok(Some((rule, end)));
        }
    }
    // Phase 1: Prefix-based rules (more specific prefixes first)
    for (rule, prefixes, body_min) in [
        // Cloud & Infrastructure
        (RuleId::DigitalOceanPat, DIGITALOCEAN_PAT_PREFIXES, 64),
        (RuleId::DigitalOceanOauth, DIGITALOCEAN_OAUTH_PREFIXES, 64),
        (
            RuleId::DigitalOceanRefresh,
            DIGITALOCEAN_REFRESH_PREFIXES,
            64,
        ),
        (RuleId::HerokuApiKey, HEROKU_API_KEY_PREFIXES, 58),
        // Package Managers
        (RuleId::ClojarsToken, CLOJARS_TOKEN_PREFIXES, 48),
        (RuleId::CratesioToken, CRATESIO_TOKEN_PREFIXES, 40),
        (RuleId::PyPiToken, PYPY_TOKEN_PREFIXES, 20),
        (RuleId::RubygemsApiKey, RUBYGENS_API_KEY_PREFIXES, 48),
        // Communication & Messaging
        (RuleId::SlackBotToken, SLACK_BOT_TOKEN_PREFIXES, 30),
        (RuleId::SlackUserToken, SLACK_USER_TOKEN_PREFIXES, 30),
        (
            RuleId::SlackWorkspaceToken,
            SLACK_WORKSPACE_TOKEN_PREFIXES,
            30,
        ),
        (RuleId::SlackRefreshToken, SLACK_REFRESH_TOKEN_PREFIXES, 30),
        // SaaS & Dev Tools
        (RuleId::SentryOrgToken, SENTRY_ORG_TOKEN_PREFIXES, 32),
        (
            RuleId::GitlabCicdJobToken,
            GITLAB_CICD_JOB_TOKEN_PREFIXES,
            25,
        ),
        (
            RuleId::Auth0ManagementToken,
            AUTH0_MANAGEMENT_TOKEN_PREFIXES,
            32,
        ),
        (RuleId::OktaAccessToken, OKTA_ACCESS_TOKEN_PREFIXES, 24),
        (RuleId::NotionApiKey, NOTION_API_KEY_PREFIXES, 34),
        (RuleId::LinearApiKey, LINEAR_API_KEY_PREFIXES, 32),
        (RuleId::FigmaToken, FIGMA_TOKEN_PREFIXES, 32),
        (RuleId::SquareAccessToken, SQUARE_ACCESS_TOKEN_PREFIXES, 25),
        (
            RuleId::ShopifyAccessToken,
            SHOPIFY_ACCESS_TOKEN_PREFIXES,
            32,
        ),
        (
            RuleId::ShopifyCustomToken,
            SHOPIFY_CUSTOM_TOKEN_PREFIXES,
            32,
        ),
        (
            RuleId::ShopifySharedSecret,
            SHOPIFY_SHARED_SECRET_PREFIXES,
            32,
        ),
        (
            RuleId::ShopifyAppPassword,
            SHOPIFY_APP_PASSWORD_PREFIXES,
            32,
        ),
        (RuleId::StripeAccessToken, STRIPE_ACCESS_TOKEN_PREFIXES, 32),
        // AI / ML Providers
        (RuleId::MistralKey, MISTRAL_KEY_PREFIXES, 20),
        (RuleId::CerebrasKey, CEREBRAS_KEY_PREFIXES, 20),
        (RuleId::TogetheraiKey, TOGETHERAI_KEY_PREFIXES, 20),
        (RuleId::FireworksAiKey, FIREWORKS_AI_KEY_PREFIXES, 20),
        (RuleId::StabilityAiKey, STABILITY_AI_KEY_PREFIXES, 20),
        (RuleId::DeepgramKey, DEEPGRAM_KEY_PREFIXES, 20),
        (RuleId::RazorpayKey, RAZORPAY_KEY_PREFIXES, 16),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = api_key_match_with_min(bytes, prefixes, body_min)? {
            return Ok(Some((rule, end)));
        }
    }
    // GitLab token families with documented exact body lengths.
    for (rule, prefixes, body_len) in [
        (
            RuleId::GitlabPersonalAccessToken,
            GITLAB_PERSONAL_ACCESS_TOKEN_PREFIXES,
            20,
        ),
        (RuleId::GitlabDeployToken, GITLAB_DEPLOY_TOKEN_PREFIXES, 20),
        (
            RuleId::GitlabFeatureFlagToken,
            GITLAB_FEATURE_FLAG_TOKEN_PREFIXES,
            20,
        ),
        (RuleId::GitlabRunnerToken, GITLAB_RUNNER_TOKEN_PREFIXES, 20),
        (
            RuleId::GitlabRunnerRegistrationToken,
            GITLAB_RUNNER_REGISTRATION_TOKEN_PREFIXES,
            20,
        ),
        (RuleId::GitlabFeedToken, GITLAB_FEED_TOKEN_PREFIXES, 20),
        (RuleId::GitlabScimToken, GITLAB_SCIM_TOKEN_PREFIXES, 20),
        (
            RuleId::GitlabIncomingMailToken,
            GITLAB_INCOMING_MAIL_TOKEN_PREFIXES,
            25,
        ),
        (RuleId::GitlabAgentToken, GITLAB_AGENT_TOKEN_PREFIXES, 50),
        (
            RuleId::GitlabOauthAppSecret,
            GITLAB_OAUTH_APP_SECRET_PREFIXES,
            64,
        ),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = gitlab_token_match(bytes, prefixes, body_len) {
            return Ok(Some((rule, end)));
        }
    }
    if !disabled.contains(&RuleId::GitlabTriggerToken) {
        if let Some(end) = lower_hex_token_match(bytes, GITLAB_TRIGGER_TOKEN_PREFIXES, 40) {
            return Ok(Some((RuleId::GitlabTriggerToken, end)));
        }
    }
    if let Some((rule, end)) = circleci_match(bytes) {
        if !disabled.contains(&rule) {
            return Ok(Some((rule, end)));
        }
    }
    if !disabled.contains(&RuleId::AtlassianApiToken) {
        if let Some(end) = atlassian_token_match(bytes, ATLASSIAN_API_TOKEN_PREFIXES, 186) {
            return Ok(Some((RuleId::AtlassianApiToken, end)));
        }
    }
    if !disabled.contains(&RuleId::NetlifyAccessToken) {
        if let Some(end) = netlify_token_match(bytes, NETLIFY_ACCESS_TOKEN_PREFIXES, 36) {
            return Ok(Some((RuleId::NetlifyAccessToken, end)));
        }
    }
    if !disabled.contains(&RuleId::FlyioToken) {
        if let Some(end) = alnum_dash_token_match(bytes, FLYIO_API_TOKEN_PREFIXES, 43) {
            return Ok(Some((RuleId::FlyioToken, end)));
        }
        if let Some(end) = flyio_management_token_match(bytes, FLYIO_MANAGEMENT_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::FlyioToken, end)));
        }
    }
    if !disabled.contains(&RuleId::SentryPersonalToken) {
        if let Some(end) = lower_hex_token_match(bytes, SENTRY_PERSONAL_TOKEN_PREFIXES, 64) {
            return Ok(Some((RuleId::SentryPersonalToken, end)));
        }
    }
    if !disabled.contains(&RuleId::GrafanaServiceAccountToken) {
        if let Some(end) =
            grafana_service_account_match(bytes, GRAFANA_SERVICE_ACCOUNT_TOKEN_PREFIXES)
        {
            return Ok(Some((RuleId::GrafanaServiceAccountToken, end)));
        }
    }
    if !disabled.contains(&RuleId::AxiomToken) {
        if let Some(end) = hyphen_hex_uuid_match(bytes, AXIOM_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::AxiomToken, end)));
        }
    }
    if !disabled.contains(&RuleId::SonarQubeToken) {
        if let Some(end) = lower_hex_token_match(bytes, SONARQUBE_TOKEN_PREFIXES, 40) {
            return Ok(Some((RuleId::SonarQubeToken, end)));
        }
    }
    if !disabled.contains(&RuleId::SonarQubeCloudToken) {
        if let Some(end) = alnum_token_match(bytes, SONARQUBE_CLOUD_TOKEN_PREFIXES, 59) {
            return Ok(Some((RuleId::SonarQubeCloudToken, end)));
        }
    }
    if !disabled.contains(&RuleId::KongKonnectToken) {
        if let Some(end) = alnum_token_match(bytes, KONG_KONNECT_TOKEN_PREFIXES, 49) {
            return Ok(Some((RuleId::KongKonnectToken, end)));
        }
    }
    if !disabled.contains(&RuleId::TruffleHogEnterpriseSecret) {
        if let Some(end) = lower_hex_token_match(bytes, TRUFFLEHOG_ENTERPRISE_SECRET_PREFIXES, 32) {
            return Ok(Some((RuleId::TruffleHogEnterpriseSecret, end)));
        }
    }
    if !disabled.contains(&RuleId::DopplerToken) {
        if let Some(end) = doppler_token_match(bytes) {
            return Ok(Some((RuleId::DopplerToken, end)));
        }
    }
    if !disabled.contains(&RuleId::TailscaleApiToken) {
        if let Some(end) = tailscale_token_match(bytes, TAILSCALE_API_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::TailscaleApiToken, end)));
        }
    }
    if !disabled.contains(&RuleId::TailscaleAuthToken) {
        if let Some(end) = tailscale_token_match(bytes, TAILSCALE_AUTH_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::TailscaleAuthToken, end)));
        }
    }
    if !disabled.contains(&RuleId::ResendApiKey) {
        if let Some(end) = resend_api_key_match(bytes, RESEND_API_KEY_PREFIXES) {
            return Ok(Some((RuleId::ResendApiKey, end)));
        }
    }
    if !disabled.contains(&RuleId::LaunchDarklyServerSdkToken) {
        if let Some(end) = hyphen_hex_uuid_match(bytes, LAUNCH_DARKLY_SERVER_SDK_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::LaunchDarklyServerSdkToken, end)));
        }
    }
    if !disabled.contains(&RuleId::FlagsmithServerToken) {
        if let Some(end) = alnum_dash_token_match(bytes, FLAGSMITH_SERVER_TOKEN_PREFIXES, 43) {
            return Ok(Some((RuleId::FlagsmithServerToken, end)));
        }
    }
    if !disabled.contains(&RuleId::GrowthBookSecretKey) {
        if let Some(end) = growthbook_secret_match(bytes, GROWTHBOOK_SECRET_KEY_PREFIXES) {
            return Ok(Some((RuleId::GrowthBookSecretKey, end)));
        }
    }
    if !disabled.contains(&RuleId::PostHogPersonalToken) {
        if let Some(end) = posthog_personal_token_match(bytes, POSTHOG_PERSONAL_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::PostHogPersonalToken, end)));
        }
    }
    for (rule, prefixes) in [
        (RuleId::PlanetscalePassword, PLANETSCALE_PASSWORD_PREFIXES),
        (RuleId::PlanetscaleToken, PLANETSCALE_TOKEN_PREFIXES),
        (
            RuleId::PlanetscaleOauthToken,
            PLANETSCALE_OAUTH_TOKEN_PREFIXES,
        ),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = planetscale_token_match(bytes, prefixes) {
            return Ok(Some((rule, end)));
        }
    }
    if !disabled.contains(&RuleId::PaddleApiKey) {
        if let Some(end) = paddle_api_key_match(bytes, PADDLE_API_KEY_PREFIXES) {
            return Ok(Some((RuleId::PaddleApiKey, end)));
        }
    }
    if !disabled.contains(&RuleId::PlaidAccessToken) {
        if let Some(end) = hyphen_hex_uuid_match(bytes, PLAID_ACCESS_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::PlaidAccessToken, end)));
        }
    }
    if !disabled.contains(&RuleId::PineconeApiKey) {
        if let Some(end) = pinecone_key_match(bytes) {
            return Ok(Some((RuleId::PineconeApiKey, end)));
        }
    }
    // Phase 2: Additional provider prefix-based rules
    for (rule, prefixes, body_min) in [
        (RuleId::AdobeClientSecret, ADOBE_CLIENT_SECRET_PREFIXES, 32),
        (RuleId::AivenAuthToken, AIVEN_AUTH_TOKEN_PREFIXES, 20),
        (
            RuleId::AivenServicePassword,
            AIVEN_SERVICE_PASSWORD_PREFIXES,
            20,
        ),
        (RuleId::ApifyApiToken, APIFY_API_TOKEN_PREFIXES, 36),
        (RuleId::AirtablePat, AIRTABLE_PAT_PREFIXES, 79),
        (RuleId::BitrisePat, BITRISE_PAT_PREFIXES, 20),
        (RuleId::CanvaAppSecret, CANVA_APP_SECRET_PREFIXES, 20),
        (
            RuleId::CanvaConnectApiSecret,
            CANVA_CONNECT_API_SECRET_PREFIXES,
            20,
        ),
        (RuleId::CanvaSecret, CANVA_SECRET_PREFIXES, 20),
        (RuleId::CloudsmithApiKey, CLOUDSMITH_API_KEY_PREFIXES, 32),
        (RuleId::DatabentoApiKey, DATABENTO_API_KEY_PREFIXES, 20),
        (
            RuleId::DatabricksApiToken,
            DATABRICKS_API_TOKEN_PREFIXES,
            32,
        ),
        (
            RuleId::DropboxShortLivedAccessToken,
            DROPBOX_ACCESS_TOKEN_PREFIXES,
            130,
        ),
        (
            RuleId::DuffelLiveAccessToken,
            DUFFEL_LIVE_ACCESS_TOKEN_PREFIXES,
            43,
        ),
        (
            RuleId::DuffelTestAccessToken,
            DUFFEL_TEST_ACCESS_TOKEN_PREFIXES,
            43,
        ),
        (RuleId::DynatraceApiToken, DYNATRACE_API_TOKEN_PREFIXES, 90),
        (
            RuleId::EasypostProductionApiKey,
            EASYPOST_PRODUCTION_API_KEY_PREFIXES,
            54,
        ),
        (
            RuleId::EasypostTestApiKey,
            EASYPOST_TEST_API_KEY_PREFIXES,
            54,
        ),
        (
            RuleId::ElasticCloudApiKey,
            ELASTIC_CLOUD_API_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::ElasticStackApiKey,
            ELASTIC_STACK_API_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::FlutterwaveLiveApiSecretKey,
            FLUTTERWAVE_LIVE_API_SECRET_KEY_PREFIXES,
            42,
        ),
        (
            RuleId::FlutterwaveTestApiSecretKey,
            FLUTTERWAVE_TEST_API_SECRET_KEY_PREFIXES,
            42,
        ),
        (
            RuleId::FrameIoDeveloperToken,
            FRAME_IO_DEVELOPER_TOKEN_PREFIXES,
            64,
        ),
        (
            RuleId::HashiCorpVaultServiceToken,
            HASHICORP_VAULT_SERVICE_TOKEN_PREFIXES,
            60,
        ),
        (
            RuleId::HashiCorpVaultBatchToken,
            HASHICORP_VAULT_BATCH_TOKEN_PREFIXES,
            60,
        ),
        (
            RuleId::HerokuPlatformApiOAuth2Token,
            HEROKU_PLATFORM_API_OAUTH2_TOKEN_PREFIXES,
            58,
        ),
        (RuleId::HexApiKey, HEX_API_KEY_PREFIXES, 40),
        (RuleId::HighnoteRkLiveKey, HIGHNOTE_RK_LIVE_KEY_PREFIXES, 20),
        (RuleId::HighnoteRkTestKey, HIGHNOTE_RK_TEST_KEY_PREFIXES, 20),
        (RuleId::HighnoteSkLiveKey, HIGHNOTE_SK_LIVE_KEY_PREFIXES, 20),
        (RuleId::HighnoteSkTestKey, HIGHNOTE_SK_TEST_KEY_PREFIXES, 20),
        (RuleId::LobLiveApiKey, LOB_LIVE_API_KEY_PREFIXES, 35),
        (RuleId::LobTestApiKey, LOB_TEST_API_KEY_PREFIXES, 35),
        (
            RuleId::MailersendApiToken,
            MAILERSEND_API_TOKEN_PREFIXES,
            20,
        ),
        (
            RuleId::MailersendSmtpPassword,
            MAILERSEND_SMTP_PASSWORD_PREFIXES,
            20,
        ),
        (
            RuleId::MailersendSmtpUsername,
            MAILERSEND_SMTP_USERNAME_PREFIXES,
            20,
        ),
        (RuleId::MailgunApiKey, MAILGUN_API_KEY_PREFIXES, 32),
        (
            RuleId::MailgunSmtpCredential,
            MAILGUN_SMTP_CREDENTIAL_PREFIXES,
            32,
        ),
        (
            RuleId::MapboxSecretAccessToken,
            MAPBOX_SECRET_ACCESS_TOKEN_PREFIXES,
            20,
        ),
        (
            RuleId::MercuryNonProductionApiToken,
            MERCURY_NON_PRODUCTION_API_TOKEN_PREFIXES,
            20,
        ),
        (
            RuleId::MercuryProductionApiToken,
            MERCURY_PRODUCTION_API_TOKEN_PREFIXES,
            20,
        ),
        (
            RuleId::MidtransProductionServerKey,
            MIDTRANS_PRODUCTION_SERVER_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::MidtransSandboxServerKey,
            MIDTRANS_SANDBOX_SERVER_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::NaverCloudGovAccessKey,
            NAVERCLOUD_GOV_ACCESS_KEY_ID_PREFIXES,
            20,
        ),
        (
            RuleId::NaverCloudGovAccessKeySecret,
            NAVERCLOUD_GOV_ACCESS_KEY_SECRET_PREFIXES,
            20,
        ),
        (RuleId::NaverCloudGovSts, NAVERCLOUD_GOV_STS_PREFIXES, 20),
        (
            RuleId::NaverCloudGovStsSecret,
            NAVERCLOUD_GOV_STS_SECRET_PREFIXES,
            20,
        ),
        (
            RuleId::NaverCloudPubAccessKey,
            NAVERCLOUD_PUB_ACCESS_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::NaverCloudPubAccessKeySecret,
            NAVERCLOUD_PUB_ACCESS_KEY_SECRET_PREFIXES,
            20,
        ),
        (RuleId::NaverCloudPubSts, NAVERCLOUD_PUB_STS_PREFIXES, 20),
        (
            RuleId::NaverCloudPubStsSecret,
            NAVERCLOUD_PUB_STS_SECRET_PREFIXES,
            20,
        ),
        // Batch 8: Polar family (shared `polar_` prefix, first enabled wins)
        (
            RuleId::PolarPersonalAccessToken,
            POLAR_PERSONAL_ACCESS_TOKEN_PREFIXES,
            16,
        ),
        (RuleId::PolarAccessToken, POLAR_ACCESS_TOKEN_PREFIXES, 16),
        (RuleId::PolarRefreshToken, POLAR_REFRESH_TOKEN_PREFIXES, 16),
        (
            RuleId::PolarAuthorizationCode,
            POLAR_AUTHORIZATION_CODE_PREFIXES,
            16,
        ),
        (
            RuleId::PolarClientRegistrationToken,
            POLAR_CLIENT_REGISTRATION_TOKEN_PREFIXES,
            16,
        ),
        (RuleId::PolarClientSecret, POLAR_CLIENT_SECRET_PREFIXES, 16),
        (
            RuleId::PolarCustomerSessionToken,
            POLAR_CUSTOMER_SESSION_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::PolarUserSessionToken,
            POLAR_USER_SESSION_TOKEN_PREFIXES,
            16,
        ),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = api_key_match_with_min(bytes, prefixes, body_min)? {
            return Ok(Some((rule, end)));
        }
    }
    // Task-target prefix-based detectors (api_key_match_with_min).
    for (rule, prefixes, body_min) in [
        (
            RuleId::NewRelicInsightsQueryKey,
            NEW_RELIC_INSIGHTS_QUERY_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::NewRelicLicenseKey,
            NEW_RELIC_LICENSE_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::NewRelicPersonalApiKey,
            NEW_RELIC_PERSONAL_API_KEY_PREFIXES,
            20,
        ),
        (
            RuleId::NewRelicRestApiKey,
            NEW_RELIC_REST_API_KEY_PREFIXES,
            20,
        ),
        (RuleId::NuGetApiKey, NUGET_API_KEY_PREFIXES, 43),
        (
            RuleId::OctopusDeployApiKey,
            OCTOPUS_DEPLOY_API_KEY_PREFIXES,
            25,
        ),
        (RuleId::PulumiAccessToken, PULUMI_ACCESS_TOKEN_PREFIXES, 20),
        (RuleId::PostmanApiKey, POSTMAN_API_KEY_PREFIXES, 59),
        (
            RuleId::PostmanCollectionKey,
            POSTMAN_COLLECTION_KEY_PREFIXES,
            59,
        ),
        (RuleId::ReadMeApiKey, READ_ME_API_KEY_PREFIXES, 70),
        (
            RuleId::SalesforceOAuth2ConsumerKey,
            SALESFORCE_OAUTH2_CONSUMER_KEY_PREFIXES,
            80,
        ),
        (
            RuleId::SalesforceRefreshToken,
            SALESFORCE_REFRESH_TOKEN_PREFIXES,
            80,
        ),
        (
            RuleId::TypeformPersonalAccessToken,
            TYPEFORM_PERSONAL_ACCESS_TOKEN_PREFIXES,
            59,
        ),
        (RuleId::VercelAPIKey, VERCEL_API_KEY_PREFIXES, 24),
        (RuleId::YandexCloudAPIKey, YANDEX_CLOUD_API_KEY_PREFIXES, 35),
        (
            RuleId::YandexCloudIAMAccessSecret,
            YANDEX_CLOUD_ACCESS_SECRET_PREFIXES,
            35,
        ),
        (
            RuleId::YandexCloudIAMToken,
            YANDEX_CLOUD_IAM_TOKEN_PREFIXES,
            20,
        ),
        (
            RuleId::YandexCloudSmartcaptchaServerKey,
            YANDEX_CLOUD_SMARTCAPTCHA_SERVER_KEY_PREFIXES,
            48,
        ),
        (
            RuleId::YandexPassportOAuthToken,
            YANDEX_PASSPORT_OAUTH_TOKEN_PREFIXES,
            55,
        ),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = api_key_match_with_min(bytes, prefixes, body_min)? {
            return Ok(Some((rule, end)));
        }
    }
    // Batch 5: additional prefix-based detectors. OnePassword requires a
    // base64 body (with `+` and `/`); Beamer requires an exact 44-char
    // body over `[a-z0-9=_-]`; the rest use the generic word-run matcher.
    if !disabled.contains(&RuleId::OnePasswordServiceAccountToken) {
        if let Some(end) =
            one_password_service_token_match(bytes, ONE_PASSWORD_SERVICE_ACCOUNT_TOKEN_PREFIXES)
        {
            return Ok(Some((RuleId::OnePasswordServiceAccountToken, end)));
        }
    }
    if !disabled.contains(&RuleId::BeamerApiKey) {
        if let Some(end) = beamer_api_key_match(bytes, BEAMER_API_KEY_PREFIXES) {
            return Ok(Some((RuleId::BeamerApiKey, end)));
        }
    }
    for (rule, prefixes, body_min) in [
        (RuleId::AdafruitIoKey, ADAFRUIT_IO_KEY_PREFIXES, 20),
        (RuleId::CcdbApiKey, CCDB_API_KEY_PREFIXES, 16),
        (
            RuleId::CdsCanadaNotifyApiKey,
            CDS_CANADA_NOTIFY_API_KEY_PREFIXES,
            8,
        ),
        (RuleId::ContentfulPat, CONTENTFUL_PAT_PREFIXES, 43),
        (RuleId::DockerPersonalPat, DOCKER_PERSONAL_PAT_PREFIXES, 27),
        (
            RuleId::DockerOrganizationPat,
            DOCKER_ORGANIZATION_PAT_PREFIXES,
            27,
        ),
        (
            RuleId::BuildkiteUserAccessToken,
            BUILDKITE_USER_ACCESS_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkiteAgentAccessToken,
            BUILDKITE_AGENT_ACCESS_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkiteAgentJobToken,
            BUILDKITE_AGENT_JOB_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkiteAgentRegistrationToken,
            BUILDKITE_AGENT_REGISTRATION_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkiteClusterToken,
            BUILDKITE_CLUSTER_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkiteClusterQueueToken,
            BUILDKITE_CLUSTER_QUEUE_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkitePackagesRegistryToken,
            BUILDKITE_PACKAGES_REGISTRY_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkitePackagesTemporaryToken,
            BUILDKITE_PACKAGES_TEMPORARY_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkitePortalToken,
            BUILDKITE_PORTAL_TOKEN_PREFIXES,
            16,
        ),
        (
            RuleId::BuildkitePortalSecret,
            BUILDKITE_PORTAL_SECRET_PREFIXES,
            16,
        ),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = api_key_match_with_min(bytes, prefixes, body_min)? {
            return Ok(Some((rule, end)));
        }
    }
    // Wakatime keys (waka_ + lowercase-hex UUID body).
    for rule in [
        RuleId::WakaTimeAPIKey,
        RuleId::WakaTimeAppSecret,
        RuleId::WakaTimeOAuthAccessToken,
        RuleId::WakaTimeOAuthRefreshToken,
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some(end) = hyphen_hex_uuid_match(bytes, WAKATIME_API_KEY_PREFIXES) {
            return Ok(Some((rule, end)));
        }
    }
    // Dropbox access token (sl. + 130+ body chars, no dots in body)
    if !disabled.contains(&RuleId::DropboxAccessToken) {
        if let Some(end) = dropbox_access_token_match(bytes, DROPBOX_ACCESS_TOKEN_PREFIXES) {
            return Ok(Some((RuleId::DropboxAccessToken, end)));
        }
    }
    // Phase 3: URI-based rules
    for (prefixes, rule) in [
        (MONGODB_URI_PREFIXES, RuleId::MongodbUri),
        (POSTGRES_URI_PREFIXES, RuleId::PostgresUri),
        (REDIS_URI_PREFIXES, RuleId::RedisUri),
        (SQLSERVER_URI_PREFIXES, RuleId::SqlserverUri),
        (MYSQL_URI_PREFIXES, RuleId::MysqlUri),
        (COCKROACHDB_URI_PREFIXES, RuleId::CockroachdbUri),
        (CLOUDINARY_URL_PREFIXES, RuleId::CloudinaryUrl),
    ] {
        if disabled.contains(&rule) {
            continue;
        }
        if let Some((matched_rule, end)) = uri_match(bytes, prefixes, rule) {
            return Ok(Some((matched_rule, end)));
        }
    }
    if disabled.contains(&RuleId::PrivateKeyMarker) {
        return Ok(None);
    }
    Ok(PRIVATE_KEY_MARKERS
        .iter()
        .find(|&&marker| bytes.starts_with(marker))
        .map(|marker| (RuleId::PrivateKeyMarker, marker.len())))
}

/// Visit matches in source order without allocating a candidate collection.
/// Callback spans are zero-based and half-open; source bytes remain borrowed.
pub fn detect_line(bytes: &[u8], emit: impl FnMut(RuleId, Range<usize>)) -> Result<(), ScanError> {
    detect_line_with_disabled(bytes, &[], emit)
}

pub(crate) fn detect_line_with_disabled(
    bytes: &[u8],
    disabled: &[RuleId],
    mut emit: impl FnMut(RuleId, Range<usize>),
) -> Result<(), ScanError> {
    // Incremental keyword feed state: the cursor walks the line once, queueing
    // per-keyword comparisons in a ring bucketed by the offset where each
    // comparison completes. `keyword_mask` keeps one bit per keyword whose
    // most recent completed occurrence still starts inside the context window,
    // replacing a per-rule rescan of the window at every candidate byte.
    let mut covered_until = 0;
    let mut keyword_cursor: usize = 0;
    let mut keyword_ring: [u32; KEYWORD_GATE_RING_LEN] = [0; KEYWORD_GATE_RING_LEN];
    let mut keyword_start: [usize; KEYWORD_GATE_WORDS.len()] =
        [usize::MAX; KEYWORD_GATE_WORDS.len()];
    let mut keyword_mask: u32 = 0;
    // Shared helpers lifted out of the candidate loop: `skip_gaps` borrows only
    // `bytes`, and the structural family table is constant, so both are built
    // once per line, not once per candidate byte.
    let skip_gaps = |cursor: usize| {
        let mut cursor = cursor;
        while cursor > 0 && (bytes[cursor - 1] == b' ' || bytes[cursor - 1] == b'\t') {
            cursor -= 1;
        }
        cursor
    };
    let azure_structural: &[(RuleId, AzureValidator)] = &[
        (
            RuleId::AzureDevopsPersonalAccessToken,
            azure_devops_pat_match,
        ),
        (RuleId::AzureFunctionKey, azure_function_key_match),
        (
            RuleId::AzureStorageAccountKey,
            azure_storage_account_key_match,
        ),
        (RuleId::AzureCognitiveServicesKey, azure_hex32_match),
        (RuleId::AzureComputerVisionKey, azure_hex32_match),
        (RuleId::AzureAiServicesKey, azure_ai_services_key_match),
        (
            RuleId::AzureCacheForRedisAccessKey,
            azure_redis_access_key_match,
        ),
        (
            RuleId::AzureActiveDirectoryApplicationSecret,
            azure_ad_application_secret_match,
        ),
    ];
    let mut keyword_active: u32 = 0;
    for (offset, &byte) in bytes.iter().enumerate() {
        // Queue comparisons for starts that can complete by this offset...
        while keyword_cursor + KEYWORD_GATE_MIN_LEN <= offset {
            let first_byte = bytes[keyword_cursor];
            let bucket = if KEYWORD_GATE_PAIR_HITS
                [(((first_byte as u16) << 8) | bytes[keyword_cursor + 1] as u16) as usize]
            {
                KEYWORD_GATE_FIRST_BITS[first_byte as usize]
            } else {
                0
            };
            if bucket != 0 {
                let mut bits = bucket;
                while bits != 0 {
                    let idx = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    keyword_ring[(keyword_cursor + KEYWORD_GATE_WORDS[idx].len())
                        % KEYWORD_GATE_RING_LEN] |= 1u32 << idx;
                }
            }
            keyword_cursor += 1;
        }
        // ...then complete the comparisons ending exactly at this offset.
        let slot = offset % KEYWORD_GATE_RING_LEN;
        let pending = keyword_ring[slot];
        if pending != 0 {
            keyword_ring[slot] = 0;
            let mut bits = pending;
            while bits != 0 {
                let idx = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let word = KEYWORD_GATE_WORDS[idx];
                if offset >= word.len()
                    && bytes[offset - word.len()..offset].eq_ignore_ascii_case(word)
                {
                    keyword_start[idx] = offset - word.len();
                    keyword_mask |= 1u32 << idx;
                    keyword_active |= 1u32 << idx;
                }
            }
        }
        // Expire keywords whose latest occurrence left the window.
        if keyword_active != 0 {
            let boundary = offset.saturating_sub(KEYWORD_GATE_WINDOW);
            let mut active = keyword_active;
            while active != 0 {
                let idx = active.trailing_zeros() as usize;
                active &= active - 1;
                if keyword_start[idx] < boundary {
                    keyword_mask &= !(1u32 << idx);
                    keyword_active &= !(1u32 << idx);
                }
            }
        }
        if offset < covered_until {
            continue;
        }
        if !matches!(
            byte,
            b'A' | b'a'
                | b'B'
                | b'b'
                | b'C'
                | b'c'
                | b'D'
                | b'd'
                | b'E'
                | b'e'
                | b'F'
                | b'f'
                | b'G'
                | b'g'
                | b'h'
                | b'H'
                | b'I'
                | b'i'
                | b'J'
                | b'j'
                | b'K'
                | b'k'
                | b'L'
                | b'l'
                | b'M'
                | b'm'
                | b'n'
                | b'N'
                | b'O'
                | b'o'
                | b'P'
                | b'p'
                | b'Q'
                | b'q'
                | b'R'
                | b'r'
                | b's'
                | b'S'
                | b'T'
                | b't'
                | b'u'
                | b'U'
                | b'v'
                | b'V'
                | b'W'
                | b'w'
                | b'X'
                | b'x'
                | b'Y'
                | b'y'
                | b'Z'
                | b'0'
                | b'1'
                | b'-'
        ) {
            continue;
        }
        if offset > 0 && is_word(bytes[offset - 1]) && byte != b'-' {
            continue;
        }
        // Keyword-gated rules use the line feed's live bitmask (window semantics
        // match the old per-rule scan of the ≤200 bytes before the candidate).
        // The context module already reports unquoted assignment right-hand
        // sides (e.g. aws_secret_access_key=value), so the generic gate only
        // complements quoted literals and bare candidates to keep detection
        // single-sourced.
        // Whole keyword-gated block skipped when no provider keyword is active
        // near this candidate: the RHS refinement and both tables are dead work
        // in that case, matching the old per-rule scan that first checked the
        // context window.
        let mut keyword_match: Option<(RuleId, usize)> = None;
        if keyword_mask != 0 {
            let mut before_cursor = offset;
            before_cursor = skip_gaps(before_cursor);
            if before_cursor > 0
                && (bytes[before_cursor - 1] == b'\'' || bytes[before_cursor - 1] == b'"')
            {
                before_cursor = skip_gaps(before_cursor - 1);
            }
            let assignment_rhs =
                before_cursor > 0 && matches!(bytes[before_cursor - 1], b'=' | b':' | b'>' | b'!');
            // Azure structural rules run before the generic keyword table so a
            // documented shape wins over any later generic `azure` keyword rule.
            // The whole family shares one keyword gate, checked a single time per
            // candidate, plus one shared union-class run prefilter (family minimum
            // length): a shorter run skips all eight shape validators.
            if !assignment_rhs {
                if keyword_mask & KEYWORD_AZURE_BIT != 0
                    && azure_union_run(&bytes[offset..]) >= AZURE_STRUCTURAL_MIN_BYTES
                {
                    for (rule, validate) in azure_structural.iter().copied() {
                        if disabled.contains(&rule) {
                            continue;
                        }
                        if let Some(length) = validate(&bytes[offset..]) {
                            keyword_match = Some((rule, length));
                            break;
                        }
                    }
                }
                if keyword_match.is_none() {
                    for (start, span, kw_index, min_val_len) in KEYWORD_GATED_SEGMENT_TABLE
                        [..KEYWORD_GATED_SEGMENT_COUNT]
                        .iter()
                        .copied()
                    {
                        if keyword_mask & (1u32 << kw_index) == 0 {
                            continue;
                        }
                        if let Some(value_len) = keyword_value_match(&bytes[offset..], min_val_len)
                        {
                            let rows_end = start + span;
                            let mut probe = start;
                            while probe < rows_end {
                                let rule = KEYWORD_GATED_ROWS[probe].0;
                                if !disabled.contains(&rule) {
                                    keyword_match = Some((rule, value_len));
                                    break;
                                }
                                probe += 1;
                            }
                            if keyword_match.is_some() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        if let Some((rule, length)) = keyword_match {
            emit(rule, offset..offset + length);
            covered_until = offset + length;
            continue;
        }
        // Header rules (batch 13) are not keyword-context, so they skip the
        // `assignment_rhs` gate: an `AUTH_HEADER = "Authorization: Basic ..."`
        // form is still a header payload by design. The hot-path gate is two
        // tiers: first-tier here, just the bytes right before the candidate
        // — a space (marker ends at the candidate) or a quote plus the space
        // — whose preceding byte completes a `c `/`r ` tail of `basic `/
        // `bearer `; the full marker/`authorization`/body comparison only
        // runs on gate hits (second tier inside the matcher).
        let header_gate_hit = offset >= 2
            && match bytes[offset - 1] {
                b' ' => matches!(bytes[offset - 2], b'c' | b'C' | b'r' | b'R'),
                b'"' | b'\'' => {
                    offset >= 3
                        && bytes[offset - 2] == b' '
                        && matches!(bytes[offset - 3], b'c' | b'C' | b'r' | b'R')
                }
                _ => false,
            };
        if header_gate_hit {
            if let Some((rule, length)) = http_auth_header_match(bytes, offset) {
                if !disabled.contains(&rule) {
                    emit(rule, offset..offset + length);
                    covered_until = offset + length;
                    continue;
                }
            }
        }
        if let Some((rule, length)) = match_at(&bytes[offset..], disabled)? {
            emit(rule, offset..offset + length);
            covered_until = offset + length;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/builtin.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/builtin_coverage.rs"]
mod coverage_tests;
