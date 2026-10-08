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
    GitlabCicdJobToken,
    GitlabDeployToken,
    GitlabFeatureFlagToken,
    GitlabPersonalAccessToken,
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
    CloudinaryUrl,
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
            Self::RubygemsApiKey => (
                "rubygems-api-key",
                "RubyGems API key",
                Severity::High,
                Confidence::High,
                "https://guides.rubygems.org/authenticating-gem-server-sessions/",
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
            Self::SquareAccessToken => (
                "square-access-token",
                "Square access token",
                Severity::High,
                Confidence::High,
                "https://developer.squareup.com/docs/docs-1/authentication/oauth",
            ),
            Self::ShopifyAccessToken => (
                "shopify-access-token",
                "Shopify custom access token",
                Severity::High,
                Confidence::High,
                "https://shopify.dev/docs/api/development",
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
            Self::TelegramBotToken => (
                "telegram-bot-token",
                "Telegram bot token",
                Severity::High,
                Confidence::High,
                "https://core.telegram.org/bots/features/bot-api",
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
                "PlanetScale password",
                Severity::High,
                Confidence::High,
                "https://planetscale.com/docs/reference/api-overview",
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
const PRIVATE_KEY_MARKERS: &[&[u8]] = &[
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
const SUPABASE_PREFIXES: &[&[u8]] = &[b"sb_publishable_", b"sb_secret_"];
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
const GITLAB_CICD_JOB_TOKEN_PREFIXES: &[&[u8]] = &[b"glcbt-"];
const GITLAB_DEPLOY_TOKEN_PREFIXES: &[&[u8]] = &[b"gldt-"];
const GITLAB_FEATURE_FLAG_TOKEN_PREFIXES: &[&[u8]] = &[b"glffct-"];
const GITLAB_PERSONAL_ACCESS_TOKEN_PREFIXES: &[&[u8]] = &[b"glpat-"];
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
const PLANETSCALE_PASSWORD_PREFIXES: &[&[u8]] = &[b"pscale_password_"];
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

fn match_at(bytes: &[u8], disabled: &[RuleId]) -> Result<Option<(RuleId, usize)>, ScanError> {
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
        (RuleId::GitlabDeployToken, GITLAB_DEPLOY_TOKEN_PREFIXES, 25),
        (
            RuleId::GitlabFeatureFlagToken,
            GITLAB_FEATURE_FLAG_TOKEN_PREFIXES,
            25,
        ),
        (
            RuleId::GitlabPersonalAccessToken,
            GITLAB_PERSONAL_ACCESS_TOKEN_PREFIXES,
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
        (
            RuleId::PlanetscalePassword,
            PLANETSCALE_PASSWORD_PREFIXES,
            40,
        ),
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
    let mut covered_until = 0;
    for (offset, &byte) in bytes.iter().enumerate() {
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
