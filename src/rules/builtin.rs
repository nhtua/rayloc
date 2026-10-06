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
        };
        RuleMetadata {
            id,
            description,
            severity,
            confidence,
            reference,
            reviewed_on: "2026-10-01",
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
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
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

fn llm_key_match(bytes: &[u8], prefixes: &[&[u8]]) -> Result<Option<usize>, ScanError> {
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
    // Minimum length validation: most LLM keys are at least 30 chars total
    Ok((body_length >= 20).then_some(length))
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
        if let Some(end) = llm_key_match(bytes, prefixes)? {
            return Ok(Some((rule, end)));
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
            b'A' | b'b'
                | b'g'
                | b's'
                | b'r'
                | b'h'
                | b'p'
                | b'x'
                | b'w'
                | b'l'
                | b'f'
                | b'a'
                | b'v'
                | b'c'
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
