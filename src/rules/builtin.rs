//! Small byte-oriented provider signatures, without regex/runtime dependencies.
//!
//! Body minima are scanner heuristics, not provider validity guarantees. Context,
//! custom regex rules, and JOSE validation belong to later implementation slices.

use std::{fmt, ops::Range};

use crate::scanner::ScanError;

pub const MAX_CANDIDATE_BYTES: usize = 64 * 1024;

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
    // Include the complete compact installation form instead of exposing a tail
    // through an incomplete span. Structural JOSE checks are implemented later.
    let allow_dot = *prefix == b"ghs_";
    let body_length = bytes[prefix.len()..]
        .iter()
        .take_while(|&&byte| is_word(byte) || (allow_dot && matches!(byte, b'.' | b'-')))
        .take(MAX_CANDIDATE_BYTES + 1)
        .count();
    let length = prefix.len() + body_length;
    if length > MAX_CANDIDATE_BYTES {
        return Err(ScanError::CandidateLimit);
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
        if !matches!(byte, b'A' | b'g' | b's' | b'r' | b'h' | b'-') {
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
