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
    RuleId::GitlabCicdJobToken,
    RuleId::GitlabDeployToken,
    RuleId::GitlabFeatureFlagToken,
    RuleId::GitlabPersonalAccessToken,
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
    RuleId::CloudinaryUrl,
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
    for delimiter in [b',', b' ', b';', b')', b'\t', b'\n'] {
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
            b"glpat-SyntheticGitlabPAT12345678901".to_vec(), // rayloc:ignore
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
