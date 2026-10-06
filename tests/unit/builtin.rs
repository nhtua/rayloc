use super::*;
type Streamed = Vec<(RuleId, Range<u64>, Vec<u8>)>;

fn matches(bytes: &[u8]) -> Vec<(RuleId, Range<usize>)> {
    let mut found = Vec::new();
    detect_line(bytes, |rule, span| found.push((rule, span))).unwrap();
    found
}

fn streamed(
    bytes: &[u8],
    fragment_bytes: usize,
    registry: &crate::rules::Registry,
) -> Result<Streamed, ScanError> {
    let mut state = ProviderState::new();
    let mut found = Vec::new();
    for fragment in bytes.chunks(fragment_bytes) {
        state.push(fragment, registry, |candidate| {
            found.push((candidate.rule, candidate.span, candidate.value.to_vec()));
        })?;
    }
    state.finish(registry, |candidate| {
        found.push((candidate.rule, candidate.span, candidate.value.to_vec()));
    })?;
    Ok(found)
}

fn complete_provider_matches(
    bytes: &[u8],
    registry: &crate::rules::Registry,
) -> Result<Streamed, ScanError> {
    let mut found = Vec::new();
    registry.detect_provider_line(bytes, |rule, span| {
        found.push((
            rule,
            span.start as u64..span.end as u64,
            bytes[span].to_vec(),
        ));
    })?;
    Ok(found)
}

#[test]
fn provider_stream_matches_whole_line_at_every_short_input_split() {
    let registry = &crate::rules::BUILTINS;
    let examples: &[&[u8]] = &[
    // rayloc:ignore
    // rayloc:ignore
    // rayloc:ignore
        b"prefix=AKIA1234567890ABCDEF;",
        b"ghp_Synthetic0123456789ABCDEF tail",
        b"sk_test_SyntheticStripeKey0123456789,",
        b"https://hooks.slack.com/services/T_mock/B_mock/synthetic-secret ",
        b"cfk_Synthetic0123456789ABCDEF.",
        b"-----BEGIN PRIVATE KEY-----",
    ];
    for input in examples {
        let expected = complete_provider_matches(input, registry).unwrap();
        for split in 0..=input.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&input[..split], &input[split..]] {
                state
                    .push(fragment, registry, |candidate| {
                        actual.push((candidate.rule, candidate.span, candidate.value.to_vec()));
                    })
                    .unwrap();
            }
            state
                .finish(registry, |candidate| {
                    actual.push((candidate.rule, candidate.span, candidate.value.to_vec()));
                })
                .unwrap();
            assert_eq!(actual, expected, "split {split} in {input:?}");
        }
        assert_eq!(streamed(input, 1, registry).unwrap(), expected);
    }
}

#[test]
fn provider_stream_waits_for_a_real_boundary() {
    let registry = &crate::rules::BUILTINS;
    let token = b"AKIA1234567890ABCDEF";
    let mut state = ProviderState::new();
    let mut found = Vec::new();
    state
        .push(token, registry, |candidate| found.push(candidate.rule))
        .unwrap();
    assert!(found.is_empty());
    state
        .push(b"Z", registry, |candidate| found.push(candidate.rule))
        .unwrap();
    state
        .finish(registry, |candidate| found.push(candidate.rule))
        .unwrap();
    assert!(found.is_empty());

    let mut state = ProviderState::new();
    state
        .push(token, registry, |candidate| found.push(candidate.rule))
        .unwrap();
    assert!(found.is_empty());
    state
        .push(b",", registry, |candidate| {
            found.push(candidate.rule);
            assert_eq!(candidate.value, token);
            assert_eq!(candidate.span, 0..20);
        })
        .unwrap();
    state
        .finish(registry, |candidate| found.push(candidate.rule))
        .unwrap();
    assert_eq!(found, [RuleId::AwsAccessKeyId]);
}

#[test]
fn provider_candidate_limit_and_disabled_rule_semantics_are_preserved() {
    let registry = &crate::rules::BUILTINS;
    for (body_bytes, expected) in [
        (MAX_CANDIDATE_BYTES - b"ghp_".len(), Ok(())),
        (
            MAX_CANDIDATE_BYTES + 1 - b"ghp_".len(),
            Err(ScanError::CandidateLimit),
        ),
    ] {
        let input = [b"ghp_".as_slice(), &vec![b'a'; body_bytes], b" "].concat();
        assert_eq!(streamed(&input, 8192, registry).map(|_| ()), expected);
    }

    let config = crate::config::parse(b"version: '1'\ndisabled_rules: [github-token]").unwrap();
    let disabled = crate::rules::Registry::compile(config).unwrap();
    let input = [
        b"AKIA1234567890ABCDEF ghp_".as_slice(),
        &vec![b'a'; MAX_CANDIDATE_BYTES + 1],
    ]
    .concat();
    let found = streamed(&input, 4096, &disabled).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, RuleId::AwsAccessKeyId);
}

#[test]
fn all_builtin_families_have_complete_spans_and_reviewed_metadata() {
    let mut fixtures: Vec<(RuleId, Vec<u8>)> = Vec::new();
    for prefix in [b"AKIA", b"ASIA"] {
        fixtures.push((
            RuleId::AwsAccessKeyId,
            [prefix.as_slice(), b"1234567890ABCDEF"].concat(),
        ));
    }
    for prefix in GITHUB_PREFIXES {
        fixtures.push((
            RuleId::GithubToken,
            [*prefix, b"Synthetic0123456789ABCDEF"].concat(),
        ));
    }
    fixtures.push((
        RuleId::GithubToken,
        b"ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30.AAAA".to_vec(),
    ));
    for (rule, prefixes) in [
        (RuleId::StripeSecretKey, STRIPE_SECRET_PREFIXES),
        (RuleId::StripeRestrictedKey, STRIPE_RESTRICTED_PREFIXES),
    ] {
        for prefix in prefixes {
            fixtures.push((rule, [*prefix, b"Synthetic0123456789ABCDEF"].concat()));
        }
    }
    for prefix in SLACK_PREFIXES {
        fixtures.push((
            RuleId::SlackWebhook,
            [*prefix, b"T_mock/B_mock/synthetic-secret"].concat(),
        ));
    }
    for marker in PRIVATE_KEY_MARKERS {
        fixtures.push((RuleId::PrivateKeyMarker, marker.to_vec()));
    }
    // LLM provider API keys
    fixtures.push((
        RuleId::OpenaiKey,
        b"sk-SyntheticOpenAIKey1234567890ABCDEF".to_vec(), /* rayloc:ignore */, /* rayloc:ignore */, /* rayloc:ignore */,
    ));
    fixtures.push((
        RuleId::OpenrouterKey,
        b"sk-or-v1-SyntheticOpenRouterKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::AnthropicKey,
        b"sk-ant-api03-SyntheticAnthropicKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::GroqKey,
        b"gsk_SyntheticGroqKey1234567890ABCDEFghijklmnop".to_vec(),
    ));
    fixtures.push((
        RuleId::PerplexityKey,
        b"pplx-SyntheticPerplexityKey1234567890abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::HuggingfaceKey,
        b"hf_SyntheticHuggingFaceKey1234567890abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::XaiKey,
        b"xai-SyntheticXAIGrokKey1234567890ABCDEFghijklmnopqrstuvwxyz".to_vec(),
    ));
    fixtures.push((
        RuleId::GoogleApiKey,
        b"AIzaSyntheticGoogleApiKey1234567890abcdefg".to_vec(),
    ));
    fixtures.push((
        RuleId::AlibabaKey,
        b"sk-ws-SyntheticAlibabaQwenKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::BaiduKey,
        b"bce-v3/ALTAK-SyntheticBaiduErnieKey1234567890".to_vec(),
    ));
    fixtures.push((
        RuleId::WandbKey,
        b"wandb_SyntheticWandbKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::FirecrawlKey,
        b"fc-SyntheticFirecrawlKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::LangsmithKey,
        b"lsv2_pt_SyntheticLangsmithPersonalKey12345".to_vec(),
    ));
    fixtures.push((
        RuleId::LangsmithKey,
        b"lsv2_sk_SyntheticLangsmithServiceKey12345".to_vec(),
    ));
    fixtures.push((
        RuleId::VoyageKey,
        b"al-SyntheticVoyageAtlasKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::CartesiaKey,
        b"sk_car_SyntheticCartesiaKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::ReplicateKey,
        b"r8_SyntheticReplicateKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::VercelKey,
        b"vcp_SyntheticVercelPersonalAccessToken".to_vec(),
    ));
    fixtures.push((
        RuleId::SupabaseKey,
        b"sb_secret_xxxxxxxxxxxxxxxxxxxxxx1234".to_vec(),
    ));
    fixtures.push((
        RuleId::CloudflareKey,
        b"cfut_SyntheticCloudflareUserToken12345678".to_vec(),
    ));
    for (rule, value) in fixtures {
        let input = [b"\0\xff value = \"".as_slice(), &value, b"\";\r"].concat();
        let start = 12;
        assert_eq!(
            matches(&input),
            vec![(rule, start..start + value.len())],
            "{rule:?}"
        );
        assert_eq!(matches(&value), vec![(rule, 0..value.len())]);
        let metadata = rule.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-01");
    }
}

#[test]
fn provider_negatives_and_boundaries_are_not_findings() {
    for value in [
        "",
        "ordinary code without credentials",
        "AIDA1234567890ABCDEF",
        "AROA1234567890ABCDEF",
        "AGPA1234567890ABCDEF",
        "AKIA1234567890ABCDE",
        "AKIA1234567890ABCDEa",
        concat!("AKIA1234", "567890AB", "CDEF", "Z"),
        concat!("AKIA1234", "567890AB", "CDEF", "_"),
        concat!("x", "AKIA1234", "567890AB", "CDEF"),
        "ghp_short",
        "xghp_Synthetic0123456789ABCDEF",
        "pk_live_Synthetic0123456789ABCDEF",
        "https://hooks.slack.com/services/T/B",
        "https://hooks.slack.com/services/T//secret",
        "https://hooks.slack.com/services//B/secret",
        "https://hooks.slack.com/services/T/B/",
        "https://hooks.slack.com/services/T/B/secret/extra",
        "https://hooks.slack.com/services/T!B/secret",
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN RSA PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN UNKNOWN PRIVATE KEY-----",
        "sk_short",
        "sk-or-v1-short",
        "sk-ant-api03-short",
        "gsk_short",
        "pplx-short",
        "hf_short",
        "xai-short",
        "AIzashort",
        "sk-ws-short",
        "bce-v3/ALTAK-short",
        "wandb_short",
        "fc-short",
        "lsv2_pt-short",
        "lsv2_sk-short",
        "al-short",
        "pa-short",
        "sk_car_short",
        "r8_short",
        "vcp_short",
        "sb_secret_short",
        "cfut_short",
    ] {
        assert!(
            matches(value.as_bytes()).is_empty(),
            "unexpected finding for synthetic negative"
        );
    }
    assert_eq!(
        matches(b"x-----BEGIN PRIVATE KEY-----")[0].0,
        RuleId::PrivateKeyMarker
    );
    assert_eq!(
        aws_match(&[
            65, 83, 73, 65, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48
        ]),
        Some(20)
    );
    assert_eq!(aws_match(b"unrelated"), None);
    assert_eq!(aws_match(b"AKIA"), None);
    assert!(!is_word(b'\xff'));
    assert!(is_word(b'_'));
    assert!(is_word(b'5'));
}

#[test]
fn multiple_values_preserve_source_order_and_occurrences() {
    let value = b"ghp_Synthetic0123456789ABCDEF";
    let input = [
        value.as_slice(),
        b" + -----BEGIN PRIVATE KEY----- + ",
        value,
    ]
    .concat();
    let found = matches(&input);
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].0, RuleId::GithubToken);
    assert_eq!(found[1].0, RuleId::PrivateKeyMarker);
    assert_eq!(found[2].0, RuleId::GithubToken);
    assert!(found.windows(2).all(|pair| pair[0].1.end < pair[1].1.start));
}

#[test]
fn long_compact_candidates_are_not_repeatedly_scanned_as_nested_tokens() {
    let value = b"ghs_SyntheticMockToken0123456789".repeat(1000);
    assert!(value.len() < MAX_CANDIDATE_BYTES);
    assert_eq!(matches(&value), vec![(RuleId::GithubToken, 0..value.len())]);
}

#[test]
fn candidate_limits_are_errors_and_exact_limit_is_accepted() {
    let mut token = b"ghp_".to_vec();
    token.resize(MAX_CANDIDATE_BYTES, b'A');
    assert_eq!(matches(&token)[0].1.end, MAX_CANDIDATE_BYTES);
    token.push(b'A');
    assert_eq!(
        detect_line(&token, |_, _| panic!("oversized candidate emitted")),
        Err(ScanError::CandidateLimit)
    );
    let mut webhook = b"https://hooks.slack.com/services/T/B/".to_vec();
    webhook.resize(MAX_CANDIDATE_BYTES, b'A');
    assert_eq!(matches(&webhook)[0].1.end, MAX_CANDIDATE_BYTES);
    webhook.push(b'A');
    assert_eq!(slack_match(&webhook), Err(ScanError::CandidateLimit));
    assert_eq!(
        detect_line(&webhook, |_, _| panic!("oversized URL emitted")),
        Err(ScanError::CandidateLimit)
    );
}

#[test]
fn installation_token_hyphen_span_and_limit() {
    let token = b"ghs_1234567890123456_eyJhbGciOiJIUzI1NiJ9._-8.AAAA";
    let mut spans = Vec::new();
    detect_line(token, |_, span| spans.push(span)).unwrap();
    assert_eq!(spans, vec![0..token.len()]);
    let mut oversized = b"ghs_1234567890123456.".to_vec();
    oversized.extend(std::iter::repeat_n(b'-', MAX_CANDIDATE_BYTES));
    assert_eq!(
        detect_line(&oversized, |_, _| {}),
        Err(ScanError::CandidateLimit)
    );
}

#[test]
fn malformed_dotted_installation_tokens_do_not_fall_back_to_opaque_signatures() {
    for token in [
        b"ghs_1234_notjson.e30.AAAA".as_slice(),
        b"ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30.",
        b"ghs_x_eyJhbGciOiJIUzI1NiJ9.e30.AAAA",
        b"ghs__eyJhbGciOiJIUzI1NiJ9.e30.AAAA",
        b"ghs_1234.abc.def",
    ] {
        assert!(matches(token).is_empty());
    }
}
