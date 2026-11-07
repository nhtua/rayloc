use super::*;

#[test]
fn specialized_provider_boundaries_and_oversize_inputs_are_safe() {
    let long = "a".repeat(MAX_CANDIDATE_BYTES + 1);
    assert_eq!(
        sendgrid_match(format!("SG.{long}").as_bytes()),
        Err(ScanError::CandidateLimit)
    );
    assert_eq!(
        sendgrid_match(format!("SG.{}.{long}", "a".repeat(22)).as_bytes()),
        Err(ScanError::CandidateLimit)
    );
    assert!(docker_swarm_match(format!("SWMTKN-1-{long}").as_bytes()).is_none());
    assert!(docker_swarm_match(format!("SWMTKN-1-a-{long}").as_bytes()).is_none());
    assert!(docker_swarm_match(format!("SWMKEY-1-{long}").as_bytes()).is_none());
    assert!(telegram_match(format!("12345:A{long}").as_bytes()).is_none());
    assert!(stripe_payment_intent_match(format!("pi_{long}").as_bytes()).is_none());
    assert!(stripe_payment_intent_match(format!("pi_a_secret_{long}").as_bytes()).is_none());
    assert!(api_key_match_with_min(format!("hf_{long}").as_bytes(), &[b"hf_"], 20).is_err());
    assert!(telegram_match(b"12345:Bshort").is_none());
    assert!(telegram_match(b"12345:Ashort").is_none());
    assert!(stripe_payment_intent_match(b"pi_missing").is_none());
    assert!(stripe_payment_intent_match(b"pi_a_secret").is_none());
    assert!(stripe_payment_intent_match(b"pi_a_secret_").is_none());
    assert!(
        uri_match(
            b"postgres://user@host/db",
            &[b"postgres://"],
            RuleId::PostgresUri
        )
        .is_none()
    );
}

#[test]
fn specialized_provider_matches_respect_disabled_rules() {
    let cases: Vec<(Vec<u8>, RuleId)> = vec![
        (
            format!("SWMTKN-1-a-{}", "a".repeat(24)).into_bytes(),
            RuleId::DockerSwarmJoin,
        ),
        (
            format!("SWMKEY-1-{}", "a".repeat(40)).into_bytes(),
            RuleId::DockerSwarmUnlock,
        ),
        (
            format!("SG.{}.{}", "a".repeat(22), "b".repeat(40)).into_bytes(),
            RuleId::SendgridApiKey,
        ),
        (
            format!("xkeysib-{}", "a".repeat(81)).into_bytes(),
            RuleId::SendinblueApiKey,
        ),
        (
            format!("AC{}", "a".repeat(32)).into_bytes(),
            RuleId::TwilioAccountSid,
        ),
        (
            format!("SK{}", "a".repeat(32)).into_bytes(),
            RuleId::TwilioApiKey,
        ),
        (
            format!("12345:A{}", "a".repeat(34)).into_bytes(),
            RuleId::TelegramBotToken,
        ),
        (b"pi_a_secret_b".to_vec(), RuleId::StripePaymentIntent),
        (
            format!("FLWSECK-{}", "a".repeat(32)).into_bytes(),
            RuleId::FlutterwaveKey,
        ),
    ];
    for (input, rule) in cases {
        assert_eq!(match_at(&input, &[]).unwrap().map(|(id, _)| id), Some(rule));
        assert_ne!(
            match_at(&input, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule)
        );
    }
}
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
    // rayloc:ignore
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
    // LLM provider API keys (synthetic test values)
    fixtures.push((
        RuleId::OpenaiKey,
        b"sk-SyntheticOpenAIKey1234567890ABCDEF".to_vec(), // rayloc:ignore
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
    // Phase 1: Cloud & Infrastructure
    fixtures.push((
        RuleId::DigitalOceanPat,
        b"dop_v1_0123456701234567012345670123456701234567012345670123456701234567".to_vec(),
    ));
    fixtures.push((
        RuleId::DigitalOceanOauth,
        b"doo_v1_0123456701234567012345670123456701234567012345670123456701234567".to_vec(),
    ));
    fixtures.push((
        RuleId::DigitalOceanRefresh,
        b"dor_v1_0123456701234567012345670123456701234567012345670123456701234567".to_vec(),
    ));
    fixtures.push((
        RuleId::DockerSwarmJoin,
        b"SWMTKN-1-abcdefghijABCDEFGHIJ1234567890abcdefghij-abcdefghijABCDEFGHIJklmn".to_vec(),
    ));
    fixtures.push((
        RuleId::DockerSwarmUnlock,
        b"SWMKEY-1-abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ".to_vec(),
    ));
    fixtures.push((
        RuleId::HerokuApiKey,
        b"HRKU-AA012345678901234567890123456789012345678901234567890123456789".to_vec(),
    ));
    // Phase 1: Package Managers
    fixtures.push((
        RuleId::ClojarsToken,
        b"CLOJARS_SyntheticClojarsToken1234567890abcdef1234567890ab".to_vec(),
    ));
    fixtures.push((
        RuleId::CratesioToken,
        b"cratesio_SyntheticCratesioToken1234567890abcdef1234".to_vec(),
    ));
    fixtures.push((
        RuleId::PyPiToken,
        b"pypi-AgEI_SyntheticPyPiToken1234567890abcdef1234567890".to_vec(),
    ));
    fixtures.push((
        RuleId::RubygemsApiKey,
        b"rubygems_SyntheticRubygemsApiKey1234567890abcdef1234567890abcd".to_vec(),
    ));
    // Phase 1: Communication & Messaging
    fixtures.push((
        RuleId::SendgridApiKey,
        b"SG.SyntheticSendGridApiKey1.SyntheticSendGridApiKey1234567890abcdefghij".to_vec(),
    ));
    fixtures.push((
        RuleId::SendinblueApiKey,
        b"xkeysib-01234567890123456789012345678901234567890123456789012345678901234567890123456789a".to_vec(),
    ));
    fixtures.push((
        RuleId::SlackBotToken,
        concat!(
            "xoxb-",
            "123456789012",
            "-",
            "123456789012",
            "-",
            "abcdefghijABCDEFGH1234"
        )
        .as_bytes()
        .to_vec(),
    ));
    fixtures.push((
        RuleId::SlackUserToken,
        concat!(
            "xoxp-",
            "123456789012",
            "-",
            "123456789012",
            "-",
            "abcdefgh"
        )
        .as_bytes()
        .to_vec(),
    ));
    fixtures.push((
        RuleId::SlackWorkspaceToken,
        concat!(
            "xoxa-",
            "123456789012",
            "-",
            "123456789012",
            "-",
            "abcdefgh"
        )
        .as_bytes()
        .to_vec(),
    ));
    fixtures.push((
        RuleId::SlackRefreshToken,
        concat!(
            "xoxr-",
            "123456789012",
            "-",
            "123456789012",
            "-",
            "abcdefgh"
        )
        .as_bytes()
        .to_vec(),
    ));
    // Phase 1: Databases & Storage
    fixtures.push((
        RuleId::TwilioAccountSid,
        concat!("AC", "1234567890abcdef", "1234567890abcdef")
            .as_bytes()
            .to_vec(),
    ));
    fixtures.push((
        RuleId::TwilioApiKey,
        concat!("SK", "1234567890abcdef", "1234567890abcdef")
            .as_bytes()
            .to_vec(),
    ));
    // Phase 1: SaaS & Dev Tools
    fixtures.push((
        RuleId::SentryOrgToken,
        b"sntrys_SyntheticSentryOrgToken1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::SentryPersonalToken,
        b"sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::GrafanaServiceAccountToken,
        b"glsa_SyntheticGrafanaServiceAcct01234_0123abcd".to_vec(),
    ));
    fixtures.push((
        RuleId::AxiomToken,
        b"xaat-12345678-abcd-ef01-2345-6789abcdef01".to_vec(),
    ));
    fixtures.push((
        RuleId::SonarQubeToken,
        b"squ_0123456789abcdef0123456789abcdef01234567".to_vec(),
    ));
    fixtures.push((RuleId::SonarQubeCloudToken, prefixed(b"sqco_", b'a', 59)));
    fixtures.push((RuleId::KongKonnectToken, prefixed(b"kpat_", b'9', 49)));
    fixtures.push((
        RuleId::TruffleHogEnterpriseSecret,
        b"thog-secret-0123456789abcdef0123456789abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::DopplerToken,
        b"dp.st.desktop.0123456789abcdefghijABCDEFGHIJ0123456789".to_vec(),
    ));
    fixtures.push((
        RuleId::TailscaleApiToken,
        b"tskey-api-abcDEF1CNTRL-091234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::TailscaleAuthToken,
        b"tskey-auth-xyzGHI2CNTRL-1234567890abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::ResendApiKey,
        b"re_12345678_abcdefghijkmnpqrstuvwxyz".to_vec(),
    ));
    fixtures.push((
        RuleId::LaunchDarklyServerSdkToken,
        b"sdk-12345678-abcd-ef01-2345-6789abcdef01".to_vec(),
    ));
    fixtures.push((RuleId::FlagsmithServerToken, prefixed(b"ser.", b'a', 43)));
    fixtures.push((RuleId::GrowthBookSecretKey, prefixed(b"secret_", b'a', 16)));
    fixtures.push((RuleId::PostHogPersonalToken, prefixed(b"phx_", b'a', 43)));
    fixtures.push((
        RuleId::GitlabCicdJobToken,
        b"glcbt-A_SyntheticGitlabCicd123456".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabDeployToken,
        b"gldt-SyntheticGitlabDep12".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabFeatureFlagToken,
        b"glffct-SyntheticGitlabFflg1".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabPersonalAccessToken,
        b"glpat-SyntheticGitlabP0123".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabRunnerToken,
        b"glrt-SyntheticGitlabRnr12".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabRunnerRegistrationToken,
        b"glrtr-SyntheticGitlabRgr12".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabFeedToken,
        b"glft-SyntheticGitlabFeed1".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabIncomingMailToken,
        b"glimt-SyntheticGitlabIncomingM1".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabScimToken,
        b"glsoat-SyntheticGitlabScim1".to_vec(),
    ));
    fixtures.push((
        RuleId::GitlabAgentToken,
        [b"glagent-".as_slice(), b"a".repeat(50).as_slice()].concat(),
    ));
    fixtures.push((
        RuleId::GitlabOauthAppSecret,
        [b"gloas-".as_slice(), b"b".repeat(64).as_slice()].concat(),
    ));
    fixtures.push((
        RuleId::GitlabTriggerToken,
        [b"glptt-".as_slice(), b"f".repeat(40).as_slice()].concat(),
    ));
    fixtures.push((
        RuleId::CircleCiPersonalToken,
        b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2cb".to_vec(),
    ));
    fixtures.push((
        RuleId::CircleCiProjectToken,
        b"CCIPRJ_ULUhR6rJLxYbyzyrP19iMZ_8FB1E3510325F7F09361DE22B9420346C53CA2CB".to_vec(),
    ));
    fixtures.push((
        RuleId::AtlassianApiToken,
        [
            b"ATATT3".as_slice(),
            std::iter::repeat_n(b'A', 186)
                .collect::<Vec<u8>>()
                .as_slice(),
        ]
        .concat(),
    ));
    fixtures.push((
        RuleId::NetlifyAccessToken,
        b"nfp_SyntheticNetlifyAccessToken123456789".to_vec(),
    ));
    fixtures.push((
        RuleId::FlyioToken,
        [
            b"fo1_".as_slice(),
            std::iter::repeat_n(b'Z', 43)
                .collect::<Vec<u8>>()
                .as_slice(),
        ]
        .concat(),
    ));
    fixtures.push((
        RuleId::FlyioToken,
        [
            b"fm2_".as_slice(),
            std::iter::repeat_n(b'q', 100)
                .collect::<Vec<u8>>()
                .as_slice(),
        ]
        .concat(),
    ));
    fixtures.push((
        RuleId::PlanetscaleToken,
        b"pscale_tkn_SyntheticPlanetscaleServiceToken12".to_vec(),
    ));
    fixtures.push((
        RuleId::PlanetscaleOauthToken,
        b"pscale_oauth_SyntheticPlanetscaleOauthToken123".to_vec(),
    ));
    fixtures.push((
        RuleId::PaddleApiKey,
        b"pdl_live_apikey_abcdefghijklmnopqrstuvwx01_ABCDEFGHIJKLMNOPQRSTUV_7x9".to_vec(),
    ));
    fixtures.push((
        RuleId::PlaidAccessToken,
        b"access-production-12345678-abcd-ef01-2345-6789abcdef01".to_vec(),
    ));
    fixtures.push((
        RuleId::PineconeApiKey,
        b"pcsk_2bAaB_ThisIsASyntheticPineconeKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
    ));
    fixtures.push((
        RuleId::AnthropicAdminKey,
        [
            b"sk-ant-admin01-".as_slice(),
            b"A".repeat(91).as_slice(),
            b"AA".as_slice(),
        ]
        .concat(),
    ));
    fixtures.push((
        RuleId::Auth0ManagementToken,
        b"ua2_SyntheticAuth0ManagementToken123456789ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::OktaAccessToken,
        b"00aS1SyntheticOktaAccessToken123456.okta.com".to_vec(),
    ));
    fixtures.push((
        RuleId::NotionApiKey,
        b"nt_SyntheticNotionApiKey1234567890123456".to_vec(),
    ));
    fixtures.push((
        RuleId::LinearApiKey,
        b"lin_api_SyntheticLinearApiKey1234567890ABC".to_vec(),
    ));
    fixtures.push((
        RuleId::FigmaToken,
        b"figt_SyntheticFigmaToken1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::SquareAccessToken,
        b"sq0atp-SyntheticSquareAccessToken12".to_vec(),
    ));
    fixtures.push((
        RuleId::ShopifyAccessToken,
        b"shpat_SyntheticShopifyAccessToken123456".to_vec(),
    ));
    fixtures.push((
        RuleId::ShopifyCustomToken,
        b"shpcc_SyntheticShopifyCustomToken123456".to_vec(),
    ));
    fixtures.push((
        RuleId::ShopifySharedSecret,
        b"shpss_SyntheticShopifySharedSecret12345".to_vec(),
    ));
    fixtures.push((
        RuleId::ShopifyAppPassword,
        b"shppa_SyntheticShopifyAppPassword123456".to_vec(),
    ));
    fixtures.push((
        RuleId::StripePaymentIntent,
        b"pi_live_secret_SyntheticStripePaymentIntent1".to_vec(),
    ));
    fixtures.push((
        RuleId::StripeAccessToken,
        b"sk_prod_SyntheticStripeAccessToken123456789".to_vec(),
    ));
    // Phase 1: AI / ML Providers
    fixtures.push((
        RuleId::MistralKey,
        b"mv4-SyntheticMistralApiKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::CerebrasKey,
        b"csk_SyntheticCerebrasApiKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::TogetheraiKey,
        b"tgn-SyntheticTogetheraiApiKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::FireworksAiKey,
        b"fw_SyntheticFireworksAiKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::StabilityAiKey,
        b"sk-stability-SyntheticStabilityAiKey1234567890".to_vec(),
    ));
    fixtures.push((
        RuleId::DeepgramKey,
        b"dg_SyntheticDeepgramApiKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::TelegramBotToken,
        b"123456789:AABBCCDDEE11223344556677889900aAbbccdd".to_vec(),
    ));
    fixtures.push((
        RuleId::RazorpayKey,
        b"rzp_SyntheticRazorpayKey1234567890ABCDEF".to_vec(),
    ));
    fixtures.push((
        RuleId::FlutterwaveKey,
        b"FLWSECK-1234567890abcdef1234567890abcdef".to_vec(),
    ));
    fixtures.push((
        RuleId::PlanetscalePassword,
        b"pscale_pw_SyntheticPlanetscalePassword12345678".to_vec(),
    ));
    fixtures.push((
        RuleId::CloudinaryUrl,
        b"cloudinary://apikey:apisecret1234567890abcdef@demo.cloudinary.com/abc".to_vec(),
    ));
    // Phase 3: URI-based rules
    fixtures.push((
        RuleId::MongodbUri,
        b"mongodb://user:pass123@cluster.example.com/db".to_vec(),
    ));
    fixtures.push((
        RuleId::PostgresUri,
        b"postgres://user:pass123@host/db".to_vec(),
    ));
    fixtures.push((RuleId::RedisUri, b"redis://user:pass123@host:6379".to_vec()));
    fixtures.push((
        RuleId::SqlserverUri,
        b"sqlserver://user:pass123@host/db".to_vec(),
    ));
    fixtures.push((RuleId::MysqlUri, b"mysql://user:pass123@host/db".to_vec()));
    fixtures.push((
        RuleId::CockroachdbUri,
        b"cockroachdb://user:pass123@host:26257/db".to_vec(),
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
        assert_eq!(metadata.reviewed_on, "2026-10-06");
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
        // Phase 1 negatives
        "dop_v1_short",
        "doo_v1_short",
        "dor_v1_short",
        "SWMTKN-short",
        "SWMKEY-short",
        "HRKU-short",
        "CLOJARS_short",
        "cratesio_short",
        "cratesioplus_short",
        "pypi-AgE-short",
        "pypi-Agkv-short",
        "rubygems_short",
        "SG.short.short",
        "xkeysib-short",
        "xoxb-short",
        "xoxp-short",
        "xoxa-short",
        "xoxr-short",
        "AC_short",
        "SK_short",
        "sntrys_short",
        "glcbt_short",
        "gldt_short",
        "glffct_short",
        "glpat-short",
        "ua2_short",
        "00a-short",
        "nt_short",
        "lin_api_short",
        "figt_short",
        "fig-oauth-short",
        "sq0atp-short",
        "shpat_short",
        "shpcc_short",
        "shpss_short",
        "shppa_short",
        "pi_live_short",
        "sk_prod_short",
        "rk_prod_short",
        "mv4-sh",
        "csk-sh",
        "tgn-sh",
        "fw-sh",
        "sk-stability-sh",
        "dg-sh",
        "123:Ab", // Telegram: too short body
        "FLWSECK-short",
        "FLWTESTCK-short",
        "pscale_password_short",
        "cloudinary://",                    // URI without credentials
        "mongodb://cluster.example.com/db", // scheme without credentials
        "postgres://host/db",
        "redis://host:6379",
        "sqlserver://host/db",
        "mysql://host/db",
        "cockroachdb://host/db",
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

#[test]
fn expanded_cicd_structural_families_respect_complete_spans() {
    let personal = b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2cb";
    let project = b"CCIPRJ_ULUhR6rJLxYbyzyrP19iMZ_8FB1E3510325F7F09361DE22B9420346C53CA2CB";
    assert_eq!(
        matches(personal),
        vec![(RuleId::CircleCiPersonalToken, 0..personal.len())]
    );
    assert_eq!(
        matches(project),
        vec![(RuleId::CircleCiProjectToken, 0..project.len())]
    );
}

fn prefixed(prefix: &[u8], fill: u8, count: usize) -> Vec<u8> {
    let mut value = prefix.to_vec();
    value.extend(std::iter::repeat_n(fill, count));
    value
}

#[test]
fn sentry_grafana_axiom_families_accept_documented_shapes_only() {
    let personal = [b"sntryu_".as_slice(), b"f".repeat(64).as_slice()].concat();
    assert_eq!(
        matches(&personal),
        vec![(RuleId::SentryPersonalToken, 0..personal.len())]
    );
    for hex_fill in [b'0', b'9', b'a', b'f'] {
        let service = [
            b"glsa_".as_slice(),
            b"a".repeat(32).as_slice(),
            b"_",
            std::iter::repeat_n(hex_fill, 8)
                .collect::<Vec<u8>>()
                .as_slice(),
        ]
        .concat();
        assert_eq!(
            matches(&service),
            vec![(RuleId::GrafanaServiceAccountToken, 0..service.len())],
            "{hex_fill}",
        );
    }
    for prefix in [b"xaat-".as_slice(), b"xapt-".as_slice()] {
        let token = [prefix, b"12345678-abcd-ef01-2345-6789abcdef01"].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::AxiomToken, 0..token.len())],
            "{prefix:?}",
        );
    }
}

#[test]
fn sentry_grafana_axiom_families_reject_near_misses_and_public_values() {
    let short_sentry = [b"sntryu_".as_slice(), b"f".repeat(63).as_slice()].concat();
    let long_sentry = [b"sntryu_".as_slice(), b"f".repeat(65).as_slice()].concat();
    let upper_sentry = [b"sntryu_".as_slice(), b"F".repeat(64).as_slice()].concat();
    assert!(matches(&short_sentry).is_empty(), "sentry personal short");
    assert!(matches(&long_sentry).is_empty(), "sentry personal long");
    assert!(
        matches(&upper_sentry).is_empty(),
        "sentry personal uppercase"
    );
    for group in [31, 33] {
        let service = [
            b"glsa_".as_slice(),
            b"a".repeat(group).as_slice(),
            b"_",
            b"01234567".as_slice(),
        ]
        .concat();
        assert!(matches(&service).is_empty(), "grafana group {group}");
    }
    let grafana_bad_hex = [
        b"glsa_".as_slice(),
        b"a".repeat(32).as_slice(),
        b"_",
        b"0123456G".as_slice(),
    ]
    .concat();
    assert!(
        matches(&grafana_bad_hex).is_empty(),
        "grafana non-hex suffix"
    );
    for uuid in [
        b"12345678-abcd-ef01-2345-6789abcdef".as_slice(),
        b"12345678-abcd-ef01-2345-6789abcdef012".as_slice(),
        b"12345678-ABCD-ef01-2345-6789abcdef01".as_slice(),
    ] {
        assert!(
            matches(&[b"xaat-".as_slice(), uuid].concat()).is_empty(),
            "axiom {uuid:?}",
        );
    }
    assert!(
        matches(b"xaat-reserved-public-identifier").is_empty(),
        "public counterpart",
    );
}

#[test]
fn sentry_grafana_axiom_families_respect_disabled_rules_and_stream_splits() {
    let personal = [b"sntryu_".as_slice(), b"c".repeat(64).as_slice()].concat();
    let service = [
        b"glsa_".as_slice(),
        b"b".repeat(32).as_slice(),
        b"_",
        b"abcdef01".as_slice(),
    ]
    .concat();
    let axiom = [b"xapt-".as_slice(), b"0f1e2d3c-ba98-7654-3210-fedcba987654"].concat();
    let tokens: [(&[u8], RuleId); 3] = [
        (&personal, RuleId::SentryPersonalToken),
        (&service, RuleId::GrafanaServiceAccountToken),
        (&axiom, RuleId::AxiomToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn supabase_secret_prefix_stands_alone_and_public_prefix_stays_quiet() {
    let secret = b"sb_secret_SyntheticSupabaseServerSecretKeyValue12";
    assert_eq!(
        matches(secret),
        vec![(RuleId::SupabaseKey, 0..secret.len())]
    );
    let public = b"sb_publishable_SyntheticPublicPublishableValue123";
    assert!(
        matches(public).is_empty(),
        "public prefix stays provider-silent"
    );
}

#[test]
fn resend_launchdarkly_flagsmith_growthbook_posthog_families_accept_documented_shapes_only() {
    let resend = b"re_12345678_abcdefghijkmnpqrstuvwxyz";
    assert_eq!(
        matches(resend),
        vec![(RuleId::ResendApiKey, 0..resend.len())]
    );
    let sdk = [b"sdk-".as_slice(), b"12345678-abcd-ef01-2345-6789abcdef01"].concat();
    assert_eq!(
        matches(&sdk),
        vec![(RuleId::LaunchDarklyServerSdkToken, 0..sdk.len())]
    );
    let server = prefixed(b"ser.", b'a', 43);
    assert_eq!(
        matches(&server),
        vec![(RuleId::FlagsmithServerToken, 0..server.len())]
    );
    for body in [16, 40, 64] {
        let token = prefixed(b"secret_", b'a', body);
        assert_eq!(
            matches(&token),
            vec![(RuleId::GrowthBookSecretKey, 0..token.len())],
            "{body}"
        );
    }
    for body in [43, 48] {
        let token = prefixed(b"phx_", b'a', body);
        assert_eq!(
            matches(&token),
            vec![(RuleId::PostHogPersonalToken, 0..token.len())],
            "{body}"
        );
    }
}

#[test]
fn resend_launchdarkly_flagsmith_growthbook_posthog_families_reject_near_misses_and_public_values()
{
    let short_first = b"re_1234567_abcdefghijkmnpqrstuvwxyz2";
    let long_first = b"re_123456789_abcdefghijkmnpqrstuvwxyz2";
    let bad_alphabet = b"re_12345670_abcdefghijkmnpqrstuvwxyz2";
    let merged = b"re_12345678abcdefghijkmnpqrstuvwxyz23";
    assert!(matches(short_first).is_empty(), "resend short first part");
    assert!(matches(long_first).is_empty(), "resend long first part");
    assert!(matches(bad_alphabet).is_empty(), "resend zero digit");
    for excluded in [b'O', b'I', b'l'] {
        let mut bad = bad_alphabet.to_vec();
        bad[b"re_1234567".len()] = excluded;
        assert!(
            matches(&bad).is_empty(),
            "resend excluded letter {excluded:?}"
        );
    }
    assert!(matches(merged).is_empty(), "resend no separator");
    for uuid in [
        b"12345678-ABCD-ef01-2345-6789abcdef01".as_slice(),
        b"12345678-abcd-ef01-2345-6789abcdef".as_slice(),
        b"12345678-abcd-ef01-2345-6789abcdef012".as_slice(),
    ] {
        let token = [b"sdk-".as_slice(), uuid].concat();
        assert!(matches(&token).is_empty(), "sdk {uuid:?}");
    }
    for body in [42, 44] {
        let token = prefixed(b"ser.", b'a', body);
        assert!(matches(&token).is_empty(), "flagsmith {body}");
    }
    for body in [15, 65] {
        let token = prefixed(b"secret_", b'a', body);
        assert!(matches(&token).is_empty(), "growthbook {body}");
    }
    for body in [42, 49] {
        let token = prefixed(b"phx_", b'a', body);
        assert!(matches(&token).is_empty(), "posthog {body}");
    }
    assert!(
        matches(b"phc_K8SyntheticPublicProjectTokenAAAAAAAAAA").is_empty(),
        "public posthog project token",
    );
}

#[test]
fn resend_launchdarkly_flagsmith_growthbook_posthog_families_respect_disabled_rules_and_stream_splits()
 {
    let resend = b"re_aBcDeFgH_Jkmnpqrstuvwxyz234567891".to_vec();
    let sdk = [b"sdk-".as_slice(), b"0f1e2d3c-ba98-7654-3210-fedcba987654"].concat();
    let server = prefixed(b"ser.", b'b', 43);
    let growthbook = prefixed(b"secret_", b'c', 64);
    let posthog = prefixed(b"phx_", b'd', 48);
    let tokens: [(&[u8], RuleId); 5] = [
        (&resend, RuleId::ResendApiKey),
        (&sdk, RuleId::LaunchDarklyServerSdkToken),
        (&server, RuleId::FlagsmithServerToken),
        (&growthbook, RuleId::GrowthBookSecretKey),
        (&posthog, RuleId::PostHogPersonalToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn trufflehog_doppler_tailscale_families_accept_documented_shapes_only() {
    let thog = b"thog-secret-0123456789abcdef0123456789abcdef".to_vec();
    assert_eq!(
        matches(&thog),
        vec![(RuleId::TruffleHogEnterpriseSecret, 0..thog.len())]
    );
    let secret40 = b"0123456789abcdefghijABCDEFGHIJ0123456789";
    let secret41 = b"0123456789abcdefghijABCDEFGHIJ0123456789a";
    let secret44 = b"0123456789abcdefghijABCDEFGHIJ0123456789abcd";
    for suffix in [b"ct_".as_slice(), b"pt_".as_slice(), b"sa_".as_slice()] {
        let token = [b"dp.".as_slice(), suffix, secret40].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::DopplerToken, 0..token.len())],
            "{suffix:?}"
        );
    }
    let scim = [b"dp.scim_".as_slice(), secret41].concat();
    assert_eq!(matches(&scim), vec![(RuleId::DopplerToken, 0..scim.len())]);
    let audit = [b"dp.audit_".as_slice(), secret44].concat();
    assert_eq!(
        matches(&audit),
        vec![(RuleId::DopplerToken, 0..audit.len())]
    );
    let direct = [b"dp.st.".as_slice(), secret40].concat();
    assert_eq!(
        matches(&direct),
        vec![(RuleId::DopplerToken, 0..direct.len())]
    );
    let scoped = [b"dp.st.desktop.".as_slice(), secret44].concat();
    assert_eq!(
        matches(&scoped),
        vec![(RuleId::DopplerToken, 0..scoped.len())]
    );
    for (prefix, rule) in [
        (b"tskey-api-".as_slice(), RuleId::TailscaleApiToken),
        (b"tskey-auth-".as_slice(), RuleId::TailscaleAuthToken),
    ] {
        let token = [prefix, b"abcDEF1CNTRL-091234567890ABCDEF"].concat();
        assert_eq!(matches(&token), vec![(rule, 0..token.len())], "{prefix:?}");
    }
}

#[test]
fn trufflehog_doppler_tailscale_families_reject_near_misses_and_public_values() {
    let short = [b"thog-secret-".as_slice(), b"f".repeat(31).as_slice()].concat();
    let long = [b"thog-secret-".as_slice(), b"f".repeat(33).as_slice()].concat();
    let upper = [b"thog-secret-".as_slice(), b"F".repeat(32).as_slice()].concat();
    assert!(matches(&short).is_empty(), "thog short");
    assert!(matches(&long).is_empty(), "thog long");
    assert!(matches(&upper).is_empty(), "thog uppercase");
    let short_token = [b"dp.ct_".as_slice(), b"9".repeat(39).as_slice()].concat();
    assert!(matches(&short_token).is_empty(), "doppler short secret");
    let long_token = [b"dp.ct_".as_slice(), b"9".repeat(45).as_slice()].concat();
    assert!(matches(&long_token).is_empty(), "doppler long secret");
    let unknown_type = [b"dp.dt_".as_slice(), b"a".repeat(40).as_slice()].concat();
    assert!(matches(&unknown_type).is_empty(), "doppler unknown type");
    let tiny_scope = [b"dp.st.a.".as_slice(), b"a".repeat(40).as_slice()].concat();
    assert!(matches(&tiny_scope).is_empty(), "doppler one-byte scope");
    let fat_scope = [
        b"dp.st.".as_slice(),
        b"a".repeat(36).as_slice(),
        b".".as_slice(),
        b"a".repeat(40).as_slice(),
    ]
    .concat();
    assert!(matches(&fat_scope).is_empty(), "doppler over-long scope");
    let bad_scope = [b"dp.st.Desktop.".as_slice(), b"a".repeat(40).as_slice()].concat();
    assert!(matches(&bad_scope).is_empty(), "doppler uppercase scope");
    for bad in [
        b"tskey-api--abcDEF".as_slice(),
        b"tskey-api-abcDEF-".as_slice(),
        b"tskey-api-abc-DEF-GHI".as_slice(),
    ] {
        assert!(matches(bad).is_empty(), "tailscale {bad:?}");
    }
    assert!(
        matches(b"tskey-client-abcDEF1CNTRL-091234567890ABCDEF").is_empty(),
        "public client identifier",
    );
}

#[test]
fn trufflehog_doppler_tailscale_families_respect_disabled_rules_and_stream_splits() {
    let thog = b"thog-secret-abcdef0123456789abcdef0123456789".to_vec();
    let doppler = [b"dp.st.desktop.".as_slice(), b"9".repeat(44).as_slice()].concat();
    let api = b"tskey-api-kSyntheticApiToken-CNTRL_01".to_vec();
    let auth = b"tskey-auth-kSyntheticAuthToken-CNTRL01".to_vec();
    let tokens: [(&[u8], RuleId); 4] = [
        (&thog, RuleId::TruffleHogEnterpriseSecret),
        (&doppler, RuleId::DopplerToken),
        (&api, RuleId::TailscaleApiToken),
        (&auth, RuleId::TailscaleAuthToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn sonar_and_kong_families_accept_documented_shapes_only() {
    for prefix in [b"squ_".as_slice(), b"sqp_".as_slice(), b"sqa_".as_slice()] {
        let token = [prefix, b"0123456789abcdef0123456789abcdef01234567"].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::SonarQubeToken, 0..token.len())],
            "{prefix:?}",
        );
    }
    let cloud = [b"sqco_".as_slice(), b"a".repeat(59).as_slice()].concat();
    assert_eq!(
        matches(&cloud),
        vec![(RuleId::SonarQubeCloudToken, 0..cloud.len())]
    );
    for prefix in [b"kpat_".as_slice(), b"spat_".as_slice()] {
        let token = [prefix, b"9".repeat(49).as_slice()].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::KongKonnectToken, 0..token.len())],
            "{prefix:?}",
        );
    }
}

#[test]
fn sonar_and_kong_families_reject_near_misses_and_public_values() {
    let short = [b"squ_".as_slice(), b"f".repeat(39).as_slice()].concat();
    let long = [b"squ_".as_slice(), b"f".repeat(41).as_slice()].concat();
    let upper = [b"squ_".as_slice(), b"F".repeat(40).as_slice()].concat();
    assert!(matches(&short).is_empty(), "sonar short");
    assert!(matches(&long).is_empty(), "sonar long");
    assert!(matches(&upper).is_empty(), "sonar uppercase");
    for group in [58, 60] {
        let cloud = [b"sqco_".as_slice(), b"a".repeat(group).as_slice()].concat();
        assert!(matches(&cloud).is_empty(), "sonar cloud {group}");
    }
    let cloud_underscore = [
        b"sqco_".as_slice(),
        b"a".as_slice(),
        b"_".as_slice(),
        b"a".repeat(57).as_slice(),
    ]
    .concat();
    assert!(
        matches(&cloud_underscore).is_empty(),
        "sonar cloud underscore body"
    );
    for group in [48, 50] {
        let kong = [b"kpat_".as_slice(), b"z".repeat(group).as_slice()].concat();
        assert!(matches(&kong).is_empty(), "kong {group}");
    }
    assert!(
        matches(b"0123456789abcdef0123456789abcdef01234567").is_empty(),
        "bare sonar token deferred",
    );
}

#[test]
fn sonar_and_kong_families_respect_disabled_rules_and_stream_splits() {
    let sonar = prefixed(b"sqa_", b'0', 40);
    let cloud = prefixed(b"sqco_", b'a', 59);
    let kong = prefixed(b"spat_", b'9', 49);
    let tokens: [(&[u8], RuleId); 3] = [
        (&sonar, RuleId::SonarQubeToken),
        (&cloud, RuleId::SonarQubeCloudToken),
        (&kong, RuleId::KongKonnectToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn paddle_and_plaid_families_accept_documented_shapes_only() {
    for prefix in [b"pdl_live_apikey_", b"pdl_sdbx_apikey_"] {
        let token = [
            prefix.as_slice(),
            b"a".repeat(26).as_slice(),
            b"_",
            b"B".repeat(22).as_slice(),
            b"_",
            b"9x7".as_slice(),
        ]
        .concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::PaddleApiKey, 0..token.len())],
            "{prefix:?}",
        );
    }
    for prefix in [
        b"access-sandbox-".as_slice(),
        b"access-development-".as_slice(),
        b"access-production-".as_slice(),
    ] {
        let token = [prefix, b"12345678-abcd-ef01-2345-6789abcdef01".as_slice()].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::PlaidAccessToken, 0..token.len())],
            "{prefix:?}",
        );
    }
}

#[test]
fn paddle_and_plaid_families_reject_near_misses_and_public_values() {
    let short_paddle = [
        b"pdl_live_apikey_".as_slice(),
        b"a".repeat(25).as_slice(),
        b"_",
        b"B".repeat(22).as_slice(),
        b"_",
        b"9x7",
    ]
    .concat();
    assert!(matches(&short_paddle).is_empty(), "paddle group short");
    let bad_case = [
        b"pdl_live_apikey_".as_slice(),
        b"A".repeat(26).as_slice(),
        b"_",
        b"B".repeat(22).as_slice(),
        b"_",
        b"9x7",
    ]
    .concat();
    assert!(matches(&bad_case).is_empty(), "paddle uppercase group");
    let bad_tail = [
        b"pdl_live_apikey_".as_slice(),
        b"a".repeat(26).as_slice(),
        b"_",
        b"B".repeat(22).as_slice(),
        b"_",
        b"9x77",
    ]
    .concat();
    assert!(matches(&bad_tail).is_empty(), "paddle long tail");
    for uuid in [
        b"12345678-abcd-ef01-2345-6789abcdef0".as_slice(),
        b"12345678-abcd-ef01-2345-6789abcdef010".as_slice(),
        b"12345678-ABCD-ef01-2345-6789ABCDef01".as_slice(),
    ] {
        assert!(
            matches(&[b"access-sandbox-".as_slice(), uuid].concat()).is_empty(),
            "plaid uuid {uuid:?}",
        );
    }
    assert!(
        matches(
            &[
                b"access-sandbox-".as_slice(),
                b"12345678-abcd-ef01-2345-6789abcdef01".as_slice(),
                b"a".as_slice(),
            ]
            .concat()
        )
        .is_empty(),
        "plaid trailing identifier",
    );
    assert!(
        matches(b"access-public-SyntheticPublicIdentifier".as_slice()).is_empty(),
        "public counterpart",
    );
}

#[test]
fn paddle_and_plaid_families_respect_disabled_rules_and_stream_splits() {
    let paddle = [
        b"pdl_live_apikey_".as_slice(),
        b"a".repeat(26).as_slice(),
        b"_",
        b"B".repeat(22).as_slice(),
        b"_",
        b"9x7".as_slice(),
    ]
    .concat();
    let plaid = [
        b"access-development-".as_slice(),
        b"12345678-abcd-ef01-2345-6789abcdef01".as_slice(),
    ]
    .concat();
    for (token, rule) in [
        (&paddle, RuleId::PaddleApiKey),
        (&plaid, RuleId::PlaidAccessToken),
    ] {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for token in [&paddle, &plaid] {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn pinecone_and_anthropic_admin_families_use_documented_shapes() {
    for group in [5, 6] {
        let token = [
            b"pcsk_".as_slice(),
            b"a".repeat(group).as_slice(),
            b"_",
            b"Z".repeat(63).as_slice(),
        ]
        .concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::PineconeApiKey, 0..token.len())],
            "{group}",
        );
    }
    let admin = [
        b"sk-ant-admin01-".as_slice(),
        b"A".repeat(91).as_slice(),
        b"AA".as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&admin),
        vec![(RuleId::AnthropicAdminKey, 0..admin.len())]
    );
    let admin_bodies = [
        [b"A".repeat(91).as_slice(), b"AA"].concat(),
        [b"-".repeat(91).as_slice(), b"AA"].concat(),
        [b"9".repeat(91).as_slice(), b"AA"].concat(),
    ];
    for body in admin_bodies {
        let token = [b"sk-ant-admin01-".as_slice(), body.as_slice()].concat();
        assert_eq!(
            matches(&token),
            vec![(RuleId::AnthropicAdminKey, 0..token.len())],
            "body length {token:?}",
        );
    }
}

#[test]
fn pinecone_and_anthropic_admin_families_reject_near_misses() {
    assert!(
        matches(
            &[
                b"pcsk_".as_slice(),
                b"a".as_slice(),
                b"_",
                b"Z".repeat(63).as_slice()
            ]
            .concat()
        )
        .is_empty(),
        "one group byte",
    );
    assert!(
        matches(
            &[
                b"pcsk_".as_slice(),
                b"a".repeat(4).as_slice(),
                b"_",
                b"Z".repeat(63).as_slice(),
            ]
            .concat()
        )
        .is_empty(),
        "four group bytes",
    );
    assert!(
        matches(
            &[
                b"pcsk_".as_slice(),
                b"a".repeat(7).as_slice(),
                b"_",
                b"Z".repeat(63).as_slice(),
            ]
            .concat()
        )
        .is_empty(),
        "seven group bytes",
    );
    for count in [62, 64] {
        assert!(
            matches(
                &[
                    b"pcsk_".as_slice(),
                    b"abcde".as_slice(),
                    b"_",
                    b"Z".repeat(count).as_slice(),
                ]
                .concat()
            )
            .is_empty(),
            "body {count}",
        );
    }
    // Near-miss admin bodies fall back to the opaque `sk-` rule, never the admin id.
    for body in [
        b"A".repeat(92),
        [b"A".repeat(92).as_slice(), b"AA"].concat(),
        [b"A".repeat(92).as_slice(), b"B"].concat(),
        [b"A".repeat(91).as_slice(), b"AA", b"a"].concat(),
    ] {
        let token = [b"sk-ant-admin01-".as_slice(), body.as_slice()].concat();
        assert_ne!(
            match_at(&token, &[]).unwrap().map(|(id, _)| id),
            Some(RuleId::AnthropicAdminKey),
            "admin near miss {token:?}",
        );
    }
    assert_ne!(
        match_at(b"sk-ant-orchest01-SyntheticAdmin0000000", &[])
            .unwrap()
            .map(|(id, _)| id),
        Some(RuleId::AnthropicAdminKey),
        "admin01-only variant",
    );
}

#[test]
fn pinecone_and_anthropic_admin_families_respect_disabled_rules_and_stream_splits() {
    let pinecone = [b"pcsk_ab123".as_slice(), b"_", b"Z".repeat(63).as_slice()].concat();
    let admin = [
        b"sk-ant-admin01-".as_slice(),
        b"A".repeat(91).as_slice(),
        b"AA",
    ]
    .concat();
    for (token, rule) in [
        (&pinecone, RuleId::PineconeApiKey),
        (&admin, RuleId::AnthropicAdminKey),
    ] {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for token in [&pinecone, &admin] {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn planetscale_families_use_current_prefixes_and_bounded_bodies() {
    let cases: [(&[u8], RuleId); 3] = [
        (b"pscale_pw_", RuleId::PlanetscalePassword),
        (b"pscale_tkn_", RuleId::PlanetscaleToken),
        (b"pscale_oauth_", RuleId::PlanetscaleOauthToken),
    ];
    for (prefix, rule) in cases {
        for fill in [b'a', b'Z', b'0', b'_', b'.', b'=', b'-'] {
            for count in [32, 64] {
                let token = prefixed(prefix, fill, count);
                assert_eq!(
                    matches(&token),
                    vec![(rule, 0..token.len())],
                    "{rule:?} {fill} {count}",
                );
            }
        }
    }
}

#[test]
fn planetscale_families_reject_near_misses_and_legacy_prefix() {
    let cases: [(&[u8], RuleId); 3] = [
        (b"pscale_pw_", RuleId::PlanetscalePassword),
        (b"pscale_tkn_", RuleId::PlanetscaleToken),
        (b"pscale_oauth_", RuleId::PlanetscaleOauthToken),
    ];
    for (prefix, rule) in cases {
        assert!(
            matches(&prefixed(prefix, b'a', 31)).is_empty(),
            "{rule:?} short"
        );
        assert!(
            matches(&prefixed(prefix, b'a', 65)).is_empty(),
            "{rule:?} long"
        );
        assert!(
            matches(&[prefixed(prefix, b'a', 64).as_slice(), b"a"].concat()).is_empty(),
            "{rule:?} trailing identifier",
        );
    }
    assert!(
        matches(&[b"pscale_password_".as_slice(), b"a".repeat(40).as_slice()].concat()).is_empty(),
        "legacy standalone prefix",
    );
    assert!(
        matches(b"pscale_pw_public_identifier").is_empty(),
        "public counterpart"
    );
}

#[test]
fn planetscale_families_respect_disabled_rules_and_stream_splits() {
    let first = prefixed(b"pscale_pw_", b'a', 32);
    let second = prefixed(b"pscale_tkn_", b'q', 64);
    let third = prefixed(b"pscale_oauth_", b'9', 40);
    let examples: [&[u8]; 3] = [&first, &second, &third];
    for (token, rule) in [
        (&first, RuleId::PlanetscalePassword),
        (&second, RuleId::PlanetscaleToken),
        (&third, RuleId::PlanetscaleOauthToken),
    ] {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for token in examples {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn flyio_token_family_accepts_documented_shapes_only() {
    let fo1 = prefixed(b"fo1_", b'Z', 43);
    assert_eq!(matches(&fo1), vec![(RuleId::FlyioToken, 0..fo1.len())]);
    for fill in [b'a', b'0', b'+', b'/'] {
        for count in [100, 512] {
            for padding in [0, 1, 2] {
                let mut token = prefixed(b"fm2_", fill, count);
                token.extend(std::iter::repeat_n(b'=', padding));
                assert_eq!(
                    matches(&token),
                    vec![(RuleId::FlyioToken, 0..token.len())],
                    "{fill} {count} {padding}",
                );
            }
        }
    }
    for prefix in [b"fm1a_", b"fm1r_"] {
        let token = prefixed(prefix, b'x', 100);
        assert_eq!(matches(&token), vec![(RuleId::FlyioToken, 0..token.len())]);
    }
}

#[test]
fn flyio_token_family_rejects_near_misses_and_public_values() {
    assert!(
        matches(&prefixed(b"fo1_", b'Z', 42)).is_empty(),
        "fo1 short"
    );
    assert!(matches(&prefixed(b"fo1_", b'Z', 44)).is_empty(), "fo1 long");
    assert!(
        matches(&[prefixed(b"fo1_", b'Z', 43).as_slice(), b"a"].concat()).is_empty(),
        "fo1 trailing identifier",
    );
    assert!(
        matches(&prefixed(b"fo1_", b'.', 43)).is_empty(),
        "fo1 wrong alphabet",
    );
    assert!(
        matches(&prefixed(b"fm2_", b'a', 99)).is_empty(),
        "fm2 short"
    );
    assert!(
        matches(&prefixed(b"fm2_", b'a', 513)).is_empty(),
        "fm2 long"
    );
    assert!(
        matches(&[prefixed(b"fm2_", b'a', 512).as_slice(), b"==="].concat()).is_empty(),
        "three padding bytes",
    );
    assert!(
        matches(&[prefixed(b"fm2_", b'a', 512).as_slice(), b"===="].concat()).is_empty(),
        "four padding bytes",
    );
    assert!(
        matches(&prefixed(b"fm1_", b'a', 100)).is_empty(),
        "fm1 prefix unknown"
    );
    assert!(matches(b"fo1_short").is_empty(), "public counterpart");
}

#[test]
fn flyio_token_family_respects_disabled_rules_and_stream_splits() {
    let first = prefixed(b"fo1_", b'Z', 43);
    let second = prefixed(b"fm2_", b'q', 100);
    let third = prefixed(b"fm1a_", b'x', 512);
    let examples: [&[u8]; 3] = [&first, &second, &third];
    for token in examples {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(RuleId::FlyioToken),
            "enabled",
        );
        assert_ne!(
            match_at(token, &[RuleId::FlyioToken])
                .unwrap()
                .map(|(id, _)| id),
            Some(RuleId::FlyioToken),
            "disabled",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for token in examples {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn atlassian_netlify_structural_families_respect_complete_spans() {
    let atlassian = prefixed(b"ATATT3", b'A', 186);
    let netlify = prefixed(b"nfp_", b'a', 36);
    assert_eq!(
        matches(&atlassian),
        vec![(RuleId::AtlassianApiToken, 0..atlassian.len())]
    );
    assert_eq!(
        matches(&netlify),
        vec![(RuleId::NetlifyAccessToken, 0..netlify.len())]
    );
    for fill in [b'=', b'-', b'9', b'Z'] {
        let token = prefixed(b"ATATT3", fill, 186);
        assert_eq!(
            matches(&token),
            vec![(RuleId::AtlassianApiToken, 0..token.len())],
            "{fill}",
        );
    }
}

#[test]
fn expanded_cicd_families_reject_near_misses_and_public_counterparts() {
    let short = b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2c";
    let long = [
        b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2cb".as_slice(),
        b"a".as_slice(),
    ]
    .concat();
    let encoded = b"CCIPAT_0OUlUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2cb";
    assert!(matches(short).is_empty());
    assert!(matches(&long).is_empty());
    assert!(matches(encoded).is_empty());
    assert!(
        matches(b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_public_identifier").is_empty(),
        "public counterpart",
    );
}

#[test]
fn gitlab_new_structural_families_use_documented_alphabets_and_lengths() {
    let cases: [(RuleId, &[u8], usize, &[u8]); 11] = [
        (RuleId::GitlabPersonalAccessToken, b"glpat-", 20, b"A0_-"),
        (RuleId::GitlabRunnerToken, b"glrt-", 20, b"A0_-"),
        (
            RuleId::GitlabRunnerRegistrationToken,
            b"glrtr-",
            20,
            b"A0_-",
        ),
        (RuleId::GitlabDeployToken, b"gldt-", 20, b"A0_-"),
        (RuleId::GitlabFeatureFlagToken, b"glffct-", 20, b"A0_-"),
        (RuleId::GitlabFeedToken, b"glft-", 20, b"A0_-"),
        (RuleId::GitlabIncomingMailToken, b"glimt-", 25, b"A0_-"),
        (RuleId::GitlabScimToken, b"glsoat-", 20, b"A0_-"),
        (RuleId::GitlabAgentToken, b"glagent-", 50, b"A0_-"),
        (RuleId::GitlabOauthAppSecret, b"gloas-", 64, b"A0_-"),
        (RuleId::GitlabTriggerToken, b"glptt-", 40, b"af09"),
    ];
    for (rule, prefix, body_len, alphabet) in cases {
        for fill in alphabet {
            let body = [*fill].repeat(body_len);
            let mut token = prefix.to_vec();
            token.extend(body.clone());
            assert_eq!(
                matches(&token),
                vec![(rule, 0..token.len())],
                "{rule:?} {fill}",
            );
            let mut short = prefix.to_vec();
            short.extend([*fill].repeat(body_len - 1));
            assert!(matches(&short).is_empty(), "{rule:?} short");
            let mut long = prefix.to_vec();
            long.extend(body.clone());
            long.push(*fill);
            assert!(matches(&long).is_empty(), "{rule:?} long");
            let mut next_identifier = prefix.to_vec();
            next_identifier.extend(body.clone());
            next_identifier.push(b'a');
            assert!(
                matches(&next_identifier).is_empty(),
                "{rule:?} trailing identifier",
            );
        }
    }
}

#[test]
fn atlassian_netlify_families_reject_near_misses_and_public_counterparts() {
    let short = prefixed(b"ATATT3", b'A', 185);
    let long = prefixed(b"ATATT3", b'A', 187);
    let short_netlify = prefixed(b"nfp_", b'a', 35);
    let long_netlify = prefixed(b"nfp_", b'a', 37);
    let dotted_netlify = [prefixed(b"nfp_", b'a', 35).as_slice(), b"."].concat();
    assert!(matches(&short).is_empty(), "atlassian short");
    assert!(matches(&long).is_empty(), "atlassian long");
    assert!(matches(&short_netlify).is_empty(), "netlify short");
    assert!(matches(&long_netlify).is_empty(), "netlify long");
    assert!(
        matches(&dotted_netlify).is_empty(),
        "netlify trailing identifier"
    );
    assert!(
        matches(b"ATATT3".as_slice()).is_empty(),
        "prefix alone is not a token",
    );
    assert!(
        matches(b"nfp_public_identifier").is_empty(),
        "public counterpart"
    );
}

#[test]
fn atlassian_netlify_families_respect_disabled_rules_and_stream_splits() {
    let atlassian = prefixed(b"ATATT3", b'A', 186);
    let netlify = prefixed(b"nfp_", b'0', 36);
    let tokens: [(&[u8], RuleId); 2] = [
        (&atlassian, RuleId::AtlassianApiToken),
        (&netlify, RuleId::NetlifyAccessToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn expanded_cicd_families_respect_disabled_rules_and_stream_splits() {
    let personal = b"CCIPAT_ULUhR6rJLxYbyzyrP19iMZ_8fb1e3510325f7f09361de22b9420346c53ca2cb";
    let project = b"CCIPRJ_ULUhR6rJLxYbyzyrP19iMZ_8FB1E3510325F7F09361DE22B9420346C53CA2CB";
    let runner = b"glrt-ABCDEFGHIJ0123456789";
    let registration = b"glrtr-ABCDEFGHIJ0123456789";
    let tokens: [(&[u8], RuleId); 4] = [
        (personal as &[u8], RuleId::CircleCiPersonalToken),
        (project as &[u8], RuleId::CircleCiProjectToken),
        (runner as &[u8], RuleId::GitlabRunnerToken),
        (registration as &[u8], RuleId::GitlabRunnerRegistrationToken),
    ];
    for (token, rule) in tokens {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "enabled {rule:?}",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "disabled {rule:?}",
        );
    }
    let registry = &crate::rules::BUILTINS;
    let examples: [&[u8]; 4] = [
        personal as &[u8],
        project as &[u8],
        runner as &[u8],
        registration as &[u8],
    ];
    for token in examples {
        let expected = complete_provider_matches(token, registry).unwrap();
        for split in 0..=token.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::new();
            for fragment in [&token[..split], &token[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {token:?}");
        }
        assert_eq!(streamed(token, 1, registry).unwrap(), expected);
    }
}

#[test]
fn provider_head_prefilter_agrees_with_the_registered_tables() {
    let bits = provider_head_bits();
    assert_eq!(bits, *PROVIDER_HEAD_BITS);
    for group in PROVIDER_HEAD_LITERALS {
        for prefix in *group {
            if prefix.len() >= 2 {
                assert!(bits[((prefix[0] as u16) << 8 | prefix[1] as u16) as usize]);
            }
        }
    }
    for literal in PROVIDER_HEAD_EXTRA_LITERALS {
        assert!(bits[((literal[0] as u16) << 8 | literal[1] as u16) as usize]);
    }
    for digit_head in b'0'..=b'9' {
        for second in [b'a', b'Z', b'9', b'_'] {
            assert!(bits[((digit_head as u16) << 8 | second as u16) as usize]);
        }
    }
    let doppler = [b"dp.ct_".as_slice(), b"9".repeat(40).as_slice()].concat();
    let sendgrid = [
        b"SG.".as_slice(),
        b"a".repeat(22).as_slice(),
        b".".as_slice(),
        b"b".repeat(40).as_slice(),
    ]
    .concat();
    let swarm = [b"SWMKEY-1-".as_slice(), b"a".repeat(40).as_slice()].concat();
    let sendinblue = [b"xkeysib-".as_slice(), b"a".repeat(81).as_slice()].concat();
    let flutterwave = [b"FLWSECK-".as_slice(), b"a".repeat(32).as_slice()].concat();
    let anthropic = [
        b"sk-ant-admin01-".as_slice(),
        b"A".repeat(91).as_slice(),
        b"AA".as_slice(),
    ]
    .concat();
    for probe in [
        b"AKIA1234567890ABCDEF".as_slice(),
        b"pi_a_secret_b".as_slice(),
        doppler.as_slice(),
        sendgrid.as_slice(),
        swarm.as_slice(),
        sendinblue.as_slice(),
        flutterwave.as_slice(),
        anthropic.as_slice(),
        b"pcsk_2bAaB_ThisIsASyntheticPineconeKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_slice(),
    ] {
        assert!(
            match_at(probe, &[]).unwrap().is_some(),
            "registered head survives the prefilter"
        );
    }
    for (first, second) in [
        (b'q', b'q'),
        (b'\xff', b'\x00'),
        (b' ', b' '),
        (b'\n', b'x'),
    ] {
        let head = (first as u16) << 8 | second as u16;
        assert!(!bits[head as usize]);
        let candidate = &[first, second, b'i', b'n', b'n', b'o'];
        assert_eq!(match_at(candidate, &[]).unwrap(), None);
    }
}
