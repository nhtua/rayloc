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
    // Task-target prefix-based detectors.
    fixtures.push((RuleId::HexApiKey, prefixed(b"hex_", b'a', 40)));
    fixtures.push((
        RuleId::NewRelicInsightsQueryKey,
        prefixed(b"NRAK-", b'a', 20),
    ));
    fixtures.push((RuleId::NuGetApiKey, prefixed(b"oy2", b'a', 43)));
    fixtures.push((RuleId::OctopusDeployApiKey, prefixed(b"API-", b'A', 25)));
    fixtures.push((RuleId::PulumiAccessToken, prefixed(b"pul-", b'a', 20)));
    fixtures.push((
        RuleId::PostmanApiKey,
        concat!(
            "PMAK-",
            "0123456789abcdef01234567",
            "-",
            "0123456789abcdef0123456789abcdef012345"
        )
        .as_bytes()
        .to_vec(),
    ));
    fixtures.push((RuleId::ReadMeApiKey, prefixed(b"rdme_", b'a', 70)));
    fixtures.push((
        RuleId::TypeformPersonalAccessToken,
        prefixed(b"tfp_", b'a', 59),
    ));
    fixtures.push((
        RuleId::WakaTimeAPIKey,
        concat!("waka_", "01234567-89ab-cdef-0123-456789abcdef")
            .as_bytes()
            .to_vec(),
    ));
    fixtures.push((RuleId::YandexCloudAPIKey, prefixed(b"AQVN", b'a', 35)));
    fixtures.push((RuleId::YandexCloudIAMToken, prefixed(b"t1.", b'a', 20)));
    fixtures.push((
        RuleId::YandexCloudSmartcaptchaServerKey,
        [b"ysc2_", b"a".repeat(40).as_slice(), b"01234567"].concat(),
    ));
    fixtures.push((RuleId::YandexPassportOAuthToken, prefixed(b"y0_", b'a', 55)));
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
        // Task-target negatives (prefix present but body too short / invalid).
        "hex_short",
        "NRAK-short",
        "oy2short",
        "API-short",
        "pul-short",
        "PMAK-short",
        "rdme_short",
        "3MVG9short",
        "5AEP861short",
        "tfp_short",
        "waka_short",
        "AQVNshort",
        "t1.short",
        "ysc2_short",
        "y0_short",
        // Keyword-gated negatives (keyword present but candidate too short).
        "aikido=SyntheticShort01",
        "aws_secret=SyntheticShort012",
        "datadog=SyntheticShort0123",
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

type KeywordGatedCase = (Vec<u8>, Vec<u8>, Vec<RuleId>, RuleId);

#[test]
fn keyword_gated_families_require_provider_context() {
    // Provider keyword-gated detectors fire when the provider keyword appears
    // within 200 bytes before a word-like value of at least min_val_len bytes.
    // When two rules share a keyword the earlier dispatch entry wins, so the
    // later rule is exercised with the earlier one disabled.
    let cases: Vec<KeywordGatedCase> = vec![
        (
            b"aikido_api_client_secret SyntheticAikidoApiClientSecret01".to_vec(),
            b"SyntheticAikidoApiClientSecret01".to_vec(),
            vec![],
            RuleId::AikidoApiClientSecret,
        ),
        (
            b"aikido_ci_scanning_token SyntheticAikidoCiScanningToken012".to_vec(),
            b"SyntheticAikidoCiScanningToken012".to_vec(),
            vec![RuleId::AikidoApiClientSecret],
            RuleId::AikidoCiScanningToken,
        ),
        (
            b"airtable_api_key SyntheticAirtableApiKey01234567".to_vec(),
            b"SyntheticAirtableApiKey01234567".to_vec(),
            vec![],
            RuleId::AirtableApiKey,
        ),
        (
            b"aws_api_key_id SyntheticAwsApiKeyIdentifier01".to_vec(),
            b"SyntheticAwsApiKeyIdentifier01".to_vec(),
            vec![],
            RuleId::AmazonAwsApiKeyId,
        ),
        (
            b"aws_session_token SyntheticAwsSessionTokenValue0".to_vec(),
            b"SyntheticAwsSessionTokenValue0".to_vec(),
            vec![RuleId::AmazonAwsApiKeyId],
            RuleId::AmazonAwsSessionToken,
        ),
        (
            b"aws_temporary_access_key_id SyntheticAwsTempAccessKeyId01".to_vec(),
            b"SyntheticAwsTempAccessKeyId01".to_vec(),
            vec![RuleId::AmazonAwsApiKeyId, RuleId::AmazonAwsSessionToken],
            RuleId::AmazonAwsTemporaryAccessKeyId,
        ),
        (
            b"asana_legacy_token SyntheticAsanaLegacyFormatToken1".to_vec(),
            b"SyntheticAsanaLegacyFormatToken1".to_vec(),
            vec![],
            RuleId::AsanaLegacyFormatPersonalAccessToken,
        ),
        (
            b"asana_personal_token SyntheticAsanaPersonalAccessTok01".to_vec(),
            b"SyntheticAsanaPersonalAccessTok01".to_vec(),
            vec![RuleId::AsanaLegacyFormatPersonalAccessToken],
            RuleId::AsanaPersonalAccessToken,
        ),
        (
            b"atlassian_jwt SyntheticAtlassianJwtTokenValue0".to_vec(),
            b"SyntheticAtlassianJwtTokenValue0".to_vec(),
            vec![],
            RuleId::AtlassianJwt,
        ),
        (
            b"authress_client_access_key SyntheticAuthressClientAccessKey01".to_vec(),
            b"SyntheticAuthressClientAccessKey01".to_vec(),
            vec![],
            RuleId::AuthressServiceClientAccessKey,
        ),
        (
            b"bitbucket_server_pat SyntheticBitbucketServerToken0123".to_vec(),
            b"SyntheticBitbucketServerToken0123".to_vec(),
            vec![],
            RuleId::BitbucketServerPersonalAccessToken,
        ),
        (
            b"block_api_key SyntheticBlockProtocolApiKey012".to_vec(),
            b"SyntheticBlockProtocolApiKey012".to_vec(),
            vec![],
            RuleId::BlockProtocolApiKey,
        ),
        (
            b"cashfree_api_key SyntheticCashfreeApiKey01234567".to_vec(),
            b"SyntheticCashfreeApiKey01234567".to_vec(),
            vec![],
            RuleId::CashfreeApiKey,
        ),
        (
            b"cfx_server_key SyntheticCfxreServerKeyValue0123".to_vec(),
            b"SyntheticCfxreServerKeyValue0123".to_vec(),
            vec![],
            RuleId::CfxreServerKey,
        ),
        (
            b"chief_tools_token SyntheticChiefToolsTokenValue0123".to_vec(),
            b"SyntheticChiefToolsTokenValue0123".to_vec(),
            vec![],
            RuleId::ChiefToolsToken,
        ),
        (
            b"cohere_api_key SyntheticCohereApiKey012345678901".to_vec(),
            b"SyntheticCohereApiKey012345678901".to_vec(),
            vec![],
            RuleId::CohereApiKey,
        ),
        (
            b"contentful_web_token SyntheticContentfulWebTokenValue1".to_vec(),
            b"SyntheticContentfulWebTokenValue1".to_vec(),
            vec![],
            RuleId::ContentfulWebToken,
        ),
        (
            b"contributed_credentials SyntheticContributedSystemsValue01".to_vec(),
            b"SyntheticContributedSystemsValue01".to_vec(),
            vec![],
            RuleId::ContributedSystemsCredentials,
        ),
        (
            b"coveo_access_token SyntheticCoveoAccessToken0123456789".to_vec(),
            b"SyntheticCoveoAccessToken0123456789".to_vec(),
            vec![],
            RuleId::CoveoAccessToken,
        ),
        (
            b"coveo_api_key SyntheticCoveoApiKey01234567890123".to_vec(),
            b"SyntheticCoveoApiKey01234567890123".to_vec(),
            vec![RuleId::CoveoAccessToken],
            RuleId::CoveoApiKey,
        ),
        (
            b"datadog_api_key SyntheticDatadogApiKey012345678901".to_vec(),
            b"SyntheticDatadogApiKey012345678901".to_vec(),
            vec![],
            RuleId::DatadogApiKey,
        ),
    ];
    for (input, value, disabled, expected) in cases {
        let mut found = Vec::<(RuleId, Range<usize>)>::new();
        detect_line_with_disabled(&input, &disabled, |id, span| found.push((id, span))).unwrap();
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn keyword_gated_families_respect_length_and_context_windows() {
    // Exactly min_val_len bytes is a finding...
    let boundary = b"cohere SyntheticBoundary012";
    let value = b"SyntheticBoundary012";
    assert_eq!(
        matches(boundary),
        vec![(
            RuleId::CohereApiKey,
            boundary.len() - value.len()..boundary.len()
        )]
    );
    // ...one byte short is not, and neither is a long value without a keyword.
    for negative in [
        b"cohere SyntheticBoundary01".as_slice(),
        b"unrelated_provider SyntheticBoundary0123456789",
    ] {
        assert!(
            matches(negative).is_empty(),
            "keyword-gated negative {negative:?}"
        );
    }
    // The keyword must sit within the 200-byte context window before the value.
    let near = b"z".repeat(196);
    let in_window = [
        b"aws".as_slice(),
        near.as_slice(),
        b" ".as_slice(),
        b"SyntheticAwsApiKeyIdentifier01".as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&in_window),
        vec![(RuleId::AmazonAwsApiKeyId, 200..230)]
    );
    let far = b"z".repeat(197);
    let out_of_window = [
        b"aws".as_slice(),
        far.as_slice(),
        b" ".as_slice(),
        b"SyntheticAwsApiKeyIdentifier01".as_slice(),
    ]
    .concat();
    assert!(
        matches(&out_of_window).is_empty(),
        "keyword outside the context window"
    );
}

#[test]
fn keyword_gated_families_stop_after_the_first_keyword_match() {
    // Disabling the earlier rule of a shared keyword promotes the later one,
    // and disabling every matching rule leaves no finding at all.
    let input = b"coveo SyntheticCoveoAccessToken0123456789";
    let mut promoted = Vec::<(RuleId, Range<usize>)>::new();
    detect_line_with_disabled(input, &[RuleId::CoveoAccessToken], |id, span| {
        promoted.push((id, span))
    })
    .unwrap();
    assert_eq!(promoted, vec![(RuleId::CoveoApiKey, 6..41)], "promotion");
    let mut silenced = Vec::<(RuleId, Range<usize>)>::new();
    detect_line_with_disabled(
        input,
        &[RuleId::CoveoAccessToken, RuleId::CoveoApiKey],
        |id, span| silenced.push((id, span)),
    )
    .unwrap();
    assert!(silenced.is_empty(), "both keyword-gated rules disabled");
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
    for hex_fill in *b"09af" {
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
    for excluded in *b"OIl" {
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
        for fill in *b"aZ0_.=-" {
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
    for fill in *b"a0+/" {
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
    for fill in *b"=-9Z" {
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
                assert!(bits[(((prefix[0] as u16) << 8) | prefix[1] as u16) as usize]);
            }
        }
    }
    for literal in PROVIDER_HEAD_EXTRA_LITERALS {
        assert!(bits[(((literal[0] as u16) << 8) | literal[1] as u16) as usize]);
    }
    for digit_head in b'0'..=b'9' {
        for second in *b"aZ9_" {
            assert!(bits[(((digit_head as u16) << 8) | second as u16) as usize]);
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
        let head = ((first as u16) << 8) | second as u16;
        assert!(!bits[head as usize]);
        let candidate = &[first, second, b'i', b'n', b'n', b'o'];
        assert_eq!(match_at(candidate, &[]).unwrap(), None);
    }
}

#[test]
fn batch5_prefix_families_accept_documented_shapes_only() {
    let one_password = prefixed(b"ops_eyJ", b'Z', 65);
    assert_eq!(
        match_at(&one_password, &[]).unwrap().map(|(id, _)| id),
        Some(RuleId::OnePasswordServiceAccountToken),
    );
    // Base64 `+` and `/` in the body is still a valid 1Password token:
    // the custom matcher extends the generic word-run charset.
    let one_password_b64 = [
        b"ops_eyJ".as_slice(),
        b"a+abcdefghij/klmnopqrstuvwxyzABCDEFG".as_slice(),
        b"H".as_slice(),
        b"JKLMNOPQRSTUVWXYZabcdefghijklm".as_slice(),
    ]
    .concat();
    assert!(one_password_b64.len() >= 7 + 60, "body >= 60");
    assert_eq!(
        match_at(&one_password_b64, &[]).unwrap().map(|(id, _)| id),
        Some(RuleId::OnePasswordServiceAccountToken),
    );
    let beamer = [
        b"b_".as_slice(),
        b"a".repeat(22).as_slice(),
        b"1".repeat(11).as_slice(),
        b"=".repeat(11).as_slice(),
    ]
    .concat();
    assert_eq!(beamer.len(), 2 + 44, "beamer exact body length 44");
    assert_eq!(
        match_at(&beamer, &[]).unwrap().map(|(id, _)| id),
        Some(RuleId::BeamerApiKey),
    );
    let cases: [(&[u8], usize, RuleId); 6] = [
        (b"aio_", 20, RuleId::AdafruitIoKey),
        (b"ccdb_", 16, RuleId::CcdbApiKey),
        (b"ApiKey-v1 gcntfy", 12, RuleId::CdsCanadaNotifyApiKey),
        (b"CFPAT-", 43, RuleId::ContentfulPat),
        (b"dckr_pat_", 27, RuleId::DockerPersonalPat),
        (b"bk", 20, RuleId::BuildkiteUserAccessToken),
    ];
    for (prefix, body_len, rule) in cases {
        let fixture = prefixed(prefix, b'Z', body_len);
        assert_eq!(
            match_at(&fixture, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "{rule:?} positive",
        );
    }
}

#[test]
fn batch5_prefix_families_reject_near_misses() {
    // Short bodies fail on min-length rules (min_body matches the dispatch
    // tables in `src/rules/builtin.rs`).
    let cases: [(&[u8], usize); 7] = [
        (b"ops_eyJ", 60),
        (b"aio_", 20),
        (b"ccdb_", 16),
        (b"ApiKey-v1 gcntfy", 8),
        (b"CFPAT-", 43),
        (b"dckr_pat_", 27),
        (b"bk", 16),
    ];
    for (prefix, min_body) in cases {
        let short = prefixed(prefix, b'a', min_body - 1);
        let found = matches(&short);
        let short_len = short.len();
        assert!(
            found.is_empty(),
            "{prefix:?} short -> {found:?} len {short_len}",
        );
    }
    // BeamerApiKey has an exact 44-char body over `[a-z0-9=_-]`. Short (43),
    // long (45), and wrong-charset (uppercase) bodies all fail.
    let short_beamer = prefixed(b"b_", b'a', 43);
    assert!(matches(&short_beamer).is_empty(), "beamer short");
    let long_beamer = prefixed(b"b_", b'a', 45);
    assert!(matches(&long_beamer).is_empty(), "beamer long");
    let bad_charset_beamer = [
        b"b_".as_slice(),
        b"a".repeat(43).as_slice(),
        b"Z".as_slice(),
    ]
    .concat();
    assert!(
        matches(&bad_charset_beamer).is_empty(),
        "beamer bad charset"
    );
    // OnePassword base64 body with a `.` in the body stops the match before
    // 60 chars.
    let one_password_bad = [
        b"ops_eyJ".as_slice(),
        b"a".repeat(30).as_slice(),
        b".".as_slice(),
        b"b".repeat(30).as_slice(),
    ]
    .concat();
    assert!(
        matches(&one_password_bad).is_empty(),
        "onepassword dot in body"
    );
}

#[test]
fn batch5_buildkite_docker_contentful_adafruit_families_promote_on_disabled_siblings() {
    // Mirrors the batch-4 flyio_token_family test: the earlier rule wins when
    // enabled; disabling the earlier rule promotes the later one; disabling
    // every rule silences the token entirely.
    let bk_token = prefixed(b"bk", b'Z', 20);
    let docker_token = prefixed(b"dckr_pat_", b'Z', 27);
    let buildkite_rules: [RuleId; 10] = [
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
    ];
    // With every rule enabled, the first (BuildkiteUserAccessToken) wins.
    assert_eq!(
        match_at(&bk_token, &[]).unwrap().map(|(id, _)| id),
        Some(RuleId::BuildkiteUserAccessToken),
        "buildkite first",
    );
    // Disabling the first promotes the second.
    assert_eq!(
        match_at(&bk_token, &[RuleId::BuildkiteUserAccessToken])
            .unwrap()
            .map(|(id, _)| id),
        Some(RuleId::BuildkiteAgentAccessToken),
        "buildkite promoted",
    );
    // Disabling the first three promotes the fourth.
    assert_eq!(
        match_at(
            &bk_token,
            &[
                RuleId::BuildkiteUserAccessToken,
                RuleId::BuildkiteAgentAccessToken,
                RuleId::BuildkiteAgentJobToken,
            ],
        )
        .unwrap()
        .map(|(id, _)| id),
        Some(RuleId::BuildkiteAgentRegistrationToken),
        "buildkite promotion",
    );
    // Disabling every Buildkite rule silences the token entirely.
    assert_eq!(
        match_at(&bk_token, &buildkite_rules).unwrap(),
        None,
        "buildkite all disabled"
    );
    // Docker: personal listed first, organization second. Disabling personal
    // promotes organization.
    assert_eq!(
        match_at(&docker_token, &[]).unwrap().map(|(id, _)| id),
        Some(RuleId::DockerPersonalPat),
        "docker personal first",
    );
    assert_eq!(
        match_at(&docker_token, &[RuleId::DockerPersonalPat])
            .unwrap()
            .map(|(id, _)| id),
        Some(RuleId::DockerOrganizationPat),
        "docker organization promoted",
    );
    assert_eq!(
        match_at(
            &docker_token,
            &[RuleId::DockerPersonalPat, RuleId::DockerOrganizationPat],
        )
        .unwrap(),
        None,
        "docker all disabled",
    );
    // Single-family rules: disabling the rule silences it (no sibling to
    // promote to).
    let cfpat = prefixed(b"CFPAT-", b'Z', 43);
    let aio = prefixed(b"aio_", b'Z', 20);
    let ccdb = prefixed(b"ccdb_", b'Z', 16);
    let beam = prefixed(b"b_", b'a', 44);
    let opst = prefixed(b"ops_eyJ", b'Z', 65);
    let cds = prefixed(b"ApiKey-v1 gcntfy", b'Z', 12);
    let singletons: [(&[u8], RuleId); 6] = [
        (&cfpat, RuleId::ContentfulPat),
        (&aio, RuleId::AdafruitIoKey),
        (&ccdb, RuleId::CcdbApiKey),
        (&beam, RuleId::BeamerApiKey),
        (&opst, RuleId::OnePasswordServiceAccountToken),
        (&cds, RuleId::CdsCanadaNotifyApiKey),
    ];
    for (token, rule) in singletons {
        assert_eq!(
            match_at(token, &[]).unwrap().map(|(id, _)| id),
            Some(rule),
            "{rule:?} enabled",
        );
        assert_ne!(
            match_at(token, &[rule]).unwrap().map(|(id, _)| id),
            Some(rule),
            "{rule:?} disabled",
        );
    }
}

#[test]
fn batch5_families_survive_stream_splits() {
    let registry = &crate::rules::BUILTINS;
    let opst = prefixed(b"ops_eyJ", b'Z', 65);
    let beam = prefixed(b"b_", b'a', 44);
    let aio = prefixed(b"aio_", b'Z', 20);
    let ccdb = prefixed(b"ccdb_", b'Z', 16);
    let cds = prefixed(b"ApiKey-v1 gcntfy", b'Z', 12);
    let cfpat = prefixed(b"CFPAT-", b'Z', 43);
    let dpat = prefixed(b"dckr_pat_", b'Z', 27);
    let bkt = prefixed(b"bk", b'Z', 20);
    let tokens: [(&[u8], RuleId); 8] = [
        (&opst, RuleId::OnePasswordServiceAccountToken),
        (&beam, RuleId::BeamerApiKey),
        (&aio, RuleId::AdafruitIoKey),
        (&ccdb, RuleId::CcdbApiKey),
        (&cds, RuleId::CdsCanadaNotifyApiKey),
        (&cfpat, RuleId::ContentfulPat),
        (&dpat, RuleId::DockerPersonalPat),
        (&bkt, RuleId::BuildkiteUserAccessToken),
    ];
    for (token, _) in tokens {
        let expected = complete_provider_matches(token, registry).unwrap();
        assert_eq!(expected.len(), 1, "batch-5 single candidate");
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

// Batch 8: Polar prefix family and Azure structural keyword-gated family.
#[test]
fn batch8_polar_families_accept_documented_shapes_only() {
    let polar_rules: [RuleId; 8] = [
        RuleId::PolarPersonalAccessToken,
        RuleId::PolarAccessToken,
        RuleId::PolarRefreshToken,
        RuleId::PolarAuthorizationCode,
        RuleId::PolarClientRegistrationToken,
        RuleId::PolarClientSecret,
        RuleId::PolarCustomerSessionToken,
        RuleId::PolarUserSessionToken,
    ];
    // The bare `polar_ VALUE` form (no assignment) is the positive fixture.
    let token = prefixed(b"polar_", b'Z', 16);
    assert_eq!(
        match_at(&token, &[]).unwrap().map(|(id, _)| id),
        Some(polar_rules[0]),
        "polar first-listed wins",
    );
    // Disabling earlier siblings promotes the next rule of the family.
    for index in 1..polar_rules.len() {
        let disabled = polar_rules[..index].to_vec();
        assert_eq!(
            match_at(&token, &disabled).unwrap().map(|(id, _)| id),
            Some(polar_rules[index]),
            "polar promotion at {index}",
        );
    }
    // Disabling the whole family silences the token.
    assert_eq!(
        match_at(&token, &polar_rules).unwrap(),
        None,
        "polar all disabled"
    );
    for rule in polar_rules {
        let metadata = rule.metadata();
        assert!(metadata.id.starts_with("polar-"), "{rule:?} id");
        assert!(!metadata.description.is_empty(), "{rule:?} description");
        assert_eq!(metadata.severity, Severity::High, "{rule:?} severity");
        assert_eq!(
            metadata.confidence,
            Confidence::Medium,
            "{rule:?} confidence"
        );
        assert_eq!(
            metadata.reference, "https://docs.polar.sh/",
            "{rule:?} reference"
        );
    }
}

#[test]
fn batch8_polar_families_reject_short_and_punctuated_bodies() {
    // Body below the 16-byte minimum stays quiet...
    let short = prefixed(b"polar_", b'Z', 15);
    assert!(matches(&short).is_empty(), "polar body 15");
    // ...and 16 is the accepted boundary.
    let boundary = prefixed(b"polar_", b'Z', 16);
    assert_eq!(
        matches(&boundary),
        vec![(RuleId::PolarPersonalAccessToken, 0..boundary.len())],
        "polar body 16",
    );
    // Dotted bodies are module paths, not standalone keys.
    let dotted = b"polar_synthetic.short.body_extension";
    assert!(matches(dotted).is_empty(), "polar dotted body");
    // Multi-underscore bodies belong to larger identifiers.
    let underscored = b"polar_synthetic_body_value_extension";
    assert!(
        matches(underscored).is_empty(),
        "polar multi-underscore body"
    );
}

type AzureGatedCase = (Vec<u8>, Vec<u8>, Vec<RuleId>, RuleId);

fn azure_structural_fixtures() -> Vec<AzureGatedCase> {
    // All bodies are synthetic fixtures, never vendor-real shapes.
    let devops = [
        b"a".repeat(76).as_slice(),
        b"AZDO".as_slice(),
        b"e5f6".as_slice(),
    ]
    .concat();
    assert_eq!(devops.len(), 84, "devops body length");
    let function_key = [
        b"a9+z/".repeat(10).as_slice(),
        b"a2".as_slice(),
        b"==".as_slice(),
    ]
    .concat();
    assert_eq!(function_key.len(), 54, "function key length");
    let storage = [b"A".repeat(85).as_slice(), b"=".as_slice()].concat();
    assert_eq!(storage.len(), 86, "storage key length");
    let hex_value = b"abcdef0123456789abcdef0123456789".to_vec();
    assert_eq!(hex_value.len(), 32, "hex key length");
    let ai_services = b"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW".to_vec();
    assert_eq!(ai_services.len(), 32, "ai services key length");
    let redis = [
        b"aB3dE5".repeat(7).as_slice(),
        b"Fg".as_slice(),
        b"==".as_slice(),
    ]
    .concat();
    assert_eq!(redis.len(), 46, "cache for redis key length");
    let application_secret = [
        b"abc1Q~".as_slice(),
        b"SyntheticAdApplicationSecret012".as_slice(),
    ]
    .concat();
    assert_eq!(application_secret.len(), 37, "application secret length");
    vec![
        (
            [b"azure ".as_slice(), devops.as_slice()].concat(),
            devops,
            vec![],
            RuleId::AzureDevopsPersonalAccessToken,
        ),
        (
            [b"azure ".as_slice(), function_key.as_slice()].concat(),
            function_key,
            vec![],
            RuleId::AzureFunctionKey,
        ),
        (
            [b"azure ".as_slice(), storage.as_slice()].concat(),
            storage,
            vec![],
            RuleId::AzureStorageAccountKey,
        ),
        (
            [b"azure ".as_slice(), hex_value.clone().as_slice()].concat(),
            hex_value.clone(),
            vec![],
            RuleId::AzureCognitiveServicesKey,
        ),
        (
            [b"azure ".as_slice(), hex_value.clone().as_slice()].concat(),
            hex_value.clone(),
            vec![RuleId::AzureCognitiveServicesKey],
            RuleId::AzureComputerVisionKey,
        ),
        (
            [b"azure ".as_slice(), ai_services.as_slice()].concat(),
            ai_services,
            vec![],
            RuleId::AzureAiServicesKey,
        ),
        (
            [b"azure ".as_slice(), redis.as_slice()].concat(),
            redis,
            vec![],
            RuleId::AzureCacheForRedisAccessKey,
        ),
        (
            [b"azure ".as_slice(), application_secret.as_slice()].concat(),
            application_secret,
            vec![],
            RuleId::AzureActiveDirectoryApplicationSecret,
        ),
    ]
}

#[test]
fn batch8_azure_structural_families_require_keyword_and_documented_shapes() {
    for (input, value, disabled, expected) in azure_structural_fixtures() {
        let mut found = Vec::<(RuleId, Range<usize>)>::new();
        detect_line_with_disabled(&input, &disabled, |id, span| found.push((id, span))).unwrap();
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(
            !metadata.id.starts_with("azure.") && metadata.id.starts_with("azure-"),
            "{expected:?} id"
        );
        assert_eq!(metadata.severity, Severity::High, "{expected:?} severity");
        assert_eq!(
            metadata.confidence,
            Confidence::Medium,
            "{expected:?} confidence"
        );
        assert_eq!(
            metadata.reference, "https://learn.microsoft.com/azure/",
            "{expected:?} reference"
        );
    }
    // Without the `azure` keyword in the context window the shape stays quiet.
    let hex_value = azure_structural_fixtures()[3].1.clone();
    let no_keyword = [b"contoso ".as_slice(), hex_value.as_slice()].concat();
    assert!(matches(&no_keyword).is_empty(), "azure keyword required");
    // The keyword must sit inside the 200-byte context window.
    let far = [
        b"azure".as_slice(),
        b"z".repeat(197).as_slice(),
        b" ".as_slice(),
        hex_value.as_slice(),
    ]
    .concat();
    assert!(
        matches(&far).is_empty(),
        "azure keyword outside the context window"
    );
}

#[test]
fn batch8_azure_structural_rules_silence_when_disabled() {
    for (input, _, _, expected) in azure_structural_fixtures() {
        // Disabling the matching rule silences it (a later shared-shape rule
        // may promote, but the disabled rule never reports).
        let mut found = Vec::<(RuleId, Range<usize>)>::new();
        detect_line_with_disabled(&input, &[expected], |id, span| found.push((id, span))).unwrap();
        assert!(
            found.iter().all(|(id, _)| *id != expected),
            "{expected:?} disabled still reported",
        );
    }
    // The 32-hex shape is shared by cognitive, computer vision, and AI
    // services: disabling the earlier rules promotes the later ones.
    let hex_value = azure_structural_fixtures()[3].1.clone();
    let hex_input = [b"azure ".as_slice(), hex_value.as_slice()].concat();
    assert_eq!(
        matches(&hex_input),
        vec![(
            RuleId::AzureCognitiveServicesKey,
            hex_input.len() - hex_value.len()..hex_input.len(),
        )],
        "hex shape wins with cognitive",
    );
    let mut promoted = Vec::<(RuleId, Range<usize>)>::new();
    detect_line_with_disabled(
        &hex_input,
        &[
            RuleId::AzureCognitiveServicesKey,
            RuleId::AzureComputerVisionKey,
        ],
        |id, span| promoted.push((id, span)),
    )
    .unwrap();
    assert_eq!(
        promoted,
        vec![(
            RuleId::AzureAiServicesKey,
            hex_input.len() - hex_value.len()..hex_input.len(),
        )],
        "hex shape promotes ai-services",
    );
    let mut silenced = Vec::<(RuleId, Range<usize>)>::new();
    // The generic `azure` keyword family now catches shapes the structural
    // rules miss, so silencing the fixture means disabling the whole family.
    let all_azure_rules = [
        azure_structural_rules().to_vec(),
        azure_generic_rules().to_vec(),
    ]
    .concat();
    detect_line_with_disabled(&hex_input, &all_azure_rules, |id, span| {
        silenced.push((id, span))
    })
    .unwrap();
    assert!(silenced.is_empty(), "azure family all disabled");
}

fn azure_structural_rules() -> [RuleId; 8] {
    [
        RuleId::AzureDevopsPersonalAccessToken,
        RuleId::AzureFunctionKey,
        RuleId::AzureStorageAccountKey,
        RuleId::AzureCognitiveServicesKey,
        RuleId::AzureComputerVisionKey,
        RuleId::AzureAiServicesKey,
        RuleId::AzureCacheForRedisAccessKey,
        RuleId::AzureActiveDirectoryApplicationSecret,
    ]
}

#[test]
fn batch8_azure_validators_enforce_lengths_and_markers() {
    // DevOps: the AZDO signature must sit at relative offsets 76..80.
    let misplaced = [
        b"b".repeat(70).as_slice(),
        b"AZDO".as_slice(),
        b"c".repeat(10).as_slice(),
    ]
    .concat();
    assert_eq!(azure_devops_pat_match(&misplaced), None, "AZDO at 70");
    let short_run = [
        b"b".repeat(75).as_slice(),
        b"AZDO".as_slice(),
        b"c".repeat(4).as_slice(),
    ]
    .concat();
    assert_eq!(azure_devops_pat_match(&short_run), None, "83-byte run");
    let long_run = [
        b"b".repeat(76).as_slice(),
        b"AZDO".as_slice(),
        b"c".repeat(5).as_slice(),
    ]
    .concat();
    assert_eq!(azure_devops_pat_match(&long_run), None, "85-byte run");
    // Function keys keep the `==` padding at the very end of 54 bytes.
    let short_fn = [b"a9+z/".repeat(10).as_slice(), b"==".as_slice()].concat();
    assert_eq!(
        azure_function_key_match(&short_fn),
        None,
        "52-byte function key"
    );
    let long_fn = [
        b"a9+z/".repeat(11).as_slice(),
        b"a2".as_slice(),
        b"==".as_slice(),
    ]
    .concat();
    assert_eq!(
        azure_function_key_match(&long_fn),
        None,
        "57-byte function key"
    );
    let bad_padding = [b"a".repeat(52).as_slice(), b"=".as_slice(), b"z".as_slice()].concat();
    assert_eq!(
        azure_function_key_match(&bad_padding),
        None,
        "function key without == tail"
    );
    let upper_body = [
        b"a".repeat(51).as_slice(),
        b"A".as_slice(),
        b"==".as_slice(),
    ]
    .concat();
    assert_eq!(
        azure_function_key_match(&upper_body),
        None,
        "function key uppercase body"
    );
    // Storage keys are exactly 86 bytes.
    let storage_short = [b"A".repeat(84).as_slice(), b"=".as_slice()].concat();
    assert_eq!(
        azure_storage_account_key_match(&storage_short),
        None,
        "85-byte storage key"
    );
    let storage_long = [b"A".repeat(86).as_slice(), b"=".as_slice()].concat();
    assert_eq!(
        azure_storage_account_key_match(&storage_long),
        None,
        "87-byte storage key"
    );
    // Hex keys are exactly 32 lowercase hex bytes.
    assert_eq!(
        azure_hex32_match(b"abcdef0123456789abcdef012345678"),
        None,
        "31 hex run"
    );
    assert_eq!(
        azure_hex32_match(b"abcdef0123456789abcdef01234567890"),
        None,
        "33 hex run"
    );
    let non_hex = [b"a".repeat(31).as_slice(), b"g".as_slice()].concat();
    assert_eq!(azure_hex32_match(&non_hex), None, "non-hex byte in hex run");
    // AI services keys are exactly 32 alphanumeric bytes.
    assert_eq!(
        azure_ai_services_key_match(b"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"),
        None,
        "31 alnum run"
    );
    assert_eq!(
        azure_ai_services_key_match(b"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vWx"),
        None,
        "33 alnum run"
    );
    // Cache-for-Redis keys are 32..256 base64 bytes with at most two `=`.
    let short_b64 = [b"aB3dE5".repeat(5).as_slice(), b"a".as_slice()].concat();
    assert_eq!(
        azure_redis_access_key_match(&short_b64),
        None,
        "31-byte base64 run"
    );
    let long_b64 = b"a".repeat(257);
    assert_eq!(
        azure_redis_access_key_match(&long_b64),
        None,
        "257-byte base64 run"
    );
    let over_padded = [
        b"aB3dE5".repeat(7).as_slice(),
        b"Fg".as_slice(),
        b"===".as_slice(),
    ]
    .concat();
    assert_eq!(
        azure_redis_access_key_match(&over_padded),
        None,
        "three-byte padding tail"
    );
    // Application secrets keep the `Q~` marker at offset 4 with a digit lead.
    let secret_short = [b"abc1Q~".as_slice(), b"a".repeat(29).as_slice()].concat();
    assert_eq!(
        azure_ad_application_secret_match(&secret_short),
        None,
        "35-byte secret"
    );
    let secret_long = [b"abc1Q~".as_slice(), b"a".repeat(33).as_slice()].concat();
    assert_eq!(
        azure_ad_application_secret_match(&secret_long),
        None,
        "39-byte secret"
    );
    let late_marker = [b"abc12Q~".as_slice(), b"a".repeat(30).as_slice()].concat();
    assert_eq!(
        azure_ad_application_secret_match(&late_marker),
        None,
        "Q~ marker late"
    );
    let early_marker = [b"abQ~c".as_slice(), b"a".repeat(32).as_slice()].concat();
    assert_eq!(
        azure_ad_application_secret_match(&early_marker),
        None,
        "Q~ marker early"
    );
    let digit_absent = [b"abcxQ~".as_slice(), b"a".repeat(31).as_slice()].concat();
    assert_eq!(
        azure_ad_application_secret_match(&digit_absent),
        None,
        "no digit before Q~"
    );
}

#[test]
fn batch8_polar_family_survives_stream_splits() {
    let registry = &crate::rules::BUILTINS;
    let polar = prefixed(b"polar_", b'Z', 16);
    let tokens: [(&[u8], RuleId); 1] = [(&polar, RuleId::PolarPersonalAccessToken)];
    for (line, expected_rule) in tokens {
        let expected = complete_provider_matches(line, registry).unwrap();
        assert_eq!(expected.len(), 1, "batch-8 single candidate");
        assert_eq!(expected[0].0, expected_rule, "batch-8 rule");
        for split in 0..=line.len() {
            let mut state = ProviderState::new();
            let mut actual = Vec::<(RuleId, Range<u64>, Vec<u8>)>::new();
            for fragment in [&line[..split], &line[split..]] {
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
            assert_eq!(actual, expected, "split {split} in {line:?}");
        }
        assert_eq!(
            streamed(line, 1, registry).unwrap(),
            expected,
            "streamed byte-by-byte"
        );
    }
}

// Batch 9: the generic `azure` keyword family, 64 rules across four batches,
// every variant sharing the generic keyword gate (`azure` within 200 bytes
// before a 20-byte word run), so the dispatch order decides which sibling
// wins and disabling siblings has to promote the next one.
fn azure_generic_rules() -> [RuleId; 66] {
    [
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
        RuleId::AzureLuisAuthoringKey,
        RuleId::AzureLuisKey,
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
        RuleId::AzureLogicAppsUrl,
        RuleId::AzureManagementCertificate,
    ]
}

#[test]
fn azure_part5_fixtures_catalog_rows() {
    // Fixture shapes for the two part-5 rows only assert metadata presence;
    // the matching behaviour is exercised by the dedicated part-5 tests.
    for (input, value, expected) in azure_part5_fixtures().iter() {
        assert!(input.last() == value.last(), "fixture ends with its value");
        assert_eq!(
            input.len() - value.len(),
            b"azure ".len(),
            "keyword prefix only"
        );
        assert!(expected.metadata().id.contains("azure"), "{expected:?}");
    }
}

fn azure_part5_fixtures() -> Vec<(Vec<u8>, Vec<u8>, RuleId)> {
    vec![
        (
            b"azure AzureFakeLogicAppsUrl01".to_vec(),
            b"AzureFakeLogicAppsUrl01".to_vec(),
            RuleId::AzureLogicAppsUrl,
        ),
        (
            b"azure AzureFakeManagementCert01".to_vec(),
            b"AzureFakeManagementCert01".to_vec(),
            RuleId::AzureManagementCertificate,
        ),
    ]
}

fn adobe_keyword_rules() -> [RuleId; 5] {
    [
        RuleId::AdobeDeviceToken,
        RuleId::AdobePacToken,
        RuleId::AdobeRefreshToken,
        RuleId::AdobeServiceToken,
        RuleId::AdobeShortLivedAccessToken,
    ]
}

fn adobe_keyword_fixtures() -> Vec<(Vec<u8>, Vec<u8>, RuleId)> {
    vec![
        (
            b"adobe AdobeFakeDeviceToken01".to_vec(),
            b"AdobeFakeDeviceToken01".to_vec(),
            RuleId::AdobeDeviceToken,
        ),
        (
            b"adobe AdobeFakePacToken0001".to_vec(),
            b"AdobeFakePacToken0001".to_vec(),
            RuleId::AdobePacToken,
        ),
        (
            b"adobe AdobeFakeRefreshToken01".to_vec(),
            b"AdobeFakeRefreshToken01".to_vec(),
            RuleId::AdobeRefreshToken,
        ),
        (
            b"adobe AdobeFakeServiceToken01".to_vec(),
            b"AdobeFakeServiceToken01".to_vec(),
            RuleId::AdobeServiceToken,
        ),
        (
            b"adobe AdobeFakeShortLived01".to_vec(),
            b"AdobeFakeShortLived01".to_vec(),
            RuleId::AdobeShortLivedAccessToken,
        ),
    ]
}

fn matches_with_disabled(bytes: &[u8], disabled: &[RuleId]) -> Vec<(RuleId, Range<usize>)> {
    let mut found = Vec::new();
    detect_line_with_disabled(bytes, disabled, |rule, span| found.push((rule, span))).unwrap();
    found
}

#[test]
fn azure_keyword_families_require_keyword_context() {
    // Each variant fires on a bare `azure <value>` fixture (or an azure-bearing
    // key name) once every earlier sibling sharing the keyword is disabled.
    let fixtures: Vec<(Vec<u8>, Vec<u8>, RuleId)> = vec![
        (
            b"azure_anomaly_detector_key AzureFakeAnomalyValue01".to_vec(),
            b"AzureFakeAnomalyValue01".to_vec(),
            RuleId::AzureAnomalyDetectorKey,
        ),
        (
            b"azure_anomaly_ee_key AzureFakeAnomalyEeValue1".to_vec(),
            b"AzureFakeAnomalyEeValue1".to_vec(),
            RuleId::AzureAnomalyDetectorEeKey,
        ),
        (
            b"azure AzureFakeApimDirectValue1".to_vec(),
            b"AzureFakeApimDirectValue1".to_vec(),
            RuleId::AzureApimDirectManagementKey,
        ),
        (
            b"azure_apim_gateway_key AzureFakeApimGateway01".to_vec(),
            b"AzureFakeApimGateway01".to_vec(),
            RuleId::AzureApimGatewayKey,
        ),
        (
            b"azure AzureFakeApimRepoValue1".to_vec(),
            b"AzureFakeApimRepoValue1".to_vec(),
            RuleId::AzureApimRepositoryKey,
        ),
        (
            b"azure_apim_subscription_key AzureFakeApimSubValue01".to_vec(),
            b"AzureFakeApimSubValue01".to_vec(),
            RuleId::AzureApimSubscriptionKey,
        ),
        (
            b"azure_app_configuration_key AzureFakeAppConfigKey01".to_vec(),
            b"AzureFakeAppConfigKey01".to_vec(),
            RuleId::AzureAppConfigurationKey,
        ),
        (
            b"azure AzureFakeAppConfigConn1".to_vec(),
            b"AzureFakeAppConfigConn1".to_vec(),
            RuleId::AzureAppConfigurationConnectionString,
        ),
        (
            b"azure_batch_key AzureFakeBatchValue012".to_vec(),
            b"AzureFakeBatchValue012".to_vec(),
            RuleId::AzureBatchKeyIdentifiable,
        ),
        (
            b"azure AzureFakeCommsValue01".to_vec(),
            b"AzureFakeCommsValue01".to_vec(),
            RuleId::AzureCommunicationServicesKey,
        ),
        (
            b"azure_communication_connection_key AzureFakeCommsConnValue1".to_vec(),
            b"AzureFakeCommsConnValue1".to_vec(),
            RuleId::AzureCommunicationServicesConnectionString,
        ),
        (
            b"azure_container_registry_key AzureFakeContainerKey01".to_vec(),
            b"AzureFakeContainerKey01".to_vec(),
            RuleId::AzureContainerRegistryKeyIdentifiable,
        ),
        (
            b"azure AzureFakeModeratorKey1".to_vec(),
            b"AzureFakeModeratorKey1".to_vec(),
            RuleId::AzureContentModeratorKey,
        ),
        (
            b"azure_content_safety_key AzureFakeSafetyKeyValue".to_vec(),
            b"AzureFakeSafetyKeyValue".to_vec(),
            RuleId::AzureContentSafetyKey,
        ),
        (
            b"azure_cosmosdb_key AzureFakeCosmosdbKey01".to_vec(),
            b"AzureFakeCosmosdbKey01".to_vec(),
            RuleId::AzureCosmosdbKeyIdentifiable,
        ),
        (
            b"azure_custom_vision_prediction_key AzureFakeVisionPredict01".to_vec(),
            b"AzureFakeVisionPredict01".to_vec(),
            RuleId::AzureCustomVisionPredictionKey,
        ),
        (
            b"azure AzureFakeVisionTrainKey1".to_vec(),
            b"AzureFakeVisionTrainKey1".to_vec(),
            RuleId::AzureCustomVisionTrainingKey,
        ),
    ];
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in fixtures.iter().enumerate() {
        // Every earlier sibling sharing the `azure` keyword must stay quiet.
        let disabled = generic[..index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn azure_keyword_families_respect_length_and_context_windows() {
    // Exactly the 20-byte minimum fires...
    let boundary = b"azure AzureFakeBoundary012";
    let value = b"AzureFakeBoundary012";
    assert_eq!(
        matches(boundary),
        vec![(
            RuleId::AzureAnomalyDetectorKey,
            boundary.len() - value.len()..boundary.len(),
        )]
    );
    // ...one byte short does not, and neither does a long value with no keyword.
    for negative in [
        b"azure AzureFakeBoundary01".as_slice(),
        b"contoso AzureFakeBoundary012345678",
    ] {
        assert!(
            matches(negative).is_empty(),
            "azure-gated negative {negative:?}"
        );
    }
    // The keyword has to sit inside the 200-byte window before the value.
    let near = b"z".repeat(194);
    let in_window = [
        b"azure".as_slice(),
        near.as_slice(),
        b" ".as_slice(),
        b"AzureFakeWindowValue01".as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&in_window),
        vec![(RuleId::AzureAnomalyDetectorKey, 200..222)]
    );
    let far = b"z".repeat(197);
    let out_of_window = [
        b"azure".as_slice(),
        far.as_slice(),
        b" ".as_slice(),
        b"AzureFakeWindowValue01".as_slice(),
    ]
    .concat();
    assert!(
        matches(&out_of_window).is_empty(),
        "azure keyword outside the window"
    );
}

#[test]
fn azure_keyword_families_stop_after_the_first_keyword_match() {
    // Disabling the earlier rule of the shared `azure` keyword promotes the next
    // one, and disabling every generic Azure rule leaves no finding at all.
    let input = b"azure AzureFakePromotionValue1";
    let expected = vec![(RuleId::AzureAnomalyDetectorKey, 6..30)];
    assert_eq!(matches(input), expected, "first azure sibling wins");
    let promoted = matches_with_disabled(input, &[RuleId::AzureAnomalyDetectorKey]);
    assert_eq!(
        promoted,
        vec![(RuleId::AzureAnomalyDetectorEeKey, 6..30)],
        "promotion"
    );
    let all_generic = azure_generic_rules().to_vec();
    let silenced = matches_with_disabled(input, &all_generic);
    assert!(silenced.is_empty(), "all azure-gated rules disabled");
}

// Batch 9 part 2: the second wave of generic `azure` keyword rules. Every new
// variant shares part 1's keyword gate, so the promotion chain spans the whole
// 34-rule family: all 17 part-1 rules sit in front of each part-2 fixture.
fn azure_part2_fixtures() -> Vec<(Vec<u8>, Vec<u8>, RuleId)> {
    vec![
        (
            b"azure_event_grid_key AzureFakeEventGridValue1".to_vec(),
            b"AzureFakeEventGridValue1".to_vec(),
            RuleId::AzureEventGridKeyIdentifiable,
        ),
        (
            b"azure_event_hub_key AzureFakeEventHubValue1".to_vec(),
            b"AzureFakeEventHubValue1".to_vec(),
            RuleId::AzureEventHubKeyIdentifiable,
        ),
        (
            b"azure_face_key AzureFakeFaceKeyValue01".to_vec(),
            b"AzureFakeFaceKeyValue01".to_vec(),
            RuleId::AzureFaceKey,
        ),
        (
            b"azure AzureFakeFluidRelayValue1".to_vec(),
            b"AzureFakeFluidRelayValue1".to_vec(),
            RuleId::AzureFluidRelayKey,
        ),
        (
            b"azure_form_recognizer_key AzureFakeFormRecognValue1".to_vec(),
            b"AzureFakeFormRecognValue1".to_vec(),
            RuleId::AzureFormRecognizerKey,
        ),
        (
            b"azure AzureFakeHealthDecValue1".to_vec(),
            b"AzureFakeHealthDecValue1".to_vec(),
            RuleId::AzureHealthDecisionSupportKey,
        ),
        (
            b"azure_health_insights_key AzureFakeInsightsKey01".to_vec(),
            b"AzureFakeInsightsKey01".to_vec(),
            RuleId::AzureHealthInsightsKey,
        ),
        (
            b"azure AzureFakeImmersiveValue1".to_vec(),
            b"AzureFakeImmersiveValue1".to_vec(),
            RuleId::AzureImmersiveReaderKey,
        ),
        (
            b"azure_internal_all_in_one_key AzureFakeInternalValue01".to_vec(),
            b"AzureFakeInternalValue01".to_vec(),
            RuleId::AzureInternalAllInOneKey,
        ),
        (
            b"azure AzureFakeIotConnValue1".to_vec(),
            b"AzureFakeIotConnValue1".to_vec(),
            RuleId::AzureIotDeviceConnectionString,
        ),
        (
            b"azure_iot_device_key AzureFakeIotDevKey01".to_vec(),
            b"AzureFakeIotDevKey01".to_vec(),
            RuleId::AzureIotDeviceKey,
        ),
        (
            b"azure AzureFakeIotProvValue1".to_vec(),
            b"AzureFakeIotProvValue1".to_vec(),
            RuleId::AzureIotDeviceProvisioningKey,
        ),
        (
            b"azure_iot_hub_connection_key AzureFakeIotHubConnValue1".to_vec(),
            b"AzureFakeIotHubConnValue1".to_vec(),
            RuleId::AzureIotHubConnectionString,
        ),
        (
            b"azure AzureFakeIotHubKey01".to_vec(),
            b"AzureFakeIotHubKey01".to_vec(),
            RuleId::AzureIotHubKey,
        ),
        (
            b"azure AzureFakeIotProvisionValue1".to_vec(),
            b"AzureFakeIotProvisionValue1".to_vec(),
            RuleId::AzureIotProvisioningConnectionString,
        ),
        (
            b"azure_knowledge_key AzureFakeKnowledgeKey1".to_vec(),
            b"AzureFakeKnowledgeKey1".to_vec(),
            RuleId::AzureKnowledgeKey,
        ),
        (
            b"azure_luis_authoring_key AzureFakeLuisAuthoring1".to_vec(),
            b"AzureFakeLuisAuthoring1".to_vec(),
            RuleId::AzureLuisAuthoringKey,
        ),
    ]
}

#[test]
fn azure_keyword_families_part2_require_keyword_context() {
    // Each part-2 variant fires once every earlier family sibling (the whole
    // part-1 head plus its part-2 predecessors) stays quiet.
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part2_fixtures().iter().enumerate() {
        let disabled = generic[..17 + index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}",
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn azure_keyword_families_part2_promotion_chain() {
    // The chain spans the whole generic azure family: each step disables one
    // more sibling and promotes the next rule, from the part-1 head through
    // the part-4 tail (64 steps now), and disabling all rules leaves no
    // finding at all.
    let input = b"azure AzureFakeWholeChainValue1";
    let value_len = b"AzureFakeWholeChainValue1".len();
    let generic = azure_generic_rules();
    for index in 0..generic.len() {
        let disabled = generic[..index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let expected = generic[index];
        assert_eq!(
            found,
            vec![(expected, (input.len() - value_len)..input.len())],
            "chain step {index} promotes {expected:?}"
        );
    }
    let silenced = matches_with_disabled(input, &generic);
    assert!(silenced.is_empty(), "whole generic azure family disabled");
}

#[test]
fn azure_keyword_families_part2_silence_when_disabled() {
    // Per-rule behavior: each part-2 fixture fires when only its earlier
    // siblings are disabled, and disabling the rule itself silences it while
    // a later sibling (if any) promotes.
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part2_fixtures().iter().enumerate() {
        let start = input.len() - value.len();
        let fired = matches_with_disabled(input, &generic[..17 + index]);
        assert_eq!(
            fired,
            vec![(*expected, start..start + value.len())],
            "{expected:?} fires when enabled",
        );
        let found = matches_with_disabled(input, &generic[..17 + index + 1]);
        assert!(
            found.iter().all(|(id, _)| *id != *expected),
            "{expected:?} disabled still reported",
        );
        // A part-2 rule always has a successor now: the next part-2 rule, or
        // the part-3 head once the whole part-2 wave is disabled.
        assert_eq!(found.len(), 1, "next azure sibling promotes");
    }
}

#[test]
fn azure_keyword_families_part2_boundary() {
    // A new rule also sits exactly at the 20-byte word-run minimum: with the
    // part-1 head disabled, the boundary fixture promotes the part-2 head...
    let part1 = azure_generic_rules()[..17].to_vec();
    let boundary = b"azure AzureFakeBoundary012";
    let value = b"AzureFakeBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &part1),
        vec![(
            RuleId::AzureEventGridKeyIdentifiable,
            boundary.len() - value.len()..boundary.len()
        )],
        "20-byte boundary promotes the part-2 head",
    );
    // ...and one byte short stays quiet even for the new rules.
    let short = b"azure AzureFakeBoundary01";
    assert!(
        matches_with_disabled(short, &part1).is_empty(),
        "19-byte value stays quiet",
    );
}

// Batch 9 part 3: the third wave of generic `azure` keyword rules. Every new
// variant shares the family's keyword gate, so the promotion chain spans the
// whole 64-rule family: all 34 part-1+part-2 rules sit in front of each part-3
// fixture.
fn azure_part3_fixtures() -> Vec<(Vec<u8>, Vec<u8>, RuleId)> {
    vec![
        (
            b"azure_luis_key AzureFakeLuisKeyValue01".to_vec(),
            b"AzureFakeLuisKeyValue01".to_vec(),
            RuleId::AzureLuisKey,
        ),
        (
            b"azure_maps_key AzureFakeMapsKeyValue01".to_vec(),
            b"AzureFakeMapsKeyValue01".to_vec(),
            RuleId::AzureMapsKey,
        ),
        (
            b"azure AzureFakeMetricsAdvValue1".to_vec(),
            b"AzureFakeMetricsAdvValue1".to_vec(),
            RuleId::AzureMetricsAdvisorKey,
        ),
        (
            b"azure_mixed_reality_key AzureFakeMixedReality01".to_vec(),
            b"AzureFakeMixedReality01".to_vec(),
            RuleId::AzureMixedRealityKey,
        ),
        (
            b"azure_ml_inference_key AzureFakeMlInferValue01".to_vec(),
            b"AzureFakeMlInferValue01".to_vec(),
            RuleId::AzureMlInferenceIdentifiableKey,
        ),
        (
            b"azure AzureFakeMlInternalValue1".to_vec(),
            b"AzureFakeMlInternalValue1".to_vec(),
            RuleId::AzureMlInternalServicePrincipalIdentifiableKey,
        ),
        (
            b"azure_ml_web_classic_key AzureFakeMlWebClassValue1".to_vec(),
            b"AzureFakeMlWebClassValue1".to_vec(),
            RuleId::AzureMlWebServiceClassicIdentifiableKey,
        ),
        (
            b"azure_openai_key AzureFakeOpenAIKeyValue1".to_vec(),
            b"AzureFakeOpenAIKeyValue1".to_vec(),
            RuleId::AzureOpenAIKey,
        ),
        (
            b"azure_personalizer_key AzureFakePersonalizerKey1".to_vec(),
            b"AzureFakePersonalizerKey1".to_vec(),
            RuleId::AzurePersonalizerKey,
        ),
        (
            b"azure_qna_maker_key AzureFakeQnaMakerValue1".to_vec(),
            b"AzureFakeQnaMakerValue1".to_vec(),
            RuleId::AzureQnaMakerKey,
        ),
        (
            b"azure_qna_maker_v2_key AzureFakeQnaMakerV2Value1".to_vec(),
            b"AzureFakeQnaMakerV2Value1".to_vec(),
            RuleId::AzureQnaMakerV2Key,
        ),
        (
            b"azure_quantum_key AzureFakeQuantumKeyValue1".to_vec(),
            b"AzureFakeQuantumKeyValue1".to_vec(),
            RuleId::AzureQuantumKey,
        ),
        (
            b"azure AzureFakeRelayKeyValue1".to_vec(),
            b"AzureFakeRelayKeyValue1".to_vec(),
            RuleId::AzureRelayKeyIdentifiable,
        ),
        (
            b"azure AzureFakeSasTokenValue01".to_vec(),
            b"AzureFakeSasTokenValue01".to_vec(),
            RuleId::AzureSasToken,
        ),
        (
            b"azure_search_admin_key AzureFakeSearchAdminValue1".to_vec(),
            b"AzureFakeSearchAdminValue1".to_vec(),
            RuleId::AzureSearchAdminKey,
        ),
        (
            b"azure_search_query_key AzureFakeSearchQueryValue1".to_vec(),
            b"AzureFakeSearchQueryValue1".to_vec(),
            RuleId::AzureSearchQueryKey,
        ),
        (
            b"azure_service_bus_key AzureFakeServiceBusValue1".to_vec(),
            b"AzureFakeServiceBusValue1".to_vec(),
            RuleId::AzureServiceBusIdentifiable,
        ),
    ]
}

#[test]
fn azure_keyword_families_part3_require_keyword_context() {
    // Each part-3 variant fires once every earlier family sibling (the whole
    // 34-rule part-1+part-2 head plus its part-3 predecessors) stays quiet.
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part3_fixtures().iter().enumerate() {
        let disabled = generic[..34 + index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn azure_keyword_families_part3_silence_when_disabled() {
    // Per-rule behavior: each part-3 fixture fires when only its earlier
    // siblings are disabled, and disabling the rule itself silences it while
    // a later sibling promotes.
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part3_fixtures().iter().enumerate() {
        let start = input.len() - value.len();
        let fired = matches_with_disabled(input, &generic[..34 + index]);
        assert_eq!(
            fired,
            vec![(*expected, start..start + value.len())],
            "{expected:?} fires when enabled",
        );
        let found = matches_with_disabled(input, &generic[..34 + index + 1]);
        assert!(
            found.iter().all(|(id, _)| *id != *expected),
            "{expected:?} disabled still reported",
        );
        // A part-3 rule always has a successor now: the next part-3 rule, or
        // the part-4 head once the whole part-3 wave is disabled.
        assert_eq!(found.len(), 1, "next azure sibling promotes");
    }
}

#[test]
fn azure_keyword_families_part3_boundary() {
    // A part-3 rule also sits exactly at the 20-byte word-run minimum: with
    // the part-1+part-2 head disabled, the boundary fixture promotes the part-3
    // head...
    let head = azure_generic_rules()[..34].to_vec();
    let boundary = b"azure AzureFakeBoundary012";
    let value = b"AzureFakeBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &head),
        vec![(
            RuleId::AzureLuisKey,
            boundary.len() - value.len()..boundary.len(),
        ),],
        "20-byte boundary promotes the part-3 head",
    );
    // ...and one byte short stays quiet even for the part-3 rules.
    let short = b"azure AzureFakeBoundary01";
    assert!(
        matches_with_disabled(short, &head).is_empty(),
        "19-byte value stays quiet",
    );
}

// Batch 9 part 4: the fourth wave of generic `azure` keyword rules. Every new
// variant shares the family's keyword gate, so the promotion chain spans the
// whole 64-rule family: all 51 part-1+part-2+part-3 rules sit in front of each
// part-4 fixture.
fn azure_part4_fixtures() -> Vec<(Vec<u8>, Vec<u8>, RuleId)> {
    vec![
        (
            b"azure_signalr_connection_string AzureFakeSignalrConn01".to_vec(),
            b"AzureFakeSignalrConn01".to_vec(),
            RuleId::AzureSignalrConnectionString,
        ),
        (
            b"azure_signalr_key AzureFakeSignalrKey01".to_vec(),
            b"AzureFakeSignalrKey01".to_vec(),
            RuleId::AzureSignalrKey,
        ),
        (
            b"azure AzureFakeSpeechSvcValue1".to_vec(),
            b"AzureFakeSpeechSvcValue1".to_vec(),
            RuleId::AzureSpeechServicesKey,
        ),
        (
            b"azure_speech_translation_key AzureFakeSpeechTrans01".to_vec(),
            b"AzureFakeSpeechTrans01".to_vec(),
            RuleId::AzureSpeechTranslationKey,
        ),
        (
            b"azure AzureFakeCloudSaValue01".to_vec(),
            b"AzureFakeCloudSaValue01".to_vec(),
            RuleId::AzureSqlInternalDefaultCloudSaKey,
        ),
        (
            b"azure_sql_password AzureFakeSqlPassword01".to_vec(),
            b"AzureFakeSqlPassword01".to_vec(),
            RuleId::AzureSqlPassword,
        ),
        (
            b"azure_text_analytics_key AzureFakeTextAnalytics01".to_vec(),
            b"AzureFakeTextAnalytics01".to_vec(),
            RuleId::AzureTextAnalyticsKey,
        ),
        (
            b"azure AzureFakeTextTransValue1".to_vec(),
            b"AzureFakeTextTransValue1".to_vec(),
            RuleId::AzureTextTranslationKey,
        ),
        (
            b"azure_video_intelligence_key AzureFakeVideoIntelValue1".to_vec(),
            b"AzureFakeVideoIntelValue1".to_vec(),
            RuleId::AzureVideoIntelligenceKey,
        ),
        (
            b"azure_web_app_bot_key AzureFakeWebAppBotValue1".to_vec(),
            b"AzureFakeWebAppBotValue1".to_vec(),
            RuleId::AzureWebAppBotKey,
        ),
        (
            b"azure AzureFakePubSubConn01".to_vec(),
            b"AzureFakePubSubConn01".to_vec(),
            RuleId::AzureWebPubSubConnectionString,
        ),
        (
            b"azure_web_pub_sub_key AzureFakePubSubKeyValue1".to_vec(),
            b"AzureFakePubSubKeyValue1".to_vec(),
            RuleId::AzureWebPubSubKey,
        ),
        (
            b"azure_entra_secret AzureFakeEntraIdValue01".to_vec(),
            b"AzureFakeEntraIdValue01".to_vec(),
            RuleId::MicrosoftAzureEntraIdToken,
        ),
    ]
}

#[test]
fn azure_keyword_families_part4_require_keyword_context() {
    // Each part-4 variant fires once every earlier family sibling (the whole
    // 51-rule part-1+part-2+part-3 head plus its part-4 predecessors) stays
    // quiet.
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part4_fixtures().iter().enumerate() {
        let disabled = generic[..51 + index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn azure_keyword_families_part4_silence_when_disabled() {
    // Per-rule behavior: each part-4 fixture fires when only its earlier
    // siblings are disabled, and disabling the rule itself silences it while a
    // later sibling promotes. The Entra ID token is no longer the tail of the
    // whole generic family: the part-5 rules follow it.
    let generic = azure_generic_rules();
    let fixture_count = azure_part4_fixtures().len();
    for (index, (input, value, expected)) in azure_part4_fixtures().iter().enumerate() {
        let start = input.len() - value.len();
        let fired = matches_with_disabled(input, &generic[..51 + index]);
        assert_eq!(
            fired,
            vec![(*expected, start..start + value.len())],
            "{expected:?} fires when enabled",
        );
        let found = matches_with_disabled(input, &generic[..51 + index + 1]);
        assert!(
            found.iter().all(|(id, _)| *id != *expected),
            "{expected:?} disabled still reported",
        );
        if index + 1 < fixture_count {
            assert_eq!(found.len(), 1, "next azure sibling promotes");
        } else {
            assert_eq!(
                found.len(),
                1,
                "the part-5 head promotes at the family tail"
            );
        }
    }
}

#[test]
fn azure_keyword_families_part4_boundary() {
    // A part-4 rule also sits exactly at the 20-byte word-run minimum: with the
    // part-1+part-2+part-3 head disabled, the boundary fixture promotes the
    // part-4 head...
    let head = azure_generic_rules()[..51].to_vec();
    let boundary = b"azure AzureFakeBoundary012";
    let value = b"AzureFakeBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &head),
        vec![(
            RuleId::AzureSignalrConnectionString,
            boundary.len() - value.len()..boundary.len(),
        )],
        "20-byte boundary promotes the part-4 head",
    );
    // ...and one byte short stays quiet even for the part-4 rules.
    let short = b"azure AzureFakeBoundary01";
    assert!(
        matches_with_disabled(short, &head).is_empty(),
        "19-byte value stays quiet",
    );
}

#[test]
fn azure_keyword_families_part5_require_keyword_context() {
    // Part 5 closes the two Azure catalog rows that the earlier waves missed:
    // the Logic Apps URL and the management certificate. Both share the
    // `azure` keyword gate with the rest of the generic family.
    for (index, (input, value, expected)) in azure_part5_fixtures().iter().enumerate() {
        let disabled = azure_generic_rules()[..64 + index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn azure_keyword_families_part5_silence_when_disabled() {
    let generic = azure_generic_rules();
    for (index, (input, value, expected)) in azure_part5_fixtures().iter().enumerate() {
        let start = input.len() - value.len();
        let fired = matches_with_disabled(input, &generic[..64 + index]);
        assert_eq!(
            fired,
            vec![(*expected, start..start + value.len())],
            "{expected:?} fires when enabled",
        );
        let found = matches_with_disabled(input, &generic[..64 + index + 1]);
        assert!(
            found.iter().all(|(id, _)| *id != *expected),
            "{expected:?} disabled still reported"
        );
        if index + 1 < azure_part5_fixtures().len() {
            assert_eq!(found.len(), 1, "next azure sibling promotes");
        } else {
            assert!(
                found.is_empty(),
                "disabling the family tail silences the fixture"
            );
        }
    }
}

#[test]
fn azure_keyword_families_part5_boundary() {
    // The part-5 head sits exactly at the 20-byte word-run minimum; one byte
    // short stays quiet even with every earlier azure rule disabled.
    let head = azure_generic_rules()[..64].to_vec();
    let value = b"AzureFakeBoundary012";
    let boundary = b"azure AzureFakeBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &head),
        vec![(
            RuleId::AzureLogicAppsUrl,
            boundary.len() - value.len()..boundary.len(),
        )],
        "20-byte boundary promotes the part-5 head",
    );
    let short = b"azure AzureFakeBoundary01";
    assert!(
        matches_with_disabled(short, &head).is_empty(),
        "19-byte value stays quiet"
    );
}

#[test]
fn adobe_keyword_families_require_provider_context() {
    // The five Adobe keyword-gated catalog rows share the `adobe` keyword
    // gate; table order picks the winner and each later rule promotes once the
    // earlier siblings are disabled.
    for (index, (input, value, expected)) in adobe_keyword_fixtures().iter().enumerate() {
        let disabled = adobe_keyword_rules()[..index].to_vec();
        let found = matches_with_disabled(input, &disabled);
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(*expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn adobe_keyword_families_stop_after_the_last_sibling() {
    let all = adobe_keyword_rules();
    for (input, _, _) in adobe_keyword_fixtures().iter() {
        assert!(
            matches_with_disabled(input, all.as_slice()).is_empty(),
            "all adobe rules disabled silences the fixture",
        );
    }
    let fixtures = adobe_keyword_fixtures();
    let (input, value, expected) = fixtures.first().unwrap();
    let none: [RuleId; 0] = [];
    let head_only = matches_with_disabled(input.as_slice(), &none);
    assert_eq!(
        head_only,
        vec![(*expected, input.len() - value.len()..input.len())],
        "adobe head wins",
    );
}

#[test]
fn adobe_keyword_families_boundary_and_absence() {
    let none: [RuleId; 0] = [];
    let value = b"AdobeFakeBoundary012";
    let boundary = b"adobe AdobeFakeBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &none),
        vec![(
            RuleId::AdobeDeviceToken,
            boundary.len() - value.len()..boundary.len()
        )],
        "20-byte boundary fires the head",
    );
    let short = b"adobe AdobeFakeBoundary01";
    assert!(
        matches_with_disabled(short, &none).is_empty(),
        "19-byte value stays quiet",
    );
    // No provider keyword means silence.
    assert!(
        matches_with_disabled(b"vendor AdobeFakeToken00000000", &none).is_empty(),
        "missing keyword keeps every adobe rule quiet",
    );
}

#[test]
fn azure_keyword_gate_window_edge_matches_legacy_scan() {
    // The incremental feed must keep the legacy ≤200-byte window semantics:
    // the keyword occurrence may start exactly `KEYWORD_GATE_WINDOW` bytes
    // before the candidate, but not one byte further. The generic family head
    // wins because the structural validators reject the plain word-run value.
    let none: [RuleId; 0] = [];
    let value = b"WindowsEdge0123456789012";
    let mut at_edge = b"azure".to_vec();
    at_edge.extend(b" ".repeat(195));
    at_edge.extend(value);
    assert_eq!(
        at_edge.len() - value.len(),
        KEYWORD_GATE_WINDOW,
        "candidate at the window edge"
    );
    assert_eq!(
        matches_with_disabled(&at_edge, &none),
        vec![(
            RuleId::AzureAnomalyDetectorKey,
            at_edge.len() - value.len()..at_edge.len()
        )],
        "keyword inside the window gates the generic head",
    );
    let mut past_edge = b"azure".to_vec();
    past_edge.extend(b" ".repeat(196));
    past_edge.extend(value);
    assert!(
        matches_with_disabled(&past_edge, &none).is_empty(),
        "one byte beyond the window keeps the family quiet",
    );
    let mut upper = b"AZURE".to_vec();
    upper.extend(b" ");
    upper.extend(value);
    assert_eq!(
        matches_with_disabled(&upper, &none),
        vec![(
            RuleId::AzureAnomalyDetectorKey,
            upper.len() - value.len()..upper.len()
        )],
        "uppercase keyword queues through the case-folded gates",
    );
}

#[test]
fn amazon_aws_temporary_access_key_id_keyword_gate() {
    // The new `aws` sibling sits behind the two existing rows, so an `aws`
    // fixture still reports the earlier rules while they are enabled and only
    // promotes the new rule once both of them are disabled.
    let input = b"aws_temporary_access_key_id SyntheticAwsTempAccessKeyId01";
    let value = b"SyntheticAwsTempAccessKeyId01";
    let start = input.len() - value.len();
    let span = start..start + value.len();
    assert_eq!(
        matches(input),
        vec![(RuleId::AmazonAwsApiKeyId, span.clone())],
        "earlier aws sibling wins",
    );
    assert_eq!(
        matches_with_disabled(input, &[RuleId::AmazonAwsApiKeyId]),
        vec![(RuleId::AmazonAwsSessionToken, span.clone())],
        "second aws sibling wins next",
    );
    let earlier: Vec<RuleId> = vec![RuleId::AmazonAwsApiKeyId, RuleId::AmazonAwsSessionToken];
    assert_eq!(
        matches_with_disabled(input, &earlier),
        vec![(RuleId::AmazonAwsTemporaryAccessKeyId, span)],
        "the new aws sibling promotes last",
    );
    // An unquoted assignment right-hand side belongs to the context module, so
    // the keyword gate never reports it.
    let rhs = b"aws_temporary_key_id = SyntheticAwsTempValue01";
    assert!(
        matches(rhs)
            .iter()
            .all(|(id, _)| *id != RuleId::AmazonAwsTemporaryAccessKeyId),
        "assignment rhs skips the keyword gate"
    );
    // Exactly the 20-byte minimum fires, one byte short stays quiet.
    let boundary = b"aws SyntheticBoundary012";
    let small = b"SyntheticBoundary012";
    assert_eq!(
        matches_with_disabled(boundary, &earlier),
        vec![(
            RuleId::AmazonAwsTemporaryAccessKeyId,
            boundary.len() - small.len()..boundary.len(),
        )],
        "20-byte aws boundary",
    );
    let short = b"aws SyntheticBoundary01";
    assert!(
        matches_with_disabled(short, &earlier).is_empty(),
        "19-byte aws value stays quiet",
    );
}

#[test]
fn batch12_keyword_gated_families_require_provider_context() {
    // Batch 12: generic keyword rows (keyword + >= 20-byte word run). Shared
    // keywords fire in dispatch order, so later siblings are exercised with
    // the earlier family members disabled. The `docker` keyword gates only
    // the generic Swarm rows; the `dckr_pat_` PAT rules and the `SWMTKN`/
    // `SWMKEY` prefix rules are separate detectors.
    let cases: Vec<KeywordGatedCase> = vec![
        (
            b"apiclub_api_key SyntheticApiclubApiKey012345".to_vec(),
            b"SyntheticApiclubApiKey012345".to_vec(),
            vec![],
            RuleId::ApiclubApiKey,
        ),
        (
            b"asaas_api_token SyntheticAsaasApiTokenValue012".to_vec(),
            b"SyntheticAsaasApiTokenValue012".to_vec(),
            vec![],
            RuleId::AsaasApiToken,
        ),
        (
            b"docker_swarm_join_token SyntheticDockerSwarmJoin01234".to_vec(),
            b"SyntheticDockerSwarmJoin01234".to_vec(),
            vec![],
            RuleId::DockerSwarmJoinToken,
        ),
        (
            b"docker_swarm_unlock_key SyntheticDockerSwarmUnlockKey1".to_vec(),
            b"SyntheticDockerSwarmUnlockKey1".to_vec(),
            vec![RuleId::DockerSwarmJoinToken],
            RuleId::DockerSwarmUnlockKey,
        ),
        (
            b"onechronos_api_key SyntheticOneChronosApiKey0123".to_vec(),
            b"SyntheticOneChronosApiKey0123".to_vec(),
            vec![],
            RuleId::OneChronosApiKey,
        ),
        (
            b"onechronos_eb_api_key SyntheticOneChronosEbApiKey01234".to_vec(),
            b"SyntheticOneChronosEbApiKey01234".to_vec(),
            vec![RuleId::OneChronosApiKey],
            RuleId::OneChronosEbApiKey,
        ),
        (
            b"onechronos_eb_encryption_key SyntheticOneChronosEbEnc01".to_vec(),
            b"SyntheticOneChronosEbEnc01".to_vec(),
            vec![RuleId::OneChronosApiKey, RuleId::OneChronosEbApiKey],
            RuleId::OneChronosEbEncryptionKey,
        ),
        (
            b"onechronos_oauth_token SyntheticOneChronosOauth0123".to_vec(),
            b"SyntheticOneChronosOauth0123".to_vec(),
            vec![
                RuleId::OneChronosApiKey,
                RuleId::OneChronosEbApiKey,
                RuleId::OneChronosEbEncryptionKey,
            ],
            RuleId::OneChronosOauthToken,
        ),
        (
            b"onechronos_refresh_token SyntheticOneChronosRefresh01".to_vec(),
            b"SyntheticOneChronosRefresh01".to_vec(),
            vec![
                RuleId::OneChronosApiKey,
                RuleId::OneChronosEbApiKey,
                RuleId::OneChronosEbEncryptionKey,
                RuleId::OneChronosOauthToken,
            ],
            RuleId::OneChronosRefreshToken,
        ),
        (
            b"onesignal_rich_authentication_token SyntheticOneSignalRichAuth012".to_vec(),
            b"SyntheticOneSignalRichAuth012".to_vec(),
            vec![],
            RuleId::OneSignalRichAuthenticationToken,
        ),
    ];
    for (input, value, disabled, expected) in cases {
        let mut found = Vec::<(RuleId, Range<usize>)>::new();
        detect_line_with_disabled(&input, &disabled, |id, span| found.push((id, span))).unwrap();
        let start = input.len() - value.len();
        assert_eq!(
            found,
            vec![(expected, start..start + value.len())],
            "{expected:?}"
        );
        let metadata = expected.metadata();
        assert!(!metadata.id.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(metadata.reference.starts_with("https://"));
        assert_eq!(metadata.reviewed_on, "2026-10-06");
    }
}

#[test]
fn batch12_keyword_families_respect_length_and_context_windows() {
    // Each new keyword family honours the 20-byte minimum and the 200-byte
    // context window exactly like the pre-populated generic table rows.
    let families: Vec<(RuleId, &[u8])> = vec![
        (RuleId::ApiclubApiKey, b"apiclub"),
        (RuleId::AsaasApiToken, b"asaas"),
        (RuleId::DockerSwarmJoinToken, b"docker"),
        (RuleId::OneChronosApiKey, b"onechronos"),
        (RuleId::OneSignalRichAuthenticationToken, b"onesignal"),
    ];
    let value = b"SyntheticBoundary012";
    for (rule, keyword) in families {
        let input = [keyword, b" ", value.as_slice()].concat();
        assert_eq!(
            matches(&input),
            vec![(rule, input.len() - value.len()..input.len())],
            "{rule:?} 20-byte boundary",
        );
        let short = [keyword, b" SyntheticBoundary01"].concat();
        assert!(
            matches(&short).is_empty(),
            "{rule:?} 19-byte value stays quiet"
        );
        let filler = b"z".repeat(keyword.len() + 24);
        let no_keyword = [filler.as_slice(), b" ", value.as_slice()].concat();
        assert!(
            matches(&no_keyword).is_empty(),
            "{rule:?} no keyword in window"
        );
    }
    // The keyword must sit within the 200-byte context window: flush at the
    // window edge fires...
    let near = b"z".repeat(190);
    let edge = [
        b"onesignal".as_slice(),
        near.as_slice(),
        b" ",
        value.as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&edge),
        vec![(
            RuleId::OneSignalRichAuthenticationToken,
            edge.len() - value.len()..edge.len(),
        )],
        "keyword flush with the 200-byte window edge still fires",
    );
    // ...one byte further back stays quiet.
    let far = b"z".repeat(191);
    let out = [
        b"onesignal".as_slice(),
        far.as_slice(),
        b" ",
        value.as_slice(),
    ]
    .concat();
    assert!(
        matches(&out).is_empty(),
        "keyword outside the context window"
    );
}

#[test]
fn batch12_shared_keyword_families_promote_in_dispatch_order() {
    // Docker shares one keyword gate: the join row wins first, unlocking only
    // when it is disabled; disabling the whole family silences the fixture.
    let docker_input = b"docker_swarm SyntheticDockerSwarmValue0123";
    let docker_value = b"SyntheticDockerSwarmValue0123";
    let docker_start = docker_input.len() - docker_value.len();
    let docker_span = docker_start..docker_start + docker_value.len();
    assert_eq!(
        matches(docker_input),
        vec![(RuleId::DockerSwarmJoinToken, docker_span.clone())],
        "docker family head wins",
    );
    assert_eq!(
        matches_with_disabled(docker_input, &[RuleId::DockerSwarmJoinToken]),
        vec![(RuleId::DockerSwarmUnlockKey, docker_span.clone())],
        "unlock key promotes",
    );
    assert!(
        matches_with_disabled(
            docker_input,
            &[RuleId::DockerSwarmJoinToken, RuleId::DockerSwarmUnlockKey],
        )
        .is_empty(),
        "docker family disabled",
    );
    // The OneChronos family spans five rows sharing the `onechronos` keyword.
    let chronos_input = b"onechronos SyntheticOneChronosValue012";
    let chronos_value = b"SyntheticOneChronosValue012";
    let chronos_start = chronos_input.len() - chronos_value.len();
    let chronos_span = chronos_start..chronos_start + chronos_value.len();
    let family: Vec<RuleId> = vec![
        RuleId::OneChronosApiKey,
        RuleId::OneChronosEbApiKey,
        RuleId::OneChronosEbEncryptionKey,
        RuleId::OneChronosOauthToken,
        RuleId::OneChronosRefreshToken,
    ];
    for (index, promoted) in family.iter().enumerate() {
        let found = matches_with_disabled(chronos_input, &family[..index]);
        assert_eq!(found.len(), 1, "onechronos promotion chain");
        assert_eq!(found[0].0, *promoted, "onechronos promoted rule");
        assert_eq!(
            found[0].1,
            chronos_span.clone(),
            "onechronos promotion span"
        );
    }
    assert!(
        matches_with_disabled(chronos_input, &family).is_empty(),
        "entire onchronos family disabled",
    );
}

#[test]
fn docker_pat_and_swarm_prefix_rules_are_untouched_by_generic_keyword_rows() {
    // The generic `docker` keyword rows do not disturb the `dckr_pat_` PAT
    // fixtures (no `docker` keyword in their context) or the `SWMTKN`/`SWMKEY`
    // prefix fixtures, which are separate rules.
    let pat = [b"dckr_pat_".as_slice(), b"a".repeat(27).as_slice()].concat();
    assert_eq!(
        matches(&pat),
        vec![(RuleId::DockerPersonalPat, 0..pat.len())],
        "PAT prefix unaffected",
    );
    assert_eq!(
        matches_with_disabled(
            &pat,
            &[RuleId::DockerSwarmJoinToken, RuleId::DockerSwarmUnlockKey],
        ),
        vec![(RuleId::DockerPersonalPat, 0..pat.len())],
        "disabling generic swarm rows leaves the PAT rule intact",
    );
    let join = [b"SWMTKN-1-a-".as_slice(), b"b".repeat(24).as_slice()].concat();
    assert_eq!(
        matches(&join),
        vec![(RuleId::DockerSwarmJoin, 0..join.len())],
        "prefix join fixture unaffected",
    );
}

#[test]
fn http_authentication_header_rules_detect_authorization_values() {
    // Header-triggered rules: the `Authorization` word itself is the trigger
    // and must sit within 30 bytes before the case-insensitive `basic `/
    // `bearer ` marker that ends immediately before the value (optionally one
    // quote back). Basic bodies are `[A-Za-z0-9+/]{12,128}` with at most three
    // `=`; bearer bodies are `[A-Za-z0-9._-]{10,256}`.
    let basic_value = b"QUQmZmY1MjIrc01";
    let basic = [b"Authorization: Basic ".as_slice(), basic_value.as_slice()].concat();
    let basic_start = basic.len() - basic_value.len();
    assert_eq!(
        matches(&basic),
        vec![(
            RuleId::HttpBasicAuthenticationHeader,
            basic_start..basic.len()
        )],
        "basic credentials",
    );
    // Uppercase header and quoted payload still report.
    let quoted_basic = [
        b"PROXY-AUTHORIZATION: BASIC ".as_slice(),
        b"\"QUQmZmY1MjIrc012\"".as_slice(),
    ]
    .concat();
    let quoted_basic_value = b"QUQmZmY1MjIrc012";
    let quoted_basic_start = quoted_basic.len() - 1 - quoted_basic_value.len();
    assert_eq!(
        matches(&quoted_basic),
        vec![(
            RuleId::HttpBasicAuthenticationHeader,
            quoted_basic_start..quoted_basic.len() - 1,
        )],
        "uppercase header quoted payload",
    );
    let bearer_value = b"abc.def-ghi_JKL012";
    let bearer = [
        b"Authorization: Bearer ".as_slice(),
        bearer_value.as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&bearer),
        vec![(
            RuleId::HttpBearerAuthenticationHeader,
            bearer.len() - bearer_value.len()..bearer.len(),
        )],
        "bearer token",
    );
    let quoted_bearer = [
        b"proxy-authorization: bearer ".as_slice(),
        b"'BearerSynthetic0123'".as_slice(),
    ]
    .concat();
    let quoted_bearer_value = b"BearerSynthetic0123";
    assert_eq!(
        matches(&quoted_bearer),
        vec![(
            RuleId::HttpBearerAuthenticationHeader,
            quoted_bearer.len() - 1 - quoted_bearer_value.len()..quoted_bearer.len() - 1,
        )],
        "lowercase header quoted bearer",
    );
}

#[test]
fn http_authentication_header_rules_reject_near_misses_and_window_misses() {
    // No `authorization` within 30 bytes before the marker...
    let bare_basic = b"Basic QUQmZmY1MjIrc01";
    assert!(matches(bare_basic).is_empty(), "header word required");
    // ...or parked beyond the 30-byte window before the marker.
    let parked = [
        b"authorization zzzzzzzzzzzzzzzzzzzzzzzzzzz Basic ".as_slice(),
        b"QUQmZmY1MjIrc01".as_slice(),
    ]
    .concat();
    assert!(
        matches(&parked).is_empty(),
        "authorization outside the 30-byte window"
    );
    // Eleven-byte basic body stays quiet...
    let short_basic = b"Authorization: Basic QUQmZmY1Mj";
    assert!(matches(short_basic).is_empty(), "basic body minimum is 12");
    // ...and so does a nine-byte bearer body.
    let short_bearer = b"Authorization: Bearer abcdefghi";
    assert!(
        matches(short_bearer).is_empty(),
        "bearer body minimum is 10"
    );
    // A non-header word parked in front of `Bearer` stays quiet.
    let no_header = b"Cache Bearer abcdefghiJKL";
    assert!(matches(no_header).is_empty(), "authorization word required");
    // Four `=` tail bytes are rejected, three pad bytes are accepted.
    let four_pad = [
        b"Authorization: Basic ".as_slice(),
        b"QUQmZmY1MjIrc01====".as_slice(),
    ]
    .concat();
    assert!(
        matches(&four_pad).is_empty(),
        "basic padding capped at three"
    );
    let three_pad = [
        b"Authorization: Basic ".as_slice(),
        b"QUQmZmY1MjIrc01===".as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&three_pad),
        vec![(RuleId::HttpBasicAuthenticationHeader, 21..three_pad.len())],
        "three pad bytes accepted",
    );
    // Assignment forms are not gated away: a header payload keeps firing even
    // though the generic keyword gate skips assignment right-hand sides.
    let assignment = [
        b"AUTH_HEADER = \"Authorization: Basic ".as_slice(),
        b"QUQmZmY1MjIrc01".as_slice(),
        b"\"".as_slice(),
    ]
    .concat();
    assert_eq!(
        matches(&assignment),
        vec![(
            RuleId::HttpBasicAuthenticationHeader,
            assignment.len() - 1 - 15..assignment.len() - 1,
        )],
        "assignment form still reports the header rule",
    );
    // The marker alone (or unrelated words) keeps the family quiet.
    let marker_only = b"Authorization: bearer";
    assert!(matches(marker_only).is_empty(), "marker without body");
    let unrelated = b"basic authorization QUQmZmY1MjIrc01";
    assert!(
        matches(unrelated).is_empty(),
        "marker must immediately precede the candidate",
    );
}

#[test]
fn http_authentication_header_rules_honor_disable() {
    // Disabling either header rule silences exactly its fixture path: the
    // header fallback never leaks through to the prefix table.
    let basic_value = b"QUQmZmY1MjIrc01";
    let basic = [b"Authorization: Basic ".as_slice(), basic_value.as_slice()].concat();
    assert!(
        matches_with_disabled(&basic, &[RuleId::HttpBasicAuthenticationHeader]).is_empty(),
        "basic header disabled",
    );
    let bearer_value = b"abc.def-ghi_JKL012";
    let bearer = [
        b"Authorization: Bearer ".as_slice(),
        bearer_value.as_slice(),
    ]
    .concat();
    assert!(
        matches_with_disabled(&bearer, &[RuleId::HttpBearerAuthenticationHeader]).is_empty(),
        "bearer header disabled",
    );
    // Each rule also stays quiet when the *other* header rule is disabled,
    // proving the two paths are independent.
    assert_eq!(
        matches_with_disabled(&basic, &[RuleId::HttpBearerAuthenticationHeader]),
        vec![(RuleId::HttpBasicAuthenticationHeader, 21..basic.len())],
        "basic header independent of bearer disable",
    );
}
