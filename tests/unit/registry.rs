use super::*;
fn build_registry(text: &str) -> Registry {
    Registry::compile(crate::config::parse(text.as_bytes()).unwrap()).unwrap()
}
#[test]
fn capture_only_gates_optional_groups_and_all_severities() {
    let registry = build_registry(
        "version: \"1\"\nrules:\n - {id: low, regex: '(abc)?DEF', secret_group: 1, severity: Low}\n - {id: medium, regex: 'key=([0-9a-f]+)', secret_group: 1, entropy: 3, severity: Medium}\n - {id: unicode, regex: 'é+', severity: Critical}\n - {id: byte, regex: '(?-u:\\xff+)', severity: High}",
    );
    let mut findings = Vec::new();
    registry
        .detect_line(
            b"DEF abcDEF key=0000 key=0123456789abcdef \xc3\xa9 \xff",
            &mut Histogram::new(),
            |id, span| findings.push((id, span)),
        )
        .unwrap();
    assert_eq!(
        findings,
        [
            (RuleId::Custom(1, builtin::Severity::Low), 4..7),
            (RuleId::Custom(2, builtin::Severity::Medium), 24..40),
            (RuleId::Custom(3, builtin::Severity::Critical), 41..43),
            (RuleId::Custom(4, builtin::Severity::High), 44..45)
        ]
    );
    assert_eq!(registry.default_entropy_threshold, 4.5);
    assert!(registry.entropy_thresholds.is_empty());
}
#[test]
fn invalid_capture_empty_language_unreachable_entropy_and_programs_rejected() {
    for fields in [
        "regex: '('",
        "regex: 'a*'",
        "regex: '\\b'",
        "regex: 'a', secret_group: 1",
        "regex: '(a)', entropy: 1",
        "regex: '[a-f]{2}', entropy: 2",
        "regex: '[0-9a-f]{20}', entropy: 4.1",
        "regex: 'a{1000000}'",
        "regex: '[ab]+', secret_group: 999999999",
        "regex: '(a?)b', secret_group: 1, entropy: 1",
    ] {
        let config = crate::config::parse(
            format!("version: \"1\"\nrules: [{{id: custom, {fields}}}]").as_bytes(),
        )
        .unwrap();
        assert!(Registry::compile(config).is_err(), "{fields}");
    }
    assert!(
        Registry::compile(
            crate::config::parse(b"version: \"1\"\ndisabled_rules: [unknown]").unwrap()
        )
        .is_err()
    );
    let reg = build_registry(
        "version: \"1\"\nrules: [{id: ok, regex: '(é){2}', secret_group: 1, entropy: 1}]",
    );
    let mut count = 0;
    reg.detect_line("éé".as_bytes(), &mut Histogram::new(), |_, _| count += 1)
        .unwrap();
    assert_eq!(count, 1);
}
#[test]
fn disables_do_not_disable_other_sources_and_custom_candidates_are_bounded() {
    let registry = build_registry(
        "version: \"1\"\ndisabled_rules: [github-token, custom]\nrules: [{id: custom, regex: 'corp_.*'}]",
    );
    let mut findings = Vec::new();
    registry
        .detect_line(
            b"ghp_abcdefghijklmnop corp_secret -----BEGIN PRIVATE KEY-----",
            &mut Histogram::new(),
            |id, _| findings.push(id),
        )
        .unwrap();
    assert_eq!(findings, [RuleId::PrivateKeyMarker]);
    let registry = build_registry(
        "version: \"1\"\nrules: [{id: custom, regex: 'corp_([a-z]+)', secret_group: 1}]",
    );
    let bytes = [b"corp_".as_slice(), &vec![b'a'; MAX_CANDIDATE_BYTES + 1]].concat();
    assert_eq!(
        registry.detect_line(&bytes, &mut Histogram::new(), |_, _| {}),
        Err(ScanError::CandidateLimit)
    );
    let reg =
        build_registry("version: \"1\"\nrules: [{id: custom, regex: '(a*)b', secret_group: 1}]");
    let mut count = 0;
    reg.detect_line(b"b", &mut Histogram::new(), |_, _| count += 1)
        .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn disabled_builtin_rules_do_not_evaluate_candidate_limits() {
    let registry = build_registry(
        "version: \"1\"\ndisabled_rules: [aws-access-key-id, github-token, stripe-secret-key, stripe-restricted-key, slack-webhook, private-key-marker]",
    );
    let mut bytes = b"ghs_".to_vec();
    bytes.extend(std::iter::repeat_n(b'a', MAX_CANDIDATE_BYTES + 1));
    assert_eq!(
        registry.detect_line(&bytes, &mut Histogram::new(), |_, _| panic!(
            "disabled match"
        )),
        Ok(())
    );
}
#[test]
fn byte_class_entropy_capture_recursion_and_impossible_patterns_are_validated() {
    let reg = build_registry(
        "version: \"1\"\nrules: [{id: byte, regex: '(?-u:([a-d]{4}))', secret_group: 1, entropy: 2}, {id: nested, regex: '(x(y))', secret_group: 2}, {id: unicode, regex: '[éö]+', entropy: 1}]",
    );
    let mut count = 0;
    reg.detect_line("abcd xy éö".as_bytes(), &mut Histogram::new(), |_, _| {
        count += 1
    })
    .unwrap();
    assert_eq!(count, 3);
    for regex in ["(?-u:[a&&b])", "abc()"] {
        let fields = if regex.ends_with("()") {
            ", secret_group: 1, entropy: 0"
        } else {
            ""
        };
        let config = crate::config::parse(
            format!("version: \"1\"\nrules: [{{id: x, regex: '{regex}'{fields}}}]").as_bytes(),
        )
        .unwrap();
        assert!(Registry::compile(config).is_err());
    }
}
#[test]
fn registry_revalidates_programmatic_numeric_policy() {
    for threshold in [f64::NAN, f64::INFINITY, -1.0, 8.1] {
        let config = Config {
            default_entropy_threshold: Some(threshold),
            ..Config::default()
        };
        assert!(Registry::compile(config).is_err());
    }
    for (key, value) in [("unknown", 1.0), ("hex", 4.1), ("base64", f64::NAN)] {
        let mut config = Config::default();
        config.entropy_thresholds.insert(key.into(), value);
        assert!(Registry::compile(config).is_err());
    }
}
#[test]
fn aggregate_compiled_set_budget_rejects_many_individually_valid_programs() {
    let one = "version: \"1\"\nrules: [{id: one, regex: '[a-z]{1000}'}]";
    assert!(Registry::compile(crate::config::parse(one.as_bytes()).unwrap()).is_ok());
    let many = format!(
        "version: \"1\"\nrules: [{}]",
        (0..256)
            .map(|n| format!("{{id: rule{n}, regex: '[a-z]{{1000}}'}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(Registry::compile(crate::config::parse(many.as_bytes()).unwrap()).is_err());
}
