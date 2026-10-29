use super::*;

#[test]
fn legacy_whole_line_rules_emit_captures_and_reject_oversized_values() {
    let registry = Registry::compile(
        crate::config::parse(
            b"version: '1'\nrules: [{id: legacy, regex: '^(abc)?D+' , secret_group: 1}]",
        )
        .unwrap(),
    )
    .unwrap();
    let mut histogram = Histogram::new();
    let mut spans = Vec::new();
    registry
        .detect_legacy_line(b"D", &mut histogram, |candidate| spans.push(candidate.span))
        .unwrap();
    assert!(spans.is_empty());
    registry
        .detect_legacy_line(b"abcDDD", &mut histogram, |candidate| {
            spans.push(candidate.span)
        })
        .unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0], 0..3);
    let registry = Registry::compile(
        crate::config::parse(b"version: '1'\nrules: [{id: legacy, regex: '^D+'}]").unwrap(),
    )
    .unwrap();
    assert_eq!(
        registry.detect_legacy_line(
            &vec![b'D'; builtin::MAX_CANDIDATE_BYTES + 1],
            &mut histogram,
            |_| {}
        ),
        Err(crate::scanner::ScanError::CandidateLimit)
    );
}

#[test]
fn legacy_entropy_gate_is_evaluated_for_matching_candidates() {
    let registry = build_registry(
        "version: \"1\"\nrules: [{id: legacy, regex: '^corp_([a-z]+)$', secret_group: 1, entropy: 1.5}]",
    );
    assert!(registry.legacy_line_rules().next().is_some());

    let mut candidates = Vec::new();
    registry
        .detect_legacy_line(b"corp_abcdef", &mut Histogram::new(), |candidate| {
            candidates.push(candidate.span)
        })
        .unwrap();

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0], 5..11);
}

#[test]
fn windowed_rules_only_yields_enabled_custom_rules_with_byte_limits() {
    let registry = build_registry(
        "version: \"1\"\ndisabled_rules: [off]\nrules: [{id: bounded, regex: 'corp_[a-z]{3}'}, {id: streaming, regex: 'corp_.*'}, {id: off, regex: 'corp_[a-z]{4}'}]",
    );
    let entries: Vec<_> = registry.windowed_rules().collect();
    assert_eq!(
        entries.len(),
        1,
        "disabled rules and unbounded rules leave the window"
    );
    let (index, _regex, _group, _entropy, id, maximum) = entries[0];
    assert_eq!(index, 0);
    assert!(matches!(id, RuleId::Custom(1, _)));
    assert_eq!(maximum, 8);
    // The disabled and unbounded companions stay reachable for the other feeds.
    assert_eq!(registry.legacy_line_rules().count(), 1);
    assert_eq!(
        registry
            .legacy_line_rules()
            .map(|(_, _, _, _, id)| id)
            .collect::<Vec<_>>(),
        [RuleId::Custom(2, builtin::Severity::High)]
    );
}

#[test]
fn pathless_detection_defaults_to_text_and_source_api_is_additive() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let line = b"password=self.DUMMY_API_KEY";
    let mut pathless = Vec::new();
    registry
        .detect_line(line, &mut Histogram::new(), |rule, span| {
            pathless.push((rule, span));
        })
        .unwrap();
    assert_eq!(pathless.len(), 1);
    assert_eq!(pathless[0].0, RuleId::PasswordAssignment);

    let mut code = Vec::new();
    let mut suppressions = context::Suppressions::default();
    registry
        .detect_line_in_source(
            line,
            SourceSyntax::Code,
            &mut Histogram::new(),
            &mut suppressions,
            |rule, span| code.push((rule, span)),
        )
        .unwrap();
    assert!(code.is_empty());
    assert_eq!(suppressions.reference, 1);
}

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

#[test]
fn whole_line_rules_reject_records_beyond_the_legacy_window() {
    let registry = build_registry("version: \"1\"\nrules: [{id: streaming, regex: 'corp_.*'}]");
    assert!(registry.requires_whole_line());
    let over = vec![b'x'; LEGACY_LINE_BYTES + 1];
    assert_eq!(
        registry.detect_line(&over, &mut Histogram::new(), |_, _| {}),
        Err(ScanError::RuleWindowLimit)
    );
    // The window limit is strict: the exact boundary line is still accepted.
    let boundary = vec![b'x'; LEGACY_LINE_BYTES];
    registry
        .detect_line(&boundary, &mut Histogram::new(), |_, _| {})
        .unwrap();
    // Bounded rules keep long lines readable because they never need the line.
    let bounded = build_registry("version: \"1\"\nrules: [{id: bounded, regex: 'corp_[a-z]{3}'}]");
    assert!(!bounded.requires_whole_line());
    assert_eq!(
        bounded.detect_line(&over, &mut Histogram::new(), |_, _| {}),
        Ok(())
    );
}

#[test]
fn entropy_gates_read_the_top_level_capture_and_its_alphabet() {
    // `(abc)` exposes its capture directly, so group 1 resolves at the root.
    let registry = build_registry(
        "version: \"1\"\nrules: [{id: top, regex: '(abc)', secret_group: 1, entropy: 1}, {id: literal, regex: 'abcdef', entropy: 1}]",
    );
    let mut findings = Vec::new();
    registry
        .detect_line(b"abc abcdef", &mut Histogram::new(), |id, span| {
            findings.push((id, span))
        })
        .unwrap();
    assert_eq!(
        findings
            .iter()
            .map(|(_, span)| span.clone())
            .collect::<Vec<_>>(),
        [0..3, 4..7, 4..10]
    );
    // Rule 1 also matches the `abc` prefix of `abcdef`, so each rule reports
    // exactly the spans its own capture produces.
    assert_eq!(
        findings
            .iter()
            .map(|(id, _)| matches!(id, RuleId::Custom(1, _)))
            .collect::<Vec<_>>(),
        [true, true, false]
    );
    // A byte class alphabet counts its range: 6 symbols over 4 bytes allow 2 bits.
    assert!(
        Registry::compile(
            crate::config::parse(
                b"version: \"1\"\nrules: [{id: bytes, regex: '(?-u:[a-f]{4})', entropy: 2}]"
            )
            .unwrap()
        )
        .is_ok()
    );
    assert!(
        Registry::compile(
            crate::config::parse(
                b"version: \"1\"\nrules: [{id: bytes, regex: '(?-u:[a-f]{4})', entropy: 2.1}]"
            )
            .unwrap()
        )
        .is_err()
    );
}

#[test]
fn identical_spans_from_two_custom_rules_emit_once() {
    let registry = build_registry(
        "version: \"1\"\nrules: [{id: one, regex: 'corp_[a-z]{3}'}, {id: two, regex: 'corp_[a-z]{3}'}]",
    );
    let mut count = 0;
    registry
        .detect_line(b"corp_abc", &mut Histogram::new(), |_, _| count += 1)
        .unwrap();
    assert_eq!(count, 1, "the duplicate span is deduplicated");
}

#[test]
fn custom_rule_stream_compatibility_is_classified_from_the_full_expression() {
    for (pattern, whole) in [
        ("corp_([a-z]{16})", false),
        ("corp_([a-z]+)", true),
        ("prefix.*(SECRET)", true),
        ("^corp_[a-z]{16}$", true),
        ("\\bcorp_[a-z]{16}\\b", true),
    ] {
        let mut config = Config::default();
        config.rules.push(crate::config::CustomRule {
            id: "custom".into(),
            pattern: pattern.into(),
            group: 0,
            entropy: None,
            severity: builtin::Severity::High,
        });
        let registry = Registry::compile(config).unwrap();
        assert_eq!(registry.requires_whole_line(), whole, "{pattern}");
    }
    let mut config = Config::default();
    config.rules.push(crate::config::CustomRule {
        id: "custom".into(),
        pattern: "prefix.*(SECRET)".into(),
        group: 0,
        entropy: None,
        severity: builtin::Severity::High,
    });
    config.disabled.push("custom".into());
    let disabled = Registry::compile(config).unwrap();
    assert!(!disabled.requires_whole_line());
}
