use rayloc::{
    config::Config,
    rules::{Registry, entropy::Histogram},
    scanner::engine::scan_reader_with_registry,
};
use std::io::Cursor;
fn rules(line: &[u8]) -> Vec<(&'static str, std::ops::Range<usize>)> {
    let registry = Registry::compile(Config::default()).unwrap();
    let mut matches = Vec::new();
    registry
        .detect_line(line, &mut Histogram::new(), |rule, span| {
            matches.push((rule.metadata().id, span))
        })
        .unwrap();
    matches
}
#[test]
fn strong_passwords_do_not_require_entropy_and_references_are_not_literals() {
    for line in [
        b"password = 'aaaaaaaa'".as_slice(),
        b"passwd: \"weakweak\"",
        b"dbPassword = \"testEXAMPLEfoo123\"",
        b"PASSWORD=aaaaaaaa",
    ] {
        assert_eq!(rules(line).len(), 1);
        assert_eq!(rules(line)[0].0, "password-assignment");
    }
    for line in [
        b"password = 'short'".as_slice(),
        b"password = os.getenv('PASSWORD')",
        b"password = process.env.PASSWORD",
        b"password = ${PASSWORD}",
        b"password: 'changeme'",
        b"password: \"${PASSWORD}\"",
        b"password = config.password",
        b"password = 'rayloc:ignore' + suffix",
    ] {
        assert!(rules(line).is_empty());
    }
}
#[test]
fn contexts_support_short_random_hex_headers_json_and_escaped_quotes() {
    for line in [
        b"api_key=Q7v2n9B4x6M1z8K3".as_slice(),
        b"{\"accessToken\": \"u4f8m1r9B2g6q7X5\"}",
        b"client_secret: 9f21c7ab6e40d835",
        b"Authorization: Bearer Q7v2n9B4x6M1z8K3",
        b"const apiKey = \"Q7v2n9B4\\\"6M1z8K3\";",
        b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD",
    ] {
        assert_eq!(rules(line).len(), 1);
    }
    for line in [
        b"key=Q7v2n9B4x6M1z8K3".as_slice(),
        b"Q7v2n9B4x6M1z8K3",
        b"api_key=0123456789abcdef",
        b"api_key=aaaaaaaaaaaaaaaa",
        b"api_key_sha256=9f21c7ab6e40d835",
        b"password_checksum=9f21c7ab6e40d835",
    ] {
        assert!(rules(line).is_empty());
    }
    assert_eq!(rules(b"api_key=9f21c7ab6e40d835")[0].0, "context-secret");
    assert_eq!(
        rules(b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD")[0].0,
        "aws-secret-access-key"
    );
}
#[test]
fn inline_comments_suppress_only_their_physical_line() {
    let registry = Registry::compile(Config::default()).unwrap();
    let outcome = scan_reader_with_registry(&mut Cursor::new(b"password='aaaaaaaa' # rayloc:ignore\npassword='bbbbbbbb'\npassword='cccccccc' // rayloc:ignore\npassword='value # rayloc:ignore'\n"), 1, &registry);
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(outcome.findings[0].line, 2);
    assert_eq!(outcome.findings[1].line, 4);
}
#[test]
fn jose_structure_supports_unsecured_jws_and_jwe_without_eyj_prefix() {
    for token in [
        b"eyJhbGciOiJIUzI1NiJ9.e30.AAAA".as_slice(),
        b"eyJhbGciOiJub25lIn0.e30.",
        b"eyAiYWxnIiA6ICJSU0EyNTYiIH0.e30.AAAA",
        b"eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAA.AAAA.AAAA",
    ] {
        assert_eq!(rules(token).len(), 1);
        assert_eq!(rules(token)[0].0, "jose-token");
    }
    for token in [
        b"a.b.c".as_slice(),
        b"eyJhbGciOiJIUzI1NiJ9.e30.",
        b"eyJhbGciOiJub25lIn0.e30.AAAA",
        b"eyJhbGciOjF9.e30.AAAA",
        b"eyJhbGciOiJIUzI1NiJ9.e30=.AAAA",
        b"eyJhbGciOiJIUzI1NiJ9..AAAA",
        b"eyJhbGciOiJkaXIifQ..AAAA.AAAA.AAAA",
    ] {
        assert!(rules(token).is_empty());
    }
}
#[test]
fn identical_provider_and_context_spans_are_one_finding_but_occurrences_survive() {
    let matches = rules(&[
        97, 112, 105, 95, 107, 101, 121, 61, 39, 103, 104, 112, 95, 65, 98, 67, 100, 69, 102, 71,
        104, 73, 106, 75, 108, 77, 110, 79, 112, 81, 114, 83, 116, 85, 118, 87, 120, 89, 122, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 39, 32, 97, 112, 105, 95, 107, 101, 121, 61, 39, 103,
        104, 112, 95, 65, 98, 67, 100, 69, 102, 71, 104, 73, 106, 75, 108, 77, 110, 79, 112, 81,
        114, 83, 116, 85, 118, 87, 120, 89, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 39,
    ]);
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|(id, _)| *id == "github-token"));
}
#[test]
fn suppression_counters_are_reported_without_source_values() {
    let registry = Registry::compile(Config::default()).unwrap();
    let input = b"password='aaaaaaaa' # rayloc:ignore\npassword='changeme'\npassword='${PASSWORD}'\napi_key_sha256=9f21c7ab6e40d835\napi_key=aaaaaaaaaaaaaaaa\n";
    let outcome = scan_reader_with_registry(&mut Cursor::new(input), 1, &registry);
    let mut report = Vec::new();
    rayloc::report::terminal::render(&outcome, &mut report).unwrap();
    let report = String::from_utf8(report).unwrap();
    assert!(report.contains("inline=1; placeholder=1; reference=1; checksum=1; generic-filter=1"));
    assert!(!report.contains("aaaaaaaa"));
}
#[test]
fn generic_class_overrides_and_length_caps_do_not_change_custom_entropy() {
    let config = rayloc::config::parse(b"version: \"1\"\ndefault_entropy_threshold: 8\nentropy_thresholds: {hex: 4, alphanumeric: 5.9, base64: 6}\nrules: [{id: exact, regex: 'custom=([A-Za-z0-9]{16})', secret_group: 1, entropy: 4}]").unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut detected = Vec::new();
    registry
        .detect_line(
            b"api_key=Q7v2n9B4x6M1z8K3 custom=aaaabbbbccccdddd",
            &mut Histogram::new(),
            |rule, span| detected.push((rule.metadata().id, span)),
        )
        .unwrap();
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].0, "context-secret");
    for class in ["hex", "alphanumeric", "base64"] {
        assert!(registry.entropy_thresholds.contains_key(class));
    }
}
#[test]
fn context_candidate_limits_fail_even_on_ignored_lines_and_bound_deduplication() {
    let registry = Registry::compile(Config::default()).unwrap();
    for suffix in [b"".as_slice(), b" # rayloc:ignore"] {
        let input = [b"password='".as_slice(), &vec![b'a'; 65537], b"'", suffix].concat();
        assert_eq!(
            scan_reader_with_registry(&mut Cursor::new(input), 1, &registry).exit_code(),
            2
        );
    }
    let input = b"password='aaaaaaaa' ".repeat(10001);
    let outcome = scan_reader_with_registry(&mut Cursor::new(input), 1, &registry);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.findings.len(), 10000);
}
#[test]
fn provider_span_wins_over_identical_custom_capture() {
    let config =
        rayloc::config::parse(b"version: \"1\"\nrules: [{id: overlap, regex: 'ghp_[A-Za-z0-9]+'}]")
            .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut detected = Vec::new();
    registry
        .detect_line(
            &[
                103, 104, 112, 95, 65, 98, 67, 100, 69, 102, 71, 104, 73, 106, 75, 108, 77, 110,
                79, 112, 81, 114, 83, 116, 85, 118, 87, 120, 89, 122, 48, 49, 50, 51, 52, 53, 54,
                55, 56, 57,
            ],
            &mut Histogram::new(),
            |rule, _| detected.push(rule.metadata().id),
        )
        .unwrap();
    assert_eq!(detected, ["github-token"]);
}
#[test]
fn oversized_jose_headers_and_deep_json_report_incomplete_scans() {
    let registry = Registry::compile(Config::default()).unwrap();
    let input = [vec![b'A'; 8193], b".e30.AAAA".to_vec()].concat();
    assert_eq!(
        scan_reader_with_registry(&mut Cursor::new(input), 1, &registry).exit_code(),
        2
    );
}
#[test]
fn quoted_authorization_headers_capture_only_the_bearer_value() {
    let line = b"{\"Authorization\": \"Bearer Q7v2n9B4x6M1z8K3\"}";
    let matches = rules(line);
    assert_eq!(matches, [("context-secret", 26..42)]);
}
#[test]
fn strong_context_words_use_snake_and_camel_boundaries() {
    for line in [
        b"compassword='aaaaaaaa'".as_slice(),
        b"notapikey=Q7v2n9B4x6M1z8K3",
    ] {
        assert!(rules(line).is_empty());
    }
    for line in [
        b"DB_PASSWORD='aaaaaaaa'".as_slice(),
        b"clientSecret=Q7v2n9B4x6M1z8K3",
        b"serviceAPIKey=Q7v2n9B4x6M1z8K3",
        b"api_key_sha256suffix=Q7v2n9B4x6M1z8K3",
    ] {
        // Last case is a key qualifier, not a recognized checksum word; it is weak context.
        if line.starts_with(b"api_key_sha256suffix") {
            assert!(rules(line).is_empty());
        } else {
            assert_eq!(rules(line).len(), 1);
        }
    }
}
#[test]
fn trailing_ignore_after_an_unquoted_webhook_is_a_directive() {
    assert!(
        rules(b"webhook=https://hooks.slack.com/services/T/B/synthetic-secret # rayloc:ignore")
            .is_empty()
    );
    assert_eq!(
        rules(b"webhook=https://hooks.slack.com/services/T/B/synthetic-secret").len(),
        1
    );
}
