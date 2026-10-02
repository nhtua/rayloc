use super::*;
#[test]
fn comment_lexing_ignores_strings_urls_escapes_and_non_directives() {
    for line in [
        b"password='value \\' # rayloc:ignore'".as_slice(),
        b"x='unterminated # rayloc:ignore",
        b"x=42 # rayloc:ignore later",
        b"x=42 // ordinary",
        b"x='https://example.com/#'",
        b"x=42",
    ] {
        assert!(!directive(line));
    }
    for line in [
        b"x=42 # rayloc:ignore".as_slice(),
        b"x=42 // rayloc:ignore\r",
        b"# rayloc:ignore",
    ] {
        assert!(directive(line));
    }
}
#[test]
fn incomplete_assignments_scoped_placeholders_and_disabled_rules_are_safe() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut histogram = Histogram::new();
    let mut suppressed = Suppressions::default();
    for line in [
        b"'unterminated".as_slice(),
        b"password=",
        b"password='unterminated",
        b"api_key=aaaaaabbbbbbbcccccc",
        b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ] {
        registry
            .detect_line_with_suppressions(line, &mut histogram, &mut suppressed, |_, _| {
                panic!("invalid/placeholder emitted")
            })
            .unwrap();
    }
    assert_eq!(suppressed.placeholder, 1);
    let mut ids = Vec::new();
    registry
        .detect_line(
            b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+///",
            &mut histogram,
            |rule, _| ids.push(rule),
        )
        .unwrap();
    assert_eq!(ids, [RuleId::AwsSecretAccessKey]);
    let registry = Registry::compile(crate::config::parse(b"version: \"1\"\ndisabled_rules: [aws-secret-access-key, password-assignment, context-secret, jose-token]").unwrap()).unwrap();
    registry
        .detect_line(
            b"password='aaaaaaaa' api_key=Q7v2n9B4x6M1z8K3 eyJhbGciOiJIUzI1NiJ9.e30.AAAA",
            &mut histogram,
            |_, _| panic!("disabled rule emitted"),
        )
        .unwrap();
}
#[test]
fn public_suppression_accumulators_are_checked_for_overflow() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for (line, kind) in [
        (b"password='aaaaaaaa' # rayloc:ignore".as_slice(), 0),
        (b"password='changeme'", 1),
        (b"password='${PASSWORD}'", 2),
        (b"api_key_checksum=9f21c7ab6e40d835", 3),
        (b"api_key=aaaaaaaaaaaaaaaa", 4),
    ] {
        let mut counters = Suppressions::default();
        let field = match kind {
            0 => &mut counters.inline,
            1 => &mut counters.placeholder,
            2 => &mut counters.reference,
            3 => &mut counters.checksum,
            _ => &mut counters.generic_filter,
        };
        *field = usize::MAX;
        assert_eq!(
            registry.detect_line_with_suppressions(
                line,
                &mut Histogram::new(),
                &mut counters,
                |_, _| {}
            ),
            Err(ScanError::CounterOverflow)
        );
    }
}
