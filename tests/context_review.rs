use rayloc::{
    config,
    rules::{Registry, entropy::Histogram},
    scanner::engine::scan_reader_with_registry,
};
use std::io::Cursor;
fn registry(disabled: &str) -> Registry {
    Registry::compile(
        config::parse(format!("version: \"1\"\ndisabled_rules: [{disabled}]").as_bytes()).unwrap(),
    )
    .unwrap()
}
#[test]
fn checksum_words_do_not_suppress_concrete_password_assignments() {
    let policy = registry("");
    for field in ["checksum_password", "sha256_password", "digest_passwd"] {
        for value in ["aaaaaaaa", "aaaaaaaaaaaaaaaa"] {
            let input = format!("{field}='{value}'");
            let outcome = scan_reader_with_registry(&mut Cursor::new(input), 1, &policy);
            assert_eq!(outcome.exit_code(), 1);
            assert_eq!(
                outcome.findings[0].rule.metadata().id,
                "password-assignment"
            );
        }
    }
    let outcome = scan_reader_with_registry(
        &mut Cursor::new(b"digest='9f21c7ab6e40d835' checksum_api_key='9f21c7ab6e40d835'"),
        1,
        &policy,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.stats.suppressions.checksum, 2);
}
#[test]
fn checksum_candidates_enforce_exact_limit_before_all_suppression_policies() {
    for inline_enabled in [true, false] {
        let mut policy = registry("");
        policy.inline_ignores = inline_enabled;
        for comment in ["", " # rayloc:ignore"] {
            for (length, want) in [(65536, 0), (65537, 2)] {
                let input = format!("checksum_api_key='{}'{comment}", "a".repeat(length));
                let outcome = scan_reader_with_registry(&mut Cursor::new(input), 1, &policy);
                assert_eq!(outcome.exit_code(), want);
            }
        }
    }
}
#[test]
fn disabled_context_rules_skip_evaluation_but_enabled_branches_keep_limits() {
    let all_disabled =
        registry("aws-secret-access-key, password-assignment, context-secret, jose-token");
    let input = format!("password='{}'", "a".repeat(65537));
    assert_eq!(
        scan_reader_with_registry(&mut Cursor::new(&input), 1, &all_disabled).exit_code(),
        0
    );
    for disabled in ["password-assignment", "context-secret"] {
        assert_eq!(
            scan_reader_with_registry(&mut Cursor::new(&input), 1, &registry(disabled)).exit_code(),
            2
        );
    }
    let input = b"password='Q7v2n9B4x6M1z8K3'";
    let outcome =
        scan_reader_with_registry(&mut Cursor::new(input), 1, &registry("password-assignment"));
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.findings[0].rule.metadata().id, "context-secret");
    let input = b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD";
    let outcome = scan_reader_with_registry(
        &mut Cursor::new(input),
        1,
        &registry("aws-secret-access-key"),
    );
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.findings[0].rule.metadata().id, "context-secret");
    let input = format!("api_key='{}'", "a".repeat(65537));
    assert_eq!(
        scan_reader_with_registry(&mut Cursor::new(&input), 1, &registry("context-secret"))
            .exit_code(),
        0
    );
    let input = format!("aws_secret_access_key='{}'", "a".repeat(65537));
    assert_eq!(
        scan_reader_with_registry(
            &mut Cursor::new(&input),
            1,
            &registry("aws-secret-access-key, context-secret")
        )
        .exit_code(),
        0
    );
    assert_eq!(
        scan_reader_with_registry(&mut Cursor::new(&input), 1, &registry("context-secret"))
            .exit_code(),
        2
    );
    let mut counts = rayloc::rules::context::Suppressions {
        generic_filter: usize::MAX,
        ..Default::default()
    };
    registry("context-secret")
        .detect_line_with_suppressions(
            b"api_key=aaaaaaaaaaaaaaaa",
            &mut Histogram::new(),
            &mut counts,
            |_, _| panic!("disabled emission"),
        )
        .unwrap();
    assert_eq!(counts.generic_filter, usize::MAX);
    let input = format!("ghp_{}", "a".repeat(65537));
    assert_eq!(
        scan_reader_with_registry(&mut Cursor::new(input), 1, &all_disabled).exit_code(),
        2
    );
}
#[test]
fn padded_app_jwt_segments_are_rejected_without_emitting_a_truncated_prefix() {
    let policy = registry("");
    for token in [
        "ghs_1234_eyJhbGciOiJIUzI1NiJ9=.e30.AAAA",
        "ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30=.AAAA",
        "ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30.AAAA=",
        "ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30.AAAA==",
    ] {
        let outcome = scan_reader_with_registry(&mut Cursor::new(token), 1, &policy);
        assert_eq!(outcome.exit_code(), 0);
        assert!(outcome.findings.is_empty());
    }
    let token = "ghs_1234_eyJhbGciOiJIUzI1NiJ9.e30.AAAA";
    let outcome = scan_reader_with_registry(&mut Cursor::new(token), 1, &policy);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        (
            outcome.findings[0].start_column,
            outcome.findings[0].end_column
        ),
        (1, token.len() + 1)
    );
}
