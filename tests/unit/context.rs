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
fn directive_state_matches_complete_directive_at_each_split() {
    for (line, expected) in [
        (b"password='value \\\' # rayloc:ignore'".as_slice(), false),
        (b"x='unterminated # rayloc:ignore", false),
        (b"x=42 # rayloc:ignore later", false),
        (b"x=42 // ordinary", false),
        (b"x='https://example.com/#'", false),
        (b"x=42 // rayloc:ignore\r", true),
        (b"x=42 # rayloc:ignore  \t", true),
        (b"x=42 :// rayloc:ignore", false),
        (b"x=42 // rayloc:ignore\0", false),
        (b"x=42 // 'rayloc:ignore", false),
        (b"x=42 // first comment # rayloc:ignore", false),
        (b"x=42 'escaped \\\' quote' # rayloc:ignore", true),
        (b"x=42 'rayloc:ignore'", false),
    ] {
        assert_eq!(
            directive(line),
            expected,
            "fixture must agree with baseline"
        );
        for split in 0..=line.len() {
            let mut state = DirectiveState::new();
            state.push(&line[..split]);
            state.push(&line[split..]);
            assert_eq!(state.finish(), expected, "split {split} in {line:?}");
        }
        let mut bytewise = DirectiveState::new();
        for byte in line.chunks(1) {
            bytewise.push(byte);
        }
        assert_eq!(bytewise.finish(), expected, "bytewise {line:?}");
    }
}

#[test]
fn directive_state_reset_and_large_comment_are_bounded() {
    let mut state = DirectiveState::new();
    state.push(b"x=1 // ");
    state.push(&vec![b'a'; 2 * 1024 * 1024]);
    assert!(!state.finish());
    state.reset();
    state.push(b"x=1 # rayloc:ignore\r");
    assert!(state.finish());
}

#[test]
fn context_stream_matches_complete_line_across_every_split() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for line in [
        b"api_key=Q7v2n9B4x6M1z8K3".as_slice(),
        b"password='weakweak'",
        b"Authorization: Bearer Q7v2n9B4x6M1z8K3",
        b"Authorization: \"Bearer Q7v2n9B4x6M1z8K3\"",
        b"clientSecret=Q7v2n9B4x6M1z8K3",
        b"password='changeme'",
        b"api_key_sha256=9f21c7ab6e40d835",
        b"api_key=Q7v2n9B4x6M1z8K3 + suffix",
    ] {
        let mut expected = Vec::new();
        let mut expected_suppressions = Suppressions::default();
        registry
            .detect_line_with_suppressions(
                line,
                &mut Histogram::new(),
                &mut expected_suppressions,
                |rule, span| expected.push((rule, span)),
            )
            .unwrap();
        for split in 0..=line.len() {
            let mut state = ContextState::new();
            let mut actual = Vec::new();
            let mut histogram = Histogram::new();
            let mut suppressions = Suppressions::default();
            let mut emit = |candidate: Candidate<'_>| {
                actual.push((
                    candidate.rule,
                    candidate.span.start as usize..candidate.span.end as usize,
                ))
            };
            state
                .push(
                    &line[..split],
                    &registry,
                    &mut histogram,
                    &mut suppressions,
                    &mut emit,
                )
                .unwrap();
            state
                .push(
                    &line[split..],
                    &registry,
                    &mut histogram,
                    &mut suppressions,
                    &mut emit,
                )
                .unwrap();
            state
                .finish(&registry, &mut histogram, &mut suppressions, &mut emit)
                .unwrap();
            assert_eq!(actual, expected, "split {split} in {line:?}");
            assert_eq!(
                suppressions, expected_suppressions,
                "split {split} suppressions in {line:?}"
            );
        }
    }
}

#[test]
fn non_bearer_authorization_values_are_irrelevant_even_when_long() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut line = b"Authorization=\"".to_vec();
    line.extend(std::iter::repeat_n(b'x', MAX_CANDIDATE_BYTES + 10));
    line.push(b'"');
    let mut state = ContextState::new();
    let mut output = Vec::new();
    let mut emit = |candidate: Candidate<'_>| output.push(candidate.rule);
    state
        .push(
            &line,
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .expect("non-Bearer authorization content is not a candidate");
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert!(output.is_empty());
    assert!(state.value.capacity() <= MAX_CANDIDATE_BYTES);
}

#[test]
fn context_stream_handles_long_whitespace_irrelevant_values_and_suffix_names() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let long_spaces = vec![b' '; 2 * 1024 * 1024];
    let mut operator = b"api_key=Q7v2n9B4x6M1z8K3".to_vec();
    operator.extend_from_slice(&long_spaces);
    operator.extend_from_slice(b"+suffix");
    let mut huge_name = vec![b'x'; 2 * 1024 * 1024];
    huge_name.extend_from_slice(b"_password='weakweak'");
    let mut line = b"noise='embedded api_key=Q7v2n9B4x6M1z8K3'; ".to_vec();
    line.extend_from_slice(&huge_name);
    let mut state = ContextState::new();
    let mut out = Vec::new();
    let mut hist = Histogram::new();
    let mut sup = Suppressions::default();
    let mut emit = |c: Candidate<'_>| out.push((c.rule, c.value.to_vec()));
    for chunk in line.chunks(256 * 1024) {
        state
            .push(chunk, &registry, &mut hist, &mut sup, &mut emit)
            .unwrap();
    }
    state
        .finish(&registry, &mut hist, &mut sup, &mut emit)
        .unwrap();
    assert_eq!(out, [(RuleId::PasswordAssignment, b"weakweak".to_vec())]);
    assert!(state.value.capacity() <= MAX_CANDIDATE_BYTES);
    assert!(state.name.tail.capacity() <= 64);
    assert!(state.name.component.capacity() <= 32);

    state.reset();
    out.clear();
    hist = Histogram::new();
    sup = Suppressions::default();
    let mut emit = |c: Candidate<'_>| out.push((c.rule, c.value.to_vec()));
    for chunk in operator.chunks(256 * 1024) {
        state
            .push(chunk, &registry, &mut hist, &mut sup, &mut emit)
            .unwrap();
    }
    state
        .finish(&registry, &mut hist, &mut sup, &mut emit)
        .unwrap();
    assert!(out.is_empty(), "a distant operator rejects the candidate");
    assert!(state.value.capacity() <= MAX_CANDIDATE_BYTES);
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
