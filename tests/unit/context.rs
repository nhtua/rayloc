use super::*;
use crate::rules::context::{ContextState, DirectiveState, Suppressions};
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
fn directive_state_with_unterminated_quote_never_matches() {
    // An unterminated quote should never match the directive
    let mut state = DirectiveState::new();
    state.push(b"x='unterminated # rayloc:ignore");
    assert!(!state.finish());
}

#[test]
fn directive_state_with_escaped_quote_matches() {
    // Escaped quotes should not terminate the string
    let mut state = DirectiveState::new();
    state.push(b"x='escaped \\\' quote' # rayloc:ignore");
    assert!(state.finish());
}

#[test]
fn directive_state_with_uri_comment_does_not_match() {
    // URIs with # should not be treated as comments
    let mut state = DirectiveState::new();
    state.push(b"x='https://example.com/#fragment'");
    assert!(!state.finish());
}

#[test]
fn context_stream_with_exact_name_matching() {
    // Test exact name matching for known context fields
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    // Test api_key exact match
    state
        .push(
            b"api_key=Q7v2n9B4x6M1z8K3",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, RuleId::ContextSecret);
}

#[test]
fn context_stream_with_bearer_token() {
    // Test Bearer token detection in Authorization header
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"Authorization: Bearer Q7v2n9B4x6M1z8K3",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    // Should find the Bearer token
    assert_eq!(found.len(), 1);
}

#[test]
fn context_stream_reference_suppression() {
    // Test that references are suppressed
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"api_key=${ENV_VAR}",
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    assert!(found.is_empty());
    assert_eq!(suppressions.reference, 1);
}

fn detect_with_syntax(
    line: &[u8],
    syntax: crate::rules::SourceSyntax,
) -> (Vec<(RuleId, std::ops::Range<usize>)>, Suppressions) {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut findings = Vec::new();
    let mut suppressions = Suppressions::default();
    registry
        .detect_line_in_source(
            line,
            syntax,
            &mut Histogram::new(),
            &mut suppressions,
            |rule, span| findings.push((rule, span)),
        )
        .unwrap();
    (findings, suppressions)
}

fn stream_with_syntax(
    line: &[u8],
    syntax: crate::rules::SourceSyntax,
    split: usize,
) -> (Vec<(RuleId, std::ops::Range<usize>)>, Suppressions) {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::with_syntax(syntax);
    let mut findings = Vec::new();
    let mut histogram = Histogram::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |candidate: Candidate<'_>| {
        findings.push((
            candidate.rule,
            candidate.span.start as usize..candidate.span.end as usize,
        ));
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
    (findings, suppressions)
}

#[test]
fn code_members_do_not_become_generic_or_password_findings() {
    let line = b"api_key=args.vllm_api_key; api_key=self.allow_credentials; api_key=self.DUMMY_API_KEY; api_key=args.allow_credentials; api_key=auth.accessToken; api_key=deps.completeCredential; api_key=input.credential; api_key=row.externalCredential ?? null; api_key=input.configPath; api_key=grantRef.configPath; api_key=input.env.COGNEE_API_KEY; api_key=credentials.accessToken; password=credentials.clientSecret)";
    let (findings, suppressions) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
    assert!(findings.is_empty());
    assert_eq!(suppressions.reference, 13);

    for split in 0..=line.len() {
        let (streamed, counters) =
            stream_with_syntax(line, crate::rules::SourceSyntax::Code, split);
        assert_eq!(streamed, findings, "split {split}");
        assert_eq!(counters, suppressions, "split {split}");
    }
}

#[test]
fn ternary_keys_are_not_bindings_but_real_code_values_remain_eligible() {
    for line in [
        b"route.auth === \"api_key\" ? \"ANTHROPIC_API_KEY\" : \"ANTHROPIC_AUTH_TOKEN\"".as_slice(),
        b"condition ? \"configPath\" : \"fallbackToken\"",
        b"condition ? TOKEN : \"fallback\"",
    ] {
        let (findings, suppressions) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
        assert!(findings.is_empty(), "{line:?}");
        assert_eq!(suppressions.reference, 0, "{line:?}");
        for split in 0..=line.len() {
            let (streamed, counters) =
                stream_with_syntax(line, crate::rules::SourceSyntax::Code, split);
            assert!(streamed.is_empty(), "split {split} in {line:?}");
            assert_eq!(counters.reference, 0, "split {split} in {line:?}");
        }
    }

    let secret = b"Q7v2n9B4x6M1z8K3";
    for line in [
        [b"flag ? {api_key: ".as_slice(), secret, b"} : fallback"].concat(),
        [b"condition ? TOKEN : { api_key: ".as_slice(), secret, b" }"].concat(),
        [b"  api_key: ".as_slice(), secret, b", // isolated property"].concat(),
        b"route.auth === \"selector\" ? \"KEY_A\" : \"KEY_B\"; password='weakweak'".to_vec(),
    ] {
        let (findings, _) = detect_with_syntax(&line, crate::rules::SourceSyntax::Code);
        if line
            .windows(b"weakweak".len())
            .any(|part| part == b"weakweak")
        {
            assert!(
                findings
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::PasswordAssignment)
            );
        } else {
            assert!(
                findings
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::ContextSecret)
            );
        }
    }
}

#[test]
fn code_syntax_keeps_opaque_values_and_weak_passwords_eligible() {
    let token = b"Q7v2n9B4x6M1z8K3";
    for syntax in [
        crate::rules::SourceSyntax::Text,
        crate::rules::SourceSyntax::Code,
    ] {
        let generic = [b"api_key=".as_slice(), token].concat();
        let (findings, _) = detect_with_syntax(&generic, syntax);
        assert!(
            findings
                .iter()
                .any(|(rule, _)| *rule == RuleId::ContextSecret)
        );

        let (findings, _) = detect_with_syntax(b"password=aaaaaaaa", syntax);
        assert!(
            findings
                .iter()
                .any(|(rule, _)| *rule == RuleId::PasswordAssignment)
        );

        let literal = [b"password='self.DUMMY_API_KEY'; password='config.password'; password='ANTHROPIC_AUTH_TOKEN'".as_slice()];
        let (findings, suppressions) = detect_with_syntax(&literal.concat(), syntax);
        assert_eq!(
            findings
                .iter()
                .filter(|(rule, _)| *rule == RuleId::PasswordAssignment)
                .count(),
            3
        );
        assert_eq!(suppressions.reference, 0);
    }

    let (findings, counters) =
        detect_with_syntax(b"password='${PASSWORD}'", crate::rules::SourceSyntax::Code);
    assert!(findings.is_empty());
    assert_eq!(counters.reference, 1);

    let generic = [b"allowCredentials=".as_slice(), token].concat();
    let (findings, _) = detect_with_syntax(&generic, crate::rules::SourceSyntax::Code);
    assert!(
        findings
            .iter()
            .any(|(rule, _)| *rule == RuleId::ContextSecret)
    );
}

#[test]
fn equality_associations_report_password_literals_with_exact_spans() {
    for line in [
        b"if (password == 'weakweak') {}".as_slice(),
        b"if (password === 'weakweak') {}",
    ] {
        let (findings, _) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
        let start = line
            .windows(b"weakweak".len())
            .position(|part| part == b"weakweak")
            .unwrap();
        assert!(
            findings.contains(&(RuleId::PasswordAssignment, start..start + 8)),
            "{line:?}: {findings:?}"
        );
        for split in 0..=line.len() {
            assert_eq!(
                stream_with_syntax(line, crate::rules::SourceSyntax::Code, split).0,
                findings,
                "split {split}"
            );
        }
    }

    let line = b"api_key === 'Q7v2n9B4x6M1z8K3'";
    let (findings, _) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
    assert!(
        findings
            .iter()
            .any(|(rule, _)| *rule == RuleId::ContextSecret)
    );
    for split in 0..=line.len() {
        assert_eq!(
            stream_with_syntax(line, crate::rules::SourceSyntax::Code, split).0,
            findings,
            "split {split}"
        );
    }

    let crlf = b"password='weakweak'\r";
    let (findings, _) = detect_with_syntax(crlf, crate::rules::SourceSyntax::Code);
    assert!(
        findings
            .iter()
            .any(|(rule, _)| *rule == RuleId::PasswordAssignment)
    );
    for split in 0..=crlf.len() {
        assert_eq!(
            stream_with_syntax(crlf, crate::rules::SourceSyntax::Code, split).0,
            findings,
            "CRLF split {split}"
        );
    }
}

#[test]
fn non_association_operators_do_not_create_context_candidates() {
    for line in [
        b"api_key => 'Q7v2n9B4x6M1z8K3'".as_slice(),
        b"api_key::'Q7v2n9B4x6M1z8K3'",
        b"api_key:='Q7v2n9B4x6M1z8K3'",
        b"flag ? api_key: 'Q7v2n9B4x6M1z8K3'",
    ] {
        let (expected, counters) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
        assert!(expected.is_empty(), "{line:?}");
        assert_eq!(counters.reference, 0, "{line:?}");
        for split in 0..=line.len() {
            let (actual, streamed) =
                stream_with_syntax(line, crate::rules::SourceSyntax::Code, split);
            assert_eq!(actual, expected, "split {split} in {line:?}");
            assert_eq!(streamed, counters, "split {split} in {line:?}");
        }
    }
}

#[test]
fn code_member_operators_are_split_safe_and_require_complete_identifiers() {
    let line = b"api_key=node->secret; api_key=client?.credential";
    let (expected, suppressions) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
    assert!(expected.is_empty());
    assert_eq!(suppressions.reference, 2);
    for split in 0..=line.len() {
        let (actual, counters) = stream_with_syntax(line, crate::rules::SourceSyntax::Code, split);
        assert_eq!(actual, expected, "split {split}");
        assert_eq!(counters, suppressions, "split {split}");
    }

    let line = b"api_key=client?.";
    let (findings, suppressions) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
    assert!(findings.is_empty());
    assert_eq!(suppressions.reference, 0);
    for split in 0..=line.len() {
        let (actual, counters) = stream_with_syntax(line, crate::rules::SourceSyntax::Code, split);
        assert_eq!(actual, findings, "split {split}");
        assert_eq!(counters, suppressions, "split {split}");
    }
}

#[test]
fn text_assignment_and_unquoted_literals_keep_legacy_behavior() {
    let (text_findings, _) =
        detect_with_syntax(b"PASSWORD==aaaaaaaa", crate::rules::SourceSyntax::Text);
    assert!(
        text_findings
            .iter()
            .any(|(rule, _)| *rule == RuleId::PasswordAssignment)
    );

    for line in [
        b"password=self.DUMMY_API_KEY".as_slice(),
        b"PASSWORD=aaaaaaaa",
    ] {
        let (findings, _) = detect_with_syntax(line, crate::rules::SourceSyntax::Text);
        assert!(
            findings
                .iter()
                .any(|(rule, _)| *rule == RuleId::PasswordAssignment),
            "{line:?}"
        );
    }
    let (code_findings, code_suppressions) = detect_with_syntax(
        b"password=self.DUMMY_API_KEY",
        crate::rules::SourceSyntax::Code,
    );
    assert!(code_findings.is_empty());
    assert_eq!(code_suppressions.reference, 1);
}

#[test]
fn code_test_credentials_keep_existing_inline_ignore_controls() {
    assert_eq!(
        crate::rules::SourceSyntax::from_path(b"fixture.test.ts"),
        crate::rules::SourceSyntax::Code
    );
    let line = b"password='aaaaaaaa' # rayloc:ignore";
    let (ignored, counters) = detect_with_syntax(line, crate::rules::SourceSyntax::Code);
    assert!(ignored.is_empty());
    assert_eq!(counters.inline, 1);

    let mut registry = Registry::compile(crate::config::Config::default()).unwrap();
    registry.inline_ignores = false;
    let mut findings = Vec::new();
    registry
        .detect_line_in_source(
            line,
            crate::rules::SourceSyntax::Code,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            |rule, span| findings.push((rule, span)),
        )
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].0, RuleId::PasswordAssignment);

    let unsupported = b"password='aaaaaaaa' # rayloc:ignored";
    let (findings, counters) = detect_with_syntax(unsupported, crate::rules::SourceSyntax::Code);
    assert_eq!(findings.len(), 1);
    assert_eq!(counters.inline, 0);
}

#[test]
fn source_grammar_does_not_change_provider_or_custom_matches() {
    let registry = Registry::compile(
        crate::config::parse(
            b"version: \"1\"\nrules: [{id: marker, regex: '(?P<value>client\\.secret)'}]",
        )
        .unwrap(),
    )
    .unwrap();
    let mut found = Vec::new();
    let mut suppressions = Suppressions::default();
    registry
        .detect_line_in_source(
            b"api_key=client.secret",
            crate::rules::SourceSyntax::Code,
            &mut Histogram::new(),
            &mut suppressions,
            |rule, span| found.push((rule, span)),
        )
        .unwrap();
    assert!(
        found
            .iter()
            .any(|(rule, _)| matches!(rule, RuleId::Custom(..)))
    );
    assert_eq!(suppressions.reference, 1);

    let mut provider = Vec::new();
    registry
        .detect_line_in_source(
            b"api_key=ghp_12345678901234567890",
            crate::rules::SourceSyntax::Code,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            |rule, span| provider.push((rule, span)),
        )
        .unwrap();
    assert!(
        provider
            .iter()
            .any(|(rule, _)| *rule == RuleId::GithubToken)
    );
}

#[test]
fn code_reference_limits_and_counter_overflow_are_checked_before_suppression() {
    let mut long = b"api_key=client.".to_vec();
    long.extend(std::iter::repeat_n(b'x', MAX_CANDIDATE_BYTES));
    long.extend_from_slice(b" # rayloc:ignore");
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    assert_eq!(
        registry.detect_line_in_source(
            &long,
            crate::rules::SourceSyntax::Code,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            |_, _| {},
        ),
        Err(ScanError::CandidateLimit)
    );

    let mut counters = Suppressions {
        reference: usize::MAX,
        ..Suppressions::default()
    };
    assert_eq!(
        registry.detect_line_in_source(
            b"api_key=client.secret",
            crate::rules::SourceSyntax::Code,
            &mut Histogram::new(),
            &mut counters,
            |_, _| {},
        ),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn context_stream_placeholder_suppression() {
    // Test that placeholders are suppressed
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"password='changeme'",
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    assert!(found.is_empty());
    assert_eq!(suppressions.placeholder, 1);
}

#[test]
fn descriptive_api_key_placeholders_are_suppressed_at_every_input_split() {
    let registry = &crate::rules::BUILTINS;
    for line in [
        b"export HINDSIGHT_API_LLM_API_KEY=your-minimax-api-key".as_slice(),
        b"export HINDSIGHT_API_LLM_API_KEY=your-atlascloud-api-key",
        b"export HINDSIGHT_API_LLM_API_KEY=your-meta-model-api-key",
        b"export HINDSIGHT_API_RERANKER_ALIBABA_API_KEY=your-dashscope-api-key",
        b"api_key='your_meta_model_api_key'",
        b"api_key: \"YOUR_META_MODEL_API_KEY_HERE\"",
        b"api_key=your-api-key",
        b"api_key=your_api_key_here",
    ] {
        let mut counts = Suppressions::default();
        detect(
            line,
            crate::rules::SourceSyntax::Text,
            registry,
            &mut Histogram::new(),
            &mut counts,
            |_, _| panic!("placeholder emitted"),
        )
        .unwrap();
        assert_eq!(counts.placeholder, 1);
        for split in 0..=line.len() {
            let mut state = ContextState::new();
            let mut counts = Suppressions::default();
            let mut histogram = Histogram::new();
            for fragment in [&line[..split], &line[split..]] {
                state
                    .push(fragment, registry, &mut histogram, &mut counts, |_| {
                        panic!("streamed placeholder emitted at split {split}")
                    })
                    .unwrap();
            }
            state
                .finish(registry, &mut histogram, &mut counts, |_| {
                    panic!("streamed placeholder emitted at split {split}")
                })
                .unwrap();
            assert_eq!(counts.placeholder, 1, "split {split}");
        }
    }
}

#[test]
fn placeholder_patterns_do_not_hide_concrete_values_or_passwords() {
    for value in [
        b"Q7v2_n9B4_x6M1z8K3".as_slice(),
        b"your_Q7v2_n9B4_api_key",
        b"prefix_your_meta_model_api_key",
        b"your_meta_model_api_key_suffix",
        b"your__meta_api_key",
        b"your-meta_model-api-key",
        b"your-meta-model-api-key!",
        b"your-meta-model-client-secret",
        b"yourmeta-model-api-key",
        b"your",
    ] {
        assert!(!placeholder(value, false, false));
    }
    assert!(!placeholder(b"your-meta-model-api-key", true, false));
}

#[test]
fn context_stream_checksum_suppression() {
    // Test that checksums are suppressed
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"api_key_sha256=9f21c7ab6e40d835",
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    assert!(found.is_empty());
    assert_eq!(suppressions.checksum, 1);
}

#[test]
fn context_stream_aws_secret_detection() {
    // Test AWS secret access key detection
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let value = b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab+/";
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab+/",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found, [(RuleId::AwsSecretAccessKey, value.to_vec())]);
}

#[test]
fn context_stream_sequential_suppression() {
    // Test that same-byte values are suppressed
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"api_key=AAAAAAAAAAAAAAAA",
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    assert!(found.is_empty());
    assert_eq!(suppressions.generic_filter, 1);
}

#[test]
fn context_stream_candidate_limit_is_enforced() {
    // Test that oversized candidates return CandidateLimit
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    // Create an oversized value (> 64KB) for api_key (which is a strong field)
    let mut line = b"api_key=".to_vec();
    line.extend(std::iter::repeat_n(b'A', 65537));

    let result = state.push(
        &line,
        &registry,
        &mut Histogram::new(),
        &mut Suppressions::default(),
        &mut emit,
    );
    assert_eq!(result, Err(ScanError::CandidateLimit));
}

#[test]
fn context_stream_with_bearer_jose_token() {
    // Test Bearer JOSE token detection
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgBTBF",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    // Should find the JOSE token
    assert!(!found.is_empty());
}

#[test]
fn context_stream_with_client_secret() {
    // Test client_secret detection
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"client_secret=Q7v2n9B4x6M1z8K3",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, RuleId::ContextSecret);
}

#[test]
fn context_stream_with_password_assignment() {
    // Test password assignment detection
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"password='weakweak'",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, RuleId::PasswordAssignment);
}

#[test]
fn context_stream_with_quoted_values() {
    // Test quoted value handling
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"api_key=\"Q7v2n9B4x6M1z8K3\"",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, b"Q7v2n9B4x6M1z8K3");
}

#[test]
fn context_stream_with_escaped_quotes_in_name() {
    // Test escaped quotes in quoted name
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"'not\\'a_key'=ignored api_key=Q7v2n9B4x6M1z8K3",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    // Should find the key with quoted name
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, b"Q7v2n9B4x6M1z8K3");
}

#[test]
fn authorization_parser_rejects_non_bearer_and_preserves_bearer_spacing() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for line in [
        b"Authorization: Basi Q7v2n9B4x6M1z8K3".as_slice(),
        b"Authorization: \"Basic Q7v2n9B4x6M1z8K3\"",
        b"Authorization: \"Basic \\\"quoted\\\" token\"",
    ] {
        let mut state = ContextState::new();
        let mut findings = Vec::new();
        let mut histogram = Histogram::new();
        let mut suppressions = Suppressions::default();
        let mut emit = |candidate: Candidate<'_>| findings.push(candidate.rule);
        state
            .push(
                line,
                &registry,
                &mut histogram,
                &mut suppressions,
                &mut emit,
            )
            .unwrap();
        state
            .finish(&registry, &mut histogram, &mut suppressions, &mut emit)
            .unwrap();
        assert!(findings.is_empty(), "non-Bearer value: {line:?}");
    }

    let line = b"Authorization: Bearer   Q7v2n9B4x6M1z8K3";
    let mut state = ContextState::new();
    let mut findings = Vec::new();
    let mut histogram = Histogram::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |candidate: Candidate<'_>| {
        findings.push((candidate.rule, candidate.span));
    };
    state
        .push(
            line,
            &registry,
            &mut histogram,
            &mut suppressions,
            &mut emit,
        )
        .unwrap();
    state
        .finish(&registry, &mut histogram, &mut suppressions, &mut emit)
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        &line[findings[0].1.start as usize..findings[0].1.end as usize],
        b"Q7v2n9B4x6M1z8K3"
    );
}

#[test]
fn context_stream_with_comment_after_value() {
    // Test comment after value
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut state = ContextState::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.rule, c.value.to_vec()));

    state
        .push(
            b"api_key=Q7v2n9B4x6M1z8K3 // comment",
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    state
        .finish(
            &registry,
            &mut Histogram::new(),
            &mut Suppressions::default(),
            &mut emit,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, b"Q7v2n9B4x6M1z8K3");
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

#[test]
fn context_phase2_field_suffixes_in_strong_list() {
    let suffixes: [&str; 31] = [
        "api_key",
        "access_token",
        "client_secret",
        "credential",
        "credentials",
        "auth_token",
        "secret_key",
        "datadog_api_key",
        "datadog_app_key",
        "azure_ad_client_secret",
        "npm_token",
        "nuget_api_key",
        "pagerduty_key",
        "pagerduty_integration_key",
        "snyk_token",
        "sonar_token",
        "newrelic_license_key",
        "newrelic_insights_key",
        "splunk_observability_token",
        "intercom_api_key",
        "vultr_api_key",
        "trello_api_key",
        "postman_api_key",
        "unsplash_api_key",
        "sumologic_access_id",
        "sumologic_access_key",
        "grafana_service_account",
        "honeycomb_api_key",
        "logdna_api_key",
        "zoom_oauth_client_secret",
        "allow_credentials",
    ];
    for suffix in suffixes {
        let line = format!("{suffix}=Q7v2n9B4x6M1z8K3");
        let (complete, complete_suppressions) =
            detect_with_syntax(line.as_bytes(), crate::rules::SourceSyntax::Text);
        let (streamed, stream_suppressions) = stream_with_syntax(
            line.as_bytes(),
            crate::rules::SourceSyntax::Text,
            line.len(),
        );
        assert_eq!(
            complete,
            [(RuleId::ContextSecret, suffix.len() + 1..line.len())],
            "{suffix}"
        );
        assert_eq!(streamed, complete, "streaming field {suffix}");
        assert_eq!(
            complete_suppressions, stream_suppressions,
            "counters {suffix}"
        );
    }

    let long_name = format!("checksum_{}_api_key=Q7v2n9B4x6M1z8K3", "x".repeat(80));
    let (complete, complete_suppressions) =
        detect_with_syntax(long_name.as_bytes(), crate::rules::SourceSyntax::Text);
    let (streamed, stream_suppressions) = stream_with_syntax(
        long_name.as_bytes(),
        crate::rules::SourceSyntax::Text,
        long_name.len(),
    );
    assert!(complete.is_empty());
    assert!(streamed.is_empty());
    assert_eq!(complete_suppressions.checksum, 1);
    assert_eq!(stream_suppressions, complete_suppressions);
}

#[test]
fn context_stream_rejects_malformed_and_low_confidence_assignments() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut histogram = Histogram::new();
    let mut suppressions = Suppressions::default();
    let mut emitted = Vec::new();

    for line in [
        // Quoted values may contain delimiters that terminate an unquoted value.
        b"api_key='Q7v2n9B4x6M1z8K3\\'".as_slice(),
        b"api_key=Q7v2n9B4x6M1z8K3(continued)",
        b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab+*",
        b"api_key=aaaaaaaaaaaaaaaZ",
    ] {
        let mut state = ContextState::new();
        let mut emit = |candidate: Candidate<'_>| {
            emitted.push((line.to_vec(), candidate.rule, candidate.value.to_vec()))
        };
        state
            .push(
                line,
                &registry,
                &mut histogram,
                &mut suppressions,
                &mut emit,
            )
            .unwrap();
        state
            .finish(&registry, &mut histogram, &mut suppressions, &mut emit)
            .unwrap();
    }

    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].1, RuleId::ContextSecret);
    assert!(emitted[0].0.starts_with(b"aws_secret_access_key="));
    assert_eq!(suppressions.generic_filter, 0);
}

#[test]
fn context_stream_reports_suppression_counter_overflow() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for (line, kind) in [
        (b"password='${PASSWORD}'".as_slice(), 0),
        (b"password='changeme'", 1),
        (b"api_key_sha256=9f21c7ab6e40d835", 2),
        (b"api_key=AAAAAAAAAAAAAAAA", 3),
    ] {
        let mut suppressions = Suppressions::default();
        match kind {
            0 => suppressions.reference = usize::MAX,
            1 => suppressions.placeholder = usize::MAX,
            2 => suppressions.checksum = usize::MAX,
            _ => suppressions.generic_filter = usize::MAX,
        }
        let mut state = ContextState::new();
        let mut histogram = Histogram::new();
        let mut emit = |_candidate: Candidate<'_>| {};
        let result = state
            .push(
                line,
                &registry,
                &mut histogram,
                &mut suppressions,
                &mut emit,
            )
            .and_then(|()| state.finish(&registry, &mut histogram, &mut suppressions, &mut emit));
        assert_eq!(result, Err(ScanError::CounterOverflow));
    }
}

#[test]
fn context_state_fails_closed_on_offset_and_value_counter_overflow() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut histogram = Histogram::new();
    let mut suppressions = Suppressions::default();
    let mut emit = |_candidate: Candidate<'_>| {};

    let mut empty = ContextState::new();
    empty
        .finish(&registry, &mut histogram, &mut suppressions, &mut emit)
        .unwrap();

    let mut offset_overflow = ContextState::new();
    offset_overflow.offset = u64::MAX;
    assert_eq!(
        offset_overflow.push(
            b"x",
            &registry,
            &mut histogram,
            &mut suppressions,
            &mut emit,
        ),
        Err(ScanError::CounterOverflow)
    );

    let mut quoted_start_overflow = ContextState::new();
    quoted_start_overflow.mode = super::ContextMode::BeforeValue;
    quoted_start_overflow.offset = u64::MAX;
    assert_eq!(
        quoted_start_overflow.push(
            b"'",
            &registry,
            &mut histogram,
            &mut suppressions,
            &mut emit,
        ),
        Err(ScanError::CounterOverflow)
    );

    let mut value_length_overflow = ContextState::new();
    value_length_overflow.mode = super::ContextMode::UnquotedValue;
    value_length_overflow.active = true;
    value_length_overflow.value_len = usize::MAX;
    assert_eq!(
        value_length_overflow.push(
            b"x",
            &registry,
            &mut histogram,
            &mut suppressions,
            &mut emit,
        ),
        Err(ScanError::CounterOverflow)
    );

    let mut value_end_overflow = ContextState::new();
    value_end_overflow.mode = super::ContextMode::Pending;
    value_end_overflow.active = true;
    value_end_overflow.has_password_field = true;
    value_end_overflow.password_enabled = true;
    value_end_overflow.value.extend_from_slice(b"longsecret");
    value_end_overflow.value_len = value_end_overflow.value.len();
    value_end_overflow.value_start = u64::MAX - 4;
    assert_eq!(
        value_end_overflow.finish(&registry, &mut histogram, &mut suppressions, &mut emit,),
        Err(ScanError::CounterOverflow)
    );
}
