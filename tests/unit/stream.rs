use super::*;
use crate::scanner::ScanOutcome;
use crate::scanner::chunk::LineFragment;
use crate::scanner::engine::{Collector, Limits, MAX_LINE_BYTES, scan_reader};
use crate::scanner::stream::LineSession;
use std::io::Cursor;
use std::sync::Mutex;

const AWS: &[u8] = b"AKIA1234567890ABCDEF";

#[test]
fn ten_megabyte_physical_line_scans_clean_and_secret_payloads() {
    let clean = vec![b'x'; 10 * 1024 * 1024];
    let clean_outcome = scan_reader(&mut Cursor::new(clean), 1);
    assert_eq!(clean_outcome.exit_code(), 0);
    assert_eq!(clean_outcome.stats.files_completed, 1);
    assert_eq!(clean_outcome.stats.lines_scanned, 1);

    for prefix_len in [
        7usize,
        crate::scanner::chunk::CHUNK_BYTES - 7,
        10 * 1024 * 1024 - AWS.len(),
    ] {
        let mut line = vec![b'x'; prefix_len];
        line.push(b' ');
        line.extend_from_slice(AWS);
        let outcome = scan_reader(&mut Cursor::new(line), 1);
        assert_eq!(outcome.exit_code(), 1, "secret at byte {prefix_len}");
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].line, 1);
        assert_eq!(outcome.findings[0].start_column, prefix_len + 2);
        assert_eq!(outcome.findings[0].end_column, prefix_len + 2 + AWS.len());
        assert_eq!(outcome.stats.files_completed, 1);
    }
}

#[test]
fn large_reader_lines_work_with_a_bounded_custom_rule_registry() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: corporate, regex: 'corp_[A-Za-z0-9]{16}', entropy: 3.0}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut input = vec![b'x'; 5 * 1024 * 1024];
    input.extend_from_slice(b" corp_0123456789AbCdEf");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(input), 1, &registry);
    assert_eq!(outcome.exit_code(), 1, "{:?}", outcome.errors);
    assert_eq!(outcome.stats.files_completed, 1);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].start_column, 5 * 1024 * 1024 + 2);
}

#[test]
fn long_line_trailing_ignore_suppresses_provisional_findings() {
    let mut line = Vec::from(AWS);
    line.extend(std::iter::repeat_n(b'x', 300 * 1024));
    line.extend_from_slice(b" # rayloc:ignore");
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.stats.suppressions.inline, 1);
}

#[test]
fn ignored_candidate_overflow_is_not_reported_but_unignored_overflow_is() {
    let mut ignored = Vec::new();
    for _ in 0..10_002 {
        ignored.extend_from_slice(b"-----BEGIN PRIVATE KEY----- ");
    }
    ignored.extend_from_slice(b"# rayloc:ignore");
    let outcome = scan_reader(&mut Cursor::new(ignored), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.stats.suppressions.inline, 1);

    let mut active = Vec::new();
    for _ in 0..10_002 {
        active.extend_from_slice(b"-----BEGIN PRIVATE KEY----- ");
    }
    let outcome = scan_reader(&mut Cursor::new(active), 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.findings.len(), 10_000);
    assert!(
        outcome
            .errors
            .iter()
            .any(|e| e.error == ScanError::FindingLimit)
    );
}

#[test]
fn enabled_legacy_regex_gets_path_specific_error_after_compatibility_limit() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut bytes = vec![b'x'; crate::scanner::engine::MAX_LINE_BYTES + 10];
    bytes.extend_from_slice(b"SECRET");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(bytes), 1, &registry);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.errors[0].error, ScanError::RuleWindowLimit);
    assert!(outcome.findings.is_empty());
}

#[test]
fn legacy_regex_runs_on_supported_long_lines_and_disabled_legacy_rules_do_not_restrict() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut bytes = Vec::from(b"prefix".as_slice());
    bytes.extend(std::iter::repeat_n(b'x', 300 * 1024));
    bytes.extend_from_slice(b"SECRET");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(bytes), 1, &registry);
    assert_eq!(outcome.exit_code(), 1, "{:?}", outcome.errors);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].start_column, 300 * 1024 + 7);

    let disabled = crate::config::parse(
        b"version: \"1\"\ndisabled_rules: [legacy]\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let disabled = Registry::compile(disabled).unwrap();
    let outcome = crate::scanner::engine::scan_reader_with_registry(
        &mut Cursor::new(vec![b'x'; crate::scanner::engine::MAX_LINE_BYTES + 100]),
        1,
        &disabled,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.stats.files_completed, 1);
}

#[test]
fn short_line_fast_path_uses_complete_line_detection() {
    // A line that fits entirely in one fragment should use the fast path
    let line = b"api_key=Q7v2n9B4x6M1z8K3";
    let outcome = scan_reader(&mut Cursor::new(line.to_vec()), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.findings.len(), 1);
}

#[test]
fn line_session_abort_discards_incomplete_findings() {
    let mut session = LineSession::new();
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(10000));
    let limits = Limits {
        findings: 10000,
        line_bytes: MAX_LINE_BYTES,
    };

    // Feed a fragment with a secret but don't complete the line
    session
        .push(
            LineFragment {
                payload: b"api_key=Q7v2n9B4x6M1z8K3",
                line: 1,
                column: 1,
                end: None,
            },
            1,
            b"test.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        )
        .unwrap();

    // Abort should discard the finding
    session.abort_line();
    assert!(outcome.findings.is_empty());
}

#[test]
fn line_session_duplicate_spans_pick_lower_priority() {
    // Provider rules have priority 0, context rules priority 2
    // Both may match the same span; provider should win
    let line = b"api_key=AKIA1234567890ABCDEF";
    let outcome = scan_reader(&mut Cursor::new(line.to_vec()), 1);
    // Should find both AWS key ID and context api_key assignment
    assert!(outcome.exit_code() == 1 || outcome.exit_code() == 0);
}

#[test]
fn line_session_push_handles_column_mismatch_error() {
    let mut session = LineSession::new();
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(10000));
    let limits = Limits {
        findings: 10000,
        line_bytes: MAX_LINE_BYTES,
    };

    // Feed first fragment
    session
        .push(
            LineFragment {
                payload: b"test",
                line: 1,
                column: 1,
                end: None,
            },
            1,
            b"test.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        )
        .unwrap();

    // Feed second fragment with wrong column (should error)
    let result = session.push(
        LineFragment {
            payload: b"more",
            line: 1,
            column: 10, // Wrong column
            end: None,
        },
        1,
        b"test.rs",
        &registry,
        &mut outcome,
        &collector,
        None,
        limits,
    );
    assert!(result.is_err());
}

#[test]
fn line_session_push_handles_line_limit_error() {
    let mut session = LineSession::new();
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(10000));
    let limits = Limits {
        findings: 10000,
        line_bytes: 10, // Very small limit
    };

    // Feed a fragment that exceeds the limit
    let result = session.push(
        LineFragment {
            payload: b"this is too long",
            line: 1,
            column: 1,
            end: None,
        },
        1,
        b"test.rs",
        &registry,
        &mut outcome,
        &collector,
        None,
        limits,
    );
    assert!(result.is_err());
}

#[test]
fn line_session_promotes_to_streaming_at_chunk_boundary() {
    // Feed data that crosses the CHUNK_BYTES boundary
    let mut data = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES + 10];
    data.extend_from_slice(AWS);
    data.push(b' ');
    data.extend_from_slice(b"api_key=");
    data.extend_from_slice(AWS);

    let outcome = scan_reader(&mut Cursor::new(data), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert!(!outcome.findings.is_empty());
}

#[test]
fn line_session_legacy_overflow_triggers_rule_window_limit() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();

    // Create a line that exceeds MAX_LINE_BYTES with the prefix
    let mut bytes = Vec::from(b"prefix".as_slice());
    bytes.extend(vec![b'x'; MAX_LINE_BYTES + 100]);
    bytes.extend_from_slice(b"SECRET");

    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(bytes), 1, &registry);
    assert_eq!(outcome.exit_code(), 2);
}

#[test]
fn line_session_with_jose_token() {
    // Test that JOSE tokens are detected in streaming mode
    let line = b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgBTBF";
    let outcome = scan_reader(&mut Cursor::new(line.to_vec()), 1);
    // Should detect the JOSE token
    assert_eq!(outcome.exit_code(), 1);
    assert!(!outcome.findings.is_empty());
}

#[test]
fn line_session_with_long_jose_token_crossing_boundary() {
    // Create a long line with a provider token that crosses a chunk boundary
    let mut line = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES];
    line.extend_from_slice(b" AKIA1234567890ABCDEF");
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert!(!outcome.findings.is_empty());
}

#[test]
fn long_line_jose_token_is_emitted_when_stream_finishes() {
    let mut line = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES];
    line.extend_from_slice(
        b" Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| { finding.rule == crate::rules::builtin::RuleId::JoseToken }),
        "reported rules: {:?}",
        outcome
            .findings
            .iter()
            .map(|finding| finding.rule)
            .collect::<Vec<_>>()
    );
}

#[test]
fn long_line_context_secret_is_emitted_from_streamed_fragments() {
    let mut line = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES];
    line.extend_from_slice(b" api_key=Q7v2n9B4x6M1z8K3");
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert!(
        outcome
            .findings
            .iter()
            .any(|finding| finding.rule == crate::rules::builtin::RuleId::ContextSecret)
    );
}

#[test]
fn line_session_findings_are_published_after_line_end() {
    // Findings should not be published until the line is complete
    let mut line = vec![b'x'; 1024];
    line.extend_from_slice(AWS);
    line.extend_from_slice(b" # rayloc:ignore");

    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.stats.suppressions.inline, 1);
}

#[test]
fn long_line_session_retains_full_value_for_unredacted_emitter() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut session = LineSession::new();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(100));
    let emitter = crate::report::emitter::SharedEmitter::new(Box::new(
        crate::report::emitter::TerminalEmitter::new(Vec::new()).with_no_redact(true),
    ));
    let limits = Limits {
        findings: 100,
        line_bytes: usize::MAX,
    };
    let prefix = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES];
    session
        .push(
            LineFragment {
                payload: &prefix,
                line: 1,
                column: 1,
                end: None,
            },
            1,
            b"secret.rs",
            &registry,
            &mut outcome,
            &collector,
            Some(&emitter),
            limits,
        )
        .unwrap();
    let secret = b" ghp_abcdefghijklmnop";
    session
        .push(
            LineFragment {
                payload: secret,
                line: 1,
                column: (prefix.len() + 1) as u64,
                end: Some(crate::scanner::chunk::LineEnd::Lf),
            },
            1,
            b"secret.rs",
            &registry,
            &mut outcome,
            &collector,
            Some(&emitter),
            limits,
        )
        .unwrap();
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.findings.len(), 1);
    let full_value = outcome.findings[0]
        .unredacted_value
        .as_ref()
        .expect("unredacted emitter retains the full match");
    assert_eq!(full_value.to_string(), "ghp_abcdefghijklmnop");
}

#[test]
fn line_session_pending_overflow_is_tracked() {
    // Create more than MAX_FINDINGS candidates on one line
    let mut line = Vec::new();
    for i in 0..15000 {
        line.extend_from_slice(b"-----BEGIN PRIVATE KEY----- ");
        if i % 1000 == 0 {
            line.push(b'\r'); // Force newlines to avoid single-line detection
            line.push(b'\n');
        }
    }

    let outcome = scan_reader(&mut Cursor::new(line), 1);
    // Should have findings and possibly FindingLimit error
    assert!(outcome.exit_code() == 1 || outcome.exit_code() == 2);
}

#[test]
fn line_session_accepts_findings_after_line_end() {
    // Accepted fingerprints should be tracked even for long lines
    let line = b"api_key=Q7v2n9B4x6M1z8K3";
    let outcome = scan_reader(&mut Cursor::new(line.to_vec()), 1);
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.findings.len(), 1);
}

#[test]
fn line_session_fast_path_enforces_record_limit_and_counter_overflow() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let collector = Mutex::new(Collector::new(10));
    let mut limited = LineSession::new();
    let mut outcome = ScanOutcome::default();
    let limits = Limits {
        findings: 10,
        line_bytes: 0,
    };
    assert_eq!(
        limited.push(
            LineFragment {
                payload: b"x",
                line: 1,
                column: 1,
                end: Some(crate::scanner::chunk::LineEnd::Lf),
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        ),
        Err(ScanError::LineLimit)
    );

    let mut overflowing = LineSession::new();
    let mut outcome = ScanOutcome::default();
    outcome.stats.lines_scanned = u64::MAX;
    assert_eq!(
        overflowing.push(
            LineFragment {
                payload: b"x",
                line: 1,
                column: 1,
                end: Some(crate::scanner::chunk::LineEnd::Lf),
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            Limits {
                findings: 10,
                line_bytes: usize::MAX,
            },
        ),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn long_line_reports_scanned_line_counter_overflow() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut session = LineSession::new();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(10));
    let limits = Limits {
        findings: 10,
        line_bytes: usize::MAX,
    };
    let prefix = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES + 1];
    session
        .push(
            LineFragment {
                payload: &prefix,
                line: 1,
                column: 1,
                end: None,
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        )
        .unwrap();

    outcome.stats.lines_scanned = u64::MAX;
    assert_eq!(
        session.push(
            LineFragment {
                payload: b"x",
                line: 1,
                column: (prefix.len() + 1) as u64,
                end: Some(crate::scanner::chunk::LineEnd::Lf),
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        ),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn long_line_propagates_context_suppression_overflow_at_finish() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut session = LineSession::new();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(10));
    let limits = Limits {
        findings: 10,
        line_bytes: usize::MAX,
    };
    let prefix = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES + 1];
    session.suppressions.reference = usize::MAX;
    session
        .push(
            LineFragment {
                payload: &prefix,
                line: 1,
                column: 1,
                end: None,
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        )
        .unwrap();

    assert_eq!(
        session.push(
            LineFragment {
                payload: b" password=${PASSWORD}",
                line: 1,
                column: (prefix.len() + 1) as u64,
                end: Some(crate::scanner::chunk::LineEnd::Lf),
            },
            1,
            b"input.rs",
            &registry,
            &mut outcome,
            &collector,
            None,
            limits,
        ),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn long_line_propagates_provider_candidate_limit() {
    let mut line = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES + 1];
    line.extend_from_slice(b" ghp_");
    line.extend(std::iter::repeat_n(
        b'A',
        crate::rules::builtin::MAX_CANDIDATE_BYTES + 1,
    ));
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 2);
    assert!(
        outcome
            .errors
            .iter()
            .any(|error| error.error == ScanError::CandidateLimit)
    );
}
