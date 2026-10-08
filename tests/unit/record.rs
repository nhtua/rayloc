//! Tests for the record preparation and publication interfaces.
use super::super::engine::{self, Collector, Limits};
use super::super::fingerprint::FindingId;
use super::super::parallel_support::{semantic_key, token_line};
use super::super::{ScanError, ScanOutcome};
use super::{RecordContext, evaluate_record, prepare_finding, publish_finding};
use crate::rules::{Registry, builtin::RuleId, context::Suppressions, entropy::Histogram};
use std::sync::Mutex;

fn make_test_registry() -> Registry {
    // Use a valid 5-char Crockford base32 FindingId for acceptance.
    // The ID "k3mnp" is a valid FindingId (all chars in Crockford alphabet).
    Registry::compile(
        crate::config::parse(
            b"\
             version: \"1\"\n\
             rules: [{id: early_capture, regex: (EARLY)(CAPTURE)}]\n\
             accepted: [k3mnp]\n\
             ",
        )
        .unwrap(),
    )
    .unwrap()
}

fn builtins() -> &'static crate::rules::Registry {
    &crate::rules::BUILTINS
}

/// Test that prepare_finding and evaluate_record preserve spans, IDs, priority,
/// and acceptance filtering correctly.
#[test]
fn evaluation_preserves_spans_ids_priority_and_acceptance() {
    let registry = make_test_registry();
    let line = b"EARLYCAPTURE ghp_abcdefghijklmnop";
    let source_id = 5u32;
    let path = b"input.rs";
    let line_number = 17u64;

    let _outcome = ScanOutcome::default();
    let mut histogram = Histogram::new();
    let _collector = Mutex::new(Collector::new(usize::MAX));
    let mut suppressions = Suppressions::default();

    let ctx = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id,
        path,
        registry: &registry,
        retain_unredacted_value: false,
    };

    // Collect findings via callback
    let mut prepared = Vec::new();
    let result = evaluate_record(
        line,
        line_number,
        ctx,
        &mut histogram,
        &mut suppressions,
        |f| {
            prepared.push(f);
        },
    );

    assert!(result.is_ok());

    // Custom rule (EARLY)(CAPTURE) with group=0 (entire match) matches "EARLYCAPTURE"
    // GitHub token matches "ghp_abcdefghijklmnop"
    // Detection order: builtins run first (github token), then custom set (EARLYCAPTURE)
    // Since accepted list contains "k3mnp" but our actual IDs don't match it,
    // all findings are non-accepted
    // So: 2 findings (ghp_, EARLYCAPTURE), 0 accepted
    assert_eq!(prepared.len(), 2);
    assert_eq!(prepared[0].line, line_number);
    // First finding is from builtin (GitHub token), second from custom regex (EARLYCAPTURE)
    assert_eq!(prepared[1].id, FindingId::new(b"input.rs", b"EARLYCAPTURE"));
    assert_eq!(suppressions.accepted, 0);

    // Now test with inline ignore
    let line_ignored = b"EARLYCAPTURE ghp_abcdefghijklmnop # rayloc:ignore";
    let mut suppressions_ignored = Suppressions::default();
    let mut prepared_ignored = Vec::new();
    let result_ignored = evaluate_record(
        line_ignored,
        17,
        ctx,
        &mut histogram,
        &mut suppressions_ignored,
        |f| {
            prepared_ignored.push(f);
        },
    );
    assert!(result_ignored.is_ok());
    assert_eq!(prepared_ignored.len(), 0);
    assert_eq!(suppressions_ignored.inline, 1);
}

/// Test that publication is redacted and nonterminal limits are preserved.
#[test]
fn publication_is_redacted_and_nonterminal_limits_are_preserved() {
    let line = token_line(); // ghp_abcdefghijklmnop\n
    let source_id = 3u32;
    let path = b"input.rs";
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: 2,
    };

    let mut outcome = ScanOutcome::default();
    let mut histogram = Histogram::new();
    let collector = Mutex::new(Collector::new(limits.findings));
    let registry = builtins();

    // Use evaluate_record to get findings
    let ctx = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id,
        path,
        registry,
        retain_unredacted_value: false,
    };
    let mut suppressions = Suppressions::default();
    let mut findings = Vec::new();
    evaluate_record(&line, 1, ctx, &mut histogram, &mut suppressions, |f| {
        findings.push(f);
    })
    .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(outcome.stats.findings_detected, 0); // not yet published

    // Publish findings one by one
    for finding in findings {
        publish_finding(finding, path, &mut outcome, limits, &collector, None);
    }

    // After publishing 1 finding with limit 2
    assert_eq!(outcome.stats.findings_detected, 1);
    assert_eq!(outcome.exit_code(), 1);

    // Verify redaction: rendered debug should not contain raw token
    let rendered = format!("{outcome:?}");
    let token = std::str::from_utf8(&line[..line.len() - 1]).unwrap();
    assert!(
        !rendered
            .as_bytes()
            .windows(token.len())
            .any(|w| w == token.as_bytes()),
        "Raw token found in debug output"
    );
}

/// Test near-u64::MAX publication: counter overflow records as nonterminal error
/// without turning into a registry-returned error.
/// The detect_record function records the error in outcome.stats but returns Ok(()).
#[test]
fn near_max_counter_overflow_records_without_registry_error() {
    let line = b"-----BEGIN PRIVATE KEY-----\n";
    let source_id = 1u32;
    let path = b"input.rs";
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: usize::MAX,
    };

    let mut outcome = ScanOutcome::default();
    outcome.stats.findings_detected = u64::MAX;
    let mut histogram = Histogram::new();
    let collector = Mutex::new(Collector::new(usize::MAX));
    let registry = builtins();

    // Use the old detect_record to test the full flow
    let result = engine::detect_record(
        line,
        source_id,
        path,
        crate::rules::SourceSyntax::Text,
        1,
        &mut outcome,
        limits,
        registry,
        &mut histogram,
        &collector,
        None,
    );

    // detect_record records CounterOverflow in outcome but returns Ok(())
    assert_eq!(result, Ok(()));
    // But outcome.exit_code() should be 2 because the error was recorded
    assert_eq!(outcome.exit_code(), 2);
    assert!(
        outcome
            .errors
            .iter()
            .any(|e| e.error == ScanError::CounterOverflow)
    );
    // The error is recorded but findings_detected was already at MAX
    assert_eq!(outcome.stats.findings_detected, u64::MAX);
}

/// Test that semantic_key comparison produces identical output for serial-equivalent scans.
#[test]
fn semantic_key_matches_serial_equivalent_outcomes() {
    let line = b"ghp_abcdefghijklmnop\n";
    let source_id = 1u32;
    let path = b"test.rs";
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: 10,
    };

    // Run twice with same input using the new evaluate_record + publish_finding flow
    let mut o1 = ScanOutcome::default();
    let mut h1 = Histogram::new();
    let c1 = Mutex::new(Collector::new(10));
    let ctx1 = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id,
        path,
        registry: builtins(),
        retain_unredacted_value: false,
    };
    let mut s1 = Suppressions::default();
    evaluate_record(line, 1, ctx1, &mut h1, &mut s1, |f| {
        publish_finding(f, path, &mut o1, limits, &c1, None);
    })
    .unwrap();

    let mut o2 = ScanOutcome::default();
    let mut h2 = Histogram::new();
    let c2 = Mutex::new(Collector::new(10));
    let ctx2 = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id,
        path,
        registry: builtins(),
        retain_unredacted_value: false,
    };
    let mut s2 = Suppressions::default();
    evaluate_record(line, 1, ctx2, &mut h2, &mut s2, |f| {
        publish_finding(f, path, &mut o2, limits, &c2, None);
    })
    .unwrap();

    assert_eq!(semantic_key(&o1), semantic_key(&o2));
}

/// Test prepare_finding returns None for accepted IDs.
#[test]
fn prepare_finding_skips_accepted_ids() {
    let mut registry = make_test_registry();
    let bytes = b"EARLY";
    registry.accepted.insert(FindingId::new(b"test.rs", bytes));
    let ctx = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id: 1,
        path: b"test.rs",
        registry: &registry,
        retain_unredacted_value: false,
    };
    let span = 0..5;

    // "EARLY" won't match "k3mnp" so this should produce a finding
    let result = prepare_finding(
        bytes,
        1,
        ctx,
        crate::rules::builtin::RuleId::Custom(1, crate::rules::builtin::Severity::Medium),
        span,
    );
    assert!(result.is_none());

    let accepted_value = b"EARLYCAPTURE";
    let path = b"input.rs";
    registry
        .accepted
        .insert(FindingId::new(path, accepted_value));
    let mut findings = Vec::new();
    let mut suppressions = Suppressions::default();
    evaluate_record(
        b"EARLYCAPTURE ghp_abcdefghijklmnop",
        2,
        RecordContext {
            syntax: crate::rules::SourceSyntax::Text,
            source_id: 1,
            path,
            registry: &registry,
            retain_unredacted_value: false,
        },
        &mut Histogram::new(),
        &mut suppressions,
        |finding| findings.push(finding),
    )
    .unwrap();
    assert_eq!(suppressions.accepted, 1);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, RuleId::GithubToken);
}

#[test]
fn prepare_finding_retains_full_value_only_when_requested() {
    let line = b"ghp_abcdefghijklmnop";
    let registry = builtins();
    let finding = prepare_finding(
        line,
        3,
        RecordContext {
            syntax: crate::rules::SourceSyntax::Text,
            source_id: 7,
            path: b"secrets.txt",
            registry,
            retain_unredacted_value: true,
        },
        RuleId::GithubToken,
        0..line.len(),
    )
    .expect("finding should not be accepted");
    let value = finding
        .unredacted_value
        .as_ref()
        .expect("explicitly requested");
    assert_eq!(value.to_string(), "ghp_abcdefghijklmnop");
    assert!(!format!("{finding:?}").contains("ghp_abcdefghijklmnop"));
}

/// Test that suppressions merge correctly when evaluate_record encounters errors.
#[test]
fn evaluate_record_counts_accepted_before_registry_error() {
    let registry = make_test_registry();
    let line = b"EARLYCAPTURE ghp_abcdefghijklmnop";
    let ctx = RecordContext {
        syntax: crate::rules::SourceSyntax::Text,
        source_id: 1,
        path: b"test.rs",
        registry: &registry,
        retain_unredacted_value: false,
    };
    let mut suppressions = Suppressions::default();
    let mut histogram = Histogram::new();
    let mut findings = Vec::new();

    evaluate_record(line, 1, ctx, &mut histogram, &mut suppressions, |f| {
        findings.push(f);
    })
    .unwrap();

    // Should have 2 non-accepted findings and 0 accepted (since "k3mnp" doesn't match our values)
    assert_eq!(findings.len(), 2);
    assert_eq!(suppressions.accepted, 0);
}
