use super::*;
use crate::scanner::SourceError;

#[test]
fn every_scan_error_has_a_safe_stable_display() {
    let errors = [
        ScanError::Open,
        ScanError::NotRegularFile,
        ScanError::Read,
        ScanError::LineLimit,
        ScanError::RuleWindowLimit,
        ScanError::CandidateLimit,
        ScanError::FindingLimit,
        ScanError::CounterOverflow,
        ScanError::Discovery,
        ScanError::ScopeLimit,
        ScanError::GitMetadata,
        ScanError::Policy,
        ScanError::NoGlobMatches,
        ScanError::Pool,
    ];
    for error in errors {
        let display = error.to_string();
        assert!(!display.is_empty());
        assert!(!display.contains("secret"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn source_error_formats_with_and_without_a_path() {
    let with_path = SourceError::new(ScanError::Read, Some("src/file.rs".into()));
    let without_path = SourceError::new(ScanError::Read, None);
    assert_eq!(
        with_path.to_string(),
        "src/file.rs — cannot read selected source"
    );
    assert_eq!(without_path.to_string(), "cannot read selected source");
}

#[test]
fn outcomes_obey_exit_precedence_and_deduplicate_errors() {
    let mut outcome = ScanOutcome::default();
    assert_eq!(outcome.exit_code(), 0);
    let sentinel = b"synthetic-private-sentinel";
    outcome.stats.findings_detected = 1;
    outcome.findings.push(Finding {
        source_id: 7,
        line: 42,
        start_column: 3,
        end_column: 28,
        rule: RuleId::GithubToken,
        value: RedactedString::new(sentinel),
        unredacted_value: None,
        id: super::fingerprint::FindingId::new(b"", sentinel),
    });
    assert_eq!(outcome.exit_code(), 1);
    outcome.fail(ScanError::Read);
    outcome.fail(ScanError::Read);
    outcome.fail(ScanError::FindingLimit);
    assert_eq!(
        outcome.errors,
        vec![
            SourceError::new(ScanError::Read, None),
            SourceError::new(ScanError::FindingLimit, None)
        ]
    );
    assert_eq!(outcome.exit_code(), 2);
    let debug = format!("{outcome:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(std::str::from_utf8(sentinel).unwrap()));
    outcome.findings.clear();
    assert_eq!(outcome.exit_code(), 2);
}
