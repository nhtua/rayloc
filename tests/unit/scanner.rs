use super::*;
use crate::scanner::SourceError;

#[test]
fn error_categories_are_safe_and_implement_error() {
    for (error, message) in [
        (ScanError::Open, "cannot open selected file"),
        (
            ScanError::NotRegularFile,
            "selected path is not a regular file",
        ),
        (ScanError::Read, "cannot read selected source"),
        (ScanError::LineLimit, "physical line exceeds scan limit"),
        (ScanError::CandidateLimit, "candidate exceeds scan limit"),
        (ScanError::FindingLimit, "finding count exceeds scan limit"),
        (
            ScanError::CounterOverflow,
            "scan counter exceeds supported range",
        ),
        (ScanError::Discovery, "cannot enumerate selected scope"),
        (
            ScanError::ScopeLimit,
            "selected scope exceeds resource limit",
        ),
        (ScanError::GitMetadata, "cannot read tracked scope metadata"),
        (ScanError::Policy, "cannot load scope ignore policy"),
        (ScanError::NoGlobMatches, "glob matches no regular files"),
        (ScanError::Pool, "cannot initialize scan workers"),
    ] {
        assert_eq!(error.to_string(), message);
        let error: &dyn std::error::Error = &error;
        assert!(error.source().is_none());
        assert!(!format!("{error:?}").is_empty());
    }
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
