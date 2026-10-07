//! Test support for parallel line batch tests.
//! Not production code.
use crate::scanner::ScanOutcome;

/// Produces a token line containing a GitHub token pattern.
pub fn token_line() -> Vec<u8> {
    [b"ghp_".as_slice(), b"abcdefgh", b"ijklmnop", b"\n"].concat()
}

/// Compares two ScanOutcome for semantic equality, excluding elapsed time.
pub fn semantic_key(outcome: &ScanOutcome) -> String {
    let findings = outcome
        .findings
        .iter()
        .map(|f| {
            format!(
                "({}, {}, {}, {}, {:?})",
                f.source_id, f.line, f.start_column, f.end_column, f.rule
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let sources: Vec<String> = outcome
        .sources
        .iter()
        .map(|(k, v)| format!("({k}, {v:?})"))
        .collect();
    let errors: Vec<String> = outcome.errors.iter().map(|e| format!("{e:?}")).collect();
    let stats = format!(
        "({}, {}, {}, {}, {}, {}, {:?})",
        outcome.stats.files_attempted,
        outcome.stats.files_completed,
        outcome.stats.files_excluded,
        outcome.stats.bytes_read,
        outcome.stats.lines_scanned,
        outcome.stats.findings_detected,
        outcome.stats.suppressions,
    );
    format!(
        "findings:[{}] sources:[{}] errors:[{}] stats={} exit={}",
        findings,
        sources.join(";"),
        errors.join(";"),
        stats,
        outcome.exit_code()
    )
}
