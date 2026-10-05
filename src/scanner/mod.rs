//! Shared scanning outcomes and safe error/report boundaries.

use std::{fmt, time::Duration};

use crate::rules::builtin::RuleId;
use redaction::RedactedString;

pub mod diff;
pub mod engine;
pub mod fingerprint;
mod git;
pub mod redaction;
pub mod scope;
pub mod staged;
mod tracked;
pub mod worktree;

/// Errors contain fixed categories only, never paths, arguments, or source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ScanError {
    Open,
    NotRegularFile,
    Read,
    LineLimit,
    CandidateLimit,
    FindingLimit,
    CounterOverflow,
    Discovery,
    ScopeLimit,
    GitMetadata,
    Policy,
    NoGlobMatches,
    Pool,
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open => "cannot open selected file",
            Self::NotRegularFile => "selected path is not a regular file",
            Self::Read => "cannot read selected source",
            Self::LineLimit => "physical line exceeds scan limit",
            Self::CandidateLimit => "candidate exceeds scan limit",
            Self::FindingLimit => "finding count exceeds scan limit",
            Self::CounterOverflow => "scan counter exceeds supported range",
            Self::Discovery => "cannot enumerate selected scope",
            Self::ScopeLimit => "selected scope exceeds resource limit",
            Self::GitMetadata => "cannot read tracked scope metadata",
            Self::Policy => "cannot load scope ignore policy",
            Self::NoGlobMatches => "glob matches no regular files",
            Self::Pool => "cannot initialize scan workers",
        })
    }
}

impl std::error::Error for ScanError {}

/// Half-open, 1-based byte columns; paths resolve through `ScanOutcome::sources`.
#[derive(Debug, Clone)]
pub struct Finding {
    pub source_id: u32,
    pub line: u64,
    pub start_column: usize,
    pub end_column: usize,
    pub rule: RuleId,
    pub value: RedactedString,
    pub id: fingerprint::FindingId,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ScanStats {
    pub files_attempted: u64,
    pub files_completed: u64,
    pub files_excluded: u64,
    pub bytes_read: u64,
    pub lines_scanned: u64,
    pub findings_detected: u64,
    pub suppressions: crate::rules::context::Suppressions,
}

/// Safe to format: findings and errors own no raw source bytes, and `sources`
/// holds only sanitized paths for sources with retained findings.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub sources: std::collections::BTreeMap<u32, Box<str>>,
    pub errors: Vec<ScanError>,
    pub stats: ScanStats,
    pub elapsed: Duration,
}

impl ScanOutcome {
    /// Execution/incomplete-scan errors take precedence over detected values.
    pub fn exit_code(&self) -> u8 {
        if !self.errors.is_empty() {
            2
        } else if self.stats.findings_detected > 0 {
            1
        } else {
            0
        }
    }

    pub(crate) fn fail(&mut self, error: ScanError) {
        if !self.errors.contains(&error) {
            self.errors.push(error);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/scanner.rs"]
mod tests;
