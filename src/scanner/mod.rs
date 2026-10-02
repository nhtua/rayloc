//! Shared scanning outcomes and safe error/report boundaries.

use std::{fmt, time::Duration};

use crate::rules::builtin::RuleId;
use redaction::RedactedString;

pub mod diff;
pub mod engine;
pub mod redaction;

/// Errors contain fixed categories only, never paths, arguments, or source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanError {
    Open,
    NotRegularFile,
    Read,
    LineLimit,
    CandidateLimit,
    FindingLimit,
    CounterOverflow,
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
        })
    }
}

impl std::error::Error for ScanError {}

/// Half-open, 1-based byte columns; source IDs avoid unsafe path rendering.
#[derive(Debug)]
pub struct Finding {
    pub source_id: u32,
    pub line: u64,
    pub start_column: usize,
    pub end_column: usize,
    pub rule: RuleId,
    pub value: RedactedString,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ScanStats {
    pub files_attempted: u64,
    pub files_completed: u64,
    pub bytes_read: u64,
    pub lines_scanned: u64,
    pub findings_detected: u64,
}

/// Safe to format: neither findings nor errors own raw source bytes or paths.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
    pub stats: ScanStats,
    pub elapsed: Duration,
}

impl ScanOutcome {
    /// Execution/incomplete-scan errors take precedence over detected values.
    pub fn exit_code(&self) -> u8 {
        if !self.errors.is_empty() {
            2
        } else if !self.findings.is_empty() {
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
