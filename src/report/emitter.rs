//! Streaming findings emitter for real-time report output.
//!
//! The `FindingEmitter` trait enables scanners to emit findings as they are
//! discovered, rather than collecting them all and rendering at the end.
//! `TerminalEmitter` is the thread-safe implementation that writes findings
//! immediately to stdout and renders the summary at the end of the scan.

use std::io::Write;
use std::sync::Mutex;

use crate::scanner::{Finding, ScanOutcome};

/// Trait for emitting findings in real-time.
pub trait FindingEmitter {
    /// Called at the start of a scan.
    fn begin_scan(&mut self);

    /// Emit a single finding immediately.
    fn emit_finding(&mut self, finding: &Finding, source_path: Option<&str>);

    /// Called at the end of a scan to render the summary.
    fn finish_scan(&mut self, outcome: &ScanOutcome);
}

/// Thread-safe wrapper that delegates to the underlying emitter.
pub struct SharedEmitter {
    inner: Mutex<Box<dyn FindingEmitter>>,
}

impl SharedEmitter {
    pub fn new(emitter: Box<dyn FindingEmitter>) -> Self {
        Self {
            inner: Mutex::new(emitter),
        }
    }

    pub fn begin_scan(&self) {
        self.inner
            .lock()
            .expect("emitter lock not poisoned")
            .begin_scan();
    }

    pub fn emit_finding(&self, finding: &Finding, source_path: Option<&str>) {
        self.inner
            .lock()
            .expect("emitter lock not poisoned")
            .emit_finding(finding, source_path);
    }

    pub fn finish_scan(&self, outcome: &ScanOutcome) {
        self.inner
            .lock()
            .expect("emitter lock not poisoned")
            .finish_scan(outcome);
    }
}

/// Terminal output emitter that streams findings immediately.
pub struct TerminalEmitter<'a> {
    output: &'a mut dyn Write,
}

impl<'a> TerminalEmitter<'a> {
    pub fn new(output: &'a mut dyn Write) -> Self {
        Self { output }
    }
}

impl FindingEmitter for TerminalEmitter<'_> {
    fn begin_scan(&mut self) {
        // No header; summary is rendered at the end
    }

    fn emit_finding(&mut self, finding: &Finding, source_path: Option<&str>) {
        let metadata = finding.rule.metadata();
        if let crate::rules::builtin::RuleId::Custom(index, _) = finding.rule {
            let _ = writeln!(self.output, "Custom rule #{index}");
        }
        if let Some(path) = source_path {
            let _ = write!(self.output, "{path}");
        } else {
            let _ = write!(self.output, "source #{}", finding.source_id);
        }
        let _ = writeln!(
            self.output,
            ":{}:{}\nRule: {} ({})\nSeverity: {}; {}\nValue: {}\nID: {}",
            finding.line,
            finding.start_column,
            metadata.description,
            metadata.id,
            metadata.severity,
            metadata.confidence,
            finding.value,
            finding.id,
        );
    }

    fn finish_scan(&mut self, outcome: &ScanOutcome) {
        let status = match outcome.exit_code() {
            0 if outcome.stats.files_excluded != 0 && outcome.stats.files_attempted == 0 => {
                "EXCLUDED"
            }
            0 => "CLEAN",
            1 => "FINDINGS",
            _ => "INCOMPLETE",
        };
        let _ = writeln!(self.output);
        let _ = writeln!(self.output, "rayloc — {status}");
        let _ = writeln!(
            self.output,
            "{} finding(s); {} retained; {} of {} file(s) completed; {} line(s); {} byte(s) read",
            outcome.stats.findings_detected,
            outcome.findings.len(),
            outcome.stats.files_completed,
            outcome.stats.files_attempted,
            outcome.stats.lines_scanned,
            outcome.stats.bytes_read,
        );
        let _ = writeln!(
            self.output,
            "{} file(s) excluded",
            outcome.stats.files_excluded
        );
        let suppressed = &outcome.stats.suppressions;
        let _ = writeln!(
            self.output,
            "Suppressed: inline={}; placeholder={}; reference={}; checksum={}; generic-filter={}; accepted={}",
            suppressed.inline,
            suppressed.placeholder,
            suppressed.reference,
            suppressed.checksum,
            suppressed.generic_filter,
            suppressed.accepted
        );
        let _ = writeln!(
            self.output,
            "Elapsed: {:.3} ms",
            outcome.elapsed.as_secs_f64() * 1000.0
        );
        for error in &outcome.errors {
            let _ = writeln!(self.output, "Error: {error}");
        }
        if !outcome.findings.is_empty() {
            let _ = writeln!(self.output, "Remove exposed credentials from source code.");
            let _ = writeln!(
                self.output,
                "If a finding is a reviewed false positive, run: rayloc accept <ID>"
            );
        }
    }
}
