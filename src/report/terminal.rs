//! Reports contain masked values, sanitized paths and fixed metadata, with no
//! source excerpts.

use std::io::{self, Write};

use crate::scanner::ScanOutcome;

/// Render an outcome without receiving raw source bytes, unsanitized paths, or
/// child errors.
pub fn render(outcome: &ScanOutcome, output: &mut dyn Write) -> io::Result<()> {
    // Print findings first (streaming style)
    for finding in &outcome.findings {
        let metadata = finding.rule.metadata();
        if let crate::rules::builtin::RuleId::Custom(index, _) = finding.rule {
            writeln!(output, "Custom rule #{index}")?;
        }
        match outcome.sources.get(&finding.source_id) {
            Some(path) => write!(output, "\n{path}")?,
            None => write!(output, "\nsource #{}", finding.source_id)?,
        }
        writeln!(
            output,
            ":{}:{}\nRule: {} ({})\nSeverity: {}; {}\nValue: {}\nID: {}",
            finding.line,
            finding.start_column,
            metadata.description,
            metadata.id,
            metadata.severity,
            metadata.confidence,
            finding.value,
            finding.id,
        )?;
    }
    for error in &outcome.errors {
        writeln!(output, "Error: {error}")?;
    }
    // Print summary at the end
    let status = match outcome.exit_code() {
        0 if outcome.stats.files_excluded != 0 && outcome.stats.files_attempted == 0 => "EXCLUDED",
        0 => "CLEAN",
        1 => "FINDINGS",
        _ => "INCOMPLETE",
    };
    writeln!(output)?;
    writeln!(output, "rayloc — {status}")?;
    writeln!(
        output,
        "{} finding(s); {} retained; {} of {} file(s) completed; {} line(s); {} byte(s) read",
        outcome.stats.findings_detected,
        outcome.findings.len(),
        outcome.stats.files_completed,
        outcome.stats.files_attempted,
        outcome.stats.lines_scanned,
        outcome.stats.bytes_read,
    )?;
    writeln!(output, "{} file(s) excluded", outcome.stats.files_excluded)?;
    let suppressed = &outcome.stats.suppressions;
    writeln!(
        output,
        "Suppressed: inline={}; placeholder={}; reference={}; checksum={}; generic-filter={}; accepted={}",
        suppressed.inline,
        suppressed.placeholder,
        suppressed.reference,
        suppressed.checksum,
        suppressed.generic_filter,
        suppressed.accepted
    )?;
    writeln!(
        output,
        "Elapsed: {:.3} ms",
        outcome.elapsed.as_secs_f64() * 1000.0
    )?;
    if outcome.stats.findings_detected > 0 {
        writeln!(output, "Remove exposed credentials from source code.")?;
        writeln!(
            output,
            "If a finding is a reviewed false positive, run: rayloc accept <ID>"
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/terminal.rs"]
mod tests;
