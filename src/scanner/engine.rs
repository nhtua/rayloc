//! Bounded streaming of regular files into the shared byte detector.

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::Path,
    time::Instant,
};

use crate::rules::{BUILTINS, Registry, entropy::Histogram};

use super::{Finding, ScanError, ScanOutcome, redaction::RedactedString};

pub const READ_BUFFER_BYTES: usize = 256 * 1024;
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_FINDINGS: usize = 10_000;

#[derive(Clone, Copy)]
struct Limits {
    line_bytes: usize,
    findings: usize,
}

const LIMITS: Limits = Limits {
    line_bytes: MAX_LINE_BYTES,
    findings: MAX_FINDINGS,
};

/// Scan a regular file. Paths are never retained in findings or errors.
///
/// This low-level engine does not discover configuration or ignore policy. CLI
/// policy discovery and exclusions belong to the CLI/selection layer.
pub fn scan_file(path: &Path, source_id: u32) -> ScanOutcome {
    scan_file_with_registry(path, source_id, &BUILTINS)
}

/// Scan a file using a precompiled policy.
pub fn scan_file_with_registry(path: &Path, source_id: u32, registry: &Registry) -> ScanOutcome {
    let started = Instant::now();
    let result = open_regular(path).map(|file| {
        scan_reader_with_registry(
            &mut BufReader::with_capacity(READ_BUFFER_BYTES, file),
            source_id,
            registry,
        )
    });
    let mut outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut outcome = ScanOutcome::default();
            outcome.stats.files_attempted = 1;
            outcome.fail(error);
            outcome
        }
    };
    outcome.elapsed = started.elapsed();
    outcome
}

fn open_regular(path: &Path) -> Result<File, ScanError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ScanError::Open)?;
    if !metadata.is_file() {
        return Err(ScanError::NotRegularFile);
    }
    let file = File::open(path).map_err(|_| ScanError::Open)?;
    validate_opened(&metadata, file.metadata())?;
    Ok(file)
}

fn validate_opened(
    metadata: &fs::Metadata,
    opened: io::Result<fs::Metadata>,
) -> Result<(), ScanError> {
    let opened = opened.map_err(|_| ScanError::Open)?;
    if !opened.is_file() {
        return Err(ScanError::NotRegularFile);
    }
    // On Unix an inode/device mismatch detects replacement, including a symlink
    // swap between the metadata check and open. Never scan the substituted file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            return Err(ScanError::Open);
        }
    }
    Ok(())
}

/// Scan already-selected bytes; memory is bounded even for a giant line.
pub fn scan_reader(reader: &mut impl BufRead, source_id: u32) -> ScanOutcome {
    scan_with_limits(reader, source_id, LIMITS)
}

/// Scan selected records with a precompiled registry.
pub fn scan_reader_with_registry(
    reader: &mut impl BufRead,
    source_id: u32,
    registry: &Registry,
) -> ScanOutcome {
    scan_with_policy(reader, source_id, LIMITS, registry)
}

fn add(counter: &mut u64, amount: usize) -> Result<(), ScanError> {
    *counter = counter
        .checked_add(amount as u64)
        .ok_or(ScanError::CounterOverflow)?;
    Ok(())
}

fn scan_record(
    line: &[u8],
    source_id: u32,
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    histogram: &mut Histogram,
) -> Result<(), ScanError> {
    add(&mut outcome.stats.lines_scanned, 1)?;
    registry.detect_line(line, histogram, |rule, span| {
        if let Err(error) = add(&mut outcome.stats.findings_detected, 1) {
            outcome.fail(error);
        }
        if outcome.findings.len() == limits.findings {
            outcome.fail(ScanError::FindingLimit);
        } else {
            outcome.findings.push(Finding {
                source_id,
                line: outcome.stats.lines_scanned,
                start_column: span.start + 1,
                end_column: span.end + 1,
                rule,
                value: RedactedString::new(&line[span]),
            });
        }
    })
}

fn scan_with_limits(reader: &mut dyn BufRead, source_id: u32, limits: Limits) -> ScanOutcome {
    scan_with_policy(reader, source_id, limits, &BUILTINS)
}

fn scan_with_policy(
    reader: &mut dyn BufRead,
    source_id: u32,
    limits: Limits,
    registry: &Registry,
) -> ScanOutcome {
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    outcome.stats.files_attempted = 1;
    let result = read_records(reader, source_id, &mut outcome, limits, registry);
    match result {
        Ok(()) if outcome.errors.is_empty() => outcome.stats.files_completed = 1,
        Ok(()) => {}
        Err(error) => outcome.fail(error),
    }
    outcome.findings.sort_by_key(|finding| {
        (
            finding.source_id,
            finding.line,
            finding.start_column,
            finding.end_column,
            finding.rule,
        )
    });
    outcome.elapsed = started.elapsed();
    outcome
}

fn read_records(
    reader: &mut dyn BufRead,
    source_id: u32,
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
) -> Result<(), ScanError> {
    let mut histogram = Histogram::new();
    let mut line = Vec::with_capacity(limits.line_bytes.min(READ_BUFFER_BYTES));
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ScanError::Read),
        };
        if buffer.is_empty() {
            if !line.is_empty() {
                scan_record(&line, source_id, outcome, limits, registry, &mut histogram)?;
            }
            return Ok(());
        }
        let newline = buffer.iter().position(|&byte| byte == b'\n');
        let content = newline.unwrap_or(buffer.len());
        if content > limits.line_bytes - line.len() {
            return Err(ScanError::LineLimit);
        }
        // Grow geometrically for small input buffers, clamped to the line budget.
        if line.len() + content > line.capacity() {
            let capacity = line
                .capacity()
                .saturating_mul(2)
                .max(line.len() + content)
                .min(limits.line_bytes);
            line.reserve_exact(capacity - line.len());
        }
        line.extend_from_slice(&buffer[..content]);
        let consumed = content + usize::from(newline.is_some());
        add(&mut outcome.stats.bytes_read, consumed)?;
        reader.consume(consumed);
        if newline.is_some() {
            scan_record(&line, source_id, outcome, limits, registry, &mut histogram)?;
            line.clear();
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine.rs"]
mod tests;
