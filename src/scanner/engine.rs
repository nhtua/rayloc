//! Bounded byte readers and one deterministic, globally capped collector.
use super::{
    Finding, ScanError, ScanOutcome, ScanStats,
    fingerprint::FindingId,
    redaction::{RedactedString, safe_label},
};
use crate::rules::{BUILTINS, Registry, entropy::Histogram};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufRead, Read},
    path::Path,
    sync::Mutex,
    time::Instant,
};
pub const READ_BUFFER_BYTES: usize = 256 * 1024;
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_FINDINGS: usize = 10_000;
#[derive(Clone, Copy)]
pub(super) struct Limits {
    line_bytes: usize,
    findings: usize,
}
pub(super) const LIMITS: Limits = Limits {
    line_bytes: MAX_LINE_BYTES,
    findings: MAX_FINDINGS,
};
type FindingKey = (u32, u64, usize, usize, crate::rules::builtin::RuleId);
pub(super) struct Collector {
    entries: BTreeMap<FindingKey, Finding>,
    labels: BTreeMap<u32, Box<str>>,
    limit: usize,
    emitter: Option<crate::report::emitter::SharedEmitter>,
}

impl Collector {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            labels: BTreeMap::new(),
            limit,
            emitter: None,
        }
    }
    #[allow(dead_code)]
    pub(super) fn with_emitter(
        limit: usize,
        emitter: crate::report::emitter::SharedEmitter,
    ) -> Self {
        Self {
            entries: BTreeMap::new(),
            labels: BTreeMap::new(),
            limit,
            emitter: Some(emitter),
        }
    }
    fn offer(&mut self, finding: Finding) {
        let key = (
            finding.source_id,
            finding.line,
            finding.start_column,
            finding.end_column,
            finding.rule,
        );
        // Skip duplicates
        if self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() == self.limit {
            let Some((&last, _)) = self.entries.last_key_value() else {
                return;
            };
            if key >= last {
                return;
            }
            self.entries.pop_last();
        }
        // Emit immediately if emitter is configured
        if let Some(ref emitter) = self.emitter {
            let source_path = self
                .labels
                .get(&finding.source_id)
                .map(|label| label.as_ref());
            emitter.emit_finding(&finding, source_path);
        }
        self.entries.insert(key, finding);
    }
    /// Record a printable path for a source that produced findings.
    pub(super) fn label(&mut self, source_id: u32, path: &[u8]) {
        if let Some(label) = safe_label(path) {
            self.labels.insert(source_id, label);
        }
    }
    pub(super) fn finish(mut self, outcome: &mut ScanOutcome) {
        let retained: BTreeSet<u32> = self.entries.keys().map(|key| key.0).collect();
        self.labels.retain(|id, _| retained.contains(id));
        outcome.sources = self.labels;
        // When emitter is used, findings were already emitted; don't duplicate
        if self.emitter.is_none() {
            outcome.findings = self.entries.into_values().collect();
        }
        if outcome.stats.findings_detected > self.limit as u64 {
            outcome.fail(ScanError::FindingLimit);
        }
        outcome.errors.sort_unstable();
    }
}
/// One reusable state per admitted lane, independent of Rayon job splitting.
pub(super) struct Worker {
    read: Vec<u8>,
    line: Vec<u8>,
    histogram: Histogram,
}
impl Worker {
    pub(super) fn new() -> Self {
        Self {
            read: vec![0; READ_BUFFER_BYTES],
            line: Vec::with_capacity(READ_BUFFER_BYTES),
            histogram: Histogram::new(),
        }
    }
    pub(super) fn file(
        &mut self,
        path: &Path,
        label: &Path,
        source_id: u32,
        registry: &Registry,
        collector: &Mutex<Collector>,
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        outcome.stats.files_attempted = 1;
        // Add label before scanning so findings can reference it
        collector
            .lock()
            .expect("collector lock is not poisoned")
            .label(source_id, label.as_os_str().as_encoded_bytes());
        match open_regular(path) {
            Err(error) => outcome.fail(error),
            Ok(file) => {
                let mut reader = BufferedFile {
                    file,
                    storage: &mut self.read,
                    start: 0,
                    end: 0,
                };
                let result = read_records_into(
                    &mut reader,
                    source_id,
                    label.as_os_str().as_encoded_bytes(),
                    &mut outcome,
                    LIMITS,
                    registry,
                    &mut self.line,
                    &mut self.histogram,
                    collector,
                );
                match result {
                    Err(error) => outcome.fail(error),
                    Ok(()) if outcome.errors.is_empty() => outcome.stats.files_completed = 1,
                    Ok(()) => {}
                }
            }
        }
        outcome
    }
}
struct BufferedFile<'a> {
    file: File,
    storage: &'a mut [u8],
    start: usize,
    end: usize,
}
impl Read for BufferedFile<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let bytes = self.fill_buf()?;
        let length = bytes.len().min(output.len());
        output[..length].copy_from_slice(&bytes[..length]);
        self.consume(length);
        Ok(length)
    }
}
impl BufRead for BufferedFile<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start == self.end {
            self.end = self.file.read(self.storage)?;
            self.start = 0;
        }
        Ok(&self.storage[self.start..self.end])
    }
    fn consume(&mut self, amount: usize) {
        self.start = (self.start + amount).min(self.end);
    }
}
pub fn scan_file(path: &Path, source_id: u32) -> ScanOutcome {
    scan_file_with_registry(path, path, source_id, &BUILTINS)
}
/// `label` is the path shown in reports, e.g. relative to the scope root.
pub fn scan_file_with_registry(
    path: &Path,
    label: &Path,
    source_id: u32,
    registry: &Registry,
) -> ScanOutcome {
    scan_file_with_registry_and_emitter(path, label, source_id, registry, None)
}

pub fn scan_file_with_registry_and_emitter(
    path: &Path,
    label: &Path,
    source_id: u32,
    registry: &Registry,
    emitter: Option<crate::report::emitter::SharedEmitter>,
) -> ScanOutcome {
    let started = Instant::now();
    let collector = match emitter {
        Some(e) => Mutex::new(Collector::with_emitter(MAX_FINDINGS, e)),
        None => Mutex::new(Collector::new(MAX_FINDINGS)),
    };
    let mut outcome = Worker::new().file(path, label, source_id, registry, &collector);
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            return Err(ScanError::Open);
        }
    }
    Ok(())
}
pub fn scan_reader(reader: &mut impl BufRead, source_id: u32) -> ScanOutcome {
    scan_with_limits(reader, source_id, LIMITS)
}
pub fn scan_reader_with_registry(
    reader: &mut impl BufRead,
    source_id: u32,
    registry: &Registry,
) -> ScanOutcome {
    scan_with_policy(reader, source_id, LIMITS, registry)
}
pub(super) fn add(counter: &mut u64, amount: usize) -> Result<(), ScanError> {
    *counter = counter
        .checked_add(u64::try_from(amount).map_err(|_| ScanError::CounterOverflow)?)
        .ok_or(ScanError::CounterOverflow)?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn scan_record_into(
    line: &[u8],
    source_id: u32,
    path: &[u8],
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    histogram: &mut Histogram,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    add(&mut outcome.stats.lines_scanned, 1)?;
    detect_record(
        line,
        source_id,
        path,
        outcome.stats.lines_scanned,
        outcome,
        limits,
        registry,
        histogram,
        collector,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn detect_record(
    line: &[u8],
    source_id: u32,
    path: &[u8],
    line_number: u64,
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    histogram: &mut Histogram,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    let mut suppressions = crate::rules::context::Suppressions::default();
    let mut accepted = 0;
    let result =
        registry.detect_line_with_suppressions(line, histogram, &mut suppressions, |rule, span| {
            let id = FindingId::new(path, &line[span.clone()]);
            if registry.accepted.contains(&id) {
                accepted += 1;
                return;
            }
            if let Err(error) = add(&mut outcome.stats.findings_detected, 1) {
                outcome.fail(error);
                return;
            }
            if outcome.stats.findings_detected > limits.findings as u64 {
                outcome.fail(ScanError::FindingLimit);
            }
            collector
                .lock()
                .expect("collector lock is not poisoned")
                .offer(Finding {
                    source_id,
                    line: line_number,
                    start_column: span.start + 1,
                    end_column: span.end + 1,
                    rule,
                    value: RedactedString::new(&line[span]),
                    id,
                });
        });
    suppressions.accepted = accepted;
    merge_suppressions(&mut outcome.stats.suppressions, &suppressions)?;
    result
}
fn merge_suppressions(
    target: &mut crate::rules::context::Suppressions,
    source: &crate::rules::context::Suppressions,
) -> Result<(), ScanError> {
    for (counter, amount) in [
        (&mut target.inline, source.inline),
        (&mut target.placeholder, source.placeholder),
        (&mut target.reference, source.reference),
        (&mut target.checksum, source.checksum),
        (&mut target.generic_filter, source.generic_filter),
        (&mut target.accepted, source.accepted),
    ] {
        *counter = counter
            .checked_add(amount)
            .ok_or(ScanError::CounterOverflow)?;
    }
    Ok(())
}
pub(super) fn merge(outcome: &mut ScanOutcome, source: ScanOutcome) {
    let result = merge_stats(&mut outcome.stats, &source.stats);
    for error in source.errors {
        outcome.fail(error);
    }
    if let Err(error) = result {
        outcome.fail(error);
    }
}
fn merge_stats(target: &mut ScanStats, source: &ScanStats) -> Result<(), ScanError> {
    for (counter, amount) in [
        (&mut target.files_attempted, source.files_attempted),
        (&mut target.files_completed, source.files_completed),
        (&mut target.files_excluded, source.files_excluded),
        (&mut target.bytes_read, source.bytes_read),
        (&mut target.lines_scanned, source.lines_scanned),
        (&mut target.findings_detected, source.findings_detected),
    ] {
        *counter = counter
            .checked_add(amount)
            .ok_or(ScanError::CounterOverflow)?;
    }
    merge_suppressions(&mut target.suppressions, &source.suppressions)
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
    let collector = Mutex::new(Collector::new(limits.findings));
    let mut outcome = ScanOutcome::default();
    outcome.stats.files_attempted = 1;
    let result = read_records_into(
        reader,
        source_id,
        b"",
        &mut outcome,
        limits,
        registry,
        &mut Vec::with_capacity(limits.line_bytes.min(READ_BUFFER_BYTES)),
        &mut Histogram::new(),
        &collector,
    );
    match result {
        Err(error) => outcome.fail(error),
        Ok(()) if outcome.errors.is_empty() => outcome.stats.files_completed = 1,
        Ok(()) => {}
    }
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    outcome.elapsed = started.elapsed();
    outcome
}
#[allow(clippy::too_many_arguments)]
fn read_records_into(
    reader: &mut dyn BufRead,
    source_id: u32,
    path: &[u8],
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    line: &mut Vec<u8>,
    histogram: &mut Histogram,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    line.clear();
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ScanError::Read),
        };
        if buffer.is_empty() {
            if !line.is_empty() {
                scan_record_into(
                    line, source_id, path, outcome, limits, registry, histogram, collector,
                )?;
            }
            return Ok(());
        }
        let newline = buffer.iter().position(|&byte| byte == b'\n');
        let content = newline.unwrap_or(buffer.len());
        if content > limits.line_bytes - line.len() {
            return Err(ScanError::LineLimit);
        }
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
            scan_record_into(
                line, source_id, path, outcome, limits, registry, histogram, collector,
            )?;
            line.clear();
        }
    }
}
#[cfg(test)]
#[path = "../../tests/unit/engine.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/engine_collector.rs"]
mod collector_tests;
