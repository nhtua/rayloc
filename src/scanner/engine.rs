//! Bounded byte readers and one deterministic, globally capped collector.
use super::{
    Finding, ScanError, ScanOutcome, ScanStats, binary::detect_binary, redaction::safe_label,
};
use crate::rules::{BUILTINS, Registry, entropy::Histogram};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufRead, Read, Seek, SeekFrom},
    path::Path,
    sync::Mutex,
    time::Instant,
};
pub const READ_BUFFER_BYTES: usize = 256 * 1024;
/// Compatibility budget retained for legacy whole-line custom regex rules.
/// Physical file lines without such a rule are streamed beyond this size.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_FINDINGS: usize = 10_000;
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) line_bytes: usize,
    pub(super) findings: usize,
}
pub(super) const LIMITS: Limits = Limits {
    line_bytes: usize::MAX,
    findings: MAX_FINDINGS,
};
type FindingKey = (u32, u64, usize, usize, crate::rules::builtin::RuleId);
pub(super) struct Collector {
    entries: BTreeMap<FindingKey, Finding>,
    pub(super) labels: BTreeMap<u32, Box<str>>,
    limit: usize,
}

impl Collector {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            labels: BTreeMap::new(),
            limit,
        }
    }
    /// Returns true if finding was accepted (not duplicate).
    pub(super) fn offer(&mut self, finding: Finding, path: &[u8]) -> bool {
        let key = (
            finding.source_id,
            finding.line,
            finding.start_column,
            finding.end_column,
            finding.rule,
        );
        // Skip duplicates
        if self.entries.contains_key(&key) {
            return false;
        }
        if self.entries.len() == self.limit {
            let Some((&last, _)) = self.entries.last_key_value() else {
                return false;
            };
            if key >= last {
                return false;
            }
            self.entries.pop_last();
        }
        // Register label lazily on first finding for this source
        if let std::collections::btree_map::Entry::Vacant(e) = self.labels.entry(finding.source_id)
        {
            if let Some(label) = safe_label(path) {
                e.insert(label);
            }
        }
        self.entries.insert(key, finding);
        true
    }
    pub(super) fn finish(mut self, outcome: &mut ScanOutcome) {
        let retained: BTreeSet<u32> = self.entries.keys().map(|key| key.0).collect();
        self.labels.retain(|id, _| retained.contains(id));
        outcome.sources = self.labels;
        outcome.findings = self.entries.into_values().collect();
        if outcome.stats.findings_detected > self.limit as u64 {
            outcome.fail(ScanError::FindingLimit);
        }
        outcome.errors.sort_unstable();
    }
}
/// One reusable state per admitted lane, independent of Rayon job splitting.
pub(super) struct Worker {
    read: Vec<u8>,
    line: super::stream::LineSession,
    histogram: Histogram,
}
impl Worker {
    pub(super) fn new() -> Self {
        Self {
            read: vec![0; READ_BUFFER_BYTES],
            line: super::stream::LineSession::new(),
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
        emitter: Option<&crate::report::emitter::SharedEmitter>,
    ) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();
        outcome.stats.files_attempted = 1;
        let label_string = label.to_string_lossy().into_owned();
        let label_box: Box<str> = label_string.into();
        match open_regular(path) {
            Err(error) => outcome.fail_at(error, Some(label_box)),
            Ok(mut file) => {
                // Binary file detection: sample initial bytes for null bytes
                let is_binary = match file.metadata() {
                    Ok(metadata) => {
                        let result = detect_binary(&mut file, metadata.len());
                        if !result {
                            let _ = file.seek(SeekFrom::Start(0));
                        }
                        result
                    }
                    Err(_) => false,
                };
                if is_binary {
                    outcome.stats.files_excluded = 1;
                    return outcome;
                }

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
                    emitter,
                );
                match result {
                    Err(error) => {
                        outcome.fail_at(error, Some(label_box));
                    }
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
    let collector = Mutex::new(Collector::new(MAX_FINDINGS));
    let mut outcome = Worker::new().file(
        path,
        label,
        source_id,
        registry,
        &collector,
        emitter.as_ref(),
    );
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
#[cfg(test)]
fn scan_record_into(
    line: &[u8],
    source_id: u32,
    path: &[u8],
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    histogram: &mut Histogram,
    collector: &Mutex<Collector>,
    emitter: Option<&crate::report::emitter::SharedEmitter>,
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
        emitter,
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
    emitter: Option<&crate::report::emitter::SharedEmitter>,
) -> Result<(), ScanError> {
    use super::record::{RecordContext, evaluate_record, publish_finding};
    let mut suppressions = crate::rules::context::Suppressions::default();
    let ctx = RecordContext {
        source_id,
        path,
        registry,
    };
    let mut findings = Vec::new();
    let result = evaluate_record(
        line,
        line_number,
        ctx,
        histogram,
        &mut suppressions,
        |finding| {
            findings.push(finding);
        },
    );
    for finding in findings {
        publish_finding(finding, path, outcome, limits, collector, emitter);
    }
    merge_suppressions(&mut outcome.stats.suppressions, &suppressions)?;
    result
}
pub(super) fn merge_suppressions(
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
        outcome.fail_at(error.error, error.path);
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
        &mut super::stream::LineSession::new(),
        &mut Histogram::new(),
        &collector,
        None,
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
    line: &mut super::stream::LineSession,
    _histogram: &mut Histogram,
    collector: &Mutex<Collector>,
    emitter: Option<&crate::report::emitter::SharedEmitter>,
) -> Result<(), ScanError> {
    let mut progress = super::chunk::ReadProgress::default();
    let result = super::chunk::visit_line_fragments(reader, &mut progress, |fragment| {
        line.push(
            fragment, source_id, path, registry, outcome, collector, emitter, limits,
        )
    });
    outcome.stats.bytes_read = outcome
        .stats
        .bytes_read
        .checked_add(progress.bytes_read)
        .ok_or(ScanError::CounterOverflow)?;
    if result.is_err() {
        line.abort_line();
    }
    result
}
#[cfg(test)]
#[path = "../../tests/unit/engine.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/engine_collector.rs"]
mod collector_tests;
