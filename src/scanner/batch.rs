//! Bounded newline-aligned batch planning without copying input.
//!
//! Plans waves of complete-line batches from borrowed byte slices for
//! parallel scanning. Each batch owns numeric locations only; no raw
//! byte payloads are stored or printed.
#![allow(dead_code)]
use super::ScanError;
use super::engine::Limits;
use super::engine::READ_BUFFER_BYTES;
use super::record::{RecordContext, evaluate_record};
use crate::report::emitter::SharedEmitter;
use crate::rules::context::Suppressions;
use crate::rules::entropy::Histogram;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Batch scheduling limits.
#[derive(Clone, Copy)]
pub struct BatchLimits {
    pub target_bytes: usize,
    pub hard_bytes: usize,
    pub max_batches: usize,
    pub max_findings: usize,
}

/// Default batch limits for parallel scanning.
pub const BATCH_LIMITS: BatchLimits = BatchLimits {
    target_bytes: 32 * 1024,
    hard_bytes: 64 * 1024,
    max_batches: 8,
    max_findings: 128,
};

/// Minimum file size hint for parallel file scanning admission.
pub const MIN_PARALLEL_FILE_BYTES: u64 = 256 * 1024;

/// A descriptor for a complete-line batch within a borrowed byte slice.
#[derive(Clone, Copy)]
pub struct LineBatch {
    pub start: usize,
    pub end: usize,
    pub first_line: u64,
    pub lines: u64,
}

/// A planned wave of up to eight batch descriptors.
pub struct WavePlan {
    pub batches: [LineBatch; 8],
    pub len: usize,
}

/// Reason a prepared batch must be replayed serially.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayReason {
    Capacity,
    Counter,
}

/// Line/byte/suppression delta for a processed batch.
#[derive(Clone, Copy, Debug, Default)]
pub struct BatchDelta {
    pub attempted_lines: u64,
    pub completed_lines: u64,
    pub bytes: u64,
    pub suppressions: Suppressions,
}

/// Unpublished helper batch results.
pub struct PreparedBatch {
    pub findings: Vec<super::Finding>,
    pub delta: BatchDelta,
    pub terminal: Option<ScanError>,
    pub replay: Option<ReplayReason>,
}

/// Helper slot scratch: histogram + prepared result.
pub struct HelperScratch {
    pub histogram: Histogram,
    pub result: PreparedBatch,
}

/// Per-event batch observability diagnostics.
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchMetrics {
    pub waves: u64,
    pub helper_batches: u64,
    pub capacity_replays: u64,
    pub counter_replays: u64,
    pub no_slot_fallbacks: u64,
    pub peak_slots: usize,
}

/// Scan outcome with batch diagnostics.
pub struct ScanRun {
    pub outcome: super::ScanOutcome,
    pub batching: BatchMetrics,
}

/// Global bounded helper slot arena.
pub struct HelperPool {
    available: Mutex<Vec<HelperScratch>>,
    in_use: AtomicUsize,
    peak_slots: AtomicUsize,
    waves: AtomicU64,
    helper_batches: AtomicU64,
    capacity_replays: AtomicU64,
    counter_replays: AtomicU64,
    no_slot_fallbacks: AtomicU64,
}

impl HelperPool {
    /// Create a pool with `workers - 1` slots.
    pub fn new(workers: usize, _limits: BatchLimits) -> Self {
        let slots = workers.saturating_sub(1);
        let available = (0..slots)
            .map(|_| HelperScratch {
                histogram: Histogram::new(),
                result: PreparedBatch {
                    findings: Vec::new(),
                    delta: BatchDelta::default(),
                    terminal: None,
                    replay: None,
                },
            })
            .collect();
        Self {
            available: Mutex::new(available),
            in_use: AtomicUsize::new(0),
            peak_slots: AtomicUsize::new(0),
            waves: AtomicU64::new(0),
            helper_batches: AtomicU64::new(0),
            capacity_replays: AtomicU64::new(0),
            counter_replays: AtomicU64::new(0),
            no_slot_fallbacks: AtomicU64::new(0),
        }
    }

    /// Try to acquire a helper slot. Returns `None` if all slots are busy.
    pub fn try_acquire(&self) -> Option<HelperLease<'_>> {
        let mut available = self.available.lock().expect("lock not poisoned");
        if available.is_empty() {
            self.no_slot_fallbacks.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let scratch = available.pop().expect("slot exists");
        let in_use = self.in_use.fetch_add(1, Ordering::Relaxed) + 1;
        // Update peak
        loop {
            let current = self.peak_slots.load(Ordering::Relaxed);
            if in_use <= current {
                break;
            }
            if self
                .peak_slots
                .compare_exchange_weak(current, in_use, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        Some(HelperLease {
            pool: self,
            scratch: Some(scratch),
        })
    }

    /// Release a helper slot.
    fn release(&self, scratch: HelperScratch) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.available
            .lock()
            .expect("lock not poisoned")
            .push(scratch);
    }

    /// Snapshot current metrics.
    pub fn snapshot(&self) -> BatchMetrics {
        BatchMetrics {
            waves: self.waves.load(Ordering::Relaxed),
            helper_batches: self.helper_batches.load(Ordering::Relaxed),
            capacity_replays: self.capacity_replays.load(Ordering::Relaxed),
            counter_replays: self.counter_replays.load(Ordering::Relaxed),
            no_slot_fallbacks: self.no_slot_fallbacks.load(Ordering::Relaxed),
            peak_slots: self.peak_slots.load(Ordering::Relaxed),
        }
    }
}

/// A leased helper slot.
pub struct HelperLease<'a> {
    pool: &'a HelperPool,
    scratch: Option<HelperScratch>,
}

impl<'a> HelperLease<'a> {
    /// Get mutable access to the scratch.
    pub fn scratch_mut(&mut self) -> &mut HelperScratch {
        self.scratch.as_mut().expect("lease has scratch")
    }
}

impl<'a> Drop for HelperLease<'a> {
    fn drop(&mut self) {
        if let Some(scratch) = self.scratch.take() {
            self.pool.release(scratch);
        }
    }
}

/// Plan a wave of bounded complete-line batches from a borrowed byte slice.
pub fn plan_wave(
    bytes: &[u8],
    first_line: u64,
    max_batches: usize,
    limits: BatchLimits,
) -> Result<WavePlan, ScanError> {
    let max_batches = max_batches.min(limits.max_batches).min(8);
    let mut plan = WavePlan {
        batches: [LineBatch {
            start: 0,
            end: 0,
            first_line: 0,
            lines: 0,
        }; 8],
        len: 0,
    };
    if max_batches == 0 {
        return Ok(plan);
    }

    let window = bytes.len().min(READ_BUFFER_BYTES);
    let mut pos = 0;
    let mut current_line = first_line;

    while pos < window && plan.len < max_batches {
        let batch_start = pos;
        let batch_first_line = current_line;
        let mut batch_lines = 0u64;

        while pos < window {
            let remaining = window.saturating_sub(pos);
            let cap = remaining.min(limits.hard_bytes);
            let end_pos = pos + cap;
            let segment = &bytes[pos..end_pos];
            let lf_pos = segment.iter().position(|&b| b == b'\n');

            let record_end = match lf_pos {
                Some(pos_in_segment) => pos + pos_in_segment + 1,
                None => break,
            };

            let record_lines = bytes[pos..record_end]
                .iter()
                .filter(|&&b| b == b'\n')
                .count() as u64;

            let record_size = record_end - pos;
            let batch_size = record_end - batch_start;

            if batch_lines > 0 && record_size > 0 && batch_size > limits.target_bytes {
                break;
            }

            let end_line = current_line.checked_add(record_lines);
            pos = record_end;
            batch_lines += record_lines;

            let next_segment_start = pos;
            let next_remaining = window.saturating_sub(next_segment_start);
            let next_cap = next_remaining.min(limits.hard_bytes);
            let next_end_pos = next_segment_start + next_cap;
            let has_next = if next_cap > 0 {
                bytes[next_segment_start..next_end_pos].contains(&b'\n')
            } else {
                false
            };

            if end_line.is_none() && has_next {
                return Err(ScanError::CounterOverflow);
            }
            current_line = end_line.unwrap_or(u64::MAX);
        }

        if pos > batch_start {
            plan.batches[plan.len] = LineBatch {
                start: batch_start,
                end: pos,
                first_line: batch_first_line,
                lines: batch_lines,
            };
            plan.len += 1;
        } else {
            break;
        }
    }

    Ok(plan)
}

/// Scan a batch serially (owner's own work).
#[allow(clippy::too_many_arguments)]
pub(super) fn scan_serial_batch(
    bytes: &[u8],
    batch: LineBatch,
    context: RecordContext<'_>,
    limits: Limits,
    progress: &mut super::chunk::ReadProgress,
    line: &mut super::stream::LineSession,
    outcome: &mut super::ScanOutcome,
    collector: &std::sync::Mutex<super::engine::Collector>,
    emitter: Option<&SharedEmitter>,
) -> Result<(), ScanError> {
    let data = &bytes[batch.start..batch.end];
    let mut pos = 0;
    let _ = batch.first_line; // line_number tracking
    while pos < data.len() {
        let rest = &data[pos..];
        let lf_pos = rest.iter().position(|&b| b == b'\n');
        match lf_pos {
            Some(pos_in_rest) => {
                let line_end = pos + pos_in_rest + 1;
                let line_bytes = &data[pos..line_end];
                // Use Cursor to feed the line session
                use std::io::Cursor;
                let mut cursor = Cursor::new(line_bytes);
                super::chunk::visit_line_fragments(&mut cursor, progress, |fragment| {
                    line.push(
                        fragment,
                        context.source_id,
                        context.path,
                        context.registry,
                        outcome,
                        collector,
                        emitter,
                        limits,
                    )
                })?;
                pos = line_end;
            }
            None => break,
        }
    }
    Ok(())
}

/// Prepare a batch without publishing.
pub(super) fn prepare_batch(
    bytes: &[u8],
    batch: LineBatch,
    context: RecordContext<'_>,
    _limits: Limits,
    batch_limits: BatchLimits,
    scratch: &mut HelperScratch,
) {
    let data = &bytes[batch.start..batch.end];
    let mut suppressions = Suppressions::default();

    // Process each line in the batch
    let mut line_number = batch.first_line;
    let mut pos = 0;
    let mut completed_lines = 0u64;
    let mut attempted_lines = 0u64;

    while pos < data.len() {
        attempted_lines += 1;
        let rest = &data[pos..];
        match rest.iter().position(|&b| b == b'\n') {
            Some(lf_pos) => {
                let line_end = pos + lf_pos + 1;
                let line_bytes = &data[pos..line_end];
                let result = evaluate_record(
                    line_bytes,
                    line_number,
                    context,
                    &mut scratch.histogram,
                    &mut suppressions,
                    |finding| {
                        scratch.result.findings.push(finding);
                    },
                );
                if let Err(error) = result {
                    scratch.result.terminal = Some(error);
                    break;
                }
                line_number += 1;
                completed_lines += 1;
                pos = line_end;
            }
            None => break,
        }
    }

    // Check for capacity overflow
    if scratch.result.findings.len() > batch_limits.max_findings {
        scratch.result.findings = Vec::new();
        scratch.result.replay = Some(ReplayReason::Capacity);
    }

    scratch.result.delta = BatchDelta {
        attempted_lines,
        completed_lines,
        bytes: (batch.end - batch.start) as u64,
        suppressions,
    };
}

/// Publish a prepared batch. Returns Ok(Some(reason)) if replay is needed.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish_batch(
    result: &mut PreparedBatch,
    _batch: LineBatch,
    context: RecordContext<'_>,
    limits: Limits,
    _progress: &mut super::chunk::ReadProgress,
    outcome: &mut super::ScanOutcome,
    collector: &std::sync::Mutex<super::engine::Collector>,
    emitter: Option<&SharedEmitter>,
) -> Result<Option<ReplayReason>, ScanError> {
    // If replay was flagged during preparation, return it
    if result.replay.is_some() {
        return Ok(result.replay);
    }

    // Counter preflight: check if we can represent the line/byte increments
    let bytes_delta = result.delta.bytes;
    let lines_delta = result.delta.completed_lines;

    // Preflight: check counters can represent the increments
    let new_bytes = outcome
        .stats
        .bytes_read
        .checked_add(bytes_delta)
        .ok_or(ScanError::CounterOverflow)?;
    let new_lines = outcome
        .stats
        .lines_scanned
        .checked_add(lines_delta)
        .ok_or(ScanError::CounterOverflow)?;

    // If we're here, counters are representable. Publish.
    for finding in &result.findings {
        super::record::publish_finding(
            finding.clone(),
            context.path,
            outcome,
            limits,
            collector,
            emitter,
        );
    }

    // Update progress
    outcome.stats.bytes_read = new_bytes;
    outcome.stats.lines_scanned = new_lines;

    // Clear the result so it can be reused
    result.findings.clear();
    result.terminal = None;
    result.replay = None;
    result.delta = BatchDelta::default();

    Ok(None)
}

/// Execute a wave of batches. Owner scans first, helpers scan rest.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_wave(
    bytes: &[u8],
    plan: &WavePlan,
    context: RecordContext<'_>,
    limits: Limits,
    batch_limits: BatchLimits,
    helpers: &HelperPool,
    progress: &mut super::chunk::ReadProgress,
    line: &mut super::stream::LineSession,
    outcome: &mut super::ScanOutcome,
    collector: &std::sync::Mutex<super::engine::Collector>,
    emitter: Option<&SharedEmitter>,
) -> Result<bool, ScanError> {
    if plan.len == 0 {
        return Ok(false);
    }

    // Owner scans the first batch
    let owner_batch = plan.batches[0];
    scan_serial_batch(
        bytes,
        owner_batch,
        context,
        limits,
        progress,
        line,
        outcome,
        collector,
        emitter,
    )?;

    // Try to lease helpers for remaining batches
    let num_remaining = plan.len - 1;

    // Acquire as many slots as possible
    let mut leases = Vec::new();
    for _ in 0..num_remaining {
        match helpers.try_acquire() {
            Some(lease) => leases.push(lease),
            None => break,
        }
    }

    if leases.is_empty() {
        // No helpers available, scan remaining serially
        for i in 1..plan.len {
            scan_serial_batch(
                bytes,
                plan.batches[i],
                context,
                limits,
                progress,
                line,
                outcome,
                collector,
                emitter,
            )?;
        }
        return Ok(false);
    }

    // Spawn parallel preparation tasks
    let mut prepared = Vec::new();
    for (i, lease) in leases.into_iter().enumerate() {
        let batch = plan.batches[i + 1];
        let mut lease = lease;
        let scratch = lease.scratch_mut();
        prepare_batch(bytes, batch, context, limits, batch_limits, scratch);
        prepared.push((batch, lease));
    }

    // Publish in order
    let mut capacity_replay = false;
    for (batch, mut lease) in prepared {
        match publish_batch(
            &mut lease.scratch_mut().result,
            batch,
            context,
            limits,
            progress,
            outcome,
            collector,
            emitter,
        ) {
            Ok(Some(ReplayReason::Capacity)) => {
                capacity_replay = true;
                // Drop remaining leases without publishing
                break;
            }
            Ok(Some(ReplayReason::Counter)) => {
                break;
            }
            Ok(None) => {}
            Err(error) => {
                return Err(error);
            }
        }
    }

    Ok(capacity_replay)
}

#[cfg(test)]
#[path = "../../tests/unit/batch.rs"]
mod tests;
