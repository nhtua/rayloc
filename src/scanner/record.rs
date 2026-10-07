//! Shared safe record preparation and publication.
//!
//! Extracts record preparation/publication from `engine::detect_record` so that
//! parallel helpers can prepare batches without writing to the global collector.
use super::{
    Finding, ScanError, ScanOutcome,
    engine::{Collector, Limits, add},
    fingerprint::FindingId,
    redaction::RedactedString,
};
use crate::rules::{Registry, builtin::RuleId, context::Suppressions, entropy::Histogram};
use std::{ops::Range, sync::Mutex};

/// Context shared across record preparation.
#[derive(Clone, Copy)]
pub struct RecordContext<'a> {
    pub source_id: u32,
    pub path: &'a [u8],
    pub registry: &'a Registry,
}

/// Prepare a Finding from registry match output.
///
/// Returns `None` only when the finding's ID is in the registry's accepted set.
/// Spans are validated registry output; the caller must not trust them for
/// bounds beyond what the registry guarantees.
pub fn prepare_finding(
    bytes: &[u8],
    line_number: u64,
    context: RecordContext<'_>,
    rule: RuleId,
    span: Range<usize>,
) -> Option<Finding> {
    let id = FindingId::new(context.path, &bytes[span.clone()]);
    if context.registry.accepted.contains(&id) {
        return None;
    }
    Some(Finding {
        source_id: context.source_id,
        line: line_number,
        start_column: span.start + 1,
        end_column: span.end + 1,
        rule,
        value: RedactedString::new(&bytes[span]),
        id,
    })
}

/// Evaluate one record (line) through the registry and collect results.
///
/// Counts accepted findings, including before a registry error, and preserves
/// the callback order from the registry. Returns the registry result.
///
/// `emit` receives each prepared finding (non-accepted only) in source order.
pub fn evaluate_record(
    bytes: &[u8],
    line_number: u64,
    context: RecordContext<'_>,
    histogram: &mut Histogram,
    suppressions: &mut Suppressions,
    mut emit: impl FnMut(Finding),
) -> Result<(), ScanError> {
    let mut accepted = 0u64;
    let result = context.registry.detect_line_with_suppressions(
        bytes,
        histogram,
        suppressions,
        |rule, span| {
            if let Some(finding) = prepare_finding(bytes, line_number, context, rule, span) {
                emit(finding);
            } else {
                accepted = accepted.saturating_add(1);
            }
        },
    );
    suppressions.accepted = accepted as usize;
    result
}

/// Publish a single finding to the collector and emitter.
///
/// Handles nonterminal finding-limit overflow (increments counter, records error)
/// and releases the collector lock before emitting to avoid holding locks during I/O.
pub(super) fn publish_finding(
    finding: Finding,
    path: &[u8],
    outcome: &mut ScanOutcome,
    limits: Limits,
    collector: &Mutex<Collector>,
    emitter: Option<&crate::report::emitter::SharedEmitter>,
) {
    // Check counter overflow first (nonterminal)
    if let Err(error) = add(&mut outcome.stats.findings_detected, 1) {
        outcome.fail(error);
        return;
    }
    if outcome.stats.findings_detected > limits.findings as u64 {
        outcome.fail(ScanError::FindingLimit);
    }

    let accepted = {
        let mut c = collector.lock().expect("collector lock is not poisoned");
        c.offer(finding.clone(), path)
    };
    // Emit after dropping collector lock
    if accepted {
        if let Some(em) = emitter {
            let source_path = collector
                .lock()
                .expect("collector lock not poisoned")
                .labels
                .get(&finding.source_id)
                .cloned();
            em.emit_finding(&finding, source_path.as_deref());
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/record.rs"]
mod tests;
