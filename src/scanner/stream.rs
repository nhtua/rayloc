//! Physical-line transaction state for bounded streaming detection.
use super::{
    Finding, ScanError, ScanOutcome,
    chunk::LineFragment,
    engine::{Collector, Limits, MAX_FINDINGS, add, detect_record, merge_suppressions},
    fingerprint::FindingId,
    redaction::RedactedString,
};
use crate::{
    report::emitter::SharedEmitter,
    rules::{
        Registry,
        builtin::ProviderState,
        context::{ContextState, DirectiveState, Suppressions},
        entropy::Histogram,
        jose::JoseState,
        stream::Candidate,
        window::WindowState,
    },
};
use std::{collections::BTreeMap, sync::Mutex};

struct Pending {
    finding: Finding,
}

/// Holds long-line matches privately until the real line terminator is seen.
pub(crate) struct LineSession {
    short: Vec<u8>,
    legacy: Vec<u8>,
    legacy_overflow: bool,
    long: bool,
    line: u64,
    next_column: u64,
    provider: ProviderState,
    jose: JoseState,
    context: ContextState,
    directive: DirectiveState,
    window: WindowState,
    histogram: Histogram,
    suppressions: Suppressions,
    pending: BTreeMap<(u16, u64, u64), Pending>,
    by_span: BTreeMap<(u64, u64), (u16, u64, u64)>,
    pending_overflow: bool,
}

impl LineSession {
    pub(crate) fn new() -> Self {
        Self {
            short: Vec::with_capacity(crate::scanner::chunk::CHUNK_BYTES),
            legacy: Vec::new(),
            legacy_overflow: false,
            long: false,
            line: 0,
            next_column: 1,
            provider: ProviderState::new(),
            jose: JoseState::new(),
            context: ContextState::new(),
            directive: DirectiveState::new(),
            window: WindowState::new(),
            histogram: Histogram::new(),
            suppressions: Suppressions::default(),
            pending: BTreeMap::new(),
            by_span: BTreeMap::new(),
            pending_overflow: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn push(
        &mut self,
        fragment: LineFragment<'_>,
        source_id: u32,
        path: &[u8],
        registry: &Registry,
        outcome: &mut ScanOutcome,
        collector: &Mutex<Collector>,
        emitter: Option<&SharedEmitter>,
        limits: Limits,
    ) -> Result<(), ScanError> {
        // Most source records fit in one reader slice. Send those directly to
        // the existing complete-line matcher without copying or resetting the
        // streaming recognizers, which are only used after promotion.
        if !self.long && self.short.is_empty() && fragment.column == 1 && fragment.end.is_some() {
            if fragment.payload.len() > limits.line_bytes {
                return Err(ScanError::LineLimit);
            }
            add(&mut outcome.stats.lines_scanned, 1)?;
            detect_record(
                fragment.payload,
                source_id,
                path,
                fragment.line,
                outcome,
                limits,
                registry,
                &mut self.histogram,
                collector,
                emitter,
            )?;
            self.reset();
            return Ok(());
        }
        let current_length = usize::try_from(self.next_column.saturating_sub(1))
            .map_err(|_| ScanError::CounterOverflow)?;
        if fragment.payload.len() > limits.line_bytes.saturating_sub(current_length) {
            return Err(ScanError::LineLimit);
        }
        if self.line == 0 {
            self.line = fragment.line;
        }
        if fragment.line != self.line || fragment.column != self.next_column {
            return Err(ScanError::CounterOverflow);
        }
        self.next_column = super::chunk::next_column(self.next_column, fragment.payload.len())?;
        if !self.long
            && self.short.len().saturating_add(fragment.payload.len())
                > crate::scanner::chunk::CHUNK_BYTES
        {
            self.long = true;
            let prefix = std::mem::take(&mut self.short);
            self.retain_legacy(&prefix, registry);
            self.feed(&prefix, registry, source_id, path)?;
        }
        if self.long {
            self.retain_legacy(fragment.payload, registry);
            self.feed(fragment.payload, registry, source_id, path)?;
        } else {
            self.short.extend_from_slice(fragment.payload);
        }
        if fragment.end.is_some() {
            if self.long {
                self.finish_long(
                    source_id,
                    path,
                    registry,
                    outcome,
                    collector,
                    emitter,
                    limits.findings,
                )?;
                add(&mut outcome.stats.lines_scanned, 1)?;
            } else {
                add(&mut outcome.stats.lines_scanned, 1)?;
                detect_record(
                    &self.short,
                    source_id,
                    path,
                    fragment.line,
                    outcome,
                    limits,
                    registry,
                    &mut self.histogram,
                    collector,
                    emitter,
                )?;
            }
            self.reset();
        }
        Ok(())
    }

    fn feed(
        &mut self,
        bytes: &[u8],
        registry: &Registry,
        source_id: u32,
        path: &[u8],
    ) -> Result<(), ScanError> {
        self.directive.push(bytes);
        let mut candidates = Vec::new();
        self.provider.push(bytes, registry, |c| {
            candidates.push(capture(c, source_id, self.line, path))
        })?;
        if registry.jose_enabled() {
            self.jose.push(bytes, |c| {
                candidates.push(capture(c, source_id, self.line, path))
            })?;
        }
        self.context.push(
            bytes,
            registry,
            &mut self.histogram,
            &mut self.suppressions,
            |c| candidates.push(capture(c, source_id, self.line, path)),
        )?;
        self.window
            .push(bytes, registry, &mut self.histogram, |c| {
                candidates.push(capture(c, source_id, self.line, path))
            })?;
        for item in candidates {
            self.offer(item?);
        }
        Ok(())
    }

    fn retain_legacy(&mut self, bytes: &[u8], registry: &Registry) {
        if !registry.requires_whole_line() || self.legacy_overflow {
            return;
        }
        if bytes.len() > super::engine::MAX_LINE_BYTES.saturating_sub(self.legacy.len()) {
            self.legacy.clear();
            self.legacy_overflow = true;
        } else {
            self.legacy.extend_from_slice(bytes);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_long(
        &mut self,
        source_id: u32,
        path: &[u8],
        registry: &Registry,
        outcome: &mut ScanOutcome,
        collector: &Mutex<Collector>,
        emitter: Option<&SharedEmitter>,
        finding_limit: usize,
    ) -> Result<(), ScanError> {
        let mut candidates = Vec::new();
        self.provider.finish(registry, |c| {
            candidates.push(capture(c, source_id, self.line, path))
        })?;
        if registry.jose_enabled() {
            self.jose
                .finish(|c| candidates.push(capture(c, source_id, self.line, path)))?;
        }
        self.context
            .finish(registry, &mut self.histogram, &mut self.suppressions, |c| {
                candidates.push(capture(c, source_id, self.line, path))
            })?;
        self.window.finish(registry, &mut self.histogram, |c| {
            candidates.push(capture(c, source_id, self.line, path))
        })?;
        if registry.requires_whole_line() {
            if self.legacy_overflow {
                outcome.fail_at(ScanError::RuleWindowLimit, safe_path(path));
            } else {
                registry.detect_legacy_line(&self.legacy, &mut self.histogram, |c| {
                    candidates.push(capture(c, source_id, self.line, path))
                })?;
            }
        }
        for item in candidates {
            self.offer(item?);
        }
        if registry.inline_ignores && self.directive.finish() {
            crate::rules::context::increment(&mut self.suppressions.inline)?;
            self.pending.clear();
            self.by_span.clear();
            self.pending_overflow = false;
        }
        self.suppressions.accepted = 0;
        for pending in std::mem::take(&mut self.pending).into_values() {
            let id = pending.finding.id;
            if registry.accepted.contains(&id) {
                self.suppressions.accepted = self.suppressions.accepted.saturating_add(1);
                continue;
            }
            add(&mut outcome.stats.findings_detected, 1)?;
            if outcome.stats.findings_detected > finding_limit as u64 {
                outcome.fail(ScanError::FindingLimit);
            }
            let accepted = collector
                .lock()
                .expect("collector lock is not poisoned")
                .offer(pending.finding.clone(), path);
            if accepted {
                if let Some(emitter) = emitter {
                    let label = collector
                        .lock()
                        .expect("collector lock is not poisoned")
                        .labels
                        .get(&source_id)
                        .cloned();
                    emitter.emit_finding(&pending.finding, label.as_deref());
                }
            }
        }
        if self.pending_overflow {
            add(&mut outcome.stats.findings_detected, 1)?;
            outcome.fail(ScanError::FindingLimit);
        }
        merge_suppressions(&mut outcome.stats.suppressions, &self.suppressions)
    }

    fn offer(&mut self, item: (u16, Finding)) {
        let (priority, finding) = item;
        let span = (
            finding.start_column.saturating_sub(1) as u64,
            finding.end_column.saturating_sub(1) as u64,
        );
        let key = (priority, span.0, span.1);
        if let Some(existing) = self.by_span.get(&span).copied() {
            if existing.0 <= priority {
                return;
            }
            self.pending.remove(&existing);
        }
        self.pending.insert(key, Pending { finding });
        self.by_span.insert(span, key);
        if self.pending.len() > MAX_FINDINGS {
            self.pending_overflow = true;
            if let Some((worst, _)) = self.pending.pop_last() {
                self.by_span.remove(&(worst.1, worst.2));
            }
        }
    }

    pub(crate) fn abort_line(&mut self) {
        self.reset();
    }
    fn reset(&mut self) {
        let was_long = self.long;
        self.short.clear();
        self.legacy.clear();
        self.legacy_overflow = false;
        self.long = false;
        self.line = 0;
        self.next_column = 1;
        self.suppressions = Suppressions::default();
        if was_long {
            self.provider.reset();
            self.jose.reset();
            self.context.reset();
            self.directive.reset();
            self.window.reset();
            self.pending.clear();
            self.by_span.clear();
            self.pending_overflow = false;
        }
    }
}

fn capture(
    candidate: Candidate<'_>,
    source_id: u32,
    line: u64,
    path: &[u8],
) -> Result<(u16, Finding), ScanError> {
    let start = usize::try_from(candidate.span.start).map_err(|_| ScanError::CounterOverflow)?;
    let end = usize::try_from(candidate.span.end).map_err(|_| ScanError::CounterOverflow)?;
    let start_column = start.checked_add(1).ok_or(ScanError::CounterOverflow)?;
    let end_column = end.checked_add(1).ok_or(ScanError::CounterOverflow)?;
    Ok((
        candidate.priority,
        Finding {
            source_id,
            line,
            start_column,
            end_column,
            rule: candidate.rule,
            value: RedactedString::new(candidate.value),
            id: FindingId::new(path, candidate.value),
        },
    ))
}

fn safe_path(path: &[u8]) -> Option<Box<str>> {
    if path.is_empty() {
        return None;
    }
    std::str::from_utf8(path)
        .ok()
        .map(|s| s.to_owned().into_boxed_str())
}

#[cfg(test)]
#[path = "../../tests/unit/stream.rs"]
mod tests;
