//! Bounded custom-regex matching for expressions with finite full-match bounds.
use super::{Registry, entropy::Histogram, stream::Candidate};
use crate::scanner::{ScanError, chunk::CHUNK_BYTES};
use regex_syntax::hir::{Hir, HirKind};

const MAX_WINDOW_MATCH_BYTES: usize = 64 * 1024;
const MAX_WINDOW_BYTES: usize = CHUNK_BYTES + MAX_WINDOW_MATCH_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleInput {
    Windowed { max_match_bytes: usize },
    WholeLine,
}

/// Classify the complete expression. Captures can be short while the expression
/// still needs unbounded context, so the expression's HIR bound is authoritative.
pub(crate) fn classify_input(hir: &Hir) -> RuleInput {
    if contains_look(hir) {
        return RuleInput::WholeLine;
    }
    match hir.properties().maximum_len() {
        Some(length) if length <= MAX_WINDOW_MATCH_BYTES => RuleInput::Windowed {
            max_match_bytes: length,
        },
        _ => RuleInput::WholeLine,
    }
}

fn contains_look(hir: &Hir) -> bool {
    matches!(hir.kind(), HirKind::Look(_)) || hir.kind().subs().iter().any(contains_look)
}

pub(crate) struct WindowState {
    bytes: Vec<u8>,
    base: u64,
    end: u64,
    cursors: Vec<(usize, u64)>,
}

impl WindowState {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            base: 0,
            end: 0,
            cursors: Vec::new(),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.bytes.clear();
        self.base = 0;
        self.end = 0;
        self.cursors.clear();
    }

    pub(crate) fn push(
        &mut self,
        input: &[u8],
        registry: &Registry,
        histogram: &mut Histogram,
        emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        let mut emit = emit;
        for fragment in input.chunks(CHUNK_BYTES) {
            self.feed(fragment, false, registry, histogram, &mut emit)?;
        }
        if input.is_empty() {
            self.feed(input, false, registry, histogram, emit)?;
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        registry: &Registry,
        histogram: &mut Histogram,
        emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        self.feed(&[], true, registry, histogram, emit)
    }

    fn feed(
        &mut self,
        input: &[u8],
        final_input: bool,
        registry: &Registry,
        histogram: &mut Histogram,
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        let input_len = u64::try_from(input.len()).map_err(|_| ScanError::CounterOverflow)?;
        self.end = self
            .end
            .checked_add(input_len)
            .ok_or(ScanError::CounterOverflow)?;
        let required = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or(ScanError::CounterOverflow)?;
        if required > MAX_WINDOW_BYTES {
            return Err(ScanError::CounterOverflow);
        }
        self.bytes
            .try_reserve_exact(input.len())
            .map_err(|_| ScanError::Read)?;
        self.bytes.extend_from_slice(input);

        for (index, regex, group, entropy, id, maximum) in registry.windowed_rules() {
            let cursor = self.cursor(index);
            let mature_end = if final_input {
                self.end
            } else {
                self.end.saturating_sub(maximum as u64)
            };
            let mut search = cursor.max(self.base);
            while search < mature_end {
                let local =
                    usize::try_from(search - self.base).map_err(|_| ScanError::CounterOverflow)?;
                let Some(captures) = regex.captures_at(&self.bytes, local) else {
                    search = mature_end;
                    break;
                };
                let Some(full) = captures.get(0) else {
                    search = mature_end;
                    break;
                };
                let full_start = self.base + full.start() as u64;
                let full_end = self.base + full.end() as u64;
                if full_start >= mature_end {
                    search = mature_end;
                    break;
                }
                search = full_end;
                if let Some(value) = captures.get(group) {
                    if value.is_empty() {
                        continue;
                    }
                    if entropy.is_none_or(|gate| histogram.measure(value.as_bytes()) >= gate) {
                        let start = self.base + value.start() as u64;
                        let end = self.base + value.end() as u64;
                        emit(Candidate {
                            rule: id,
                            span: start..end,
                            value: value.as_bytes(),
                            priority: 3u16.saturating_add(index.min(u16::MAX as usize) as u16),
                        });
                    }
                }
            }
            self.set_cursor(index, search);
        }
        self.discard_consumed();
        Ok(())
    }

    fn cursor(&self, index: usize) -> u64 {
        self.cursors
            .iter()
            .find_map(|(key, cursor)| (*key == index).then_some(*cursor))
            .unwrap_or(self.base)
    }

    fn set_cursor(&mut self, index: usize, cursor: u64) {
        if let Some((_, saved)) = self.cursors.iter_mut().find(|(key, _)| *key == index) {
            *saved = cursor;
        } else {
            self.cursors.push((index, cursor));
        }
    }

    fn discard_consumed(&mut self) {
        let keep_from = self
            .cursors
            .iter()
            .map(|(_, cursor)| *cursor)
            .min()
            .unwrap_or(self.end)
            .min(self.end);
        let discard = usize::try_from(keep_from.saturating_sub(self.base))
            .unwrap_or(self.bytes.len())
            .min(self.bytes.len());
        self.bytes.drain(..discard);
        self.base += discard as u64;
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/window.rs"]
mod tests;
