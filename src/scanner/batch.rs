//! Bounded newline-aligned batch planning without copying input.
//!
//! Plans waves of complete-line batches from borrowed byte slices for
//! parallel scanning. Each batch owns numeric locations only; no raw
//! byte payloads are stored or printed.
#![allow(dead_code)]
use super::ScanError;
use super::engine::READ_BUFFER_BYTES;

/// Batch scheduling limits.
#[derive(Clone, Copy)]
#[allow(dead_code)]
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

/// Plan a wave of bounded complete-line batches from a borrowed byte slice.
///
/// Greedily packs complete lines into batches up to `target_bytes`, starting
/// a new batch when the target would be exceeded. Lines exceeding `hard_bytes`
/// terminate planning. At most `max_batches` descriptors are produced.
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
        // Start a new batch
        let batch_start = pos;
        let batch_first_line = current_line;
        let mut batch_lines = 0u64;

        // Greedily accumulate complete lines into this batch
        while pos < window {
            // Find the next LF within the hard cap
            let remaining = window.saturating_sub(pos);
            let cap = remaining.min(limits.hard_bytes);
            let end_pos = pos + cap;
            let segment = &bytes[pos..end_pos];
            let lf_pos = segment.iter().position(|&b| b == b'\n');

            let record_end = match lf_pos {
                Some(pos_in_segment) => pos + pos_in_segment + 1,
                None => break, // Record exceeds hard cap, stop this batch
            };

            // Count lines in this record
            let record_lines = bytes[pos..record_end]
                .iter()
                .filter(|&&b| b == b'\n')
                .count() as u64;

            // Check if adding this record would exceed target for current batch
            let record_size = record_end - pos;
            let batch_size = record_end - batch_start;

            if batch_lines > 0 && record_size > 0 && batch_size > limits.target_bytes {
                // Adding this record would exceed target; close current batch
                break;
            }

            // Compute the line number after this record. A single line at
            // u64::MAX is OK (end_line overflows but there's no next record).
            // Two lines at u64::MAX fails (end_line overflows and there IS
            // a next record).
            let end_line = current_line.checked_add(record_lines);

            // Extend batch to include this record
            pos = record_end;
            batch_lines += record_lines;

            // Try to find the next record
            let next_segment_start = pos;
            let next_remaining = window.saturating_sub(next_segment_start);
            let next_cap = next_remaining.min(limits.hard_bytes);
            let next_end_pos = next_segment_start + next_cap;
            let has_next = if next_cap > 0 {
                bytes[next_segment_start..next_end_pos].contains(&b'\n')
            } else {
                false
            };

            // If end_line overflowed and there's a next record, that's an error
            if end_line.is_none() && has_next {
                return Err(ScanError::CounterOverflow);
            }

            current_line = end_line.unwrap_or(u64::MAX);
        }

        // Only record a batch if it has content
        if pos > batch_start {
            plan.batches[plan.len] = LineBatch {
                start: batch_start,
                end: pos,
                first_line: batch_first_line,
                lines: batch_lines,
            };
            plan.len += 1;
        } else {
            // No content accumulated (first line exceeds hard cap), stop
            break;
        }
    }

    Ok(plan)
}

#[cfg(test)]
#[path = "../../tests/unit/batch.rs"]
mod tests;
