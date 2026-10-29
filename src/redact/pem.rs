//! Per-channel private-key block intervals and label state.

use std::{io, ops::Range};

use crate::rules::builtin::PRIVATE_KEY_MARKERS;

#[derive(Default)]
pub(super) struct PemState {
    label: Option<usize>,
}

pub(super) struct PemRecord {
    pub(super) sensitive: Vec<Range<usize>>,
    pub(super) blocks_started: u64,
}

impl PemState {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Return the sensitive byte ranges of one record while tracking the open
    /// block label. The record body itself is never retained.
    pub(super) fn record(&mut self, content: &[u8], enabled: bool) -> Result<PemRecord, io::Error> {
        let mut result = PemRecord {
            sensitive: Vec::new(),
            blocks_started: 0,
        };
        if !enabled {
            return Ok(result);
        }
        const BEGIN: &[u8] = b"-----BEGIN ";
        let mut cursor = 0;
        while cursor < content.len() {
            if let Some(index) = self.label {
                let marker = PRIVATE_KEY_MARKERS[index];
                let mut end_marker = b"-----END ".to_vec();
                end_marker.extend_from_slice(&marker[b"-----BEGIN ".len()..]);
                let end = content[cursor..]
                    .windows(end_marker.len())
                    .position(|window| window == end_marker)
                    .map(|offset| cursor + offset + end_marker.len());
                result.sensitive.push(cursor..end.unwrap_or(content.len()));
                match end {
                    Some(end) => {
                        self.label = None;
                        cursor = end;
                    }
                    None => break,
                }
            } else {
                let Some(offset) = content[cursor..]
                    .windows(BEGIN.len())
                    .position(|w| w == BEGIN)
                else {
                    break;
                };
                let start = cursor + offset;
                match PRIVATE_KEY_MARKERS
                    .iter()
                    .position(|marker| content[start..].starts_with(marker))
                {
                    Some(index) => {
                        result.blocks_started += 1;
                        self.label = Some(index);
                        cursor = start;
                    }
                    None => cursor = start + BEGIN.len(),
                }
            }
            if result.sensitive.len() > crate::scanner::engine::MAX_FINDINGS {
                return Err(io::Error::other("finding limit"));
            }
        }
        Ok(result)
    }

    pub(super) fn unfinished(&self) -> bool {
        self.label.is_some()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/redact_pem.rs"]
mod tests;
