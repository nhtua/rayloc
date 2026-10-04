//! Values that can be formatted without disclosing credential bytes.

use std::fmt;

/// Most bytes ever retained, and never more than a quarter of the value.
/// Values shorter than eight bytes keep nothing.
const PREVIEW_BYTES: usize = 4;
const MASK: &str = "********";
const MAX_LABEL_BYTES: usize = 4096;

/// A masked value. Construction keeps at most a short ASCII-printable prefix.
///
/// Detection operates on borrowed source spans. Once a finding is recorded, its
/// value retains only the preview bytes. There is no raw getter, dereference,
/// or serialization implementation. The fixed-width mask hides the length.
pub struct RedactedString {
    preview: [u8; PREVIEW_BYTES],
    length: usize,
}

impl RedactedString {
    pub fn new(value: &[u8]) -> Self {
        let mut length = PREVIEW_BYTES.min(value.len() / 4);
        if length < 2 || !value[..length].iter().all(u8::is_ascii_graphic) {
            length = 0;
        }
        let mut preview = [0; PREVIEW_BYTES];
        preview[..length].copy_from_slice(&value[..length]);
        Self { preview, length }
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.length == 0 {
            return formatter.write_str("[REDACTED]");
        }
        // Preview bytes are ASCII-graphic by construction.
        for &byte in &self.preview[..self.length] {
            fmt::Write::write_char(formatter, char::from(byte))?;
        }
        formatter.write_str(MASK)
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// A source path safe to print, or `None` when it could spoof terminal output.
pub fn safe_label(bytes: &[u8]) -> Option<Box<str>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let unsafe_char = |c: char| {
        c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
    };
    (!text.is_empty() && text.len() <= MAX_LABEL_BYTES && !text.chars().any(unsafe_char))
        .then(|| text.into())
}

#[cfg(test)]
#[path = "../../tests/unit/redaction.rs"]
mod tests;
