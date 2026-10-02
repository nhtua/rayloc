//! Values that can be formatted without disclosing credential bytes.

use std::fmt;

/// A fully masked value. Construction deliberately discards the input bytes.
///
/// Detection operates on borrowed source spans. Once a finding is recorded, its
/// value has no reason to retain a copy of the secret. There is no raw getter,
/// dereference, or serialization implementation.
pub struct RedactedString {
    _private: (),
}

impl RedactedString {
    pub fn new(_value: &[u8]) -> Self {
        Self { _private: () }
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/redaction.rs"]
mod tests;
