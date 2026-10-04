//! Short, stable finding IDs derived from a source path and a detected value.
//!
//! An ID keeps 25 bits of a 64-bit FNV-1a digest, so it cannot reproduce the
//! value. Accepting an ID covers that value in that path only.

use std::fmt;

/// Crockford base32 without `i`, `l`, `o` and `u`, avoiding lookalike characters.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
pub const ID_LENGTH: usize = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FindingId([u8; ID_LENGTH]);

impl FindingId {
    /// `path` is relative to the scope root; `\` separators count as `/`.
    pub fn new(path: &[u8], value: &[u8]) -> Self {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        let separators = path.iter().map(|&b| if b == b'\\' { b'/' } else { b });
        for byte in separators.chain([0]).chain(value.iter().copied()) {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        // SplitMix64 finalizer spreads FNV's weak high bits.
        hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        hash ^= hash >> 31;
        let mut id = [0; ID_LENGTH];
        for (i, slot) in id.iter_mut().enumerate() {
            *slot = ALPHABET[((hash >> (5 * i)) & 31) as usize];
        }
        Self(id)
    }

    /// Accept lowercase or uppercase IDs; reject anything outside the alphabet.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes: [u8; ID_LENGTH] = text.as_bytes().try_into().ok()?;
        let id = bytes.map(|b| b.to_ascii_lowercase());
        id.iter().all(|b| ALPHABET.contains(b)).then_some(Self(id))
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bytes come from the ASCII alphabet by construction.
        self.0
            .iter()
            .try_for_each(|&b| fmt::Write::write_char(formatter, char::from(b)))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/fingerprint.rs"]
mod tests;
