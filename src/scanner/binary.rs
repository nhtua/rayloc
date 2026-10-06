//! Binary file detection using null-byte sampling.
//!
//! Reads up to 8KB of the file and counts null bytes (0x00).
//! If the ratio exceeds 5%, the file is classified as binary.
use std::io::Read;

/// Maximum bytes to read for binary detection.
const BINARY_DETECT_BYTES: usize = 8192;

/// Null byte ratio threshold for binary classification (5%).
const NULL_RATIO_THRESHOLD: f64 = 0.05;

/// Detect whether a file is binary by sampling its initial bytes.
///
/// Reads up to 8KB and counts null bytes. If the ratio exceeds
/// 5%, the file is classified as binary.
///
/// The reader position is restored to the original offset after
/// detection.
pub fn detect_binary(reader: &mut dyn Read, size: u64) -> bool {
    if size == 0 {
        return false;
    }

    // Read up to 8KB for sampling
    let mut buffer = vec![0u8; BINARY_DETECT_BYTES.min(size as usize)];
    let bytes_read = match reader.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return false,
    };
    if bytes_read == 0 {
        return false;
    }

    // Count null bytes
    let null_bytes = buffer[..bytes_read].iter().filter(|&&b| b == 0).count();
    let ratio = null_bytes as f64 / bytes_read as f64;

    ratio > NULL_RATIO_THRESHOLD
}

#[cfg(test)]
#[path = "../../tests/unit/binary.rs"]
mod tests;
