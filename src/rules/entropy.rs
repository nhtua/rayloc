//! Reusable byte histogram, with entropy measured only over captured values.
pub struct Histogram {
    bins: [usize; 256],
}
impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}
impl Histogram {
    pub fn new() -> Self {
        Self { bins: [0; 256] }
    }
    pub fn measure(&mut self, bytes: &[u8]) -> f64 {
        self.bins.fill(0);
        if bytes.is_empty() {
            return 0.0;
        }
        for &byte in bytes {
            self.bins[byte as usize] += 1;
        }
        let length = bytes.len() as f64;
        self.bins
            .iter()
            .filter(|&&count| count != 0)
            .map(|&count| {
                let p = count as f64 / length;
                -p * p.log2()
            })
            .sum()
    }
}
#[cfg(test)]
#[path = "../../tests/unit/entropy.rs"]
mod tests;

/// Hex precedes alphanumeric, which precedes Base64; only padding is removed.
pub(super) fn generic_passes(
    bytes: &[u8],
    registry: &super::Registry,
    histogram: &mut Histogram,
) -> bool {
    let (class, default, measured) = if bytes.iter().all(u8::is_ascii_hexdigit) {
        ("hex", 3.0, bytes)
    } else if bytes.iter().all(u8::is_ascii_alphanumeric) {
        ("alphanumeric", 4.2, bytes)
    } else {
        let unpadded = bytes.trim_ascii_end();
        let body = unpadded
            .strip_suffix(b"==")
            .or_else(|| unpadded.strip_suffix(b"="))
            .unwrap_or(unpadded);
        let base64 = body
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'));
        if base64 {
            ("base64", 4.5, body)
        } else {
            ("other", registry.default_entropy_threshold, bytes)
        }
    };
    let threshold = registry
        .entropy_thresholds
        .get(class)
        .copied()
        .unwrap_or(default);
    let cap: f64 = match measured.len() {
        0..=23 => 3.5,
        24..=31 => 4.0,
        _ => 8.0,
    };
    histogram.measure(measured) >= threshold.min(cap)
}
