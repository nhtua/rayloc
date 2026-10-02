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
