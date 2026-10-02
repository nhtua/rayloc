use super::*;
#[test]
fn histogram_entropy_is_reusable_and_byte_exact() {
    let mut histogram = Histogram::default();
    for (bytes, expected) in [
        (b"".as_slice(), 0.0),
        (b"aaaa", 0.0),
        (b"abab", 1.0),
        (b"abcd", 2.0),
        (b"aaaabbcc", 1.5),
        (b"\xff\xfe", 1.0),
        (b"aa", 0.0),
    ] {
        assert!((histogram.measure(bytes) - expected).abs() < 1e-12);
    }
    let all: Vec<_> = (0..=255).collect();
    assert_eq!(histogram.measure(&all), 8.0);
}
