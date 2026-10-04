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
#[test]
fn generic_classes_caps_and_base64_padding_measure_only_body_bytes() {
    let registry = super::super::Registry::compile(crate::config::Config::default()).unwrap();
    let mut histogram = Histogram::new();
    for (bytes, expected) in [
        (b"9f21c7ab6e40d835".as_slice(), true),
        (b"Q7v2n9B4x6M1z8K3", true),
        (b"Q7v2n9B4x6M1z8+3==", true),
        (b"Q7v2n9B4x6M1z8-3=", true),
        (b"!@#$%^&*()abcDEF", true),
        (b"aaaabbbbccccdddd", false),
        (b"aabbccddeeffgghhiijjkkllmmnnoopp", false),
        (b"Q7v2n9B4x6M1z8K3u5J0r8wZ", true),
    ] {
        assert_eq!(generic_passes(bytes, &registry, &mut histogram), expected);
    }
}
