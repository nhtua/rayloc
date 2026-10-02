use super::*;

#[test]
fn values_are_fully_masked_by_both_formatters() {
    for bytes in [
        b"".as_slice(),
        b"x",
        "秘密🔑".as_bytes(),
        &[0xff, 0, 0x80],
        b"synthetic-secret-value",
    ] {
        let value = RedactedString::new(bytes);
        assert_eq!(format!("{value}"), "[REDACTED]");
        assert_eq!(format!("{value:?}"), "[REDACTED]");
        assert_eq!(format!("{value:#?}"), "[REDACTED]");
    }
}
