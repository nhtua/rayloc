use super::*;

#[test]
fn short_or_non_ascii_values_are_fully_masked() {
    for bytes in [
        b"".as_slice(),
        b"x",
        b"1234567",
        "秘密🔑秘密🔑".as_bytes(),
        &[0xff, 0, 0x80, b'a', b'b', b'c', b'd', b'e'],
        b"a b synthetic-value",
    ] {
        let value = RedactedString::new(bytes);
        assert_eq!(format!("{value}"), "[REDACTED]");
        assert_eq!(format!("{value:?}"), "[REDACTED]");
    }
}

#[test]
fn display_reveals_a_bounded_prefix_and_a_fixed_mask() {
    for (bytes, expected) in [
        (b"12345678".as_slice(), "12********"),
        (b"123456789abc", "123********"),
        (b"ghp_SyntheticSecret0123456789", "ghp_********"),
    ] {
        let value = RedactedString::new(bytes);
        assert_eq!(format!("{value}"), expected);
        assert_eq!(format!("{value:?}"), "[REDACTED]");
        assert_eq!(format!("{value:#?}"), "[REDACTED]");
    }
}

#[test]
fn labels_withhold_unprintable_or_oversized_paths() {
    assert_eq!(
        safe_label(b"src/config.rs").as_deref(),
        Some("src/config.rs")
    );
    assert_eq!(
        safe_label("docs/秘密.md".as_bytes()).as_deref(),
        Some("docs/秘密.md")
    );
    for bytes in [
        b"".as_slice(),
        &[0xff, b'a'],
        b"a\x1b[31mb",
        b"a\nb",
        "a\u{202E}b".as_bytes(),
        "a\u{200B}b".as_bytes(),
        "a\u{2066}b".as_bytes(),
        "a\u{FEFF}b".as_bytes(),
        &[b'a'; MAX_LABEL_BYTES + 1],
    ] {
        assert_eq!(safe_label(bytes), None);
    }
    assert!(safe_label(&[b'a'; MAX_LABEL_BYTES]).is_some());
}
