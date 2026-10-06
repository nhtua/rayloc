use crate::scanner::binary::detect_binary;
use std::io::Cursor;

#[test]
fn detect_binary_identifies_text_file() {
    let content = b"This is a text file with some content.\nIt has multiple lines.\n";
    let mut reader = Cursor::new(content);
    assert!(!detect_binary(&mut reader, content.len() as u64));
}

#[test]
fn detect_binary_identifies_binary_file_with_null_bytes() {
    // Create binary content with high null byte ratio
    let mut content = vec![0u8; 100];
    content[0] = 65; // 'A'
    content[1] = 66; // 'B'
    let mut reader = Cursor::new(content);
    assert!(detect_binary(&mut reader, 100));
}

#[test]
fn detect_binary_identifies_empty_file_as_text() {
    let content: Vec<u8> = Vec::new();
    let mut reader = Cursor::new(content);
    assert!(!detect_binary(&mut reader, 0));
}

#[test]
fn detect_binary_identifies_low_null_ratio_as_text() {
    // Create content with < 5% null bytes (below threshold)
    let mut content = vec![65; 100]; // All 'A's
    content[50] = 0; // One null byte (1%)
    let mut reader = Cursor::new(content);
    assert!(!detect_binary(&mut reader, 100));
}

#[test]
fn detect_binary_identifies_high_null_ratio_as_binary() {
    // Create content with > 5% null bytes (above threshold)
    let mut content = vec![65; 100];
    for i in (0..100).step_by(2) {
        content[i] = 0; // 50 null bytes (50%)
    }
    let mut reader = Cursor::new(content);
    assert!(detect_binary(&mut reader, 100));
}

#[test]
fn detect_binary_reads_up_to_8kb() {
    // Create content with null bytes only after 8KB
    let mut content = vec![65; 16384]; // 16KB of 'A's
    content[8192..].fill(0); // Null bytes in second half
    let mut reader = Cursor::new(content);
    // Should not read beyond 8KB, so should not see the null bytes
    assert!(!detect_binary(&mut reader, 16384));
}

#[test]
fn detect_binary_small_file_with_nulls() {
    // Small file that fits entirely in buffer
    let mut content = vec![0u8; 10];
    content[0] = 84; // 'T'
    content[1] = 69; // 'E'
    content[2] = 88; // 'X'
    let mut reader = Cursor::new(content);
    assert!(detect_binary(&mut reader, 10));
}
