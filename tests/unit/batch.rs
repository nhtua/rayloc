//! Tests for bounded batch planning.
use super::BatchLimits;
use super::{BATCH_LIMITS, MIN_PARALLEL_FILE_BYTES, plan_wave};

/// Assert production constants exactly.
#[test]
fn wave_planner_obeys_exact_budgets() {
    assert_eq!(BATCH_LIMITS.target_bytes, 32 * 1024);
    assert_eq!(BATCH_LIMITS.hard_bytes, 64 * 1024);
    assert_eq!(BATCH_LIMITS.max_batches, 8);
    assert_eq!(BATCH_LIMITS.max_findings, 128);
    assert_eq!(MIN_PARALLEL_FILE_BYTES, 256 * 1024);

    // Zero requested descriptors returns an empty plan
    let plan = plan_wave(b"hello\n", 1, 0, BATCH_LIMITS).unwrap();
    assert_eq!(plan.len, 0);

    // Plan with normal input respects hard cap
    let plan = plan_wave(b"a\n", 1, 8, BATCH_LIMITS).unwrap();
    assert_eq!(plan.len, 1);
    assert_eq!(plan.batches[0].start, 0);
    assert_eq!(plan.batches[0].end, 2); // includes LF
    assert_eq!(plan.batches[0].first_line, 1);
    assert_eq!(plan.batches[0].lines, 1);
}

/// Test CRLF, empty lines, and incomplete line handling.
#[test]
fn wave_planner_preserves_crlf_empty_and_incomplete_lines() {
    // CRLF line: "a\r\n" is 3 bytes, end should be 3 (exclusive, at LF+1)
    let limits = BATCH_LIMITS;
    let plan = plan_wave(b"a\r\n", 1, 8, limits).unwrap();
    assert_eq!(plan.len, 1);
    let b = plan.batches[0];
    assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 3, 1, 1));

    // Empty line: "\n" is a complete record (1 byte)
    let plan = plan_wave(b"\n", 5, 8, limits).unwrap();
    assert_eq!(plan.len, 1);
    let b = plan.batches[0];
    assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 1, 5, 1));

    // CRLF + empty line: "a\r\n\n" is 4 bytes, 2 lines
    let plan = plan_wave(b"a\r\n\n", 10, 8, limits).unwrap();
    assert_eq!(plan.len, 1);
    let b = plan.batches[0];
    assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 4, 10, 2));

    // Incomplete line (no LF at end) should not be included as a batch
    let plan = plan_wave(b"a\nlast", 1, 8, limits).unwrap();
    assert_eq!(plan.len, 1);
    let b = plan.batches[0];
    assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 2, 1, 1));
    // "last" is incomplete, so it's not a batch
}

/// Test that planning stops before oversized lines and handles location overflow.
#[test]
fn wave_planner_stops_before_oversized_lines_and_location_overflow() {
    // Reduced limits for testing
    let limits = BatchLimits {
        target_bytes: 4,
        hard_bytes: 8,
        max_batches: 8,
        max_findings: 128,
    };

    // CRLF + empty + "last": only first 4 bytes are eligible
    let plan = plan_wave(b"a\r\n\nlast", 10, 8, limits).unwrap();
    assert_eq!(plan.len, 1);
    let b = plan.batches[0];
    assert_eq!((b.start, b.end, b.first_line, b.lines), (0, 4, 10, 2));

    // With "a\r\n\nlast\n": first batch "a\r\n\n" (4 bytes), second "last\n" (5 bytes)
    // Hard cap is 8, so "last\n" (5 bytes) fits within hard cap
    let plan = plan_wave(b"a\r\n\nlast\n", 10, 8, limits).unwrap();
    assert_eq!(plan.len, 2);
    let b0 = plan.batches[0];
    let b1 = plan.batches[1];
    assert_eq!((b0.start, b0.end), (0, 4));
    assert_eq!((b1.start, b1.end), (4, 9));
    assert_eq!(b0.lines, 2);
    assert_eq!(b1.lines, 1);

    // Verify contiguous/nonoverlapping spans
    assert_eq!(b0.end, b1.start);
    // Verify len <= 8
    assert!(plan.len <= 8);

    // Two lines starting at u64::MAX return CounterOverflow
    let result = plan_wave(b"a\nb\n", u64::MAX, 8, limits);
    assert!(matches!(
        result,
        Err(super::super::ScanError::CounterOverflow)
    ));

    // One representable line must not fail just because a next line would overflow
    let result = plan_wave(b"a\n", u64::MAX, 8, limits);
    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.len, 1);
    assert_eq!(plan.batches[0].first_line, u64::MAX);

    // Hard cap prevents crossing oversized boundaries
    // A single line larger than hard_bytes should not be batched
    let large_line = vec![b'a'; 100];
    let plan = plan_wave(&large_line, 1, 8, limits);
    // The line is 100 bytes which exceeds hard cap of 8, so no batches
    assert_eq!(plan.unwrap().len, 0);
}

/// Test with large inputs to verify window-bounded inspection.
#[test]
fn wave_planner_inspects_only_window_budget() {
    // Create input larger than 256 KiB
    let mut input = Vec::new();
    for _ in 0..300 * 1024 {
        input.push(b'x');
        input.push(b'\n');
    }
    // Should not panic and should respect the 256 KiB window
    let plan = plan_wave(&input, 1, 8, BATCH_LIMITS).unwrap();
    // Should cap at 8 batches
    assert_eq!(plan.len, 8);
    // Each batch should end at an LF boundary
    for i in 0..plan.len {
        assert!(input[plan.batches[i].end - 1] == b'\n');
        let span = &input[plan.batches[i].start..plan.batches[i].end];
        assert!(span.len() <= BATCH_LIMITS.hard_bytes);
    }
    // Spans should be contiguous
    for i in 1..plan.len {
        assert_eq!(plan.batches[i - 1].end, plan.batches[i].start);
    }
}

/// Test line count arithmetic across batches.
#[test]
fn wave_planner_line_numbers_are_contiguous() {
    let input = b"line1\nline2\nline3\nline4\nline5\n";
    let plan = plan_wave(input, 10, 8, BATCH_LIMITS).unwrap();
    assert_eq!(plan.len, 1);
    // Single batch covers all 5 lines
    assert_eq!(plan.batches[0].first_line, 10);
    assert_eq!(plan.batches[0].lines, 5);
}
