//! Tests for bounded batch planning and preparation.
use super::BatchLimits;
use super::{BATCH_LIMITS, MIN_PARALLEL_FILE_BYTES, plan_wave};
use crate::rules::context::Suppressions;
use crate::rules::entropy::Histogram;
use crate::scanner::engine::Limits;
use crate::scanner::parallel_support::token_line;
use crate::scanner::record::RecordContext;

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
    let limits = BATCH_LIMITS;

    // CRLF line: "a\r\n" is 3 bytes
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
}

/// Test that planning stops before oversized lines and handles location overflow.
#[test]
fn wave_planner_stops_before_oversized_lines_and_location_overflow() {
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
    let large_line = vec![b'a'; 100];
    let plan = plan_wave(&large_line, 1, 8, limits).unwrap();
    assert_eq!(plan.len, 0);
}

/// Test with large inputs to verify window-bounded inspection.
#[test]
fn wave_planner_inspects_only_window_budget() {
    let mut input = Vec::new();
    for _ in 0..300 * 1024 {
        input.push(b'x');
        input.push(b'\n');
    }
    let plan = plan_wave(&input, 1, 8, BATCH_LIMITS).unwrap();
    assert_eq!(plan.len, 8);
    for i in 0..plan.len {
        assert!(input[plan.batches[i].end - 1] == b'\n');
        let span = &input[plan.batches[i].start..plan.batches[i].end];
        assert!(span.len() <= BATCH_LIMITS.hard_bytes);
    }
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
    assert_eq!(plan.batches[0].first_line, 10);
    assert_eq!(plan.batches[0].lines, 5);
}

/// Lease capacity is bounded by width-1, nonblocking, and reusable.
#[test]
fn helper_leases_are_global_nonblocking_and_reusable() {
    let helpers = super::HelperPool::new(4, BATCH_LIMITS);
    let leases: Vec<_> = (0..3).map(|_| helpers.try_acquire().unwrap()).collect();
    assert!(helpers.try_acquire().is_none());
    assert_eq!(helpers.snapshot().peak_slots, 3);
    drop(leases);
    assert!(helpers.try_acquire().is_some());
    assert!(
        super::HelperPool::new(1, BATCH_LIMITS)
            .try_acquire()
            .is_none()
    );
}

/// Prepared batch matches serial evaluation without publishing.
#[test]
fn prepared_batches_match_serial_records_without_publication() {
    use crate::rules::BUILTINS;
    let token = token_line();
    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &BUILTINS,
    };
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: 1000,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 0,
                completed_lines: 0,
                bytes: 0,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        },
    };
    let batch = super::LineBatch {
        start: 0,
        end: token.len(),
        first_line: 1,
        lines: 1,
    };
    super::prepare_batch(&token, batch, context, limits, BATCH_LIMITS, &mut scratch);
    assert_eq!(scratch.result.findings.len(), 1);
    assert_eq!(scratch.result.delta.completed_lines, 1);
    assert_eq!(scratch.result.delta.bytes, token.len() as u64);
    assert_eq!(scratch.result.replay, None);
}

/// 129th non-accepted finding triggers capacity replay.
#[test]
fn prepared_batches_replay_at_129_without_losing_findings() {
    use crate::rules::BUILTINS;
    let token = token_line();
    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &BUILTINS,
    };
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: 1000,
    };
    let batch_limits = BatchLimits {
        target_bytes: 32 * 1024,
        hard_bytes: 64 * 1024,
        max_batches: 8,
        max_findings: 128,
    };

    // Build 128 lines with tokens (one finding each)
    let mut input = Vec::new();
    for _ in 0..128 {
        input.extend_from_slice(&token);
    }
    let batch = super::LineBatch {
        start: 0,
        end: input.len(),
        first_line: 1,
        lines: 128,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 0,
                completed_lines: 0,
                bytes: 0,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        },
    };
    super::prepare_batch(&input, batch, context, limits, batch_limits, &mut scratch);
    assert_eq!(scratch.result.findings.len(), 128);
    assert_eq!(scratch.result.replay, None);

    // Now 129 lines
    input.extend_from_slice(&token);
    let batch = super::LineBatch {
        start: 0,
        end: input.len(),
        first_line: 1,
        lines: 129,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 0,
                completed_lines: 0,
                bytes: 0,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        },
    };
    super::prepare_batch(&input, batch, context, limits, batch_limits, &mut scratch);
    assert!(matches!(
        scratch.result.replay,
        Some(super::ReplayReason::Capacity)
    ));
    // Findings are discarded on replay
    assert!(scratch.result.findings.is_empty());

    // Reusing the same lease for a later sparse batch clears replay state.
    let batch = super::LineBatch {
        start: 0,
        end: token.len(),
        first_line: 130,
        lines: 1,
    };
    super::prepare_batch(&token, batch, context, limits, batch_limits, &mut scratch);
    assert_eq!(scratch.result.replay, None);
    assert_eq!(scratch.result.findings.len(), 1);
}

/// Accepted/ignored findings do not consume capacity.
#[test]
fn accepted_ignored_and_reused_batches_do_not_consume_capacity() {
    // Use a registry with a custom rule to create findings
    let registry = crate::rules::Registry::compile(
        crate::config::parse(
            b"\
             version: \"1\"\n\
             rules: [{id: test-rule, regex: secret}]\n\
             ",
        )
        .unwrap(),
    )
    .unwrap();

    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &registry,
    };
    let limits = Limits {
        line_bytes: usize::MAX,
        findings: 1000,
    };
    let batch_limits = BatchLimits {
        target_bytes: 32 * 1024,
        hard_bytes: 64 * 1024,
        max_batches: 8,
        max_findings: 128,
    };

    // 129 lines with findings should trigger capacity replay
    let mut input = Vec::new();
    for i in 0..129 {
        input.extend_from_slice(format!("secret{i}\n").as_bytes());
    }
    let batch = super::LineBatch {
        start: 0,
        end: input.len(),
        first_line: 1,
        lines: 129,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 0,
                completed_lines: 0,
                bytes: 0,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        },
    };
    super::prepare_batch(&input, batch, context, limits, batch_limits, &mut scratch);
    assert!(matches!(
        scratch.result.replay,
        Some(super::ReplayReason::Capacity)
    ));

    // Now test accepted findings don't consume capacity
    // Create input with inline ignores (accepted)
    let mut accepted_input = Vec::new();
    for i in 0..129 {
        accepted_input.extend_from_slice(format!("secret{i} # rayloc:ignore\n").as_bytes());
    }
    let batch = super::LineBatch {
        start: 0,
        end: accepted_input.len(),
        first_line: 1,
        lines: 129,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 0,
                completed_lines: 0,
                bytes: 0,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        },
    };
    super::prepare_batch(
        &accepted_input,
        batch,
        context,
        limits,
        batch_limits,
        &mut scratch,
    );
    // All findings are ignored, so no capacity replay
    assert_eq!(scratch.result.replay, None);
    assert!(scratch.result.findings.is_empty());
}

/// Diagnostics saturate at u64::MAX without affecting scan results.
#[test]
fn diagnostics_saturate_without_affecting_scan_results() {
    let counter = std::sync::atomic::AtomicU64::new(u64::MAX);
    super::saturating_increment(&counter);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), u64::MAX);
}

/// Helper pool metrics track concurrent usage.
#[test]
fn helper_pool_tracks_concurrent_usage() {
    let helpers = super::HelperPool::new(4, BATCH_LIMITS);

    // Acquire all slots
    let mut leases = Vec::new();
    for _ in 0..3 {
        leases.push(helpers.try_acquire().unwrap());
    }

    // Peak should be 3
    let metrics = helpers.snapshot();
    assert_eq!(metrics.peak_slots, 3);

    // Release all
    leases.clear();

    // Peak should still be 3
    let metrics = helpers.snapshot();
    assert_eq!(metrics.peak_slots, 3);
}

/// Lease scratch access works correctly.
#[test]
fn lease_scratch_access_works() {
    let helpers = super::HelperPool::new(4, BATCH_LIMITS);
    let mut lease = helpers.try_acquire().unwrap();
    let scratch = lease.scratch_mut();
    // Just verify we can access it
    assert_eq!(scratch.result.findings.len(), 0);
}

/// Wave planning with multiple small batches.
#[test]
fn wave_planner_multiple_small_batches() {
    let input = b"a\nb\nc\nd\ne\nf\ng\nh\n";
    let limits = BatchLimits {
        target_bytes: 4,
        hard_bytes: 8,
        max_batches: 8,
        max_findings: 128,
    };
    let plan = plan_wave(input, 1, 8, limits).unwrap();
    // Each line is 2 bytes, target is 4, so 2 lines per batch
    assert_eq!(plan.len, 4);
    for i in 0..plan.len {
        assert_eq!(plan.batches[i].lines, 2);
    }
}

/// Wave planning respects max_batches parameter.
#[test]
fn wave_planner_respects_max_batches() {
    let input = b"a\nb\nc\nd\ne\nf\ng\nh\n";
    let limits = BatchLimits {
        target_bytes: 4,
        hard_bytes: 8,
        max_batches: 8,
        max_findings: 128,
    };
    let plan = plan_wave(input, 1, 2, limits).unwrap();
    assert_eq!(plan.len, 2);
}

/// Batch delta tracks attempted vs completed lines.
#[test]
fn batch_delta_tracks_lines() {
    let delta = super::BatchDelta {
        attempted_lines: 10,
        completed_lines: 8,
        bytes: 100,
        suppressions: Suppressions::default(),
    };
    assert_eq!(delta.attempted_lines, 10);
    assert_eq!(delta.completed_lines, 8);
    assert_eq!(delta.bytes, 100);
}

/// A terminal helper error reaches the scan outcome after earlier work is committed.
#[test]
fn publishing_a_terminal_batch_error_returns_it() {
    let registry = crate::rules::Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: []").unwrap(),
    )
    .unwrap();
    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &registry,
    };
    let mut result = super::PreparedBatch {
        findings: Vec::new(),
        delta: super::BatchDelta {
            attempted_lines: 1,
            completed_lines: 0,
            bytes: 0,
            suppressions: Suppressions::default(),
        },
        terminal: Some(crate::scanner::ScanError::CandidateLimit),
        replay: None,
    };
    let mut outcome = crate::scanner::ScanOutcome::default();
    let collector = std::sync::Mutex::new(crate::scanner::engine::Collector::new(100));
    let mut progress = crate::scanner::chunk::ReadProgress::default();

    let result = super::publish_batch(
        &mut result,
        super::LineBatch {
            start: 0,
            end: 0,
            first_line: 1,
            lines: 1,
        },
        context,
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        &mut progress,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(result, Err(crate::scanner::ScanError::CandidateLimit));
    assert_eq!(outcome.stats.lines_scanned, 1);
    assert_eq!(progress.lines_scanned, 0);
}

#[test]
fn counter_overflow_replays_the_helper_batch() {
    let registry = crate::rules::Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: [{id: secret, regex: secret}]").unwrap(),
    )
    .unwrap();
    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &registry,
    };
    let input = b"secret\nsecret\n";
    let limits = BatchLimits {
        target_bytes: 7,
        hard_bytes: 32,
        max_batches: 2,
        max_findings: 128,
    };
    let plan = super::plan_wave(input, 1, 2, limits).unwrap();
    let helpers = super::HelperPool::new(2, limits);
    let mut progress = crate::scanner::chunk::ReadProgress::default();
    let mut line = crate::scanner::stream::LineSession::new();
    let mut outcome = crate::scanner::ScanOutcome::default();
    outcome.stats.bytes_read = u64::MAX - 7;
    let collector = std::sync::Mutex::new(crate::scanner::engine::Collector::new(100));

    let replay = super::execute_wave(
        input,
        &plan,
        context,
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        limits,
        &helpers,
        &mut progress,
        &mut line,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(replay, Ok(true));
    assert_eq!(outcome.stats.bytes_read, u64::MAX);
    assert_eq!(progress.bytes_read, 7);
    assert_eq!(helpers.snapshot().counter_replays, 1);
}

#[test]
fn publication_replays_when_line_or_progress_counters_overflow() {
    for counter in ["lines", "progress_bytes", "progress_lines"] {
        let registry = crate::rules::Registry::compile(
            crate::config::parse(b"version: \"1\"\nrules: []").unwrap(),
        )
        .unwrap();
        let context = RecordContext {
            source_id: 1,
            path: b"input.rs",
            registry: &registry,
        };
        let mut result = super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta {
                attempted_lines: 1,
                completed_lines: 1,
                bytes: 1,
                suppressions: Suppressions::default(),
            },
            terminal: None,
            replay: None,
        };
        let mut outcome = crate::scanner::ScanOutcome::default();
        let mut progress = crate::scanner::chunk::ReadProgress::default();
        match counter {
            "lines" => outcome.stats.lines_scanned = u64::MAX,
            "progress_bytes" => progress.bytes_read = u64::MAX,
            "progress_lines" => progress.lines_scanned = u64::MAX,
            _ => unreachable!(),
        }
        let collector = std::sync::Mutex::new(crate::scanner::engine::Collector::new(100));

        let result = super::publish_batch(
            &mut result,
            super::LineBatch {
                start: 0,
                end: 1,
                first_line: 1,
                lines: 1,
            },
            context,
            Limits {
                line_bytes: usize::MAX,
                findings: 100,
            },
            &mut progress,
            &mut outcome,
            &collector,
            None,
        );

        assert_eq!(result, Ok(Some(super::ReplayReason::Counter)));
    }
}

#[test]
fn preparing_one_record_at_the_max_line_number_does_not_overflow() {
    let context = RecordContext {
        source_id: 1,
        path: b"input.rs",
        registry: &crate::rules::BUILTINS,
    };
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta::default(),
            terminal: None,
            replay: None,
        },
    };

    super::prepare_batch(
        b"clean\n",
        super::LineBatch {
            start: 0,
            end: 6,
            first_line: u64::MAX,
            lines: 1,
        },
        context,
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        BATCH_LIMITS,
        &mut scratch,
    );

    assert_eq!(scratch.result.terminal, None);
    assert_eq!(scratch.result.delta.completed_lines, 1);
    assert_eq!(scratch.result.delta.bytes, 6);
}

#[test]
fn preparing_a_second_record_after_the_max_line_number_is_terminal() {
    let mut scratch = super::HelperScratch {
        histogram: Histogram::new(),
        result: super::PreparedBatch {
            findings: Vec::new(),
            delta: super::BatchDelta::default(),
            terminal: None,
            replay: None,
        },
    };
    super::prepare_batch(
        b"clean\nnext\n",
        super::LineBatch {
            start: 0,
            end: 11,
            first_line: u64::MAX,
            lines: 2,
        },
        RecordContext {
            source_id: 1,
            path: b"input.rs",
            registry: &crate::rules::BUILTINS,
        },
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        BATCH_LIMITS,
        &mut scratch,
    );

    assert_eq!(
        scratch.result.terminal,
        Some(crate::scanner::ScanError::CounterOverflow)
    );
    assert_eq!(scratch.result.delta.completed_lines, 1);
    assert_eq!(scratch.result.delta.bytes, 6);
}

#[test]
fn executing_an_empty_wave_does_not_change_scan_progress() {
    let registry = crate::rules::Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: []").unwrap(),
    )
    .unwrap();
    let plan = super::WavePlan {
        batches: [super::LineBatch {
            start: 0,
            end: 0,
            first_line: 0,
            lines: 0,
        }; 8],
        len: 0,
    };
    let limits = BATCH_LIMITS;
    let helpers = super::HelperPool::new(2, limits);
    let mut progress = crate::scanner::chunk::ReadProgress::default();
    let mut line = crate::scanner::stream::LineSession::new();
    let mut outcome = crate::scanner::ScanOutcome::default();
    let collector = std::sync::Mutex::new(crate::scanner::engine::Collector::new(100));

    let result = super::execute_wave(
        b"",
        &plan,
        RecordContext {
            source_id: 1,
            path: b"input.rs",
            registry: &registry,
        },
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        limits,
        &helpers,
        &mut progress,
        &mut line,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(result, Ok(false));
    assert_eq!(progress.bytes_read, 0);
    assert_eq!(outcome.stats.lines_scanned, 0);
    assert_eq!(helpers.snapshot().waves, 0);
}

#[test]
fn serial_fallback_accounts_committed_bytes_before_a_later_record_error() {
    let mut input = b"first\nclean\nghp_".to_vec();
    input.resize(
        input.len() + crate::rules::builtin::MAX_CANDIDATE_BYTES + 1,
        b'A',
    );
    input.push(b'\n');
    let split = b"first\n".len();
    let batch_limits = BatchLimits {
        target_bytes: 6,
        hard_bytes: input.len(),
        max_batches: 2,
        max_findings: 128,
    };
    let empty_batch = super::LineBatch {
        start: 0,
        end: 0,
        first_line: 0,
        lines: 0,
    };
    let mut batches = [empty_batch; 8];
    batches[0] = super::LineBatch {
        start: 0,
        end: split,
        first_line: 1,
        lines: 1,
    };
    batches[1] = super::LineBatch {
        start: split,
        end: input.len(),
        first_line: 2,
        lines: 2,
    };
    let plan = super::WavePlan { batches, len: 2 };
    let helpers = super::HelperPool::new(1, batch_limits);
    let mut progress = crate::scanner::chunk::ReadProgress::default();
    let mut line = crate::scanner::stream::LineSession::new();
    let mut outcome = crate::scanner::ScanOutcome::default();
    let collector = std::sync::Mutex::new(crate::scanner::engine::Collector::new(100));
    let result = super::execute_wave(
        &input,
        &plan,
        RecordContext {
            source_id: 1,
            path: b"input.rs",
            registry: &crate::rules::BUILTINS,
        },
        Limits {
            line_bytes: usize::MAX,
            findings: 100,
        },
        batch_limits,
        &helpers,
        &mut progress,
        &mut line,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(result, Err(crate::scanner::ScanError::CandidateLimit));
    assert_eq!(progress.bytes_read, (split + 6) as u64);
    assert_eq!(outcome.stats.bytes_read, (split + 6) as u64);
    assert_eq!(outcome.stats.lines_scanned, 3);
}
