use super::*;
use crate::scanner::SourceError;
use crate::scanner::fingerprint::FindingId;
use crate::scanner::redaction::RedactedString;
use std::{
    fs::OpenOptions,
    io::{BufReader, Cursor, Read, Write},
};

use crate::test_support as support;

fn scan_record(
    line: &[u8],
    source_id: u32,
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
    histogram: &mut Histogram,
) -> Result<(), ScanError> {
    let collector = Mutex::new(Collector::new(limits.findings));
    scan_record_into(
        line, source_id, b"", outcome, limits, registry, histogram, &collector, None,
    )
}
fn read_records(
    reader: &mut dyn BufRead,
    source_id: u32,
    outcome: &mut ScanOutcome,
    limits: Limits,
    registry: &Registry,
) -> Result<(), ScanError> {
    let collector = Mutex::new(Collector::new(limits.findings));
    read_records_into(
        reader,
        source_id,
        b"",
        outcome,
        limits,
        registry,
        &mut super::super::stream::LineSession::new(),
        &mut Histogram::new(),
        &collector,
        None,
    )
}

#[test]
fn capped_collector_retains_earlier_custom_spans_emitted_after_provider_matches() {
    let registry = Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: [{id: early, regex: early}]").unwrap(),
    )
    .unwrap();
    let outcome = scan_with_policy(
        &mut Cursor::new(b"early ghp_abcdefghijklmnop"),
        1,
        Limits {
            line_bytes: 100,
            findings: 1,
        },
        &registry,
    );
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.stats.findings_detected, 2);
    assert_eq!(outcome.findings[0].start_column, 1);
}

#[test]
fn dense_batch_replay_scans_the_remaining_file() {
    let registry = Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: [{id: secret, regex: secret}]").unwrap(),
    )
    .unwrap();
    let input = b"secret\nsecret\nsecret\nsecret\n";
    let batch_limits = crate::scanner::batch::BatchLimits {
        target_bytes: 7,
        hard_bytes: 64,
        max_batches: 8,
        max_findings: 0,
    };
    let helpers = crate::scanner::batch::HelperPool::new(2, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();

    let result = read_file_with_batches(
        &mut Cursor::new(input),
        1,
        b"input.rs",
        &registry,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert!(result.is_ok());
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.findings_detected, 4);
    assert_eq!(outcome.findings.len(), 4);
    assert_eq!(outcome.stats.lines_scanned, 4);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
}

#[test]
fn batch_scan_handles_multiple_waves_and_limited_helper_slots() {
    let registry = Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: [{id: secret, regex: secret}]").unwrap(),
    )
    .unwrap();
    let input = b"secret\nsecret\nsecret\nsecret\nsecret\nsecret\n";
    let batch_limits = crate::scanner::batch::BatchLimits {
        target_bytes: 7,
        hard_bytes: 64,
        max_batches: 2,
        max_findings: 128,
    };

    for (workers, reserve_helper, want_helper_batches, want_fallbacks) in
        [(1, false, 0, 3), (3, true, 3, 0)]
    {
        let helpers = crate::scanner::batch::HelperPool::new(workers, batch_limits);
        let held = reserve_helper.then(|| helpers.try_acquire().unwrap());
        let collector = Mutex::new(Collector::new(100));
        let mut outcome = ScanOutcome::default();

        let result = read_file_with_batches(
            &mut Cursor::new(input),
            1,
            b"input.rs",
            &registry,
            &helpers,
            batch_limits,
            &mut outcome,
            &collector,
            None,
        );

        assert!(result.is_ok());
        collector
            .into_inner()
            .expect("collector lock is not poisoned")
            .finish(&mut outcome);
        assert_eq!(outcome.stats.findings_detected, 6);
        assert_eq!(outcome.findings.len(), 6);
        assert_eq!(
            outcome
                .findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(outcome.stats.lines_scanned, 6);
        assert_eq!(outcome.stats.bytes_read, input.len() as u64);
        let metrics = helpers.snapshot();
        assert_eq!(metrics.waves, 3);
        assert_eq!(metrics.helper_batches, want_helper_batches);
        assert_eq!(metrics.no_slot_fallbacks, want_fallbacks);
        drop(held);
    }
}

#[test]
fn batched_reader_errors_after_committed_records_are_reported() {
    let registry = Registry::compile(
        crate::config::parse(b"version: \"1\"\nrules: [{id: secret, regex: secret}]").unwrap(),
    )
    .unwrap();
    let input = b"clean\nsecret\n";
    let batch_limits = crate::scanner::batch::BatchLimits {
        target_bytes: 64,
        hard_bytes: 128,
        max_batches: 4,
        max_findings: 128,
    };
    let helpers = crate::scanner::batch::HelperPool::new(1, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();
    let result = read_file_with_batches(
        &mut ErrorAfterBytes {
            input: Cursor::new(input.as_slice()),
            failed: false,
        },
        1,
        b"input.rs",
        &registry,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(result, Err(ScanError::Read));
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.findings_detected, 1);
    assert_eq!(outcome.stats.lines_scanned, 2);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
}

#[test]
fn batched_scanner_streams_a_line_across_read_windows() {
    let mut input = b"clean\n".to_vec();
    input.extend(std::iter::repeat_n(b'x', 300 * 1024));
    input.extend_from_slice(b"\n");
    input.extend_from_slice(&crate::scanner::parallel_support::token_line());
    let batch_limits = crate::scanner::batch::BATCH_LIMITS;
    let helpers = crate::scanner::batch::HelperPool::new(1, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();

    let result = read_file_with_batches(
        &mut Cursor::new(input.as_slice()),
        1,
        b"input.rs",
        &BUILTINS,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert!(result.is_ok());
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
    assert_eq!(outcome.stats.lines_scanned, 3);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].line, 3);
}

#[test]
fn worker_file_batch_path_scans_large_sources_and_excludes_binary_files() {
    let directory = support::TempDir::new();
    let source = directory.path().join("large.rs");
    let mut input = vec![b'x'; 300 * 1024];
    input.push(b'\n');
    input.extend_from_slice(&crate::scanner::parallel_support::token_line());
    fs::write(&source, &input).unwrap();

    let batch_limits = crate::scanner::batch::BATCH_LIMITS;
    let helpers = crate::scanner::batch::HelperPool::new(2, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut worker = Worker::new();
    let run = worker.file_with_batches(
        &source,
        Path::new("large.rs"),
        1,
        &BUILTINS,
        &helpers,
        batch_limits,
        &collector,
        None,
    );
    let mut outcome = run.outcome;
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.files_completed, 1);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
    assert_eq!(outcome.stats.lines_scanned, 2);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].line, 2);

    let binary = directory.path().join("binary");
    fs::write(&binary, b"\0not source\n").unwrap();
    let run = worker.file_with_batches(
        &binary,
        Path::new("binary"),
        2,
        &BUILTINS,
        &helpers,
        batch_limits,
        &Mutex::new(Collector::new(100)),
        None,
    );
    assert_eq!(run.outcome.stats.files_excluded, 1);
    assert_eq!(run.outcome.stats.files_completed, 0);
}

#[test]
fn helper_detection_errors_stop_the_wave_after_committed_records() {
    let mut input = b"clean\n".to_vec();
    input.extend_from_slice(b"ghp_");
    input.resize(
        input.len() + crate::rules::builtin::MAX_CANDIDATE_BYTES + 1,
        b'A',
    );
    input.push(b'\n');
    let batch_limits = crate::scanner::batch::BatchLimits {
        target_bytes: 6,
        hard_bytes: 128 * 1024,
        max_batches: 2,
        max_findings: 128,
    };
    let helpers = crate::scanner::batch::HelperPool::new(2, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();

    let result = read_file_with_batches(
        &mut Cursor::new(input.as_slice()),
        1,
        b"input.rs",
        &BUILTINS,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert_eq!(result, Err(ScanError::CandidateLimit));
    assert_eq!(outcome.stats.lines_scanned, 2);
    assert_eq!(outcome.stats.bytes_read, 6);
    assert_eq!(outcome.stats.files_completed, 0);
}

#[test]
fn batched_reader_retries_interrupted_short_reads() {
    let input = crate::scanner::parallel_support::token_line();
    let batch_limits = crate::scanner::batch::BATCH_LIMITS;
    let helpers = crate::scanner::batch::HelperPool::new(1, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();
    let result = read_file_with_batches(
        &mut InterruptedShortReader {
            input: Cursor::new(input.as_slice()),
            interrupted: false,
        },
        1,
        b"input.rs",
        &BUILTINS,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert!(result.is_ok());
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
    assert_eq!(outcome.stats.lines_scanned, 1);
    assert_eq!(outcome.findings.len(), 1);
}

struct InterruptedShortReader<'a> {
    input: Cursor<&'a [u8]>,
    interrupted: bool,
}

impl Read for InterruptedShortReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = buffer.len().min(3);
        self.input.read(&mut buffer[..length])
    }
}

#[test]
fn oversized_complete_records_fall_back_to_streaming_line_scans() {
    let mut input = vec![b'x'; 100];
    input.push(b'\n');
    input.extend_from_slice(&crate::scanner::parallel_support::token_line());
    let batch_limits = crate::scanner::batch::BatchLimits {
        target_bytes: 16,
        hard_bytes: 32,
        max_batches: 4,
        max_findings: 128,
    };
    let helpers = crate::scanner::batch::HelperPool::new(1, batch_limits);
    let collector = Mutex::new(Collector::new(100));
    let mut outcome = ScanOutcome::default();

    let result = read_file_with_batches(
        &mut Cursor::new(input.as_slice()),
        1,
        b"input.rs",
        &BUILTINS,
        &helpers,
        batch_limits,
        &mut outcome,
        &collector,
        None,
    );

    assert!(result.is_ok());
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
    assert_eq!(outcome.stats.lines_scanned, 2);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].line, 2);
}

struct ErrorAfterBytes {
    input: Cursor<&'static [u8]>,
    failed: bool,
}

impl Read for ErrorAfterBytes {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.input.position() < self.input.get_ref().len() as u64 {
            self.input.read(bytes)
        } else if !self.failed {
            self.failed = true;
            Err(io::Error::other("private reader diagnostic"))
        } else {
            Ok(0)
        }
    }
}

#[test]
fn empty_readers_and_empty_files_are_successfully_completed() {
    let outcome = scan_reader(&mut Cursor::new([]), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.stats.files_attempted, 1);
    assert_eq!(outcome.stats.files_completed, 1);
    assert_eq!(outcome.stats.lines_scanned, 0);
    let directory = support::TempDir::new();
    let path = directory.path().join("empty");
    fs::write(&path, []).unwrap();
    assert_eq!(scan_file(&path, 1).exit_code(), 0);
    assert!(open_regular(&path).is_ok());
}

#[test]
fn locations_are_byte_based_across_small_buffers_crlf_and_no_final_newline() {
    let input = &[
        99, 108, 101, 97, 110, 13, 10, 255, 0, 34, 65, 75, 73, 65, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 48, 65, 66, 67, 68, 69, 70, 34, 13, 10, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32,
        80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45,
    ];
    for capacity in [1, 2, 7, 256] {
        let mut reader = BufReader::with_capacity(capacity, Cursor::new(input));
        let outcome = scan_reader(&mut reader, 19);
        assert_eq!(outcome.exit_code(), 1);
        assert_eq!(outcome.stats.bytes_read, input.len() as u64);
        assert_eq!(outcome.stats.lines_scanned, 4);
        assert_eq!(outcome.stats.files_completed, 1);
        assert_eq!(outcome.findings.len(), 2);
        let first = &outcome.findings[0];
        assert_eq!(
            (
                first.source_id,
                first.line,
                first.start_column,
                first.end_column
            ),
            (19, 2, 4, 24)
        );
        assert_eq!(
            (outcome.findings[1].line, outcome.findings[1].start_column),
            (4, 1)
        );
    }
    assert_eq!(
        scan_reader(&mut Cursor::new(b"\n"), 1).stats.lines_scanned,
        1
    );
    assert_eq!(
        scan_reader(&mut Cursor::new(b"\n\n"), 1)
            .stats
            .lines_scanned,
        2
    );
}

#[test]
fn reader_and_candidate_failures_keep_prior_findings_and_prevent_clean_exit() {
    let mut input = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
    input.extend_from_slice(b"ghp_");
    input.resize(
        input.len() + crate::rules::builtin::MAX_CANDIDATE_BYTES,
        b'A',
    );
    let outcome = scan_reader(&mut Cursor::new(input), 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(
        outcome.errors,
        [SourceError::new(ScanError::CandidateLimit, None)]
    );
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.stats.files_completed, 0);

    let input = b"-----BEGIN PRIVATE KEY-----\n";
    let mut reader = FaultReader {
        input: Cursor::new(input.as_slice()),
        interrupted: true,
    };
    let outcome = scan_reader(&mut reader, 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.errors, [SourceError::new(ScanError::Read, None)]);
    assert_eq!(outcome.findings.len(), 1);
    assert!(!format!("{outcome:?}").contains("sensitive-io-diagnostic"));
}

struct FaultReader {
    input: Cursor<&'static [u8]>,
    interrupted: bool,
}

impl Read for FaultReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl BufRead for FaultReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.input.position() == self.input.get_ref().len() as u64 {
            return Err(io::Error::other("sensitive-io-diagnostic"));
        }
        self.input.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.input.consume(amount);
    }
}

#[test]
fn line_limit_handles_exact_boundary_newlines_and_fragment_growth() {
    let limits = Limits {
        line_bytes: 37,
        findings: 10,
    };
    for suffix in [b"".as_slice(), b"\n"] {
        let input = [vec![b'0'; 37], suffix.to_vec()].concat();
        for capacity in [1, 37, 100] {
            let mut reader = BufReader::with_capacity(capacity, Cursor::new(&input));
            assert_eq!(scan_with_limits(&mut reader, 1, limits).exit_code(), 0);
        }
    }
    for capacity in [1, 37, 100] {
        let mut reader = BufReader::with_capacity(capacity, Cursor::new(vec![b'0'; 38]));
        let outcome = scan_with_limits(&mut reader, 1, limits);
        assert_eq!(
            outcome.errors,
            [SourceError::new(ScanError::LineLimit, None)]
        );
        assert_eq!(outcome.exit_code(), 2);
    }
    let mut input = vec![b'0'; READ_BUFFER_BYTES + 1];
    input.push(b'\n');
    let outcome = scan_reader(&mut BufReader::with_capacity(17, Cursor::new(&input)), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.stats.bytes_read, input.len() as u64);
    let exact = vec![b'0'; MAX_LINE_BYTES];
    assert_eq!(scan_reader(&mut Cursor::new(exact), 1).exit_code(), 0);
    let oversized = vec![b'0'; MAX_LINE_BYTES + 1];
    let outcome = scan_reader(&mut Cursor::new(oversized), 1);
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.stats.files_completed, 1);
}

#[test]
fn findings_are_capped_globally_with_exact_counts_and_stable_first_occurrences() {
    let input =
        b"-----BEGIN PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----";
    let outcome = scan_with_limits(
        &mut Cursor::new(input),
        1,
        Limits {
            line_bytes: 100,
            findings: 2,
        },
    );
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(
        outcome.errors,
        [SourceError::new(ScanError::FindingLimit, None)]
    );
    assert_eq!(outcome.stats.findings_detected, 3);
    assert_eq!(
        outcome.findings.iter().map(|f| f.line).collect::<Vec<_>>(),
        [1, 2]
    );
    let outcome = scan_with_limits(
        &mut Cursor::new(input),
        1,
        Limits {
            line_bytes: 100,
            findings: 0,
        },
    );
    assert_eq!(outcome.exit_code(), 2);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.stats.findings_detected, 3);
}

#[test]
fn public_scanner_enforces_the_default_ten_thousand_finding_limit() {
    let input = b"-----BEGIN PRIVATE KEY-----\n".repeat(10_002);
    let outcome = scan_reader(&mut Cursor::new(input), 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(
        outcome.errors,
        [SourceError::new(ScanError::FindingLimit, None)]
    );
    assert_eq!(outcome.findings.len(), 10_000);
    assert_eq!(outcome.findings.last().unwrap().line, 10_000);
    assert_eq!(outcome.stats.findings_detected, 10_002);
    assert_eq!(outcome.stats.lines_scanned, 10_002);
    assert_eq!(outcome.stats.files_completed, 0);
}

#[test]
fn overflow_is_safe_for_every_scanner_counter() {
    let mut counter = u64::MAX - 1;
    assert_eq!(add(&mut counter, 1), Ok(()));
    assert_eq!(counter, u64::MAX);
    assert_eq!(add(&mut counter, 1), Err(ScanError::CounterOverflow));
    let mut outcome = ScanOutcome::default();
    outcome.stats.lines_scanned = u64::MAX;
    assert_eq!(
        scan_record(
            b"",
            1,
            &mut outcome,
            LIMITS,
            &BUILTINS,
            &mut Histogram::new()
        ),
        Err(ScanError::CounterOverflow)
    );
    outcome.stats.lines_scanned = 0;
    outcome.stats.findings_detected = u64::MAX;
    assert_eq!(
        scan_record(
            b"-----BEGIN PRIVATE KEY-----",
            1,
            &mut outcome,
            LIMITS,
            &BUILTINS,
            &mut Histogram::new()
        ),
        Ok(())
    );
    assert_eq!(
        outcome.errors,
        [SourceError::new(ScanError::CounterOverflow, None)]
    );
    assert_eq!(outcome.exit_code(), 2);

    for input in [b"1".as_slice(), b"1\n"] {
        let mut outcome = ScanOutcome::default();
        outcome.stats.lines_scanned = u64::MAX;
        assert_eq!(
            read_records(&mut Cursor::new(input), 1, &mut outcome, LIMITS, &BUILTINS),
            Err(ScanError::CounterOverflow)
        );
    }
    let mut outcome = ScanOutcome::default();
    outcome.stats.bytes_read = u64::MAX;
    assert_eq!(
        read_records(&mut Cursor::new(b"x\n"), 1, &mut outcome, LIMITS, &BUILTINS),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn opened_file_validation_rejects_errors_and_replaced_sources() {
    let directory = support::TempDir::new();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    fs::write(&first, []).unwrap();
    fs::write(&second, []).unwrap();
    let metadata = fs::metadata(&first).unwrap();
    assert_eq!(validate_opened(&metadata, fs::metadata(&first)), Ok(()));
    assert_eq!(
        validate_opened(
            &metadata,
            Err(io::Error::other("sensitive-metadata-diagnostic"))
        ),
        Err(ScanError::Open)
    );
    assert_eq!(
        validate_opened(&metadata, fs::metadata(directory.path())),
        Err(ScanError::NotRegularFile)
    );
    #[cfg(unix)]
    assert_eq!(
        validate_opened(&metadata, fs::metadata(&second)),
        Err(ScanError::Open)
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        validate_opened(&metadata, fs::metadata("/proc/version")),
        Err(ScanError::Open)
    );
}

#[cfg(unix)]
#[test]
fn unreadable_regular_files_return_safe_open_errors() {
    use std::os::unix::fs::PermissionsExt;
    let directory = support::TempDir::new();
    let path = directory.path().join("unreadable");
    fs::write(&path, b"-----BEGIN PRIVATE KEY-----").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    let readable_with_current_privileges = File::open(&path).is_ok();
    let outcome = scan_file(&path, 1);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    if readable_with_current_privileges {
        assert_eq!(outcome.exit_code(), 1);
    } else {
        assert_eq!(
            outcome.errors,
            [SourceError::new(
                ScanError::Open,
                Some(path.to_string_lossy().into())
            )]
        );
        assert_eq!(outcome.exit_code(), 2);
    }
}

#[test]
fn nonexistent_paths_directories_and_symlinks_are_safe_errors() {
    let directory = support::TempDir::new();
    let sentinel = "ghp_SyntheticSensitivePath0123456789";
    let path = directory.path().join(sentinel);
    let outcome = scan_file(&path, 1);
    assert_eq!(
        outcome.errors,
        [SourceError::new(
            ScanError::Open,
            Some(path.to_string_lossy().into())
        )]
    );
    let dir_path = directory.path().to_path_buf();
    assert_eq!(
        scan_file(&dir_path, 1).errors,
        [SourceError::new(
            ScanError::NotRegularFile,
            Some(dir_path.to_string_lossy().into())
        )]
    );
    #[cfg(unix)]
    {
        let file = directory.path().join("regular");
        let link = directory.path().join("link");
        fs::write(&file, b"-----BEGIN PRIVATE KEY-----").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(
            scan_file(&link, 1).errors,
            [SourceError::new(
                ScanError::NotRegularFile,
                Some(link.to_string_lossy().into())
            )]
        );
        assert!(scan_file(&link, 1).findings.is_empty());
    }
}

#[test]
fn files_exceeding_ten_megabytes_are_streamed_and_scanned_through_the_end() {
    let directory = support::TempDir::new();
    let path = directory.path().join("large");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let chunk = [b'0'; 8192];
    for _ in 0..1400 {
        file.write_all(&chunk).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.write_all(b"-----BEGIN PRIVATE KEY-----").unwrap();
    drop(file);
    let outcome = scan_file(&path, 23);
    assert!(outcome.stats.bytes_read > 10 * 1024 * 1024);
    assert_eq!(outcome.stats.bytes_read, fs::metadata(&path).unwrap().len());
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.stats.files_completed, 1);
    assert_eq!(outcome.findings[0].line, 1401);
}
#[test]
fn registry_findings_are_sorted_by_location_across_builtin_and_custom_rules() {
    let registry = Registry::compile(
        crate::config::parse(
            b"version: \"1\"\nrules: [{id: late, regex: late}, {id: early, regex: early}]",
        )
        .unwrap(),
    )
    .unwrap();
    let outcome = scan_reader_with_registry(
        &mut Cursor::new(b"early ghp_abcdefghijklmnop late\nearly"),
        4,
        &registry,
    );
    assert_eq!(
        outcome
            .findings
            .iter()
            .map(|f| (f.line, f.start_column))
            .collect::<Vec<_>>(),
        [(1, 1), (1, 7), (1, 28), (2, 1)]
    );
}
#[test]
fn suppression_counter_overflow_returns_execution_error() {
    let mut outcome = ScanOutcome::default();
    outcome.stats.suppressions.inline = usize::MAX;
    assert_eq!(
        scan_record(
            b"password='aaaaaaaa' # rayloc:ignore",
            1,
            &mut outcome,
            LIMITS,
            &BUILTINS,
            &mut Histogram::new()
        ),
        Err(ScanError::CounterOverflow)
    );
}
#[test]
fn reusable_file_buffers_and_worker_failures_preserve_counts() {
    let temp = support::TempDir::new();
    let path = temp.path().join("input");
    fs::write(&path, b"abcdef").unwrap();
    let file = File::open(&path).unwrap();
    let mut storage = [0; 3];
    let mut reader = BufferedFile {
        file,
        storage: &mut storage,
        start: 0,
        end: 0,
    };
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"abcdef");
    fs::write(&path, vec![b'x'; MAX_LINE_BYTES + 1]).unwrap();
    let long_clean = scan_file(&path, 1);
    assert!(long_clean.errors.is_empty());
    assert_eq!(long_clean.stats.files_completed, 1);
    fs::write(&path, b"ghp_abcdefghijklmnop\n".repeat(MAX_FINDINGS + 1)).unwrap();
    let result = scan_file(&path, 1);
    assert_eq!(
        result.errors,
        [SourceError::new(ScanError::FindingLimit, None)]
    );
    assert_eq!(result.stats.files_completed, 0);
    let mut target = ScanOutcome::default();
    target.stats.files_attempted = u64::MAX;
    let mut source = ScanOutcome::default();
    source.stats.files_attempted = 1;
    source.fail(ScanError::Read);
    merge(&mut target, source);
    assert_eq!(
        target.errors,
        [
            SourceError::new(ScanError::Read, None),
            SourceError::new(ScanError::CounterOverflow, None)
        ]
    );
    for index in 0..6 {
        let mut target = ScanStats::default();
        let mut source = ScanStats::default();
        let set = |s: &mut ScanStats, v| match index {
            0 => s.files_attempted = v,
            1 => s.files_completed = v,
            2 => s.files_excluded = v,
            3 => s.bytes_read = v,
            4 => s.lines_scanned = v,
            _ => s.findings_detected = v,
        };
        set(&mut target, u64::MAX);
        set(&mut source, 1);
        assert_eq!(
            merge_stats(&mut target, &source),
            Err(ScanError::CounterOverflow)
        );
    }
    let mut collector = Collector::new(0);
    collector.offer(
        Finding {
            source_id: 1,
            line: 1,
            start_column: 1,
            end_column: 2,
            rule: crate::rules::builtin::RuleId::GithubToken,
            value: RedactedString::new(b"x"),
            unredacted_value: None,
            id: FindingId::new(b"", b"x"),
        },
        b"test/path",
    );
    assert!(collector.entries.is_empty());
}
#[cfg(unix)]
#[test]
fn buffered_read_error_propagates_without_diagnostics() {
    let temp = support::TempDir::new();
    let file = File::open(temp.path()).unwrap();
    let mut storage = [0; 8];
    let mut reader = BufferedFile {
        file,
        storage: &mut storage,
        start: 0,
        end: 0,
    };
    assert!(reader.read(&mut [0; 8]).is_err());
}
