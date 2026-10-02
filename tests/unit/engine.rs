use super::*;
use std::{
    fs::OpenOptions,
    io::{Cursor, Read, Write},
};

use crate::test_support as support;

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
    assert_eq!(outcome.errors, [ScanError::CandidateLimit]);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.stats.files_completed, 0);

    let input = b"-----BEGIN PRIVATE KEY-----\n";
    let mut reader = FaultReader {
        input: Cursor::new(input.as_slice()),
        interrupted: true,
    };
    let outcome = scan_reader(&mut reader, 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.errors, [ScanError::Read]);
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
        assert_eq!(outcome.errors, [ScanError::LineLimit]);
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
    assert_eq!(
        scan_reader(&mut Cursor::new(oversized), 1).errors,
        [ScanError::LineLimit]
    );
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
    assert_eq!(outcome.errors, [ScanError::FindingLimit]);
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
    assert_eq!(outcome.errors, [ScanError::FindingLimit]);
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
    assert_eq!(outcome.errors, [ScanError::CounterOverflow]);
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
        assert_eq!(outcome.errors, [ScanError::Open]);
        assert_eq!(outcome.exit_code(), 2);
    }
}

#[test]
fn nonexistent_paths_directories_and_symlinks_are_safe_errors() {
    let directory = support::TempDir::new();
    let sentinel = "ghp_SyntheticSensitivePath0123456789";
    let path = directory.path().join(sentinel);
    let outcome = scan_file(&path, 1);
    assert_eq!(outcome.errors, [ScanError::Open]);
    assert!(!format!("{outcome:?}").contains(sentinel));
    assert_eq!(
        scan_file(directory.path(), 1).errors,
        [ScanError::NotRegularFile]
    );
    #[cfg(unix)]
    {
        let file = directory.path().join("regular");
        let link = directory.path().join("link");
        fs::write(&file, b"-----BEGIN PRIVATE KEY-----").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(scan_file(&link, 1).errors, [ScanError::NotRegularFile]);
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
