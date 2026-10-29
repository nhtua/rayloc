use super::*;
use crate::redact::{Stats, Summary, cli::run_with_report};
use std::ffi::OsString;
use std::time::Duration;

struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive diagnostic"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("sensitive diagnostic"))
    }
}

struct FlushFailure(Vec<u8>);
impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("sensitive diagnostic"))
    }
}

#[test]
fn summary_rows_are_aggregates_without_source_metadata() {
    let summary = Summary {
        mode: "command",
        policy: true,
        sources: vec![("stdout", Some(Stats::default())), ("stderr", None)],
        child_program: Some("curl".to_owned()),
        ..Summary::default()
    };
    let mut report = Vec::new();
    write_summary(&mut report, &summary, Duration::from_millis(5), 0).unwrap();
    let report = String::from_utf8(report).unwrap();
    assert!(report.contains("mode=command"));
    assert!(report.contains("policy=true"));
    assert!(report.contains("duration_seconds=0.005000000"));
    assert!(!report.contains("elapsed_ns="));
    assert!(report.contains("invocation=rayloc redact"));
    assert!(report.contains("child_program=curl"));
    assert!(report.contains("finished_at="));
    assert!(report.contains("child=not-started"));
    assert!(report.contains("error=none"));
    assert!(report.contains("source=stdout state=filtered bytes_read=0"));
    assert!(report.contains("source=stderr state=passthrough counts=unknown"));
    assert!(report.contains("status=complete"));
    assert!(report.contains("exit=0"));
}

#[test]
fn executable_name_is_reduced_to_a_safe_basename() {
    assert_eq!(
        sanitized_program_name(OsStr::new("/usr/bin/curl")),
        Some("curl".to_owned())
    );
    assert_eq!(sanitized_program_name(OsStr::new("child\nsecret")), None);
    assert_eq!(sanitized_program_name(OsStr::new(&"a".repeat(129))), None);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            sanitized_program_name(OsStr::from_bytes(b"tool-\xff")),
            None
        );
    }
}

#[test]
fn child_status_and_failure_precedence_are_recorded() {
    let mut report = Vec::new();
    let summary = Summary {
        mode: "command",
        child_started: true,
        ..Summary::default()
    };
    write_summary(&mut report, &summary, Duration::ZERO, 2).unwrap();
    assert!(
        String::from_utf8(report)
            .unwrap()
            .contains("child=unavailable")
    );
    let raw_status = std::process::Command::new("sh")
        .args(["-c", "exit 7"])
        .status()
        .unwrap();
    let summary = Summary {
        mode: "command",
        child_started: true,
        child: Some(raw_status),
        ..Summary::default()
    };
    let mut report = Vec::new();
    write_summary(&mut report, &summary, Duration::ZERO, 2).unwrap();
    assert!(String::from_utf8(report).unwrap().contains("child=exit:7"));
}

#[test]
fn summary_write_and_flush_failures_are_propagated() {
    let summary = Summary {
        mode: "stdio",
        ..Summary::default()
    };
    assert!(write_summary(&mut BrokenWriter, &summary, Duration::ZERO, 0).is_err());
    assert!(write_summary(&mut FlushFailure(Vec::new()), &summary, Duration::ZERO, 0).is_err());
}

#[test]
fn report_creation_and_finalization_errors_return_two() {
    assert_eq!(
        run_with_report(
            Vec::new(),
            Err::<BrokenWriter, _>(io::Error::other("private"))
        ),
        2
    );
    assert_eq!(
        run_with_report(vec![OsString::from("--invalid")], Ok(BrokenWriter)),
        2
    );
    let mut report = Vec::new();
    assert_eq!(
        run_with_report(vec![OsString::from("--invalid")], Ok(&mut report)),
        2
    );
    let report = String::from_utf8(report).unwrap();
    assert!(report.contains("error=arguments"));
    assert!(!report.contains("--invalid"));
}

#[test]
fn report_creation_refuses_collisions_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = crate::test_support::TempDir::new();
    let target = directory.path().join("sentinel");
    std::fs::write(&target, b"unchanged").unwrap();
    let first = directory
        .path()
        .join("rayloc-report-1970-01-01T00:00:10-0.txt");
    symlink(&target, &first).unwrap();
    let mut file = report_in(directory.path(), 42, Duration::from_secs(10)).unwrap();
    writeln!(file, "test").unwrap();
    let created = directory
        .path()
        .join("rayloc-report-1970-01-01T00:00:10-1.txt");
    assert_eq!(
        std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        std::fs::read_to_string(&created)
            .unwrap()
            .contains("started_at=1970-01-01T00:00:10Z")
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    let leap_day = report_in(directory.path(), 43, Duration::from_secs(1_709_164_800)).unwrap();
    drop(leap_day);
    assert!(
        directory
            .path()
            .join("rayloc-report-2024-02-29T00:00:00-0.txt")
            .exists()
    );
    for index in 2..64 {
        std::fs::write(
            directory
                .path()
                .join(format!("rayloc-report-1970-01-01T00:00:10-{index}.txt")),
            b"occupied",
        )
        .unwrap();
    }
    assert!(report_in(directory.path(), 42, Duration::from_secs(10)).is_err());
    assert!(
        report_in(
            &directory.path().join("missing"),
            42,
            Duration::from_secs(10)
        )
        .is_err()
    );
}

#[test]
fn child_status_without_code_or_signal_is_unavailable() {
    use std::os::unix::process::ExitStatusExt;
    let summary = Summary {
        mode: "command",
        child_started: true,
        child: Some(std::process::ExitStatus::from_raw(0x7f)),
        ..Summary::default()
    };
    let mut report = Vec::new();
    write_summary(&mut report, &summary, Duration::ZERO, 2).unwrap();
    assert!(
        String::from_utf8(report)
            .unwrap()
            .contains("child=unavailable")
    );
}

#[test]
fn stats_row_write_failure_is_propagated() {
    struct FailSecondWrite;
    impl Write for FailSecondWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("sensitive diagnostic"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct FailAfterBytes {
        budget: usize,
        buffer: Vec<u8>,
    }
    impl Write for FailAfterBytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::other("sensitive diagnostic"));
            }
            let accepted = bytes.len().min(self.budget);
            self.budget -= accepted;
            self.buffer.extend_from_slice(&bytes[..accepted]);
            Ok(accepted)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let summary = Summary {
        mode: "stdio",
        sources: vec![("stdin", Some(Stats::default()))],
        ..Summary::default()
    };
    // The mode block is at most ~90 bytes; the budget expires mid stats row.
    let mut writer = FailAfterBytes {
        budget: 100,
        buffer: Vec::new(),
    };
    assert!(write_summary(&mut writer, &summary, Duration::ZERO, 0).is_err());
    let written = String::from_utf8(writer.buffer).unwrap();
    assert!(written.contains("mode=stdio"));
    assert!(write_summary(&mut FailSecondWrite, &summary, Duration::ZERO, 0).is_err());
}
