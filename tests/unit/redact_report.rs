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
        ..Summary::default()
    };
    let mut report = Vec::new();
    write_summary(&mut report, &summary, Duration::from_millis(5), 0).unwrap();
    let report = String::from_utf8(report).unwrap();
    assert!(report.contains("mode=command"));
    assert!(report.contains("policy=true"));
    assert!(report.contains("elapsed_ns=5000000"));
    assert!(report.contains("child=not-started"));
    assert!(report.contains("error=none"));
    assert!(report.contains("source=stdout state=filtered bytes_read=0"));
    assert!(report.contains("source=stderr state=passthrough counts=unknown"));
    assert!(report.contains("status=complete"));
    assert!(report.contains("exit=0"));
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
    let first = directory.path().join("rayloc-report-10-0-42-0.txt");
    symlink(&target, &first).unwrap();
    let mut file = report_in(directory.path(), 42, Duration::from_secs(10)).unwrap();
    writeln!(file, "test").unwrap();
    let created = directory.path().join("rayloc-report-10-0-42-1.txt");
    assert_eq!(
        std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    for index in 2..64 {
        std::fs::write(
            directory
                .path()
                .join(format!("rayloc-report-10-0-42-{index}.txt")),
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
