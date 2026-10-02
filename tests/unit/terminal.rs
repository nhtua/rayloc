use super::*;
use crate::scanner::{ScanError, engine::scan_reader};
use std::io::Cursor;

#[test]
fn clean_findings_and_partial_reports_are_distinct_and_never_leak_values() {
    let mut output = Vec::new();
    render(&ScanOutcome::default(), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("rayloc — CLEAN\n"));
    assert!(!text.contains("Remove exposed"));
    let sentinel = "ghp_SyntheticReportSecret0123456789";
    let input = format!("{sentinel} -----BEGIN PRIVATE KEY-----");
    let mut outcome = scan_reader(&mut Cursor::new(input), 7);
    let mut output = Vec::new();
    render(&outcome, &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("rayloc — FINDINGS\n"));
    assert!(text.contains("2 finding(s); 2 retained; 1 of 1 file(s) completed"));
    assert!(text.contains("source #7:1:1"));
    assert!(text.contains("High; Medium confidence"));
    assert!(text.contains("Critical; Medium confidence"));
    assert_eq!(text.matches("Value: [REDACTED]").count(), 2);
    assert!(text.contains("Remove exposed credentials from source code."));
    assert!(!text.contains(sentinel));
    assert!(!text.contains("-----BEGIN"));
    outcome.fail(ScanError::Read);
    let mut output = Vec::new();
    render(&outcome, &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("rayloc — INCOMPLETE\n"));
    assert!(text.contains("Error: cannot read selected source"));
    assert!(!text.contains(sentinel));
}

struct LimitedWriter {
    remaining: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("sensitive-output-diagnostic"));
        }
        let written = bytes.len().min(self.remaining);
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_report_write_propagates_output_failure() {
    let mut outcome = scan_reader(&mut Cursor::new(b"-----BEGIN PRIVATE KEY-----"), 1);
    outcome.fail(ScanError::LineLimit);
    let mut complete = Vec::new();
    render(&outcome, &mut complete).unwrap();
    for remaining in 0..complete.len() {
        let error = render(&outcome, &mut LimitedWriter { remaining }).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
    render(
        &outcome,
        &mut LimitedWriter {
            remaining: complete.len(),
        },
    )
    .unwrap();
}
