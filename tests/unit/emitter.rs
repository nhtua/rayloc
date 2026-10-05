//! Tests for the FindingEmitter trait and TerminalEmitter implementation.

use std::io::Cursor;

use crate::report::emitter::{FindingEmitter, TerminalEmitter};
use crate::scanner::ScanOutcome;

#[test]
fn test_terminal_emitter_basic_flow() {
    let mut output = Cursor::new(Vec::new());
    let mut emitter = TerminalEmitter::new(&mut output);
    emitter.begin_scan();
    emitter.finish_scan(&ScanOutcome::default());
    let rendered = String::from_utf8(output.into_inner()).unwrap();
    assert!(rendered.contains("CLEAN"));
    assert!(rendered.contains("finding"));
}

#[test]
fn test_emitter_emits_finding() {
    use crate::rules::builtin::RuleId;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;
    use crate::scanner::{Finding, ScanOutcome};

    let mut output = Cursor::new(Vec::new());
    let mut emitter = TerminalEmitter::new(&mut output);
    emitter.begin_scan();

    let finding = Finding {
        source_id: 1,
        line: 10,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"testsecretvalue"),
        id: FindingId::new(b"test/path.rs", b"testsecretvalue"),
    };

    emitter.emit_finding(&finding, Some("test/path.rs"));

    let outcome = ScanOutcome::default();
    emitter.finish_scan(&outcome);

    let rendered = String::from_utf8(output.into_inner()).unwrap();
    assert!(rendered.contains("test/path.rs"));
    assert!(rendered.contains("Rule:"));
    assert!(rendered.contains("Severity:"));
    assert!(rendered.contains("Value:"));
    assert!(rendered.contains("ID:"));
}
