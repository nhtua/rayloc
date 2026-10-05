//! Tests for the FindingEmitter trait and TerminalEmitter implementation.

use std::fs::File;

use crate::report::emitter::{FindingEmitter, TerminalEmitter};
use crate::scanner::ScanOutcome;
use crate::test_support::TempDir;

#[test]
fn test_terminal_emitter_basic_flow() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);
    emitter.begin_scan();
    emitter.finish_scan(&ScanOutcome::default());
    drop(emitter);
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("CLEAN"));
    assert!(content.contains("finding"));
}

#[test]
fn test_emitter_emits_finding() {
    use crate::rules::builtin::RuleId;
    use crate::scanner::Finding;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;

    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);
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
    drop(emitter);

    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("test/path.rs"));
    assert!(rendered.contains("Rule:"));
    assert!(rendered.contains("Severity:"));
    assert!(rendered.contains("Value:"));
    assert!(rendered.contains("ID:"));
}
