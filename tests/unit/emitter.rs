//! Tests for the FindingEmitter trait and TerminalEmitter implementation.

use std::fs::File;

use crate::report::emitter::{FindingEmitter, SharedEmitter, TerminalEmitter};
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

#[test]
fn test_emitter_begin_scan() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);
    emitter.begin_scan();
    // begin_scan is a no-op for terminal emitter
    emitter.finish_scan(&ScanOutcome::default());
}

#[test]
fn test_shared_emitter_clone_and_emit() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(file)));
    let cloned = emitter.clone();

    use crate::rules::builtin::RuleId;
    use crate::scanner::Finding;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;

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
    cloned.emit_finding(&finding, Some("test/path2.rs"));

    emitter.finish_scan(&ScanOutcome::default());

    let rendered = std::fs::read_to_string(&path).unwrap();
    // Both emissions should be present (emitter is shared via Arc)
    let count = rendered.matches("Rule:").count();
    assert_eq!(count, 2);
}

#[test]
fn test_thread_safe_writer() {
    use crate::report::emitter::ThreadSafeWriter;
    use std::io::Write;

    let mut buffer = Vec::new();
    let writer = ThreadSafeWriter::new(&mut buffer);
    let mut w = writer;
    w.write_all(b"test data").unwrap();
    w.flush().unwrap();
    assert_eq!(buffer, b"test data");
}

#[test]
fn test_emitter_emits_multiple_findings() {
    use crate::rules::builtin::RuleId;
    use crate::scanner::Finding;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;

    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);
    emitter.begin_scan();

    for i in 0..3 {
        let finding = Finding {
            source_id: 1,
            line: i as u64 + 1,
            start_column: 1,
            end_column: 10,
            rule: RuleId::AwsAccessKeyId,
            value: RedactedString::new(b"secret"),
            id: FindingId::new(b"test/path.rs", b"secret"),
        };
        emitter.emit_finding(&finding, Some("test/path.rs"));
    }

    emitter.finish_scan(&ScanOutcome::default());
    let rendered = std::fs::read_to_string(&path).unwrap();
    // All 3 findings should be emitted
    assert_eq!(rendered.matches("Rule:").count(), 3);
}

#[test]
fn test_emitter_custom_rule_and_source_fallback() {
    use crate::rules::builtin::RuleId;
    use crate::scanner::Finding;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;

    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);

    // Custom rule
    let finding1 = Finding {
        source_id: 1,
        line: 1,
        start_column: 1,
        end_column: 10,
        rule: RuleId::Custom(42, crate::rules::builtin::Severity::High),
        value: RedactedString::new(b"secret"),
        id: FindingId::new(b"test/path.rs", b"secret"),
    };
    emitter.emit_finding(&finding1, Some("test/path.rs"));

    // Source fallback (no path)
    let finding2 = Finding {
        source_id: 2,
        line: 1,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secret"),
        id: FindingId::new(b"test/path.rs", b"secret"),
    };
    emitter.emit_finding(&finding2, None);

    emitter.finish_scan(&ScanOutcome::default());
    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("Custom rule #42"));
    assert!(rendered.contains("source #2"));
}

#[test]
fn test_emitter_incomplete_scan_status() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);

    let mut outcome = ScanOutcome::default();
    outcome.errors.push(crate::scanner::ScanError::Read);
    emitter.finish_scan(&outcome);

    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("INCOMPLETE"));
}

#[test]
fn test_emitter_finding_with_no_source_path() {
    use crate::rules::builtin::RuleId;
    use crate::scanner::Finding;
    use crate::scanner::fingerprint::FindingId;
    use crate::scanner::redaction::RedactedString;

    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);

    let finding = Finding {
        source_id: 5,
        line: 1,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secret"),
        id: FindingId::new(b"test/path.rs", b"secret"),
    };
    emitter.emit_finding(&finding, None);
    emitter.finish_scan(&ScanOutcome::default());

    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("source #5"));
}

#[test]
fn test_emitter_excluded_scan_status() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let mut emitter = TerminalEmitter::new(file);

    let mut outcome = ScanOutcome::default();
    outcome.stats.files_excluded = 1;
    emitter.finish_scan(&outcome);

    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("EXCLUDED"));
}

#[test]
fn test_shared_emitter_begin_scan() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(file)));
    emitter.begin_scan();
    emitter.finish_scan(&ScanOutcome::default());
}
