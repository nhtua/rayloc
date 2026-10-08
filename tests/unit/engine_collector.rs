//! Tests for Collector streaming emission.

use std::fs::File;

use crate::report::emitter::SharedEmitter;
use crate::report::emitter::TerminalEmitter;
use crate::rules::builtin::RuleId;
use crate::scanner::engine::Collector;
use crate::scanner::fingerprint::FindingId;
use crate::scanner::redaction::RedactedString;
use crate::scanner::{Finding, ScanOutcome};
use crate::test_support::TempDir;

#[test]
fn test_collector_emits_findings_immediately() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(file)));

    let mut collector = Collector::new(100);

    let finding = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        unredacted_value: None,
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    // offer returns true if accepted, and registers the label
    let accepted = collector.offer(finding.clone(), b"test/path.rs");
    assert!(accepted);

    // Emit after dropping collector lock (simulated here)
    let source_path = collector.labels.get(&finding.source_id).cloned();
    emitter.emit_finding(&finding, source_path.as_deref());

    // Finding should be emitted immediately, not stored
    let rendered = std::fs::read_to_string(&path).unwrap();
    assert!(rendered.contains("test/path.rs"));
    assert!(rendered.contains("Rule:"));
}

#[test]
fn test_collector_deduplicates() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(file)));

    let mut collector = Collector::new(100);

    let finding1 = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        unredacted_value: None,
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    // Same finding should not be emitted twice
    let accepted1 = collector.offer(finding1.clone(), b"test/path.rs");
    assert!(accepted1);

    let source_path1 = collector.labels.get(&finding1.source_id).cloned();
    emitter.emit_finding(&finding1, source_path1.as_deref());

    let accepted2 = collector.offer(finding1.clone(), b"test/path.rs");
    assert!(!accepted2);

    let rendered = std::fs::read_to_string(&path).unwrap();
    // Should only appear once
    let count = rendered.matches("test/path.rs").count();
    assert_eq!(count, 1);
}

#[test]
fn test_collector_finish_does_not_duplicate_findings() {
    let temp = TempDir::new();
    let path = temp.path().join("output.txt");
    let file = File::create(&path).unwrap();
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(file)));

    let mut collector = Collector::new(100);

    let finding = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        unredacted_value: None,
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    collector.offer(finding.clone(), b"test/path.rs");
    let source_path = collector.labels.get(&finding.source_id).cloned();
    emitter.emit_finding(&finding, source_path.as_deref());

    // Finish should not re-emit findings (they were already emitted)
    let mut outcome = ScanOutcome::default();
    collector.finish(&mut outcome);
    emitter.finish_scan(&outcome);

    let rendered = std::fs::read_to_string(&path).unwrap();
    // Finding appears once (from offer, not from finish)
    let count = rendered.matches("Rule:").count();
    assert_eq!(count, 1);
}
