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
    let mut collector = Collector::with_emitter(100, emitter);

    let finding = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    collector.label(1, b"test/path.rs");
    collector.offer(finding);

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
    let mut collector = Collector::with_emitter(100, emitter);

    let finding1 = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    // Same finding should not be emitted twice
    collector.label(1, b"test/path.rs");
    collector.offer(finding1);

    let finding2 = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };
    collector.offer(finding2);

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
    let mut collector = Collector::with_emitter(100, emitter);

    let finding = Finding {
        source_id: 1,
        line: 5,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"secretvalue"),
        id: FindingId::new(b"test/path.rs", b"secretvalue"),
    };

    collector.label(1, b"test/path.rs");
    collector.offer(finding);

    // Finish should not re-emit findings (they were already emitted)
    let mut outcome = ScanOutcome::default();
    collector.finish(&mut outcome);

    let rendered = std::fs::read_to_string(&path).unwrap();
    // Finding appears once (from offer, not from finish)
    let count = rendered.matches("Rule:").count();
    assert_eq!(count, 1);
}
