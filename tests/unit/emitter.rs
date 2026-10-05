use std::io::Write;
use std::thread;

use crate::report::emitter::{
    FindingMessage, SharedEmitter, TerminalEmitter, ThreadSafeWriter, channel_emitter,
};
use crate::rules::builtin::RuleId;
use crate::scanner::fingerprint::FindingId;
use crate::scanner::redaction::RedactedString;
use crate::scanner::{Finding, ScanOutcome};

fn make_finding(id: u32) -> Finding {
    Finding {
        source_id: id,
        line: 1,
        start_column: 1,
        end_column: 10,
        rule: RuleId::AwsAccessKeyId,
        value: RedactedString::new(b"test-secret"),
        id: FindingId::new(b"test/path.rs", b"test-secret"),
    }
}

fn make_outcome(findings_detected: u64) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();
    outcome.stats.findings_detected = findings_detected;
    outcome.stats.files_attempted = 10;
    outcome.stats.files_completed = 10;
    outcome.stats.files_excluded = 0;
    outcome.stats.lines_scanned = 100;
    outcome.stats.bytes_read = 1000;
    outcome
}

#[test]
fn shared_emitter_clones_and_emits() {
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));
    let cloned = emitter.clone();

    let finding = make_finding(1);
    emitter.emit_finding(&finding, Some("test.rs"));

    let outcome = make_outcome(1);
    cloned.finish_scan(&outcome);
}

#[test]
fn channel_emitter_processes_findings() {
    let emitter = Box::new(TerminalEmitter::new(std::io::stdout()));
    let (tx, handle) = channel_emitter(emitter);

    let finding = make_finding(1);
    tx.send(FindingMessage::Finding(
        finding,
        Some("test.rs".to_string()),
    ))
    .unwrap();

    let outcome = make_outcome(1);
    tx.send(FindingMessage::Finish(outcome)).unwrap();
    drop(tx);

    handle.join().unwrap();
}

#[test]
fn shared_emitter_begin_scan() {
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));
    emitter.begin_scan();
}

#[test]
fn shared_emitter_emit_finding() {
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));
    let finding = make_finding(1);
    emitter.emit_finding(&finding, Some("test.rs"));
}

#[test]
fn shared_emitter_finish_scan() {
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));
    emitter.finish_scan(&make_outcome(0));
}

#[test]
fn finding_message_finding_variant() {
    let finding = make_finding(1);
    let msg = FindingMessage::Finding(finding, Some("test.rs".to_string()));
    match msg {
        FindingMessage::Finding(_, Some(path)) => assert_eq!(path, "test.rs"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn finding_message_finish_variant() {
    let outcome = make_outcome(0);
    let msg = FindingMessage::Finish(outcome);
    match msg {
        FindingMessage::Finish(o) => assert_eq!(o.exit_code(), 0),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn channel_emitter_multiple_findings() {
    let emitter = Box::new(TerminalEmitter::new(std::io::stdout()));
    let (tx, handle) = channel_emitter(emitter);

    for i in 1..5 {
        let finding = make_finding(i);
        let path = format!("file{i}.rs");
        tx.send(FindingMessage::Finding(finding, Some(path)))
            .unwrap();
    }

    let outcome = make_outcome(4);
    tx.send(FindingMessage::Finish(outcome)).unwrap();
    drop(tx);

    handle.join().unwrap();
}

#[test]
fn shared_emitter_concurrent_emits() {
    let emitter = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));

    let mut handles = Vec::new();
    for i in 0..4 {
        let em = emitter.clone();
        let handle = thread::spawn(move || {
            let finding = make_finding(i + 1);
            em.emit_finding(&finding, Some(&format!("thread{i}.rs")));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn shared_emitter_finish_from_different_clone() {
    let em1 = SharedEmitter::new(Box::new(TerminalEmitter::new(std::io::stdout())));
    let em2 = em1.clone();

    let finding = make_finding(1);
    em1.emit_finding(&finding, Some("test.rs"));
    em2.finish_scan(&make_outcome(1));
}

#[test]
fn thread_safe_writer_write_and_flush() {
    let mut buffer = Vec::new();
    let mut writer = ThreadSafeWriter::new(&mut buffer);
    writer.write_all(b"hello").unwrap();
    writer.flush().unwrap();
    assert_eq!(buffer, b"hello");
}
