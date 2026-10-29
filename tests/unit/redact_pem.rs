use super::*;
use crate::redact::{Stats, filter::filter};
use crate::rules::Registry;
use std::io::{BufReader, Cursor};

fn filter_all(input: &[u8], registry: &Registry) -> (Vec<u8>, Stats, std::io::Result<bool>) {
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    let mut stats = Stats::default();
    let result = filter(&mut reader, &mut output, registry, &mut stats);
    (output, stats, result)
}

#[test]
fn masks_private_key_body_until_matching_end() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input =
        b"prefix -----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY----- suffix\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(input, &registry);
    assert!(result.unwrap());
    assert_eq!(
        output,
        b"prefix [REDACTED]\n[REDACTED]\n[REDACTED] suffix\n"
    );
    assert_eq!(stats.private_key_blocks, 1);
}

#[test]
fn unrelated_begin_prefix_does_not_hide_a_later_private_key() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input = b"-----BEGIN PUBLIC KEY----- -----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY----- tail\n"; // rayloc:ignore
    let (output, _, result) = filter_all(input, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"-----BEGIN PUBLIC KEY----- [REDACTED] tail\n");
}

#[test]
fn all_six_private_labels_hide_body_and_preserve_terminators() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for begin in crate::rules::builtin::PRIVATE_KEY_MARKERS {
        let mut end = b"-----END ".to_vec();
        end.extend_from_slice(&begin[b"-----BEGIN ".len()..]);
        let input = [
            b"prefix ".as_slice(),
            begin,
            b"\nbody\n",
            end.as_slice(),
            b" suffix\n",
        ]
        .concat();
        let (output, stats, result) = filter_all(&input, &registry);
        assert!(result.unwrap());
        assert_eq!(
            output,
            b"prefix [REDACTED]\n[REDACTED]\n[REDACTED] suffix\n"
        );
        assert_eq!(stats.private_key_blocks, 1);
        assert_eq!(stats.redactions, 3);
        assert_eq!(stats.bytes_read, input.len() as u64);
        assert_eq!(stats.bytes_written, output.len() as u64);
    }
    assert_eq!(crate::rules::builtin::PRIVATE_KEY_MARKERS.len(), 6);
}

#[test]
fn empty_and_crlf_body_lines_keep_their_terminators() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input = b"-----BEGIN PRIVATE KEY-----\r\n\r\n\r\n-----END PRIVATE KEY-----\r\ntail\r\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(input, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"[REDACTED]\r\n\r\n\r\n[REDACTED]\r\ntail\r\n");
    assert_eq!(stats.redactions, 2);
}

#[test]
fn same_line_blocks_and_multiple_blocks_are_masked_independently() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let one_line = b"a -----BEGIN PRIVATE KEY-----body-----END PRIVATE KEY----- b\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(one_line, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"a [REDACTED] b\n");
    assert_eq!(stats.private_key_blocks, 1);
    let multiple = b"-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----------BEGIN RSA PRIVATE KEY-----y-----END RSA PRIVATE KEY-----z\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(multiple, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"[REDACTED]z\n");
    assert_eq!(stats.private_key_blocks, 2);
    let after_close = b"-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- ghp_SyntheticToken0123456789abcdef\n"; // rayloc:ignore
    let (output, _, result) = filter_all(after_close, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"[REDACTED] [REDACTED]\n");
}

#[test]
fn nested_and_mismatched_markers_never_end_a_block_early() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\nafter\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(input, &registry);
    assert!(result.unwrap());
    assert_eq!(output, b"[REDACTED]\n[REDACTED]\n[REDACTED]\nafter\n");
    assert_eq!(stats.private_key_blocks, 1);
}

#[test]
fn private_key_variants_and_unterminated_blocks_are_safe() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut output = Vec::new();
    let mut stats = Stats::default();
    let mut reader = BufReader::new(Cursor::new(b"-----BEGIN PRIVATE KEY-----\nbody")); // rayloc:ignore
    assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
    assert_eq!(stats.unterminated_blocks, 1);
    assert_eq!(output, b"[REDACTED]\n[REDACTED]");
}

#[test]
fn unfinished_key_state_never_completes_on_a_different_label() {
    let mut state = PemState::new();
    state
        .record(b"-----BEGIN EC PRIVATE KEY-----", true)
        .unwrap(); // rayloc:ignore
    assert!(state.unfinished());
    state.record(b"-----END PRIVATE KEY-----", true).unwrap(); // rayloc:ignore
    assert!(
        state.unfinished(),
        "a mismatched end label must not close the open block"
    );
    state.record(b"-----END EC PRIVATE KEY-----", true).unwrap(); // rayloc:ignore
    assert!(!state.unfinished());
}

#[test]
fn disabled_key_rule_passes_marker_and_body_unchanged() {
    let disabled_policy =
        crate::config::parse(b"version: '1'\ndisabled_rules: [private-key-marker]\n").unwrap();
    let enabled = Registry::compile(crate::config::Config::default()).unwrap();
    let disabled = Registry::compile(disabled_policy).unwrap();
    assert!(enabled.private_key_enabled());
    assert!(!disabled.private_key_enabled());
    let input = b"-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----\n"; // rayloc:ignore
    let (output, stats, result) = filter_all(input, &disabled);
    assert!(!result.unwrap());
    assert_eq!(output, input);
    assert_eq!(stats.private_key_blocks, 0);
    let (output, stats, result) = filter_all(input, &enabled);
    assert!(result.unwrap());
    assert_eq!(output, b"[REDACTED]\n[REDACTED]\n[REDACTED]\n");
    assert_eq!(stats.private_key_blocks, 1);
}

#[test]
fn wrong_end_label_does_not_release_body() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input =
        b"-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END EC PRIVATE KEY-----\nstill-private\n"; // rayloc:ignore
    let (output, _, result) = filter_all(input, &registry);
    assert!(result.is_err());
    assert_eq!(output, b"[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\n");
}

#[test]
fn pem_state_reuses_no_body_between_records() {
    let mut state = PemState::new();
    let begin = b"-----BEGIN PRIVATE KEY-----"; // rayloc:ignore
    let opened = state.record(begin, true).expect("begin marker accepted");
    assert_eq!(opened.sensitive, vec![0..begin.len()]);
    assert_eq!(opened.blocks_started, 1);
    assert!(state.unfinished());
    let body = state.record(b"secret-body", true).expect("body accepted");
    assert_eq!(body.sensitive, vec![0..11]);
    assert_eq!(body.blocks_started, 0);
    let closed = state
        .record(b"-----END PRIVATE KEY----- tail", true) // rayloc:ignore
        .expect("end marker accepted");
    assert_eq!(closed.sensitive, vec![0..25]);
    assert!(!state.unfinished());
    let after = state.record(b"clean", true).expect("state reset");
    assert!(after.sensitive.is_empty());
}
