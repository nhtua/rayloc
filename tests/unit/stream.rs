use super::*;
use crate::scanner::engine::scan_reader;
use std::io::Cursor;

const AWS: &[u8] = b"AKIA1234567890ABCDEF";

#[test]
fn ten_megabyte_physical_line_scans_clean_and_secret_payloads() {
    let clean = vec![b'x'; 10 * 1024 * 1024];
    let clean_outcome = scan_reader(&mut Cursor::new(clean), 1);
    assert_eq!(clean_outcome.exit_code(), 0);
    assert_eq!(clean_outcome.stats.files_completed, 1);
    assert_eq!(clean_outcome.stats.lines_scanned, 1);

    for prefix_len in [
        7usize,
        crate::scanner::chunk::CHUNK_BYTES - 7,
        10 * 1024 * 1024 - AWS.len(),
    ] {
        let mut line = vec![b'x'; prefix_len];
        line.push(b' ');
        line.extend_from_slice(AWS);
        let outcome = scan_reader(&mut Cursor::new(line), 1);
        assert_eq!(outcome.exit_code(), 1, "secret at byte {prefix_len}");
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].line, 1);
        assert_eq!(outcome.findings[0].start_column, prefix_len + 2);
        assert_eq!(outcome.findings[0].end_column, prefix_len + 2 + AWS.len());
        assert_eq!(outcome.stats.files_completed, 1);
    }
}

#[test]
fn large_reader_lines_work_with_a_bounded_custom_rule_registry() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: corporate, regex: 'corp_[A-Za-z0-9]{16}', entropy: 3.0}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut input = vec![b'x'; 5 * 1024 * 1024];
    input.extend_from_slice(b" corp_0123456789AbCdEf");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(input), 1, &registry);
    assert_eq!(outcome.exit_code(), 1, "{:?}", outcome.errors);
    assert_eq!(outcome.stats.files_completed, 1);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].start_column, 5 * 1024 * 1024 + 2);
}

#[test]
fn long_line_trailing_ignore_suppresses_provisional_findings() {
    let mut line = Vec::from(AWS);
    line.extend(std::iter::repeat_n(b'x', 300 * 1024));
    line.extend_from_slice(b" # rayloc:ignore");
    let outcome = scan_reader(&mut Cursor::new(line), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.stats.suppressions.inline, 1);
}

#[test]
fn ignored_candidate_overflow_is_not_reported_but_unignored_overflow_is() {
    let mut ignored = Vec::new();
    for _ in 0..10_002 {
        ignored.extend_from_slice(b"-----BEGIN PRIVATE KEY----- ");
    }
    ignored.extend_from_slice(b"# rayloc:ignore");
    let outcome = scan_reader(&mut Cursor::new(ignored), 1);
    assert_eq!(outcome.exit_code(), 0);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.stats.suppressions.inline, 1);

    let mut active = Vec::new();
    for _ in 0..10_002 {
        active.extend_from_slice(b"-----BEGIN PRIVATE KEY----- ");
    }
    let outcome = scan_reader(&mut Cursor::new(active), 1);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.findings.len(), 10_000);
    assert!(
        outcome
            .errors
            .iter()
            .any(|e| e.error == ScanError::FindingLimit)
    );
}

#[test]
fn enabled_legacy_regex_gets_path_specific_error_after_compatibility_limit() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut bytes = vec![b'x'; crate::scanner::engine::MAX_LINE_BYTES + 10];
    bytes.extend_from_slice(b"SECRET");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(bytes), 1, &registry);
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.errors[0].error, ScanError::RuleWindowLimit);
    assert!(outcome.findings.is_empty());
}

#[test]
fn legacy_regex_runs_on_supported_long_lines_and_disabled_legacy_rules_do_not_restrict() {
    let config = crate::config::parse(
        b"version: \"1\"\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut bytes = Vec::from(b"prefix".as_slice());
    bytes.extend(std::iter::repeat_n(b'x', 300 * 1024));
    bytes.extend_from_slice(b"SECRET");
    let outcome =
        crate::scanner::engine::scan_reader_with_registry(&mut Cursor::new(bytes), 1, &registry);
    assert_eq!(outcome.exit_code(), 1, "{:?}", outcome.errors);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].start_column, 300 * 1024 + 7);

    let disabled = crate::config::parse(
        b"version: \"1\"\ndisabled_rules: [legacy]\nrules: [{id: legacy, regex: 'prefix.*(SECRET)', secret_group: 1}]",
    )
    .unwrap();
    let disabled = Registry::compile(disabled).unwrap();
    let outcome = crate::scanner::engine::scan_reader_with_registry(
        &mut Cursor::new(vec![b'x'; crate::scanner::engine::MAX_LINE_BYTES + 100]),
        1,
        &disabled,
    );
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(outcome.stats.files_completed, 1);
}
