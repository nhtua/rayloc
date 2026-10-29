use super::*;
use crate::redact::{Stats, increment};
use crate::rules::Registry;
use std::io::{BufReader, Cursor};

struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive diagnostic"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("sensitive diagnostic"))
    }
}

#[test]
fn preserves_bytes_and_redacts_across_read_boundaries() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input = [
        b"before ghp_".as_slice(),
        b"SyntheticToken0123456789abcdef after\r\n\xff\0",
    ]
    .concat();
    for size in 1..=input.len() {
        let mut output = Vec::new();
        let mut reader = BufReader::with_capacity(size, Cursor::new(&input));
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, b"before [REDACTED] after\r\n\xff\0");
    }
}

#[test]
fn empty_input_round_trips_without_output() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for input in [b"".as_slice(), b"\n".as_slice()] {
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        let mut stats = Stats::default();
        assert!(!filter(&mut reader, &mut output, &registry, &mut stats).unwrap());
        assert_eq!(output, input);
        assert_eq!(stats.records, u64::from(!input.is_empty()));
    }
}

#[test]
fn oversized_records_are_never_emitted() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let input = vec![b'x'; MAX_RECORD + 1];
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    let mut stats = Stats::default();
    assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
    assert!(output.is_empty());
    assert_eq!(stats.detections, 0);
    assert_eq!(stats.bytes_read, (MAX_RECORD + 1) as u64);
}

#[test]
fn maximum_record_and_crlf_boundary_are_preserved() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut input = vec![b'x'; MAX_RECORD - 1];
    input.extend_from_slice(b"\r\n");
    let mut reader = BufReader::with_capacity(13, Cursor::new(&input));
    let mut output = Vec::new();
    assert!(!filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
    assert_eq!(output, input);
    let mut input = vec![b'x'; MAX_RECORD];
    input.extend_from_slice(b"\r\n");
    let mut reader = BufReader::with_capacity(13, Cursor::new(&input));
    let mut output = Vec::new();
    assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
    assert!(output.is_empty());
}

#[test]
fn counters_fail_closed_and_empty_content_is_preserved() {
    let mut max = u64::MAX;
    assert!(increment(&mut max, 1).is_err());
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut reader = BufReader::new(Cursor::new(b"\n\r\n\xff\0\r"));
    let mut output = Vec::new();
    let mut stats = Stats::default();
    assert!(!filter(&mut reader, &mut output, &registry, &mut stats).unwrap());
    assert_eq!(output, b"\n\r\n\xff\0\r");
    assert_eq!(stats.records, 3);
}

#[test]
fn overlapping_and_adjacent_custom_matches_are_merged() {
    let config = crate::config::parse(b"version: '1'\nrules:\n  - id: first\n    regex: 'abcde'\n  - id: second\n    regex: 'cdefg'\n  - id: third\n    regex: 'hi'\n").unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut reader = BufReader::new(Cursor::new(b"prefix abcdefghi suffix\n"));
    let mut output = Vec::new();
    assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
    assert_eq!(output, b"prefix [REDACTED] suffix\n");
}

#[test]
fn detector_failure_after_a_match_withholds_entire_record() {
    let config = crate::config::parse(
        b"version: '1'\nrules:\n  - id: first\n    regex: 'abc'\n  - id: large\n    regex: 'D+'\n",
    )
    .unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut input = b"abc ".to_vec();
    input.extend(std::iter::repeat_n(b'D', 65537));
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    let mut stats = Stats::default();
    assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
    assert!(output.is_empty());
    assert_eq!(stats.detections, 1);
}

#[test]
fn too_many_matches_on_one_record_are_withheld() {
    let config = crate::config::parse(b"version: '1'\nrules: [{id: single, regex: 'x'}]").unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut reader = BufReader::new(Cursor::new(vec![b'x'; 10001]));
    let mut output = Vec::new();
    assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
    assert!(output.is_empty());
}

#[test]
fn excessive_private_key_blocks_fail_without_emitting_a_partial_record() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let block = b"-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----"; // rayloc:ignore
    let input = block.repeat(10_001);
    let mut reader = BufReader::new(Cursor::new(input));
    let mut output = Vec::new();
    assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
    assert!(output.is_empty());
}

#[test]
fn writer_failures_propagate_without_source_text() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    for input in [b"clean\n".as_slice(), b"".as_slice()] {
        let mut reader = BufReader::new(Cursor::new(input));
        assert!(
            filter(
                &mut reader,
                &mut BrokenWriter,
                &registry,
                &mut Stats::default()
            )
            .is_err()
        );
    }
}

struct InterruptedReader {
    interrupted: bool,
    data: Cursor<&'static [u8]>,
}
impl io::Read for InterruptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.data.read(buf)
    }
}

#[test]
fn interrupted_reads_are_retried() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut reader = BufReader::new(InterruptedReader {
        interrupted: false,
        data: Cursor::new(b"clean\n"),
    });
    let mut output = Vec::new();
    assert!(!filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
    assert_eq!(output, b"clean\n");
}

#[test]
fn read_failures_and_counter_overflows_stop_without_raw_output() {
    struct FailedReader;
    impl io::Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("private diagnostic"))
        }
    }
    let config =
        crate::config::parse(b"version: '1'\nrules: [{id: token, regex: 'sensitive'}]").unwrap();
    let registry = Registry::compile(config).unwrap();
    let mut output = Vec::new();
    assert!(
        filter(
            &mut BufReader::new(FailedReader),
            &mut output,
            &registry,
            &mut Stats::default()
        )
        .is_err()
    );
    assert!(output.is_empty());
    let mut stats = Stats {
        detections: u64::MAX,
        ..Stats::default()
    };
    assert!(
        filter(
            &mut BufReader::new(Cursor::new(b"sensitive\n")),
            &mut output,
            &registry,
            &mut stats
        )
        .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn flush_failure_after_the_final_record_is_reported() {
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
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut stats = Stats::default();
    assert!(
        filter(
            &mut BufReader::new(Cursor::new(b"clean")),
            &mut FlushFailure(Vec::new()),
            &registry,
            &mut stats
        )
        .is_err()
    );
    assert_eq!(stats.records, 0);
}
