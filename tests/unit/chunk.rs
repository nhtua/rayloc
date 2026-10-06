use crate::scanner::{
    ScanError,
    chunk::{self, LineEnd, ReadProgress},
};
use std::io::{self, BufRead, Cursor, Read};

type ObservedFragment = (Vec<u8>, u64, u64, Option<LineEnd>);

fn collect(reader: &mut dyn BufRead) -> (Vec<ObservedFragment>, ReadProgress) {
    let mut lines = Vec::new();
    let mut progress = ReadProgress::default();
    chunk::visit_line_fragments(reader, &mut progress, |fragment| {
        lines.push((
            fragment.payload.to_vec(),
            fragment.line,
            fragment.column,
            fragment.end,
        ));
        Ok(())
    })
    .unwrap();
    (lines, progress)
}

#[test]
fn fragments_preserve_lf_crlf_empty_and_final_eof() {
    let input = b"ab\r\n\nlast";
    let (lines, progress) = collect(&mut Cursor::new(input));
    assert_eq!(
        lines,
        [
            (b"ab\r".to_vec(), 1, 1, Some(LineEnd::Lf)),
            (b"".to_vec(), 2, 1, Some(LineEnd::Lf)),
            (b"last".to_vec(), 3, 1, None),
            (b"".to_vec(), 3, 5, Some(LineEnd::Eof)),
        ]
    );
    assert_eq!(progress.bytes_read, 9);
    assert_eq!(progress.lines_scanned, 3);
}

#[test]
fn reader_slice_is_split_to_chunk_budget() {
    let input = vec![b'x'; 3 * chunk::CHUNK_BYTES];
    let mut reader = Cursor::new(&input);
    let mut progress = ReadProgress::default();
    let mut fragments = 0;
    let mut next_column = 1u64;
    chunk::visit_line_fragments(&mut reader, &mut progress, |fragment| {
        assert!(fragment.payload.len() <= chunk::CHUNK_BYTES);
        assert_eq!(fragment.column, next_column);
        next_column += fragment.payload.len() as u64;
        fragments += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(fragments, 4); // Three data chunks and an EOF marker.
    assert_eq!(next_column, input.len() as u64 + 1);
    assert_eq!(progress.bytes_read, input.len() as u64);
    assert_eq!(progress.lines_scanned, 1);
}

struct InterruptedThenError {
    state: u8,
}
impl Read for InterruptedThenError {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        unreachable!("visit_line_fragments reads through fill_buf")
    }
}
impl BufRead for InterruptedThenError {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self.state {
            0 => {
                self.state = 1;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
            1 => Ok(b"abc"),
            _ => Err(io::Error::from(io::ErrorKind::Other)),
        }
    }
    fn consume(&mut self, amount: usize) {
        assert_eq!(amount, 3);
        self.state = 2;
    }
}

#[test]
fn fragment_progress_survives_interrupted_and_failed_reads() {
    let mut reader = InterruptedThenError { state: 0 };
    let mut progress = ReadProgress::default();
    let mut observed = Vec::new();
    assert_eq!(
        chunk::visit_line_fragments(&mut reader, &mut progress, |fragment| {
            observed.push((
                fragment.payload.to_vec(),
                fragment.line,
                fragment.column,
                fragment.end,
            ));
            Ok(())
        }),
        Err(ScanError::Read)
    );
    assert_eq!(observed, [(b"abc".to_vec(), 1, 1, None)]);
    assert_eq!(progress.bytes_read, 3);
    assert_eq!(progress.lines_scanned, 0);
}

#[test]
fn callback_and_counter_errors_stop_before_claiming_a_line_end() {
    let mut reader = Cursor::new(b"abc\n".as_slice());
    let mut progress = ReadProgress::default();
    assert_eq!(
        chunk::visit_line_fragments(&mut reader, &mut progress, |_| Err(
            ScanError::CandidateLimit
        )),
        Err(ScanError::CandidateLimit)
    );
    assert_eq!(progress, ReadProgress::default());

    let mut progress = ReadProgress {
        bytes_read: u64::MAX,
        lines_scanned: 0,
    };
    let mut reader = Cursor::new(b"a".as_slice());
    assert_eq!(
        chunk::visit_line_fragments(&mut reader, &mut progress, |_| Ok(())),
        Err(ScanError::CounterOverflow)
    );
    assert_eq!(progress.bytes_read, u64::MAX);

    let mut progress = ReadProgress {
        bytes_read: 0,
        lines_scanned: u64::MAX,
    };
    let mut reader = Cursor::new(b"\n".as_slice());
    assert_eq!(
        chunk::visit_line_fragments(&mut reader, &mut progress, |_| Ok(())),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn advancing_byte_columns_fails_on_overflow() {
    assert_eq!(
        chunk::next_column(u64::MAX, 1),
        Err(ScanError::CounterOverflow)
    );
    assert_eq!(chunk::next_column(8, 4), Ok(12));
}

#[test]
fn empty_and_newline_only_inputs_have_distinct_line_counts() {
    let (empty, empty_progress) = collect(&mut Cursor::new(b""));
    assert!(empty.is_empty());
    assert_eq!(empty_progress, ReadProgress::default());
    let (newline, newline_progress) = collect(&mut Cursor::new(b"\n"));
    assert_eq!(newline, [(b"".to_vec(), 1, 1, Some(LineEnd::Lf))]);
    assert_eq!(newline_progress.bytes_read, 1);
    assert_eq!(newline_progress.lines_scanned, 1);
}
