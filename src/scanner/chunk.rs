//! Borrowed, bounded payload fragments with physical-line locations.
use super::ScanError;
use std::io::{self, BufRead};

pub(crate) const CHUNK_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineEnd {
    Lf,
    Eof,
}

pub(crate) struct LineFragment<'a> {
    pub payload: &'a [u8],
    pub line: u64,
    pub column: u64,
    pub end: Option<LineEnd>,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct ReadProgress {
    pub bytes_read: u64,
    pub lines_scanned: u64,
}

pub(crate) fn next_column(column: u64, payload_bytes: usize) -> Result<u64, ScanError> {
    column
        .checked_add(u64::try_from(payload_bytes).map_err(|_| ScanError::CounterOverflow)?)
        .ok_or(ScanError::CounterOverflow)
}

/// Visit each physical line as borrowed chunks no larger than `CHUNK_BYTES`.
/// Payloads exclude LF but retain CR. An EOF marker closes only a nonempty
/// unterminated final line. The callback must finish using each fragment
/// before returning; no source bytes are retained here.
pub(crate) fn visit_line_fragments(
    reader: &mut dyn BufRead,
    progress: &mut ReadProgress,
    mut emit: impl FnMut(LineFragment<'_>) -> Result<(), ScanError>,
) -> Result<(), ScanError> {
    let mut column = 1u64;
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ScanError::Read),
        };
        if buffer.is_empty() {
            if column > 1 {
                let line = progress
                    .lines_scanned
                    .checked_add(1)
                    .ok_or(ScanError::CounterOverflow)?;
                emit(LineFragment {
                    payload: &[],
                    line,
                    column,
                    end: Some(LineEnd::Eof),
                })?;
                progress.lines_scanned = line;
            }
            return Ok(());
        }

        let newline = buffer.iter().position(|&byte| byte == b'\n');
        let content_length = newline.unwrap_or(buffer.len());
        let payload_length = content_length.min(CHUNK_BYTES);
        let ends_line = newline == Some(payload_length);
        let consumed = payload_length + usize::from(ends_line);
        let byte_count = u64::try_from(consumed).map_err(|_| ScanError::CounterOverflow)?;
        let bytes_read = progress
            .bytes_read
            .checked_add(byte_count)
            .ok_or(ScanError::CounterOverflow)?;
        let next_column = next_column(column, payload_length)?;
        let line = progress
            .lines_scanned
            .checked_add(1)
            .ok_or(ScanError::CounterOverflow)?;

        emit(LineFragment {
            payload: &buffer[..payload_length],
            line,
            column,
            end: ends_line.then_some(LineEnd::Lf),
        })?;

        reader.consume(consumed);
        progress.bytes_read = bytes_read;
        if ends_line {
            progress.lines_scanned = line;
            column = 1;
        } else {
            column = next_column;
        }
    }
}
