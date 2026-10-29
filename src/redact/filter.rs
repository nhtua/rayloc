//! Byte-preserving record filter with bounded span replacement.

use std::io::{self, BufRead, Write};

use crate::rules::{Registry, entropy::Histogram};

use super::{Stats, increment, pem::PemState};

pub(super) const MAX_RECORD: usize = 1024 * 1024;

pub(super) struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    bytes: &'a mut u64,
}
impl Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        increment(self.bytes, count)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Filter one input without retaining it beyond a single physical record.
pub(super) fn filter(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    registry: &Registry,
    stats: &mut Stats,
) -> io::Result<bool> {
    let mut record = Vec::new();
    let mut histogram = Histogram::new();
    let mut found = false;
    let mut pem = PemState::new();
    loop {
        let buffer = match input.fill_buf() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if buffer.is_empty() {
            if !record.is_empty() {
                found |= write_record(&record, output, registry, &mut histogram, &mut pem, stats)?;
            }
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .flush()?;
            if !record.is_empty() {
                increment(&mut stats.records, 1)?;
            }
            if pem.unfinished() {
                increment(&mut stats.unterminated_blocks, 1)?;
                return Err(io::Error::other("unterminated private key"));
            }
            return Ok(found);
        }
        let newline = buffer.iter().position(|&b| b == b'\n');
        let count = newline.unwrap_or(buffer.len());
        let consumed = count + usize::from(newline.is_some());
        increment(&mut stats.bytes_read, consumed)?;
        if count > MAX_RECORD.saturating_sub(record.len()) {
            return Err(io::Error::other("record limit"));
        }
        record.extend_from_slice(&buffer[..count]);
        input.consume(consumed);
        if newline.is_some() {
            let crlf = record.last() == Some(&b'\r');
            if crlf {
                record.pop();
            }
            found |= write_record(&record, output, registry, &mut histogram, &mut pem, stats)?;
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .write_all(if crlf { b"\r\n" } else { b"\n" })?;
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .flush()?;
            increment(&mut stats.records, 1)?;
            record.clear();
        }
    }
}

fn write_record(
    record: &[u8],
    output: &mut dyn Write,
    registry: &Registry,
    histogram: &mut Histogram,
    pem: &mut PemState,
    stats: &mut Stats,
) -> io::Result<bool> {
    let pem_record = pem.record(record, registry.private_key_enabled())?;
    increment(
        &mut stats.private_key_blocks,
        pem_record.blocks_started as usize,
    )?;
    let mut spans = pem_record.sensitive;
    if !record.is_empty() && spans.len() == 1 && spans[0] == (0..record.len()) {
        CountingWriter {
            inner: output,
            bytes: &mut stats.bytes_written,
        }
        .write_all(b"[REDACTED]")?;
        increment(&mut stats.redactions, 1)?;
        return Ok(true);
    }
    let pem_intervals = spans.len();
    let detection = registry.detect_line(record, histogram, |_, span| spans.push(span));
    increment(&mut stats.detections, spans.len() - pem_intervals)?;
    detection.map_err(|_| io::Error::other("detection failed"))?;
    if spans.len() > crate::scanner::engine::MAX_FINDINGS {
        return Err(io::Error::other("finding limit"));
    }
    if spans
        .iter()
        .any(|span| span.start >= span.end || span.end > record.len())
    {
        return Err(io::Error::other("invalid span"));
    }
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let found = !spans.is_empty();
    let mut position = 0;
    let mut index = 0;
    while index < spans.len() {
        let span = &spans[index];
        let start = span.start;
        let mut end = span.end;
        index += 1;
        while index < spans.len() && spans[index].start <= end {
            end = end.max(spans[index].end);
            index += 1;
        }
        let mut writer = CountingWriter {
            inner: output,
            bytes: &mut stats.bytes_written,
        };
        writer.write_all(&record[position..start])?;
        writer.write_all(b"[REDACTED]")?;
        increment(&mut stats.redactions, 1)?;
        position = end;
    }
    CountingWriter {
        inner: output,
        bytes: &mut stats.bytes_written,
    }
    .write_all(&record[position..])?;
    Ok(found)
}

#[cfg(test)]
#[path = "../../tests/unit/redact_filter.rs"]
mod tests;
