//! Bounded pure parsing of Git's raw metadata and unified patches.
//!
//! The caller supplies raw NUL records and one LF-framed patch record at a time.
//! Each record includes its terminator in the 1-MiB cap. This module allocates
//! nothing: two borrowed raw records (at most 2 MiB), one borrowed patch record
//! (1 MiB), and constant parser state suffice regardless of stream length.
//! Acquisition owns bounded readers, source-ID allocation/order, process success,
//! and final EOF checks; detection consumes events before reusing record storage.
//! Blob identities must be known (pinned-tree protocol), not working-tree zero
//! placeholders. OID width and empty-blob identity are repository-supplied.

/// Maximum record size, including NUL or LF framing.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Fixed safe categories; no source bytes or paths enter errors.
#[derive(Debug, PartialEq, Eq)]
pub enum DiffError {
    Invalid,
    Limit,
    Overflow,
}

/// Validated authoritative raw entry. Intentionally has no path-revealing Debug.
#[derive(Clone, Copy)]
pub struct RawBinding<'a> {
    source_id: u32,
    path: &'a [u8],
    old_mode: u32,
    new_mode: u32,
    status: u8,
    old_oid: &'a [u8],
    new_oid: &'a [u8],
}
impl<'a> RawBinding<'a> {
    /// Validate exactly `:oldmode newmode oldoid newoid status NUL` and `path NUL`.
    /// Accept A/D/M/T only, known full SHA-1/SHA-256 IDs, and relative byte paths.
    pub fn parse(
        source_id: u32,
        header: &'a [u8],
        path: &'a [u8],
        oid_width: usize,
    ) -> Result<Self, DiffError> {
        if header.len() > MAX_RECORD_BYTES || path.len() > MAX_RECORD_BYTES {
            return Err(DiffError::Limit);
        }
        let header = header
            .strip_suffix(b"\0")
            .and_then(|h| h.strip_prefix(b":"))
            .ok_or(DiffError::Invalid)?;
        let path = path.strip_suffix(b"\0").ok_or(DiffError::Invalid)?;
        if path.contains(&0)
            || path
                .split(|&b| b == b'/')
                .any(|p| p.is_empty() || p == b"." || p == b"..")
        {
            return Err(DiffError::Invalid);
        }
        let mut fields = header.split(|&b| b == b' ');
        let old_mode = mode(fields.next().ok_or(DiffError::Invalid)?)?;
        let new_mode = mode(fields.next().ok_or(DiffError::Invalid)?)?;
        let old_oid = fields.next().ok_or(DiffError::Invalid)?;
        let new_oid = fields.next().ok_or(DiffError::Invalid)?;
        let status = fields.next().ok_or(DiffError::Invalid)?;
        if fields.next().is_some()
            || !valid_oid(old_oid, oid_width)
            || !valid_oid(new_oid, oid_width)
            || (old_mode == 0) != is_zero(old_oid)
            || (new_mode == 0) != is_zero(new_oid)
        {
            return Err(DiffError::Invalid);
        }
        let valid = match status {
            b"A" => old_mode == 0 && new_mode != 0,
            b"D" => old_mode != 0 && new_mode == 0,
            b"M" => {
                old_mode != 0
                    && new_mode != 0
                    && old_mode / 4096 == new_mode / 4096
                    && (old_mode != new_mode || old_oid != new_oid)
            }
            b"T" => old_mode != 0 && new_mode != 0 && old_mode / 4096 != new_mode / 4096,
            _ => false,
        };
        if !valid {
            return Err(DiffError::Invalid);
        }
        Ok(Self {
            source_id,
            path,
            old_mode,
            new_mode,
            old_oid,
            new_oid,
            status: status[0],
        })
    }
    pub fn source_id(&self) -> u32 {
        self.source_id
    }
    pub fn path(&self) -> &[u8] {
        self.path
    }
    pub fn old_mode(&self) -> u32 {
        self.old_mode
    }
    pub fn new_mode(&self) -> u32 {
        self.new_mode
    }
    pub fn status(&self) -> u8 {
        self.status
    }
}
#[cfg(test)]
#[path = "../../tests/unit/diff.rs"]
mod tests;

fn mode(bytes: &[u8]) -> Result<u32, DiffError> {
    match bytes {
        b"000000" => Ok(0),
        b"100644" => Ok(0o100644),
        b"100755" => Ok(0o100755),
        b"120000" => Ok(0o120000),
        b"160000" => Ok(0o160000),
        _ => Err(DiffError::Invalid),
    }
}
fn valid_oid(bytes: &[u8], width: usize) -> bool {
    matches!(width, 40 | 64)
        && bytes.len() == width
        && bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == b'0')
}

/// Only added non-gitlink bytes become detector input. Boundary resets any
/// consumer context; starts_run also marks the first addition after a boundary.
/// Neither event nor parser implements Debug, avoiding accidental source leaks.
pub enum Event<'a> {
    Added {
        source_id: u32,
        new_line: u64,
        payload: &'a [u8],
        starts_run: bool,
    },
    Boundary,
}
/// One logical raw entry, including both sections of a type change.
/// No allocation: binding and empty identity must outlive this parser.
pub struct Parser<'a> {
    binding: RawBinding<'a>,
    empty: &'a [u8],
    phase: Phase,
    sections: u8,
    old_mode: u32,
    new_mode: u32,
    old_oid: &'a [u8],
    new_oid: &'a [u8],
    old_left: u64,
    new_left: u64,
    old_line: u64,
    new_line: u64,
    old_end: u64,
    new_end: u64,
    old_eof: bool,
    new_eof: bool,
    previous: Option<u8>,
    in_run: bool,
    failed: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    AddedMode,
    DeletedMode,
    OldMode,
    NewMode,
    Index,
    OldPath,
    NewPath,
    Hunk,
    Body,
    ModeOnly,
}

impl<'a> Parser<'a> {
    pub fn new(binding: RawBinding<'a>, empty_blob_oid: &'a [u8]) -> Result<Self, DiffError> {
        if !valid_oid(empty_blob_oid, binding.old_oid.len()) || is_zero(empty_blob_oid) {
            return Err(DiffError::Invalid);
        }
        Ok(Self {
            binding,
            empty: empty_blob_oid,
            phase: Phase::Start,
            sections: 0,
            old_mode: 0,
            new_mode: 0,
            old_oid: b"",
            new_oid: b"",
            old_left: 0,
            new_left: 0,
            old_line: 0,
            new_line: 0,
            old_end: 0,
            new_end: 0,
            old_eof: false,
            new_eof: false,
            previous: None,
            in_run: false,
            failed: false,
        })
    }

    /// True after the first T header and until the second header is consumed.
    /// A driver feeds the next `diff --git` record here when true. Otherwise it
    /// finishes this parser before binding that lookahead to the next raw entry.
    /// This is NOT a completion check; `record`/`finish` validate truncation.
    pub fn needs_second_section(&self) -> bool {
        self.binding.status == b'T' && self.sections == 1
    }

    /// LF is mandatory and included in the 1-MiB record budget. On any error the
    /// parser becomes permanently invalid, so ignored errors cannot yield success.
    pub fn record<'r>(
        &mut self,
        record: &'r [u8],
        mut emit: impl FnMut(Event<'r>),
    ) -> Result<(), DiffError> {
        if self.failed {
            return Err(DiffError::Invalid);
        }
        let result = self.consume(record, &mut emit);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn consume<'r>(
        &mut self,
        record: &'r [u8],
        emit: &mut impl FnMut(Event<'r>),
    ) -> Result<(), DiffError> {
        if record.len() > MAX_RECORD_BYTES {
            return Err(DiffError::Limit);
        }
        let line = record.strip_suffix(b"\n").ok_or(DiffError::Invalid)?;
        if line.contains(&b'\n') {
            return Err(DiffError::Invalid);
        }
        if line.starts_with(b"diff --git ") {
            self.start_section(&line[11..])?;
        } else {
            match self.phase {
                Phase::Start | Phase::ModeOnly => return Err(DiffError::Invalid),
                Phase::AddedMode => {
                    expect_mode(line, b"new file mode ", self.new_mode)?;
                    self.phase = Phase::Index;
                }
                Phase::DeletedMode => {
                    expect_mode(line, b"deleted file mode ", self.old_mode)?;
                    self.phase = Phase::Index;
                }
                Phase::OldMode => {
                    expect_mode(line, b"old mode ", self.old_mode)?;
                    self.phase = Phase::NewMode;
                }
                Phase::NewMode => {
                    expect_mode(line, b"new mode ", self.new_mode)?;
                    self.phase = if self.old_oid == self.new_oid {
                        Phase::ModeOnly
                    } else {
                        Phase::Index
                    };
                }
                Phase::Index => {
                    self.index(line)?;
                    self.phase = Phase::OldPath;
                }
                Phase::OldPath => {
                    file_path(line, b"--- ", b"a/", self.binding.path, self.old_mode == 0)?;
                    self.phase = Phase::NewPath;
                }
                Phase::NewPath => {
                    file_path(line, b"+++ ", b"b/", self.binding.path, self.new_mode == 0)?;
                    self.phase = Phase::Hunk;
                }
                Phase::Hunk => self.hunk(line)?,
                Phase::Body => {
                    if line == b"\\ No newline at end of file" {
                        let previous = self.previous.take().ok_or(DiffError::Invalid)?;
                        self.old_eof |= previous != b'+';
                        self.new_eof |= previous != b'-';
                    } else if self.old_left == 0 && self.new_left == 0 {
                        self.hunk(line)?;
                    } else {
                        let indicator = *line.first().ok_or(DiffError::Invalid)?;
                        if !matches!(indicator, b'+' | b'-' | b' ') {
                            return Err(DiffError::Invalid);
                        }
                        if indicator != b'+' {
                            consume_side(&mut self.old_left, &mut self.old_line, self.old_eof)?;
                        }
                        let new_line = self.new_line;
                        if indicator != b'-' {
                            consume_side(&mut self.new_left, &mut self.new_line, self.new_eof)?;
                        }
                        self.previous = Some(indicator);
                        if indicator == b'+' && self.new_mode != 0o160000 {
                            emit(Event::Added {
                                source_id: self.binding.source_id,
                                new_line,
                                payload: &line[1..],
                                starts_run: !self.in_run,
                            });
                            self.in_run = true;
                            return Ok(());
                        }
                    }
                }
            }
        }
        self.in_run = false;
        emit(Event::Boundary);
        Ok(())
    }

    fn start_section(&mut self, paths: &[u8]) -> Result<(), DiffError> {
        if self.sections != 0 && (!self.needs_second_section() || !self.complete_section()) {
            return Err(DiffError::Invalid);
        }
        let tail = path_token(paths, b"a/", self.binding.path)?;
        let tail = tail.strip_prefix(b" ").ok_or(DiffError::Invalid)?;
        if !path_token(tail, b"b/", self.binding.path)?.is_empty() {
            return Err(DiffError::Invalid);
        }
        self.sections += 1; // At most two: guarded above.
        let binding = self.binding;
        self.old_mode = binding.old_mode;
        self.new_mode = binding.new_mode;
        self.old_oid = binding.old_oid;
        self.new_oid = binding.new_oid;
        if binding.status == b'T' {
            if self.sections == 1 {
                self.new_mode = 0;
                self.new_oid = zero_oid(binding.old_oid.len());
            } else {
                self.old_mode = 0;
                self.old_oid = zero_oid(binding.old_oid.len());
            }
        }
        self.old_end = 0;
        self.new_end = 0;
        self.old_eof = false;
        self.new_eof = false;
        self.previous = None;
        self.phase = if self.old_mode == 0 {
            Phase::AddedMode
        } else if self.new_mode == 0 {
            Phase::DeletedMode
        } else if self.old_mode != self.new_mode {
            Phase::OldMode
        } else {
            Phase::Index
        };
        Ok(())
    }

    fn index(&self, line: &[u8]) -> Result<(), DiffError> {
        let tail = line
            .strip_prefix(b"index ")
            .and_then(|s| s.strip_prefix(self.old_oid))
            .and_then(|s| s.strip_prefix(b".."))
            .and_then(|s| s.strip_prefix(self.new_oid))
            .ok_or(DiffError::Invalid)?;
        if self.old_mode == self.new_mode {
            expect_mode(tail, b" ", self.old_mode)
        } else if tail.is_empty() {
            Ok(())
        } else {
            Err(DiffError::Invalid)
        }
    }

    fn hunk(&mut self, line: &[u8]) -> Result<(), DiffError> {
        let mut tail = line.strip_prefix(b"@@ -").ok_or(DiffError::Invalid)?;
        let (old_start, old_count) = range(&mut tail)?;
        tail = tail.strip_prefix(b" +").ok_or(DiffError::Invalid)?;
        let (new_start, new_count) = range(&mut tail)?;
        tail = tail.strip_prefix(b" @@").ok_or(DiffError::Invalid)?;
        let (old_end, old_gap) = range_position(old_start, old_count, self.old_end)?;
        let (new_end, new_gap) = range_position(new_start, new_count, self.new_end)?;
        // Omitted context is unchanged, so both sides must skip the same span.
        // Absent, empty, and EOF-marked sides cannot contain even skipped lines.
        if (!tail.is_empty() && !tail.starts_with(b" "))
            || (old_count == 0 && new_count == 0)
            || old_gap != new_gap
            || ((self.old_mode == 0 || self.old_eof || self.old_oid == self.empty)
                && (old_count != 0 || old_gap != 0))
            || ((self.new_mode == 0 || self.new_eof || self.new_oid == self.empty)
                && (new_count != 0 || new_gap != 0))
        {
            return Err(DiffError::Invalid);
        }
        self.old_end = old_end;
        self.new_end = new_end;
        self.old_line = old_start;
        self.new_line = new_start;
        self.old_left = old_count;
        self.new_left = new_count;
        self.previous = None;
        self.phase = Phase::Body;
        Ok(())
    }

    fn complete_section(&self) -> bool {
        match self.phase {
            Phase::ModeOnly => true,
            Phase::Body => self.old_left == 0 && self.new_left == 0,
            Phase::OldPath => {
                (self.old_mode == 0 && self.new_oid == self.empty)
                    || (self.new_mode == 0 && self.old_oid == self.empty)
            }
            _ => false,
        }
    }

    /// Validate complete framing/counts and all required sections. Call at the
    /// next logical binding or patch EOF; any earlier error makes this fail too.
    pub fn finish(self) -> Result<(), DiffError> {
        if self.failed
            || self.sections == 0
            || self.needs_second_section()
            || !self.complete_section()
        {
            Err(DiffError::Invalid)
        } else {
            Ok(())
        }
    }
}

fn zero_oid(width: usize) -> &'static [u8] {
    &b"0000000000000000000000000000000000000000000000000000000000000000"[..width]
}
fn expect_mode(line: &[u8], prefix: &[u8], expected: u32) -> Result<(), DiffError> {
    if mode(line.strip_prefix(prefix).ok_or(DiffError::Invalid)?)? == expected {
        Ok(())
    } else {
        Err(DiffError::Invalid)
    }
}
fn path_token<'a>(input: &'a [u8], prefix: &[u8], path: &[u8]) -> Result<&'a [u8], DiffError> {
    if let Some(mut tail) = input.strip_prefix(b"\"") {
        for &expected in prefix.iter().chain(path) {
            let (&first, rest) = tail.split_first().ok_or(DiffError::Invalid)?;
            tail = rest;
            let decoded = if first == b'\\' {
                escape(&mut tail)?
            } else if first == b'"' {
                return Err(DiffError::Invalid);
            } else {
                first
            };
            if decoded == 0 || decoded != expected {
                return Err(DiffError::Invalid);
            }
        }
        tail.strip_prefix(b"\"").ok_or(DiffError::Invalid)
    } else {
        if path
            .iter()
            .any(|&b| !(32..127).contains(&b) || b == b'"' || b == b'\\')
        {
            return Err(DiffError::Invalid);
        }
        input
            .strip_prefix(prefix)
            .and_then(|s| s.strip_prefix(path))
            .ok_or(DiffError::Invalid)
    }
}
fn escape(input: &mut &[u8]) -> Result<u8, DiffError> {
    let (&first, rest) = input.split_first().ok_or(DiffError::Invalid)?;
    *input = rest;
    let decoded = match first {
        b'a' => 7,
        b'b' => 8,
        b't' => 9,
        b'n' => 10,
        b'v' => 11,
        b'f' => 12,
        b'r' => 13,
        b'"' | b'\\' => first,
        b'0'..=b'3' => {
            if rest.len() < 2 || !rest[..2].iter().all(|b| (b'0'..=b'7').contains(b)) {
                return Err(DiffError::Invalid);
            }
            *input = &rest[2..];
            (first - b'0') * 64 + (rest[0] - b'0') * 8 + (rest[1] - b'0')
        }
        _ => return Err(DiffError::Invalid),
    };
    Ok(decoded)
}
fn file_path(
    line: &[u8],
    header: &[u8],
    prefix: &[u8],
    path: &[u8],
    absent: bool,
) -> Result<(), DiffError> {
    let value = line.strip_prefix(header).ok_or(DiffError::Invalid)?;
    let tail = if absent {
        value.strip_prefix(b"/dev/null").ok_or(DiffError::Invalid)?
    } else {
        path_token(value, prefix, path)?
    };
    let expected_trailer = if !absent && !value.starts_with(b"\"") && path.contains(&b' ') {
        b"\t".as_slice()
    } else {
        b""
    };
    if tail == expected_trailer {
        Ok(())
    } else {
        Err(DiffError::Invalid)
    }
}
fn number(input: &mut &[u8]) -> Result<u64, DiffError> {
    let length = input.iter().take_while(|b| b.is_ascii_digit()).count();
    if length == 0 {
        return Err(DiffError::Invalid);
    }
    let mut value = 0u64;
    for &byte in &input[..length] {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or(DiffError::Overflow)?;
    }
    *input = &input[length..];
    Ok(value)
}
fn range(input: &mut &[u8]) -> Result<(u64, u64), DiffError> {
    let start = number(input)?;
    let count = if let Some(tail) = input.strip_prefix(b",") {
        *input = tail;
        number(input)?
    } else {
        1
    };
    Ok((start, count))
}
fn range_position(start: u64, count: u64, previous_end: u64) -> Result<(u64, u64), DiffError> {
    let begin = if count == 0 {
        start
    } else {
        start.checked_sub(1).ok_or(DiffError::Invalid)?
    };
    let gap = begin.checked_sub(previous_end).ok_or(DiffError::Invalid)?;
    let end = begin.checked_add(count).ok_or(DiffError::Overflow)?;
    Ok((end, gap))
}
fn consume_side(left: &mut u64, line: &mut u64, eof: bool) -> Result<(), DiffError> {
    if *left == 0 || eof {
        return Err(DiffError::Invalid);
    }
    *line = line.checked_add(1).ok_or(DiffError::Overflow)?;
    *left -= 1;
    Ok(())
}
impl std::fmt::Display for DiffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid Git patch protocol",
            Self::Limit => "Git patch record exceeds limit",
            Self::Overflow => "Git patch counter exceeds supported range",
        })
    }
}
impl std::error::Error for DiffError {}
