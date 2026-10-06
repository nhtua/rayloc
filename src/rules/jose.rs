//! Bounded compact JOSE framing and protected-header validation, never validity.
use super::builtin::{MAX_CANDIDATE_BYTES, RuleId};
use super::stream::Candidate;
use crate::scanner::ScanError;
use std::ops::Range;
const HEADER_BYTES: usize = 8192;
const JSON_DEPTH: usize = 16;
const JSON_VALUES: usize = 512;
fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}
fn decode(input: &[u8], output: &mut Vec<u8>) -> bool {
    if input.len() % 4 == 1 {
        return false;
    }
    let mut bits = 0u32;
    let mut count = 0;
    for &byte in input {
        let Some(value) = digit(byte) else {
            return false;
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            output.push((bits >> count) as u8);
        }
    }
    count == 0 || bits & ((1 << count) - 1) == 0
}
fn encoded(input: &[u8]) -> bool {
    if input.len() % 4 == 1 {
        return false;
    }
    if !input.iter().all(|b| digit(*b).is_some()) {
        return false;
    }
    let trailing = match input.len() % 4 {
        2 => 4,
        3 => 2,
        _ => 0,
    };
    input
        .last()
        .is_none_or(|b| digit(*b).unwrap() & ((1 << trailing) - 1) == 0)
}
#[derive(Default)]
struct Header {
    alg: Option<String>,
    enc: Option<String>,
}
enum Value {
    Text(String),
    Object(Header),
    Other,
}
struct Json<'a> {
    input: &'a [u8],
    offset: usize,
    remaining: usize,
    exhausted: bool,
}
impl Json<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.input.get(self.offset) != Some(&byte) {
            return false;
        }
        self.offset += 1;
        true
    }
    fn hex(&mut self) -> Option<u16> {
        let bytes = self.input.get(self.offset..self.offset + 4)?;
        let mut result = 0;
        for &b in bytes {
            result = result * 16 + (b as char).to_digit(16)? as u16;
        }
        self.offset += 4;
        Some(result)
    }
    fn string(&mut self) -> Option<String> {
        if !self.take(b'"') {
            return None;
        }
        let mut output = Vec::new();
        loop {
            let byte = *self.input.get(self.offset)?;
            self.offset += 1;
            match byte {
                b'"' => return String::from_utf8(output).ok(),
                0..=31 => return None,
                b'\\' => {
                    let escape = *self.input.get(self.offset)?;
                    self.offset += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => output.push(escape),
                        b'b' => output.push(8),
                        b'f' => output.push(12),
                        b'n' => output.push(10),
                        b'r' => output.push(13),
                        b't' => output.push(9),
                        b'u' => {
                            let first = self.hex()?;
                            let code = if (0xd800..=0xdbff).contains(&first) {
                                if self.input.get(self.offset..self.offset + 2)? != b"\\u" {
                                    return None;
                                }
                                self.offset += 2;
                                let second = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return None;
                                }
                                0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second)
                                    - 0xdc00
                            } else {
                                u32::from(first)
                            };
                            output.extend_from_slice(
                                char::from_u32(code)?.encode_utf8(&mut [0; 4]).as_bytes(),
                            );
                        }
                        _ => return None,
                    }
                }
                _ => output.push(byte),
            }
        }
    }
    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > JSON_DEPTH || self.remaining == 0 {
            self.exhausted = true;
            return None;
        }
        self.remaining -= 1;
        self.whitespace();
        match *self.input.get(self.offset)? {
            b'"' => self.string().map(Value::Text),
            b'{' => {
                self.offset += 1;
                let mut header = Header::default();
                let mut keys = Vec::new();
                if self.take(b'}') {
                    return Some(Value::Object(header));
                }
                loop {
                    let key = self.string()?;
                    if keys.contains(&key) || !self.take(b':') {
                        return None;
                    }
                    let value = self.value(depth + 1)?;
                    if depth == 0 && (key == "alg" || key == "enc") {
                        let Value::Text(text) = value else {
                            return None;
                        };
                        if text.is_empty() {
                            return None;
                        }
                        if key == "alg" {
                            header.alg = Some(text);
                        } else {
                            header.enc = Some(text);
                        }
                    }
                    keys.push(key);
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return None;
                    }
                }
                Some(Value::Object(header))
            }
            b'[' => {
                self.offset += 1;
                if self.take(b']') {
                    return Some(Value::Other);
                }
                loop {
                    self.value(depth + 1)?;
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return None;
                    }
                }
                Some(Value::Other)
            }
            b't' | b'f' | b'n' => {
                let literal = match self.input[self.offset] {
                    b't' => b"true".as_slice(),
                    b'f' => b"false",
                    _ => b"null",
                };
                if !self.input[self.offset..].starts_with(literal) {
                    return None;
                }
                self.offset += literal.len();
                Some(Value::Other)
            }
            b'-' | b'0'..=b'9' => {
                if self.input[self.offset] == b'-' {
                    self.offset += 1;
                }
                match self.input.get(self.offset)? {
                    b'0' => self.offset += 1,
                    b'1'..=b'9' => {
                        while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
                            self.offset += 1;
                        }
                    }
                    _ => return None,
                }
                if self.input.get(self.offset) == Some(&b'.') {
                    self.offset += 1;
                    self.digits()?;
                }
                if self
                    .input
                    .get(self.offset)
                    .is_some_and(|b| matches!(b, b'e' | b'E'))
                {
                    self.offset += 1;
                    if self
                        .input
                        .get(self.offset)
                        .is_some_and(|b| matches!(b, b'+' | b'-'))
                    {
                        self.offset += 1;
                    }
                    self.digits()?;
                }
                Some(Value::Other)
            }
            _ => None,
        }
    }
    fn digits(&mut self) -> Option<()> {
        let start = self.offset;
        while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        (start != self.offset).then_some(())
    }
}
/// Compact syntax only: no signature verification, claims or expiry decisions.
pub(super) fn valid(bytes: &[u8]) -> Result<bool, ScanError> {
    if bytes.len() > MAX_CANDIDATE_BYTES {
        return Err(ScanError::CandidateLimit);
    }
    let mut segments = bytes.split(|b| *b == b'.');
    let header = segments.next().unwrap();
    if header.len() > HEADER_BYTES {
        return Err(ScanError::CandidateLimit);
    }
    if header.is_empty() {
        return Ok(false);
    }
    let tail: Vec<_> = segments.take(5).collect();
    if !matches!(tail.len(), 2 | 4) || !tail.iter().all(|s| encoded(s)) {
        return Ok(false);
    }
    let mut decoded = Vec::with_capacity(header.len() * 3 / 4);
    if !decode(header, &mut decoded) || std::str::from_utf8(&decoded).is_err() {
        return Ok(false);
    }
    let mut json = Json {
        input: &decoded,
        offset: 0,
        remaining: JSON_VALUES,
        exhausted: false,
    };
    let Some(Value::Object(header)) = json.value(0) else {
        return if json.exhausted {
            Err(ScanError::CandidateLimit)
        } else {
            Ok(false)
        };
    };
    json.whitespace();
    if json.offset != decoded.len() {
        return Ok(false);
    }
    let Some(alg) = header.alg else {
        return Ok(false);
    };
    Ok(if tail.len() == 2 {
        !tail[0].is_empty()
            && (if alg == "none" {
                tail[1].is_empty()
            } else {
                !tail[1].is_empty()
            })
    } else {
        alg != "none"
            && header.enc.is_some()
            && tail[1..].iter().all(|s| !s.is_empty())
            && (if matches!(alg.as_str(), "dir" | "ECDH-ES") {
                tail[0].is_empty()
            } else {
                !tail[0].is_empty()
            })
    })
}
pub(super) fn detect(
    bytes: &[u8],
    mut emit: impl FnMut(RuleId, Range<usize>),
) -> Result<(), ScanError> {
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start].is_ascii_alphanumeric() && !matches!(bytes[start], b'-' | b'_') {
            start += 1;
            continue;
        }
        let mut end = start;
        let mut dots = 0;
        while end < bytes.len()
            && (digit(bytes[end]).is_some() || matches!(bytes[end], b'.' | b'='))
        {
            if bytes[end] == b'.' {
                dots += 1;
            }
            end += 1;
        }
        if dots >= 2 {
            if end - start > MAX_CANDIDATE_BYTES {
                return Err(ScanError::CandidateLimit);
            }
            if valid(&bytes[start..end])? {
                emit(RuleId::JoseToken, start..end);
            }
        }
        start = end;
    }
    Ok(())
}

/// Incremental compact-JOSE recognizer with a hard cap on retained candidate bytes.
#[allow(dead_code)] // Consumed by the line session in Task 5.
pub(crate) struct JoseState {
    offset: u64,
    start: Option<u64>,
    len: usize,
    dots: usize,
    oversized: bool,
    bytes: Vec<u8>,
}

#[allow(dead_code)] // Consumed by the line session in Task 5.
impl JoseState {
    pub(crate) fn new() -> Self {
        Self {
            offset: 0,
            start: None,
            len: 0,
            dots: 0,
            oversized: false,
            bytes: Vec::with_capacity(MAX_CANDIDATE_BYTES),
        }
    }
    pub(crate) fn reset(&mut self) {
        self.offset = 0;
        self.start = None;
        self.len = 0;
        self.dots = 0;
        self.oversized = false;
        self.bytes.clear();
    }
    pub(crate) fn push(
        &mut self,
        input: &[u8],
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        for &byte in input {
            let accepted = digit(byte).is_some() || matches!(byte, b'.' | b'=');
            if accepted {
                if self.start.is_none()
                    && (byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    self.start = Some(self.offset);
                }
                if self.start.is_some() {
                    self.len = self.len.checked_add(1).ok_or(ScanError::CandidateLimit)?;
                    if byte == b'.' {
                        self.dots += 1;
                    }
                    if self.len <= MAX_CANDIDATE_BYTES {
                        self.bytes.push(byte);
                    } else {
                        self.oversized = true;
                        if self.dots >= 2 {
                            return Err(ScanError::CandidateLimit);
                        }
                    }
                }
            } else {
                self.flush(&mut emit)?;
            }
            self.offset = self
                .offset
                .checked_add(1)
                .ok_or(ScanError::CounterOverflow)?;
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self, mut emit: impl FnMut(Candidate<'_>)) -> Result<(), ScanError> {
        self.flush(&mut emit)?;
        self.reset();
        Ok(())
    }
    fn flush(&mut self, emit: &mut impl FnMut(Candidate<'_>)) -> Result<(), ScanError> {
        if let Some(start) = self.start {
            if self.dots >= 2 {
                if self.oversized {
                    return Err(ScanError::CandidateLimit);
                }
                if valid(&self.bytes)? {
                    let length = u64::try_from(self.len).map_err(|_| ScanError::CounterOverflow)?;
                    let end = start
                        .checked_add(length)
                        .ok_or(ScanError::CounterOverflow)?;
                    emit(Candidate {
                        rule: RuleId::JoseToken,
                        span: start..end,
                        value: &self.bytes,
                        priority: 1,
                    });
                }
            }
        }
        self.start = None;
        self.len = 0;
        self.dots = 0;
        self.oversized = false;
        self.bytes.clear();
        Ok(())
    }
}
#[cfg(test)]
#[path = "../../tests/unit/jose.rs"]
mod tests;
