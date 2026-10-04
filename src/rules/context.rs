//! Small physical-line assignment lexer; no state crosses records or sources.
use super::{
    Registry,
    builtin::{MAX_CANDIDATE_BYTES, RuleId},
    entropy::Histogram,
};
use crate::scanner::ScanError;
use std::ops::Range;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suppressions {
    pub inline: usize,
    pub placeholder: usize,
    pub reference: usize,
    pub checksum: usize,
    pub generic_filter: usize,
    pub accepted: usize,
}

pub(super) fn increment(counter: &mut usize) -> Result<(), ScanError> {
    *counter = counter.checked_add(1).ok_or(ScanError::CounterOverflow)?;
    Ok(())
}
fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn space(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}
fn quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == quote => return Some(i),
            _ => i += 1,
        }
    }
    None
}
/// Only exact trailing comments outside single/double quoted strings count.
pub(super) fn directive(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'\'' | b'"') {
            let Some(end) = quoted(bytes, i) else {
                return false;
            };
            i = end + 1;
            continue;
        }
        let comment = if bytes[i] == b'#' {
            Some(i + 1)
        } else if bytes[i..].starts_with(b"//") && (i == 0 || bytes[i - 1] != b':') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(start) = comment {
            return bytes[space(bytes, start)..].trim_ascii() == b"rayloc:ignore";
        }
        i += 1;
    }
    false
}
fn normalized(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());
    for (i, &byte) in bytes.iter().enumerate() {
        if i > 0
            && byte.is_ascii_uppercase()
            && (bytes[i - 1].is_ascii_lowercase()
                || (bytes[i - 1].is_ascii_uppercase()
                    && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase)))
        {
            result.push(b'_');
        }
        result.push(byte.to_ascii_lowercase());
    }
    result
}
fn field(name: &[u8], suffix: &[u8]) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with(b"_"))
}
fn reference(value: &[u8]) -> bool {
    value.starts_with(b"$")
        || value.starts_with(b"{{")
        || value.starts_with(b"<")
        || [
            b"process.env".as_slice(),
            b"os.getenv",
            b"os.environ",
            b"env(",
            b"getenv(",
            b"config.",
            b"settings.",
            b"ENV[",
        ]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}
fn placeholder(value: &[u8], password: bool, aws: bool) -> bool {
    if aws && value == b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
        return true;
    }
    let lower: Vec<_> = value.iter().map(u8::to_ascii_lowercase).collect();
    if password {
        [
            b"changeme".as_slice(),
            b"your_password",
            b"your-password",
            b"password_here",
            b"example_password",
            b"replace_me",
        ]
        .contains(&lower.as_slice())
    } else {
        [
            b"your_api_key_here".as_slice(),
            b"your-api-key-here",
            b"replace_with_your_key",
            b"example_api_key",
            b"insert_token_here",
        ]
        .contains(&lower.as_slice())
    }
}
fn sequential(value: &[u8]) -> bool {
    value.windows(2).all(|p| p[0] == p[1])
        || [
            b"0123456789abcdefghijklmnopqrstuvwxyz".as_slice(),
            b"abcdefghijklmnopqrstuvwxyz0123456789",
            b"0123456789abcdef",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ]
        .iter()
        .any(|sequence| sequence.windows(value.len()).any(|v| v == value))
}
/// Scan supported assignments and header forms; every value remains borrowed.
pub(super) fn detect(
    bytes: &[u8],
    registry: &Registry,
    histogram: &mut Histogram,
    suppressions: &mut Suppressions,
    mut emit: impl FnMut(RuleId, Range<usize>),
) -> Result<(), ScanError> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' || bytes[i..].starts_with(b"//") {
            break;
        }
        let (name_start, name_end, after_name) = if matches!(bytes[i], b'\'' | b'"') {
            let Some(end) = quoted(bytes, i) else {
                break;
            };
            (i + 1, end, end + 1)
        } else if word(bytes[i]) {
            let start = i;
            while i < bytes.len() && word(bytes[i]) {
                i += 1;
            }
            (start, i, i)
        } else {
            i += 1;
            continue;
        };
        let name = normalized(&bytes[name_start..name_end]);
        let separator = space(bytes, after_name);
        if !bytes
            .get(separator)
            .is_some_and(|b| matches!(b, b'=' | b':'))
        {
            i = after_name;
            continue;
        }
        let mut start = space(bytes, separator + 1);
        let authorization = name == b"authorization";
        let mut bearer = false;
        if authorization
            && bytes
                .get(start..start + 7)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"Bearer "))
        {
            start = space(bytes, start + 7);
            bearer = true;
        }
        let Some(&first) = bytes.get(start) else {
            break;
        };
        let (mut span, next, is_quoted) = if matches!(first, b'\'' | b'"') {
            let Some(end) = quoted(bytes, start) else {
                break;
            };
            (start + 1..end, end + 1, true)
        } else {
            let mut end = start;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b',' | b';' | b'}' | b'#')
            {
                end += 1;
            }
            (start..end, end, false)
        };
        if authorization
            && bytes
                .get(span.start..span.start + 7)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"Bearer "))
        {
            span.start = space(bytes, span.start + 7).min(span.end);
            bearer = true;
        }
        i = next.max(after_name);
        let password = field(&name, b"password") || field(&name, b"passwd");
        let aws = name == b"aws_secret_access_key" || name == b"secret_access_key";
        let strong = password
            || aws
            || (authorization && bearer)
            || [
                b"api_key".as_slice(),
                b"access_token",
                b"client_secret",
                b"credential",
                b"credentials",
                b"auth_token",
                b"secret_key",
            ]
            .iter()
            .any(|suffix| field(&name, suffix));
        let checksum = [
            b"checksum".as_slice(),
            b"digest",
            b"sha256",
            b"sha512",
            b"sha1",
            b"md5",
        ]
        .iter()
        .any(|part| name.split(|b| *b == b'_').any(|v| v == *part));
        let password_enabled = password && !registry.disabled.contains(&RuleId::PasswordAssignment);
        let aws_enabled = aws && !registry.disabled.contains(&RuleId::AwsSecretAccessKey);
        let generic_enabled = !registry.disabled.contains(&RuleId::ContextSecret);
        // Disabled branches do not evaluate candidates. Digest metadata remains
        // counted only while the generic branch is enabled.
        if !(password_enabled || aws_enabled || (strong && generic_enabled)) {
            if checksum && generic_enabled && span.len() >= 16 {
                increment(&mut suppressions.checksum)?;
            }
            continue;
        }
        let value = &bytes[span.clone()];
        if span.len() > MAX_CANDIDATE_BYTES {
            return Err(ScanError::CandidateLimit);
        }
        if reference(value) {
            increment(&mut suppressions.reference)?;
            continue;
        }
        if placeholder(value, password, aws) {
            increment(&mut suppressions.placeholder)?;
            continue;
        }
        // Bare code expressions are unsupported; a following operator is not a literal.
        if (!is_quoted && value.iter().any(|b| matches!(b, b'(' | b'[')))
            || bytes
                .get(space(bytes, next))
                .is_some_and(|b| matches!(b, b'+' | b'.'))
        {
            continue;
        }
        let rule = if password_enabled && value.len() >= 8 {
            Some(RuleId::PasswordAssignment)
        } else if aws_enabled
            && value.len() == 40
            && value
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        {
            Some(RuleId::AwsSecretAccessKey)
        } else if generic_enabled && value.len() >= 16 {
            if checksum {
                increment(&mut suppressions.checksum)?;
                None
            } else if sequential(value) {
                increment(&mut suppressions.generic_filter)?;
                None
            } else if super::entropy::generic_passes(value, registry, histogram) {
                Some(RuleId::ContextSecret)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(rule) = rule {
            emit(rule, span);
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../tests/unit/context.rs"]
mod tests;
