//! Small physical-line assignment lexer; no state crosses records or sources.
use super::stream::Candidate;
use super::{
    Registry, SourceSyntax,
    assignment::{
        AssociationKind, ReferenceKind, classify_association, classify_fields, classify_reference,
    },
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

pub(crate) fn increment(counter: &mut usize) -> Result<(), ScanError> {
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

/// Incremental form of [`directive`]. It records only quote/comment state and
/// the fixed directive spelling, so arbitrarily long comments do not grow a
/// source buffer.
pub(crate) struct DirectiveState {
    quote: Option<u8>,
    escaped: bool,
    previous: Option<u8>,
    before_previous: Option<u8>,
    comment: bool,
    leading_space: bool,
    matched: usize,
    valid: bool,
}

impl DirectiveState {
    pub(crate) fn new() -> Self {
        Self {
            quote: None,
            escaped: false,
            previous: None,
            before_previous: None,
            comment: false,
            leading_space: true,
            matched: 0,
            valid: true,
        }
    }
    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        const DIRECTIVE: &[u8] = b"rayloc:ignore";
        for &b in bytes {
            if self.comment {
                if self.leading_space && b.is_ascii_whitespace() {
                    continue;
                }
                self.leading_space = false;
                if self.matched < DIRECTIVE.len() {
                    if b == DIRECTIVE[self.matched] {
                        self.matched += 1;
                    } else {
                        self.valid = false;
                    }
                } else if !b.is_ascii_whitespace() {
                    self.valid = false;
                }
                continue;
            }
            if let Some(q) = self.quote {
                if self.escaped {
                    self.escaped = false;
                } else if b == b'\\' {
                    self.escaped = true;
                } else if b == q {
                    self.quote = None;
                }
                self.before_previous = self.previous;
                self.previous = Some(b);
                continue;
            }
            if matches!(b, b'\'' | b'"') {
                self.quote = Some(b);
            } else if b == b'#'
                || (b == b'/' && self.previous == Some(b'/') && self.before_previous != Some(b':'))
            {
                self.comment = true;
                self.leading_space = true;
                self.matched = 0;
                self.valid = true;
                // For //, this slash is the second delimiter byte.
            }
            self.before_previous = self.previous;
            self.previous = Some(b);
        }
    }
    pub(crate) fn finish(&self) -> bool {
        self.comment && self.quote.is_none() && self.valid && self.matched == b"rayloc:ignore".len()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContextMode {
    Search,
    WordName,
    QuotedName,
    AfterName,
    OperatorProbe,
    BeforeValue,
    QuotedValue,
    UnquotedValue,
    Pending,
}

/// Bounded streaming lexer for context assignments. Name classification keeps
/// only normalized suffix state; only potentially relevant values are captured.
pub(crate) struct ContextState {
    mode: ContextMode,
    offset: u64,
    name: NameState,
    quoted: u8,
    escaped: bool,
    previous: Option<u8>,
    before_previous: Option<u8>,
    significant: Option<u8>,
    before_name: Option<u8>,
    operator_probe: [u8; 3],
    operator_len: usize,
    syntax: SourceSyntax,
    comment: bool,
    has_password_field: bool,
    aws: bool,
    authorization: bool,
    generic: bool,
    checksum: bool,
    password_enabled: bool,
    aws_enabled: bool,
    generic_enabled: bool,
    active: bool,
    value: Vec<u8>,
    value_len: usize,
    value_start: u64,
    quoted_value: bool,
    bearer_probe: Vec<u8>,
    bearer: bool,
    bearer_spaces: bool,
    auth_probe_done: bool,
}

struct NameState {
    tail: Vec<u8>,
    len: usize,
    component: Vec<u8>,
    component_long: bool,
    checksum: bool,
    delayed: Option<u8>,
    raw_before_delayed: Option<u8>,
}

impl NameState {
    fn new() -> Self {
        Self {
            tail: Vec::with_capacity(64),
            len: 0,
            component: Vec::with_capacity(12),
            component_long: false,
            checksum: false,
            delayed: None,
            raw_before_delayed: None,
        }
    }
    fn reset(&mut self) {
        *self = Self::new();
    }
    fn push_normalized(&mut self, b: u8) {
        if self.tail.len() == 64 {
            self.tail.remove(0);
        }
        self.tail.push(b);
        self.len = self.len.saturating_add(1);
        if b == b'_' {
            self.check_component();
        } else if self.component.len() < 16 {
            self.component.push(b);
        } else {
            self.component_long = true;
        }
    }
    fn check_component(&mut self) {
        if !self.component_long
            && [
                b"checksum".as_slice(),
                b"digest",
                b"sha256",
                b"sha512",
                b"sha1",
                b"md5",
            ]
            .contains(&self.component.as_slice())
        {
            self.checksum = true;
        }
        self.component.clear();
        self.component_long = false;
    }
    fn raw(&mut self, b: u8) {
        let prior = self.delayed.take();
        if let Some(delayed) = prior {
            if delayed.is_ascii_uppercase()
                && self
                    .raw_before_delayed
                    .is_some_and(|c| c.is_ascii_uppercase())
                && b.is_ascii_lowercase()
            {
                self.push_normalized(b'_');
            }
            self.push_normalized(delayed.to_ascii_lowercase());
            if delayed.is_ascii_lowercase() && b.is_ascii_uppercase() {
                self.push_normalized(b'_');
            }
        }
        self.raw_before_delayed = prior;
        self.delayed = Some(b);
    }
    fn finish(&mut self) {
        if let Some(b) = self.delayed.take() {
            self.push_normalized(b.to_ascii_lowercase());
        }
        self.check_component();
    }
}

impl ContextState {
    pub(crate) fn new() -> Self {
        Self::with_syntax(SourceSyntax::Text)
    }
    pub(crate) fn with_syntax(syntax: SourceSyntax) -> Self {
        Self {
            mode: ContextMode::Search,
            offset: 0,
            name: NameState::new(),
            quoted: 0,
            escaped: false,
            previous: None,
            before_previous: None,
            significant: None,
            before_name: None,
            operator_probe: [0; 3],
            operator_len: 0,
            syntax,
            comment: false,
            has_password_field: false,
            aws: false,
            authorization: false,
            generic: false,
            checksum: false,
            password_enabled: false,
            aws_enabled: false,
            generic_enabled: false,
            active: false,
            value: Vec::new(),
            value_len: 0,
            value_start: 0,
            quoted_value: false,
            bearer_probe: Vec::with_capacity(7),
            bearer: false,
            bearer_spaces: false,
            auth_probe_done: false,
        }
    }
    pub(crate) fn reset(&mut self) {
        *self = Self::with_syntax(self.syntax);
    }

    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        registry: &Registry,
        histogram: &mut Histogram,
        suppressions: &mut Suppressions,
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        for &b in bytes {
            let mut again = true;
            while again {
                again = false;
                match self.mode {
                    ContextMode::Search => {
                        if self.comment {
                            break;
                        }
                        if b == b'#'
                            || (b == b'/'
                                && self.previous == Some(b'/')
                                && self.before_previous != Some(b':'))
                        {
                            self.comment = true;
                        } else if matches!(b, b'\'' | b'"') {
                            self.name.reset();
                            self.before_name = self.significant;
                            self.quoted = b;
                            self.escaped = false;
                            self.mode = ContextMode::QuotedName;
                        } else if word(b) {
                            self.name.reset();
                            self.before_name = self.significant;
                            self.name.raw(b);
                            self.mode = ContextMode::WordName;
                        } else if !b.is_ascii_whitespace() {
                            self.significant = Some(b);
                        }
                        self.before_previous = self.previous;
                        self.previous = Some(b);
                    }
                    ContextMode::WordName => {
                        if word(b) {
                            self.name.raw(b);
                        } else {
                            self.significant = self.name.delayed;
                            self.name.finish();
                            self.mode = ContextMode::AfterName;
                            again = true;
                        }
                    }
                    ContextMode::QuotedName => {
                        if self.escaped {
                            self.name.raw(b);
                            self.escaped = false;
                        } else if b == b'\\' {
                            self.name.raw(b);
                            self.escaped = true;
                        } else if b == self.quoted {
                            self.name.finish();
                            self.significant = Some(b);
                            self.mode = ContextMode::AfterName;
                        } else {
                            self.name.raw(b);
                        }
                    }
                    ContextMode::AfterName => {
                        if b.is_ascii_whitespace() {
                        } else if matches!(b, b'=' | b':') {
                            if self.syntax == SourceSyntax::Text {
                                self.prepare_name(registry);
                                self.mode = ContextMode::BeforeValue;
                            } else {
                                self.operator_probe[0] = b;
                                self.operator_len = 1;
                                self.mode = ContextMode::OperatorProbe;
                            }
                        } else {
                            self.mode = ContextMode::Search;
                            again = true;
                        }
                    }
                    ContextMode::OperatorProbe => {
                        self.operator_probe[self.operator_len] = b;
                        self.operator_len += 1;
                        let first = self.operator_probe[0];
                        let awaiting = self.operator_len == 1
                            || (first == b'='
                                && self.operator_len == 2
                                && self.operator_probe[1] == b'=');
                        if !awaiting {
                            again = self.resolve_operator(registry)?;
                        }
                    }
                    ContextMode::BeforeValue => {
                        if self.bearer_spaces && b.is_ascii_whitespace() {
                        } else if self.bearer_spaces {
                            self.bearer_spaces = false;
                            again = true;
                        } else if !self.bearer_probe.is_empty() {
                            const PREFIX: &[u8] = b"Bearer ";
                            let expected = PREFIX[self.bearer_probe.len()];
                            if b.eq_ignore_ascii_case(&expected) {
                                self.bearer_probe.push(b);
                                if self.bearer_probe.len() == PREFIX.len() {
                                    self.bearer_probe.clear();
                                    self.bearer = true;
                                    self.active = self.strong() && self.generic_enabled;
                                    self.bearer_spaces = true;
                                }
                            } else {
                                self.begin_value(self.bearer_probe[0], registry);
                                self.value.push(b);
                                self.value_len += 1;
                                self.bearer_probe.clear();
                                self.value_start = self.offset - 1;
                                self.mode = ContextMode::UnquotedValue;
                            }
                        } else if b.is_ascii_whitespace() {
                        } else if self.authorization && b.eq_ignore_ascii_case(&b'B') {
                            self.bearer_probe.push(b);
                        } else if matches!(b, b'\'' | b'"') {
                            self.begin_value(0, registry);
                            self.quoted = b;
                            self.escaped = false;
                            self.quoted_value = true;
                            self.value_start = self
                                .offset
                                .checked_add(1)
                                .ok_or(ScanError::CounterOverflow)?;
                            self.mode = ContextMode::QuotedValue;
                        } else {
                            self.begin_value(b, registry);
                            self.value_start = self.offset;
                            self.mode = ContextMode::UnquotedValue;
                        }
                    }
                    ContextMode::QuotedValue => {
                        if self.authorization && !self.bearer && !self.auth_probe_done {
                            let content = if self.escaped {
                                self.escaped = false;
                                true
                            } else if b == b'\\' {
                                self.escaped = true;
                                true
                            } else if b == self.quoted {
                                self.mode = ContextMode::Pending;
                                false
                            } else {
                                true
                            };
                            if content {
                                self.bearer_probe.push(b);
                                const PREFIX: &[u8] = b"Bearer ";
                                if self.bearer_probe.len() == PREFIX.len() {
                                    self.auth_probe_done = true;
                                    if self.bearer_probe.eq_ignore_ascii_case(PREFIX) {
                                        self.bearer = true;
                                        self.active = self.generic_enabled;
                                        self.value.extend_from_slice(&self.bearer_probe);
                                        self.value_len = self.bearer_probe.len();
                                    }
                                    self.bearer_probe.clear();
                                }
                            } else {
                                self.auth_probe_done = true;
                                self.bearer_probe.clear();
                            }
                        } else if self.escaped {
                            self.capture(b)?;
                            self.escaped = false;
                        } else if b == b'\\' {
                            self.capture(b)?;
                            self.escaped = true;
                        } else if b == self.quoted {
                            self.significant = Some(b);
                            self.mode = ContextMode::Pending;
                        } else {
                            self.capture(b)?;
                        }
                    }
                    ContextMode::UnquotedValue => {
                        if b.is_ascii_whitespace()
                            || matches!(b, b',' | b';' | b'}' | b'#')
                            || (self.syntax == SourceSyntax::Code && b == b')')
                        {
                            self.mode = ContextMode::Pending;
                            again = true;
                        } else {
                            self.capture(b)?;
                        }
                    }
                    ContextMode::Pending => {
                        if b.is_ascii_whitespace() {
                        } else {
                            let reject = matches!(b, b'+' | b'.');
                            if !reject {
                                self.emit_value(registry, histogram, suppressions, &mut emit)?;
                            }
                            self.clear_value();
                            self.mode = ContextMode::Search;
                            again = true;
                        }
                    }
                }
            }
            self.offset = self
                .offset
                .checked_add(1)
                .ok_or(ScanError::CounterOverflow)?;
        }
        Ok(())
    }

    fn prepare_name(&mut self, registry: &Registry) {
        let evidence = classify_fields(&self.name.tail, self.name.len, self.name.checksum);
        self.has_password_field = evidence.password;
        self.aws = evidence.aws;
        self.authorization = evidence.authorization;
        self.generic = evidence.generic;
        self.checksum = evidence.checksum;
        self.password_enabled =
            self.has_password_field && !registry.disabled.contains(&RuleId::PasswordAssignment);
        self.aws_enabled = self.aws && !registry.disabled.contains(&RuleId::AwsSecretAccessKey);
        self.generic_enabled = !registry.disabled.contains(&RuleId::ContextSecret);
        self.active =
            self.password_enabled || self.aws_enabled || (self.strong() && self.generic_enabled);
        self.value.clear();
        self.value_len = 0;
        self.bearer_probe.clear();
        self.bearer = false;
        self.bearer_spaces = false;
        self.auth_probe_done = false;
    }
    fn strong(&self) -> bool {
        self.has_password_field || self.aws || (self.authorization && self.bearer) || self.generic
    }
    fn resolve_operator(&mut self, registry: &Registry) -> Result<bool, ScanError> {
        let probe_len = self.operator_len;
        let association = classify_association(
            self.syntax,
            self.before_name,
            &self.operator_probe[..probe_len],
        );
        let replay = probe_len > association.operator_len;
        if association.kind == AssociationKind::NonAssociation {
            if association.operator_len > 0 {
                self.significant = Some(self.operator_probe[association.operator_len - 1]);
            }
            self.mode = ContextMode::Search;
        } else {
            self.prepare_name(registry);
            self.mode = ContextMode::BeforeValue;
            self.significant = Some(self.operator_probe[association.operator_len - 1]);
        }
        self.operator_len = 0;
        Ok(replay)
    }
    fn begin_value(&mut self, b: u8, _registry: &Registry) {
        self.value.clear();
        self.value_len = 0;
        self.quoted_value = false;
        self.value_start = self.offset;
        if b != 0 {
            self.value.push(b);
            self.value_len = 1;
            self.significant = Some(b);
        }
    }
    fn capture(&mut self, b: u8) -> Result<(), ScanError> {
        self.significant = Some(b);
        self.value_len = self
            .value_len
            .checked_add(1)
            .ok_or(ScanError::CounterOverflow)?;
        if self.active {
            if self.value_len > MAX_CANDIDATE_BYTES {
                return Err(ScanError::CandidateLimit);
            }
            self.value.push(b);
        }
        Ok(())
    }
    fn clear_value(&mut self) {
        self.value.clear();
        self.value_len = 0;
        self.active = false;
    }
    fn emit_value(
        &mut self,
        registry: &Registry,
        histogram: &mut Histogram,
        suppressions: &mut Suppressions,
        emit: &mut impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        if self.authorization
            && self.value.len() >= 7
            && self.value[..7].eq_ignore_ascii_case(b"Bearer ")
        {
            self.bearer = true;
        }
        if self.authorization && !self.bearer && !self.password_enabled && !self.aws_enabled {
            return Ok(());
        }
        if !self.active {
            if self.checksum && self.generic_enabled && self.value_len >= 16 {
                increment(&mut suppressions.checksum)?;
            }
            return Ok(());
        }
        let mut value = self.value.as_slice();
        let mut start = self.value_start;
        if self.authorization && value.len() >= 7 && value[..7].eq_ignore_ascii_case(b"Bearer ") {
            let skip = space(value, 7);
            start = start
                .checked_add(u64::try_from(skip).map_err(|_| ScanError::CounterOverflow)?)
                .ok_or(ScanError::CounterOverflow)?;
            value = &value[skip..];
        }
        if value.len() > MAX_CANDIDATE_BYTES {
            return Err(ScanError::CandidateLimit);
        }
        if classify_reference(value, self.quoted_value, self.syntax) != ReferenceKind::None {
            increment(&mut suppressions.reference)?;
            return Ok(());
        }
        if placeholder(value, self.has_password_field, self.aws) {
            increment(&mut suppressions.placeholder)?;
            return Ok(());
        }
        if !self.quoted_value && value.iter().any(|b| matches!(b, b'(' | b'[')) {
            return Ok(());
        }
        let rule = if self.password_enabled && value.len() >= 8 {
            Some(RuleId::PasswordAssignment)
        } else if self.aws_enabled
            && value.len() == 40
            && value
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        {
            Some(RuleId::AwsSecretAccessKey)
        } else if self.generic_enabled && value.len() >= 16 {
            if self.checksum {
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
            let end = start
                .checked_add(value.len() as u64)
                .ok_or(ScanError::CounterOverflow)?;
            emit(Candidate {
                rule,
                span: start..end,
                value,
                priority: 2,
            });
        }
        Ok(())
    }
    fn finalize(
        &mut self,
        registry: &Registry,
        histogram: &mut Histogram,
        suppressions: &mut Suppressions,
        emit: &mut impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        if self.mode == ContextMode::OperatorProbe {
            self.resolve_operator(registry)?;
        }
        if self.mode == ContextMode::Pending {
            self.emit_value(registry, histogram, suppressions, emit)?;
        } else if self.mode == ContextMode::UnquotedValue {
            self.mode = ContextMode::Pending;
            self.emit_value(registry, histogram, suppressions, emit)?;
        }
        self.clear_value();
        self.mode = ContextMode::Search;
        Ok(())
    }
    pub(crate) fn finish(
        &mut self,
        registry: &Registry,
        histogram: &mut Histogram,
        suppressions: &mut Suppressions,
        mut emit: impl FnMut(Candidate<'_>),
    ) -> Result<(), ScanError> {
        self.finalize(registry, histogram, suppressions, &mut emit)
    }
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
fn previous_significant(bytes: &[u8], index: usize) -> Option<u8> {
    let mut i = index;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    i.checked_sub(1).map(|position| bytes[position])
}
fn checksum_name(name: &[u8]) -> bool {
    [
        b"checksum".as_slice(),
        b"digest",
        b"sha256",
        b"sha512",
        b"sha1",
        b"md5",
    ]
    .iter()
    .any(|part| name.split(|b| *b == b'_').any(|value| value == *part))
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
            || descriptive_api_key_placeholder(&lower)
    }
}

/// Anchored `your[-_](provider[-_])*api[-_]key([-_]here)?` placeholders.
/// Require alphabetic words and one separator style; random tokens, suffixes,
/// and concrete password literals must remain eligible for detection.
fn descriptive_api_key_placeholder(value: &[u8]) -> bool {
    let Some(rest) = value.strip_prefix(b"your") else {
        return false;
    };
    let Some((&separator, body)) = rest.split_first() else {
        return false;
    };
    if !matches!(separator, b'-' | b'_') {
        return false;
    }
    let mut words = body.split(|&byte| byte == separator).rev();
    let mut last = words.next();
    if last == Some(b"here") {
        last = words.next();
    }
    last == Some(b"key")
        && words.next() == Some(b"api")
        && words.all(|word| !word.is_empty() && word.iter().all(u8::is_ascii_lowercase))
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
    syntax: SourceSyntax,
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
        let candidate_start = i;
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
        let Some(&delimiter) = bytes.get(separator) else {
            i = after_name;
            continue;
        };
        if !matches!(delimiter, b'=' | b':') {
            i = after_name;
            continue;
        }
        let operator_end = (separator + 3).min(bytes.len());
        let association = classify_association(
            syntax,
            previous_significant(bytes, candidate_start),
            &bytes[separator..operator_end],
        );
        if association.kind == AssociationKind::NonAssociation {
            i = (separator + association.operator_len.max(1)).max(after_name);
            continue;
        }
        let mut start = space(bytes, separator + association.operator_len);
        let fields = classify_fields(&name, name.len(), checksum_name(&name));
        let authorization = fields.authorization;
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
                && !(bytes[end].is_ascii_whitespace()
                    || matches!(bytes[end], b',' | b';' | b'}' | b'#')
                    || syntax == SourceSyntax::Code && bytes[end] == b')')
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
        let password_field = fields.password;
        let aws = fields.aws;
        let strong = password_field || aws || (authorization && bearer) || fields.generic;
        let checksum = fields.checksum;
        let password_enabled =
            password_field && !registry.disabled.contains(&RuleId::PasswordAssignment);
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
        if classify_reference(value, is_quoted, syntax) != ReferenceKind::None {
            increment(&mut suppressions.reference)?;
            continue;
        }
        if placeholder(value, password_field, aws) {
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
