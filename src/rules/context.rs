//! Small physical-line assignment lexer; no state crosses records or sources.
use super::stream::Candidate;
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
    comment: bool,
    password: bool,
    aws: bool,
    authorization: bool,
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
    exact: bool,
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
            exact: true,
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
        } else {
            self.exact = true;
        }
        self.raw_before_delayed = prior;
        self.delayed = Some(b);
        self.exact &= self.len <= 64;
    }
    fn finish(&mut self) {
        if let Some(b) = self.delayed.take() {
            self.push_normalized(b.to_ascii_lowercase());
        }
        self.check_component();
    }
    fn is(&self, value: &[u8]) -> bool {
        self.len == value.len() && self.tail.as_slice() == value
    }
    fn field(&self, suffix: &[u8]) -> bool {
        self.tail.ends_with(suffix)
            && (self.len == suffix.len()
                || self
                    .tail
                    .get(self.tail.len().saturating_sub(suffix.len() + 1))
                    == Some(&b'_'))
    }
}

impl ContextState {
    pub(crate) fn new() -> Self {
        Self {
            mode: ContextMode::Search,
            offset: 0,
            name: NameState::new(),
            quoted: 0,
            escaped: false,
            previous: None,
            before_previous: None,
            comment: false,
            password: false,
            aws: false,
            authorization: false,
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
        *self = Self::new();
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
                            self.quoted = b;
                            self.escaped = false;
                            self.mode = ContextMode::QuotedName;
                        } else if word(b) {
                            self.name.reset();
                            self.name.raw(b);
                            self.mode = ContextMode::WordName;
                        }
                        self.before_previous = self.previous;
                        self.previous = Some(b);
                    }
                    ContextMode::WordName => {
                        if word(b) {
                            self.name.raw(b);
                        } else {
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
                            self.mode = ContextMode::AfterName;
                        } else {
                            self.name.raw(b);
                        }
                    }
                    ContextMode::AfterName => {
                        if b.is_ascii_whitespace() {
                        } else if matches!(b, b'=' | b':') {
                            self.prepare_name(registry);
                            self.mode = ContextMode::BeforeValue;
                        } else {
                            self.mode = ContextMode::Search;
                            again = true;
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
                            self.mode = ContextMode::Pending;
                        } else {
                            self.capture(b)?;
                        }
                    }
                    ContextMode::UnquotedValue => {
                        if b.is_ascii_whitespace() || matches!(b, b',' | b';' | b'}' | b'#') {
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
        self.password = self.name.field(b"password") || self.name.field(b"passwd");
        self.aws = self.name.is(b"aws_secret_access_key") || self.name.is(b"secret_access_key");
        self.authorization = self.name.is(b"authorization");
        self.checksum = self.name.checksum;
        self.password_enabled =
            self.password && !registry.disabled.contains(&RuleId::PasswordAssignment);
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
        self.password
            || self.aws
            || (self.authorization && self.bearer)
            || [
                b"api_key".as_slice(),
                b"access_token",
                b"client_secret",
                b"credential",
                b"credentials",
                b"auth_token",
                b"secret_key",
                // Phase 2 context-based suffixes
                b"datadog_api_key",
                b"datadog_app_key",
                b"azure_ad_client_secret",
                b"npm_token",
                b"nuget_api_key",
                b"pagerduty_key",
                b"pagerduty_integration_key",
                b"snyk_token",
                b"sonar_token",
                b"newrelic_license_key",
                b"newrelic_insights_key",
                b"splunk_observability_token",
                b"intercom_api_key",
                b"vultr_api_key",
                b"trello_api_key",
                b"postman_api_key",
                b"unsplash_api_key",
                b"sumologic_access_id",
                b"sumologic_access_key",
                b"grafana_service_account",
                b"honeycomb_api_key",
                b"logdna_api_key",
                b"zoom_oauth_client_secret",
            ]
            .iter()
            .any(|s| self.name.field(s))
    }
    fn begin_value(&mut self, b: u8, _registry: &Registry) {
        self.value.clear();
        self.value_len = 0;
        self.quoted_value = false;
        self.value_start = self.offset;
        if b != 0 {
            self.value.push(b);
            self.value_len = 1;
        }
    }
    fn capture(&mut self, b: u8) -> Result<(), ScanError> {
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
        if reference(value) {
            increment(&mut suppressions.reference)?;
            return Ok(());
        }
        if placeholder(value, self.password, self.aws) {
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
