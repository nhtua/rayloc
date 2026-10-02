//! Immutable bounded compiled policy shared by every source reader.
use crate::{
    config::{Config, ConfigError},
    scanner::ScanError,
};
use builtin::{MAX_CANDIDATE_BYTES, RuleId};
use entropy::Histogram;
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use std::{ops::Range, sync::LazyLock};
pub mod builtin;
pub mod context;
pub mod entropy;
mod jose;
const PROGRAM_BYTES: usize = 256 * 1024;
const SET_BYTES: usize = 16 * 1024 * 1024;
const DFA_BYTES: usize = 256 * 1024;
pub const BUILTIN_IDS: [RuleId; 10] = [
    RuleId::AwsAccessKeyId,
    RuleId::GithubToken,
    RuleId::StripeSecretKey,
    RuleId::StripeRestrictedKey,
    RuleId::SlackWebhook,
    RuleId::PrivateKeyMarker,
    RuleId::AwsSecretAccessKey,
    RuleId::JoseToken,
    RuleId::ContextSecret,
    RuleId::PasswordAssignment,
];
pub(crate) fn builtin_id(id: &str) -> Option<RuleId> {
    BUILTIN_IDS
        .into_iter()
        .find(|rule| rule.metadata().id == id)
}
struct CompiledRule {
    regex: Regex,
    group: usize,
    entropy: Option<f64>,
    id: RuleId,
    disabled: bool,
}
pub struct Registry {
    set: RegexSet,
    custom: Vec<CompiledRule>,
    disabled: Vec<RuleId>,
    pub inline_ignores: bool,
    pub default_entropy_threshold: f64,
    pub entropy_thresholds: std::collections::BTreeMap<String, f64>,
}
pub static BUILTINS: LazyLock<Registry> =
    LazyLock::new(|| Registry::compile(Config::default()).expect("empty policy is valid"));
fn capture(hir: &Hir, group: usize) -> Option<&Hir> {
    if group == 0 {
        return Some(hir);
    }
    if let HirKind::Capture(c) = hir.kind() {
        if c.index as usize == group {
            return Some(&c.sub);
        }
    }
    hir.kind().subs().iter().find_map(|h| capture(h, group))
}
fn alphabet(hir: &Hir, bins: &mut [bool; 256]) {
    match hir.kind() {
        HirKind::Literal(literal) => {
            for &byte in literal.0.iter() {
                bins[byte as usize] = true;
            }
        }
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                for byte in range.start()..=range.end() {
                    bins[byte as usize] = true;
                }
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            for range in class.ranges() {
                if range.end() > '\u{7f}' {
                    bins.fill(true);
                    return;
                }
                for byte in range.start() as u8..=range.end() as u8 {
                    bins[byte as usize] = true;
                }
            }
        }
        _ => {
            for child in hir.kind().subs() {
                alphabet(child, bins);
            }
        }
    }
}
impl Registry {
    /// Validate and compile all patterns before reading any selected source.
    pub fn compile(config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        let mut disabled = Vec::new();
        for id in &config.disabled {
            if let Some(rule) = builtin_id(id) {
                disabled.push(rule);
            } else if !config.rules.iter().any(|rule| &rule.id == id) {
                return Err(ConfigError::Schema);
            }
        }
        let mut custom = Vec::new();
        for (index, rule) in config.rules.iter().enumerate() {
            let hir = regex_syntax::ParserBuilder::new()
                .utf8(false)
                .build()
                .parse(&rule.pattern)
                .map_err(|_| ConfigError::Pattern)?;
            if hir
                .properties()
                .minimum_len()
                .is_none_or(|length| length == 0)
            {
                return Err(ConfigError::Pattern);
            }
            let captured = capture(&hir, rule.group).ok_or(ConfigError::Pattern)?;
            if let Some(gate) = rule.entropy {
                let mut bins = [false; 256];
                alphabet(captured, &mut bins);
                let symbols = bins.iter().filter(|&&set| set).count();
                let maximum = captured
                    .properties()
                    .maximum_len()
                    .unwrap_or(256)
                    .min(symbols);
                if maximum == 0 || gate > (maximum as f64).log2() {
                    return Err(ConfigError::Pattern);
                }
            }
            let regex = RegexBuilder::new(&rule.pattern)
                .size_limit(PROGRAM_BYTES)
                .dfa_size_limit(DFA_BYTES)
                .build()
                .map_err(|_| ConfigError::Pattern)?;
            custom.push(CompiledRule {
                regex,
                group: rule.group,
                entropy: rule.entropy,
                id: RuleId::Custom(index as u16 + 1, rule.severity),
                disabled: config.disabled.contains(&rule.id),
            });
        }
        let set = RegexSetBuilder::new(config.rules.iter().map(|r| r.pattern.as_str()))
            .size_limit(SET_BYTES)
            .dfa_size_limit(DFA_BYTES)
            .build()
            .map_err(|_| ConfigError::Pattern)?;
        Ok(Self {
            inline_ignores: true,
            set,
            custom,
            disabled,
            default_entropy_threshold: config.default_entropy_threshold.unwrap_or(4.5),
            entropy_thresholds: config.entropy_thresholds,
        })
    }
    /// Per-physical-line byte matching; missing optional captures never emit.
    pub fn detect_line(
        &self,
        bytes: &[u8],
        histogram: &mut Histogram,
        emit: impl FnMut(RuleId, Range<usize>),
    ) -> Result<(), ScanError> {
        self.detect_line_with_suppressions(
            bytes,
            histogram,
            &mut context::Suppressions::default(),
            emit,
        )
    }
    /// Counters describe dropped candidates without retaining their contents.
    pub fn detect_line_with_suppressions(
        &self,
        bytes: &[u8],
        histogram: &mut Histogram,
        suppressions: &mut context::Suppressions,
        mut emit: impl FnMut(RuleId, Range<usize>),
    ) -> Result<(), ScanError> {
        let ignored = self.inline_ignores && context::directive(bytes);
        if ignored {
            context::increment(&mut suppressions.inline)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut overflow = false;
        let mut unique = |rule, span: Range<usize>| {
            if ignored {
                return;
            }
            if seen.contains(&(span.start, span.end)) {
                return;
            }
            if seen.len() == crate::scanner::engine::MAX_FINDINGS {
                overflow = true;
                return;
            }
            seen.insert((span.start, span.end));
            emit(rule, span);
        };
        builtin::detect_line_with_disabled(bytes, &self.disabled, &mut unique)?;
        if !self.disabled.contains(&RuleId::JoseToken) {
            jose::detect(bytes, &mut unique)?;
        }
        context::detect(bytes, self, histogram, suppressions, &mut unique)?;
        for index in self.set.matches(bytes) {
            let rule = &self.custom[index];
            if rule.disabled {
                continue;
            }
            for captures in rule.regex.captures_iter(bytes) {
                let Some(value) = captures.get(rule.group) else {
                    continue;
                };
                if value.len() > MAX_CANDIDATE_BYTES {
                    return Err(ScanError::CandidateLimit);
                }
                if !value.is_empty()
                    && rule
                        .entropy
                        .is_none_or(|gate| histogram.measure(value.as_bytes()) >= gate)
                {
                    unique(rule.id, value.start()..value.end());
                }
            }
        }
        if overflow {
            return Err(ScanError::FindingLimit);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "../../tests/unit/registry.rs"]
mod tests;
