use super::*;
use crate::{
    config::Config,
    rules::window::{RuleInput, WindowState, classify_input},
};
use regex_syntax::ParserBuilder;

fn classify(pattern: &str) -> RuleInput {
    let hir = ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .unwrap();
    classify_input(&hir)
}

fn registry(pattern: &str, group: usize) -> Registry {
    let mut config = Config::default();
    config.rules.push(crate::config::CustomRule {
        id: "custom".into(),
        pattern: pattern.into(),
        group,
        entropy: None,
        severity: crate::rules::builtin::Severity::High,
    });
    Registry::compile(config).unwrap()
}

#[test]
fn classifies_the_full_expression_and_assertions() {
    assert_eq!(
        classify("corp_([a-z]{16})"),
        RuleInput::Windowed {
            max_match_bytes: 21
        }
    );
    for pattern in [
        "corp_([a-z]+)",
        "prefix.*(SECRET)",
        "^corp_[a-z]{16}$",
        r"\bcorp_[a-z]{16}\b",
        r"(?u:\b)corp_[a-z]{16}",
    ] {
        assert_eq!(classify(pattern), RuleInput::WholeLine, "{pattern}");
    }
    assert_eq!(
        classify("a{65536}"),
        RuleInput::Windowed {
            max_match_bytes: 65536
        }
    );
    assert_eq!(classify("a{65537}"), RuleInput::WholeLine);
}

#[test]
fn window_matching_waits_for_full_match_and_emits_once_across_splits() {
    let registry = registry(r"prefix([a-z]{4})suffix", 1);
    let line = b"prefixabcdsuffix--";
    for split in 0..=line.len() {
        let mut state = WindowState::new();
        let mut histogram = Histogram::new();
        let mut found = Vec::new();
        state
            .push(&line[..split], &registry, &mut histogram, |c| {
                found.push((c.span, c.value.to_vec()))
            })
            .unwrap();
        state
            .push(&line[split..], &registry, &mut histogram, |c| {
                found.push((c.span, c.value.to_vec()))
            })
            .unwrap();
        state
            .finish(&registry, &mut histogram, |c| {
                found.push((c.span, c.value.to_vec()))
            })
            .unwrap();
        assert_eq!(found, [(6..10, b"abcd".to_vec())], "split marker {split}");
        state.reset();
    }
}

#[test]
fn full_match_progress_survives_absent_and_empty_captures() {
    let registry = registry(r"(?:x([a-z]{4})|y()|z)(?:!)", 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    for bytes in [b"y!xab".as_slice(), b"cd!xefgh!".as_slice()] {
        state
            .push(bytes, &registry, &mut histogram, |c| {
                found.push((c.span, c.value.to_vec()))
            })
            .unwrap();
    }
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(3..7, b"abcd".to_vec()), (9..13, b"efgh".to_vec())]);
}

#[test]
fn greedy_full_match_has_its_complete_right_lookahead() {
    let registry = registry(r"(a{1,8})a", 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"aaaaaaaaa", &registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(0..8, b"aaaaaaaa".to_vec())]);
}

#[test]
fn long_bounded_match_crosses_chunk_boundary_once() {
    let match_len = 512;
    let registry = registry(&format!("x{{{match_len}}}"), 0);
    let mut line = vec![b'-'; crate::scanner::chunk::CHUNK_BYTES - 100];
    line.extend(std::iter::repeat_n(b'x', match_len));
    line.extend_from_slice(b"tail");
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut spans = Vec::new();
    for fragment in line.chunks(7919) {
        state
            .push(fragment, &registry, &mut histogram, |candidate| {
                spans.push((candidate.span, candidate.value.len()))
            })
            .unwrap();
    }
    state
        .finish(&registry, &mut histogram, |candidate| {
            spans.push((candidate.span, candidate.value.len()))
        })
        .unwrap();
    assert_eq!(
        spans,
        [(
            crate::scanner::chunk::CHUNK_BYTES as u64 - 100
                ..(crate::scanner::chunk::CHUNK_BYTES + match_len - 100) as u64,
            match_len
        )]
    );
}

#[test]
fn unicode_match_survives_fragment_inside_codepoint() {
    let registry = registry("(é)", 1);
    let mut line = vec![b'-'; crate::scanner::chunk::CHUNK_BYTES - 1];
    line.extend_from_slice("é".as_bytes());
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut spans = Vec::new();
    for fragment in line.chunks(crate::scanner::chunk::CHUNK_BYTES) {
        state
            .push(fragment, &registry, &mut histogram, |candidate| {
                spans.push((candidate.span, candidate.value.to_vec()))
            })
            .unwrap();
    }
    state
        .finish(&registry, &mut histogram, |candidate| {
            spans.push((candidate.span, candidate.value.to_vec()))
        })
        .unwrap();
    assert_eq!(
        spans,
        [(
            crate::scanner::chunk::CHUNK_BYTES as u64 - 1
                ..crate::scanner::chunk::CHUNK_BYTES as u64 + 1,
            "é".as_bytes().to_vec()
        )]
    );
}
