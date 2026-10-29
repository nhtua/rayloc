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

#[test]
fn window_with_chunk_boundary() {
    // Test a match that spans a chunk boundary
    let pattern = r"corp_([a-z]{20})";
    let registry = registry(pattern, 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.span, c.value.to_vec()));

    // Build input that crosses chunk boundary
    let prefix = vec![b'x'; crate::scanner::chunk::CHUNK_BYTES - 10];
    let match_part = b"corp_abcdefghij";
    let suffix = b"klmnopqrst";

    // Feed prefix
    state
        .push(&prefix, &registry, &mut histogram, &mut emit)
        .unwrap();
    // Feed match part (crosses boundary)
    state
        .push(match_part, &registry, &mut histogram, &mut emit)
        .unwrap();
    // Feed suffix and finish
    state
        .push(suffix, &registry, &mut histogram, &mut emit)
        .unwrap();
    state.finish(&registry, &mut histogram, &mut emit).unwrap();

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, b"abcdefghijklmnopqrst");
}

#[test]
fn window_with_multiple_matches() {
    // Test multiple matches on the same line
    let pattern = r"corp_([a-z]{4})";
    let registry = registry(pattern, 1);
    let line = b"corp_abcd corp_efgh corp_ijkl";
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.span, c.value.to_vec()));
    state
        .push(line, &registry, &mut histogram, &mut emit)
        .unwrap();
    state.finish(&registry, &mut histogram, &mut emit).unwrap();
    assert_eq!(found.len(), 3);
}

#[test]
fn window_with_greedy_alternation() {
    // Test greedy vs lazy alternation
    let pattern = r"corp_(a{4}|a)";
    let registry = registry(pattern, 1);
    let line = b"corp_aaaa";
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    let mut emit = |c: Candidate<'_>| found.push((c.span, c.value.to_vec()));
    state
        .push(line, &registry, &mut histogram, &mut emit)
        .unwrap();
    state.finish(&registry, &mut histogram, &mut emit).unwrap();
    // Greedy should match aaaa
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, b"aaaa");
}

#[test]
fn window_with_word_boundary_fails() {
    // Patterns with word boundaries should be classified as WholeLine
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(r"\bcorp_[a-z]{16}\b")
        .unwrap();
    assert_eq!(classify_input(&hir), RuleInput::WholeLine);
}

#[test]
fn window_state_reset_clears_cursors() {
    // Test that reset clears cursors
    let pattern = r"corp_([a-z]{4})";
    let registry = registry(pattern, 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();

    state
        .push(b"corp_abcd", &registry, &mut histogram, |_c| {})
        .unwrap();
    state.finish(&registry, &mut histogram, |_c| {}).unwrap();

    // After reset, cursors should be cleared
    state.reset();
    assert!(state.cursors.is_empty());
}

fn registry(pattern: &str, group: usize) -> Registry {
    registry_with(pattern, group, None)
}

fn registry_with(pattern: &str, group: usize, entropy: Option<f64>) -> Registry {
    let mut config = Config::default();
    config.rules.push(crate::config::CustomRule {
        id: "custom".into(),
        pattern: pattern.into(),
        group,
        entropy,
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
    let registry = registry(r"x([a-z]{0,4})!", 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"x!xabcd!", &registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(3..7, b"abcd".to_vec())]);
}

#[test]
fn empty_push_and_default_state_are_clean() {
    let registry = registry(r"corp_([a-z]{4})", 1);
    let mut state = WindowState::default();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(&[], &registry, &mut histogram, |candidate| {
            found.push(candidate.value.to_vec())
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |candidate| {
            found.push(candidate.value.to_vec())
        })
        .unwrap();
    assert!(found.is_empty());
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

#[test]
fn cursor_table_starts_at_base_then_tracks_each_index() {
    let mut state = WindowState::new();
    assert_eq!(state.cursor(0), state.base); // missing entry falls back to base
    state.set_cursor(0, 5); // insert arm
    assert_eq!(state.cursor(0), 5); // found arm
    state.set_cursor(0, 7); // update arm
    assert_eq!(state.cursor(0), 7);
    state.set_cursor(1, 3); // second index inserts alongside the first
    assert_eq!(
        (state.cursor(0), state.cursor(1), state.cursor(2)),
        (7, 3, 0)
    );
    state.reset();
    assert_eq!(state.cursor(0), 0);
    assert!(state.cursors.is_empty());
    let fresh = WindowState::default();
    assert_eq!(
        (
            fresh.bytes.len(),
            fresh.base,
            fresh.end,
            fresh.cursors.len()
        ),
        (0, 0, 0, 0)
    );
}

#[test]
fn window_defers_until_match_begins_below_mature_end() {
    let registry = registry("a{6}", 0);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"xxxxxxaaaaaa", &registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert!(
        found.is_empty(),
        "match begins at mature_end, so it is not mature"
    );
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(6..12, b"aaaaaa".to_vec())]);
}

#[test]
fn optional_capture_group_never_emits_when_absent() {
    let registry = registry(r"k([a-z]{4})?k", 1);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"kkkabcdk", &registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(3..7, b"abcd".to_vec())]);
}

#[test]
fn entropy_gate_suppresses_flat_captures_and_passes_balanced_ones() {
    let registry = registry_with(r"k([a-z]{8})", 1, Some(3.0));
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"kabcdefgh kaaaaaaaa", &registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |c| {
            found.push((c.span, c.value.to_vec()))
        })
        .unwrap();
    assert_eq!(found, [(1..9, b"abcdefgh".to_vec())]);
}

#[test]
fn whole_line_only_registry_leaves_no_window_state() {
    let registry = registry(r"\bx{4}\b", 0);
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    for fragment in [b"xxxx".as_slice(), b"yyyy"] {
        state
            .push(fragment, &registry, &mut histogram, |_| {})
            .unwrap();
        assert!(state.bytes.is_empty() && state.cursors.is_empty());
    }
    state.finish(&registry, &mut histogram, |_| {}).unwrap();
    assert_eq!((state.base, state.end), (8, 8));
}

#[test]
fn disabled_window_rule_emits_nothing() {
    let mut config = Config::default();
    config.rules.push(crate::config::CustomRule {
        id: "custom".into(),
        pattern: r"corp_([a-z]{4})".into(),
        group: 1,
        entropy: None,
        severity: crate::rules::builtin::Severity::High,
    });
    config.disabled.push("custom".into());
    let registry = Registry::compile(config).unwrap();
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"corp_wxyz corp_qrst", &registry, &mut histogram, |c| {
            found.push(c.span)
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |c| found.push(c.span))
        .unwrap();
    assert!(found.is_empty());
}

#[test]
fn two_window_rules_advance_independently_across_pushes() {
    let mut config = Config::default();
    for (id, pattern) in [("one", r"aa([a-z]{2})"), ("two", r"b([a-z]{3})z")] {
        config.rules.push(crate::config::CustomRule {
            id: id.into(),
            pattern: pattern.into(),
            group: 1,
            entropy: None,
            severity: crate::rules::builtin::Severity::High,
        });
    }
    let registry = Registry::compile(config).unwrap();
    let line = b"aazzbbzzbabczaaqqzz";
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut streamed = Vec::new();
    for fragment in line.chunks(4) {
        state
            .push(fragment, &registry, &mut histogram, |c| {
                streamed.push((c.span.start, c.span.end, c.value.to_vec()))
            })
            .unwrap();
    }
    state
        .finish(&registry, &mut histogram, |c| {
            streamed.push((c.span.start, c.span.end, c.value.to_vec()))
        })
        .unwrap();
    let mut whole: std::collections::BTreeSet<(u64, u64, Vec<u8>)> =
        std::collections::BTreeSet::new();
    registry
        .detect_line(line, &mut Histogram::new(), |_, span| {
            let entry = (
                span.start as u64,
                span.end as u64,
                line[span.start..span.end].to_vec(),
            );
            whole.insert(entry);
        })
        .unwrap();
    assert!(!whole.is_empty(), "fixture must produce windowed matches");
    let streamed: std::collections::BTreeSet<(u64, u64, Vec<u8>)> = streamed.into_iter().collect();
    assert_eq!(streamed, whole, "split scans agree with whole-line scans");
}

#[test]
fn window_skips_empty_and_entropy_rejected_captures() {
    let mut config = Config::default();
    config.rules.push(crate::config::CustomRule {
        id: "capture".into(),
        pattern: r"([a-z]{0,3})b".into(),
        group: 1,
        entropy: Some(1.0),
        severity: crate::rules::builtin::Severity::High,
    });
    let registry = Registry::compile(config).unwrap();
    let mut state = WindowState::new();
    let mut histogram = Histogram::new();
    let mut found = Vec::new();
    state
        .push(b"b ab", &registry, &mut histogram, |candidate| {
            found.push(candidate.value.to_vec())
        })
        .unwrap();
    state
        .finish(&registry, &mut histogram, |candidate| {
            found.push(candidate.value.to_vec())
        })
        .unwrap();
    assert!(found.is_empty());
}

#[test]
fn window_capacity_guard_fails_closed() {
    let registry = registry(r"(secret)", 1);
    let mut state = WindowState::new();
    state.bytes.resize(super::MAX_WINDOW_BYTES, b'x');
    let mut histogram = Histogram::new();
    assert_eq!(
        state.push(b"x", &registry, &mut histogram, |_| {}),
        Err(crate::scanner::ScanError::CounterOverflow)
    );
}
