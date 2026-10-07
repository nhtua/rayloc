# Add Secret Patterns Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 73 new secret detection rules (47 prefix-based, 20 context-based, 6 URI-based) based on a study of publicly reported secret patterns and token formats.

**Architecture:** Each new rule follows the existing pattern in `builtin.rs`: a `RuleId` enum variant, a `&[&[u8]]` prefix constant, a `llm_key_match`-based matcher in the `match_at` loop, and metadata. Phase 2 adds field suffixes to `context.rs` `NameState::strong()`. Phase 3 adds 6 URI-based prefix matchers.

**Tech Stack:** Rust, `regex` crate, `rayon` (existing), no new dependencies.

**Spec:** `/tmp/opencode/secret-patterns-study-report.md`

## Global Constraints

- Extreme Speed: All new rules use byte-prefix scanning (`starts_with` + `take_while`), zero regex overhead for Phase 1/3.
- Zero Secret Leaks: Matches use the existing `RedactedString` wrapper pattern (inherited from `Candidate`/`emit` pipeline).
- Zero-Noise Filtering: Entropy check applies to all context-based rules; short prefixes get longer body minimums.
- Deterministic & Minimal Dependencies: No new dependencies added.
- Production coverage must be >= 95% lines/regions, 100% functions. Run `cargo coverage` after each major task.
- Every rule must have positive test fixtures in `tests/unit/builtin.rs` and negative fixtures.
