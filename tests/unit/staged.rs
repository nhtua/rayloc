use super::*;
#[test]
fn object_ids_are_complete_and_safe() {
    for input in [
        b"abc".as_slice(),
        b"abc\n",
        b"0000000000000000000000000000000000000000\n",
        b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
    ] {
        assert!(oid(input.to_vec()).is_err());
    }
}
fn streams(path: &str, payload: &str) -> (Vec<u8>, Vec<u8>) {
    let old = "0".repeat(40);
    let new = "1".repeat(40);
    (format!(":000000 100644 {old} {new} A\0{path}\0").into_bytes(), format!("diff --git a/{path} b/{path}\nnew file mode 100644\nindex {old}..{new}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{payload}\n").into_bytes())
}
fn run_streams(
    mut raw: &[u8],
    mut patch: &[u8],
    ignored: &[u8],
    stats: super::super::ScanStats,
    empty: &str,
) -> ScanOutcome {
    let root = Path::new("/repo");
    let exclusions = Exclusions::from_bytes(
        root,
        Some(ignored.to_vec()),
        PolicyUsage::default(),
        ACTIVE_POLICY,
    )
    .unwrap();
    let mut outcome = ScanOutcome {
        stats,
        ..Default::default()
    };
    let collector = Mutex::new(Collector::new(MAX_FINDINGS));
    if let Err(error) = consume(
        &mut raw,
        &mut patch,
        root,
        empty,
        &crate::rules::BUILTINS,
        &exclusions,
        &mut outcome,
        &collector,
        None,
    ) {
        outcome.fail(error);
    }
    collector.into_inner().unwrap().finish(&mut outcome);
    outcome
}
const EMPTY: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
#[test]
fn stream_disagreement_truncation_duplicates_and_limits_fail_closed() {
    let (raw, patch) = streams("entry", concat!("AKIA0123", "456789AB", "CDEF"));
    assert_eq!(
        run_streams(&raw, &patch, b"", Default::default(), EMPTY).exit_code(),
        1
    );
    for (r, p) in [
        (raw[..raw.len() - 1].to_vec(), patch.clone()),
        (raw[..raw.len() - 6].to_vec(), patch.clone()),
        (b"bad\0entry\0".to_vec(), patch.clone()),
        (
            [raw.clone(), raw.clone()].concat(),
            [patch.clone(), patch.clone()].concat(),
        ),
        (raw.clone(), b"no newline".to_vec()),
        (b"unterminated".to_vec(), patch.clone()),
        (raw.clone(), patch[..patch.len() - 1].to_vec()),
    ] {
        assert_eq!(
            run_streams(&r, &p, b"", Default::default(), EMPTY).exit_code(),
            2
        );
    }
    assert_eq!(
        run_streams(&raw, &patch, b"", Default::default(), &"z".repeat(40)).exit_code(),
        2
    );
    let (raw, patch) = streams("entry", &format!("ghp_{}", "a".repeat(65537)));
    assert_eq!(
        run_streams(&raw, &patch, b"", Default::default(), EMPTY).exit_code(),
        2
    );
    let (raw, patch) = streams(".git/entry", concat!("AKIA0123", "456789AB", "CDEF"));
    let out = run_streams(&raw, &patch, b"", Default::default(), EMPTY);
    assert_eq!(out.exit_code(), 0);
    assert_eq!(out.stats.files_excluded, 1);
}
#[test]
fn all_staged_counter_overflows_keep_error_precedence() {
    use super::super::ScanStats;
    let (raw, patch) = streams("entry", concat!("AKIA0123", "456789AB", "CDEF"));
    for stats in [
        ScanStats {
            files_excluded: u64::MAX,
            ..Default::default()
        },
        ScanStats {
            files_attempted: u64::MAX,
            ..Default::default()
        },
        ScanStats {
            files_completed: u64::MAX,
            ..Default::default()
        },
        ScanStats {
            bytes_read: u64::MAX,
            ..Default::default()
        },
        ScanStats {
            lines_scanned: u64::MAX,
            ..Default::default()
        },
        ScanStats {
            findings_detected: u64::MAX,
            ..Default::default()
        },
    ] {
        let ignored = if stats.files_excluded != 0 {
            b"entry".as_slice()
        } else {
            b""
        };
        assert_eq!(
            run_streams(&raw, &patch, ignored, stats, EMPTY).exit_code(),
            2
        );
    }
}
#[test]
fn index_stat_missing_and_invalid_parent_are_distinguished() {
    let dir = crate::test_support::TempDir::new();
    assert!(index_stamp(&dir.path().join("missing")).unwrap().is_none());
    fs::write(dir.path().join("file"), "x").unwrap();
    assert!(index_stamp(&dir.path().join("file/child")).is_err());
}
#[test]
fn head_resolves_symbolic_and_detached_states() {
    let dir = crate::test_support::TempDir::new();
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "--quiet"])
            .status()
            .unwrap()
            .success()
    );
    let root = dir.path();
    let symbolic = head(root).unwrap();
    assert_eq!(symbolic.symbolic, b"refs/heads/master\n");
    assert!(symbolic.commit.is_none());
    fs::write(root.join("entry"), "fixture").unwrap();
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "base"
            ])
            .status()
            .unwrap()
            .success()
    );
    let attached = head(root).unwrap();
    assert_eq!(attached.symbolic, b"refs/heads/master\n");
    assert!(attached.commit.is_some());
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["checkout", "--detach", "HEAD"])
            .status()
            .unwrap()
            .success()
    );
    let detached = head(root).unwrap();
    assert!(detached.symbolic.is_empty());
    assert!(detached.commit.is_some());
    assert!(head(&dir.path().join("missing")).is_err());
}
#[test]
fn quoted_non_utf8_paths_and_nul_payloads_are_scanned_from_streams() {
    let (old, new) = ("0".repeat(40), "1".repeat(40));
    let secret = concat!("AKIA0123", "456789AB", "CDEF");
    let mut raw = format!(":000000 100644 {old} {new} A\0").into_bytes();
    raw.extend_from_slice(b"quotes\"\\\t\n\xff\0");
    let quoted = r#""a/quotes\"\\\t\n\377" "b/quotes\"\\\t\n\377""#;
    let target = r#""b/quotes\"\\\t\n\377""#;
    let patch = format!(
        "diff --git {quoted}\nnew file mode 100644\nindex {old}..{new}\n--- /dev/null\n+++ {target}\n@@ -0,0 +1 @@\n+zero\0 {secret}\n"
    );
    let outcome = run_streams(&raw, patch.as_bytes(), b"", Default::default(), EMPTY);
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(outcome.stats.findings_detected, 1);
}
#[test]
fn resolved_worktree_consumer_scans_quoted_non_utf8_paths() {
    let (old, new) = ("2".repeat(40), "1".repeat(40));
    let mut raw = format!(":100644 100644 {old} {new} M\0").into_bytes();
    raw.extend_from_slice(b"private\xff name\0");
    let name = r#""a/private\377 name""#;
    let target = r#""b/private\377 name""#;
    let patch = format!(
        "diff --git {name} {target}\nindex {old}..{new} 100644\n--- {name}\t\n+++ {target}\t\n@@ -1,0 +2 @@\n+{}\n",
        concat!("AKIA0123", "456789AB", "CDEF")
    );
    let root = Path::new("/repo");
    let exclusions =
        Exclusions::from_bytes(root, None, PolicyUsage::default(), ACTIVE_POLICY).unwrap();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(MAX_FINDINGS));
    consume_resolved(
        &mut raw.as_slice(),
        &mut patch.as_bytes(),
        root,
        EMPTY,
        &crate::rules::BUILTINS,
        &exclusions,
        &mut outcome,
        &collector,
        None,
        true,
    )
    .unwrap();
    collector.into_inner().unwrap().finish(&mut outcome);
    assert_eq!(outcome.stats.findings_detected, 1);
}
#[test]
fn source_ids_fail_without_wrapping_or_reusing_an_identifier() {
    let mut source = u32::MAX - 1;
    next_source(&mut source).unwrap();
    assert_eq!(source, u32::MAX);
    assert_eq!(next_source(&mut source), Err(ScanError::CounterOverflow));
    assert_eq!(source, u32::MAX);
}
#[test]
fn scan_staged_wrapper_delegates_to_emitter_variant() {
    let dir = crate::test_support::TempDir::new();
    let outcome = scan_staged(dir.path(), None, false);
    assert_eq!(outcome.exit_code(), 2);
}
#[test]
fn resolved_worktree_consumer_validates_and_excludes_dirty_gitlink() {
    let oid = "a".repeat(40);
    let raw = format!(":160000 160000 {oid} {oid} M\0sub\0");
    let patch = format!(
        "diff --git a/sub b/sub\n--- a/sub\n+++ b/sub\n@@ -1 +1 @@\n-Subproject commit {oid}\n+Subproject commit {oid}-dirty\n"
    );
    let root = Path::new("/repo");
    let exclusions =
        Exclusions::from_bytes(root, None, PolicyUsage::default(), ACTIVE_POLICY).unwrap();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(MAX_FINDINGS));
    consume_resolved(
        &mut raw.as_bytes(),
        &mut patch.as_bytes(),
        root,
        EMPTY,
        &crate::rules::BUILTINS,
        &exclusions,
        &mut outcome,
        &collector,
        None,
        true,
    )
    .unwrap();
    assert_eq!(outcome.stats.files_excluded, 1);
    assert_eq!(outcome.stats.lines_scanned, 0);
    assert!(
        consume_resolved(
            &mut b"bad\0entry\0".as_slice(),
            &mut patch.as_bytes(),
            root,
            EMPTY,
            &crate::rules::BUILTINS,
            &exclusions,
            &mut outcome,
            &collector,
            None,
            true
        )
        .is_err()
    );
}
