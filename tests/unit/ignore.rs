use super::*;
use crate::test_support as support;
use support::TempDir;
#[test]
fn root_ignore_order_negation_and_pruned_parent_semantics() {
    use std::os::unix::ffi::OsStrExt;
    let root = Path::new("/repo");
    let policy = |bytes: &[u8]| {
        Exclusions::from_bytes(
            root,
            Some(bytes.to_vec()),
            PolicyUsage::default(),
            ACTIVE_POLICY,
        )
    };
    assert!(
        !Exclusions::load(Path::new("/nonexistent-rayloc-root"))
            .unwrap()
            .excludes(&root.join("file"))
    );
    let exclusions = policy(b"/top\n*.key\n!keep.key\nprivate/\n!private/keep\nfile*\n").unwrap();
    for (path, excluded) in [
        ("top", true),
        ("nested/top", false),
        ("a.key", true),
        ("keep.key", false),
        ("nested/a.key", true),
        ("private/keep", true),
        ("other", false),
    ] {
        assert_eq!(exclusions.excludes(&root.join(path)), excluded, "{path}");
    }
    // Patterns match raw path bytes, including names that are not UTF-8.
    assert!(exclusions.excludes(&root.join(std::ffi::OsStr::from_bytes(b"file\xff"))));
    assert!(policy(b"\xff").is_err());
    assert!(policy(b"[z-a]").is_err());
}
#[test]
fn ignore_pattern_and_aggregate_budgets_reject_resource_exhaustion() {
    for text in [
        "a".repeat(super::super::MAX_PATTERN_BYTES + 1),
        "a\n".repeat(1025),
    ] {
        let bytes = Some(text.into_bytes());
        let result = Exclusions::from_bytes(
            Path::new("/repo"),
            bytes,
            PolicyUsage::default(),
            ACTIVE_POLICY,
        );
        assert!(result.is_err());
    }
    // The aggregate byte cap is enforced while reading the policy file.
    let root = TempDir::new();
    std::fs::write(
        root.path().join(".raylocignore"),
        "a".repeat(256 * 1024 + 1),
    )
    .unwrap();
    assert!(Exclusions::load(root.path()).is_err());
}
#[test]
fn policy_usage_rejects_every_overflow_and_counts_empty_files() {
    let one = PolicyUsage {
        bytes: 1,
        lines: 1,
        patterns: 1,
        complexity: 1,
        files: 1,
    };
    for huge in [
        PolicyUsage {
            bytes: usize::MAX,
            ..one
        },
        PolicyUsage {
            lines: usize::MAX,
            ..one
        },
        PolicyUsage {
            patterns: usize::MAX,
            ..one
        },
        PolicyUsage {
            complexity: usize::MAX,
            ..one
        },
        PolicyUsage {
            files: usize::MAX,
            ..one
        },
    ] {
        assert!(huge.add(one).is_err());
    }
    assert!(
        Exclusions::from_bytes(
            Path::new("/repo"),
            Some(Vec::new()),
            PolicyUsage::default(),
            PolicyUsage {
                files: 0,
                ..ACTIVE_POLICY
            }
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn ignore_unreadable_nonregular_inputs_and_escaped_markers() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new();
    let path = temp.path().join(".raylocignore");
    std::fs::create_dir(&path).unwrap();
    assert!(Exclusions::load(temp.path()).is_err());
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
    let result = Exclusions::load(temp.path());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(result.is_err());
    let child = temp.path().join("denied");
    std::fs::create_dir(&child).unwrap();
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o0)).unwrap();
    let result = Exclusions::load(&child);
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
}
#[test]
fn cumulative_policy_overflow_is_checked_with_and_without_content() {
    let huge = PolicyUsage {
        files: usize::MAX,
        ..PolicyUsage::default()
    };
    for content in [b"".as_slice(), b"a"] {
        let bytes = Some(content.to_vec());
        assert!(Exclusions::from_bytes(Path::new("/repo"), bytes, huge, ACTIVE_POLICY).is_err());
    }
}
#[test]
fn escaped_comment_and_negation_markers_are_literal_patterns() {
    let root = Path::new("/repo");
    let bytes = Some(b"\\#literal\n\\!literal\n# comment\n \n".to_vec());
    let policy =
        Exclusions::from_bytes(root, bytes, PolicyUsage::default(), ACTIVE_POLICY).unwrap();
    assert!(policy.excludes(&root.join("#literal")));
    assert!(policy.excludes(&root.join("!literal")));
    assert!(!policy.excludes(&root.join("comment")));
}
