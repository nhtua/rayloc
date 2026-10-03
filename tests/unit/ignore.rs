use super::*;
use crate::test_support as support;
use support::TempDir;
#[test]
fn root_ignore_order_negation_and_pruned_parent_semantics() {
    let root = TempDir::new();
    assert!(
        !Exclusions::load(root.path())
            .unwrap()
            .excludes(&root.path().join("file"))
    );
    std::fs::write(
        root.path().join(".raylocignore"),
        "/top\n*.key\n!keep.key\nprivate/\n!private/keep\n",
    )
    .unwrap();
    let exclusions = Exclusions::load(root.path()).unwrap();
    for (path, excluded) in [
        ("top", true),
        ("nested/top", false),
        ("a.key", true),
        ("keep.key", false),
        ("nested/a.key", true),
        ("private/keep", true),
        ("file", false),
    ] {
        assert_eq!(
            exclusions.excludes(&root.path().join(path)),
            excluded,
            "{path}"
        );
    }
    std::fs::write(root.path().join(".raylocignore"), b"\xff").unwrap();
    assert!(Exclusions::load(root.path()).is_err());
    std::fs::write(root.path().join(".raylocignore"), "[z-a]").unwrap();
    assert!(Exclusions::load(root.path()).is_err());
}
#[test]
fn ignore_pattern_and_aggregate_budgets_reject_resource_exhaustion() {
    let root = TempDir::new();
    let path = root.path().join(".raylocignore");
    for text in [
        "a".repeat(super::super::MAX_PATTERN_BYTES + 1),
        "a\n".repeat(1025),
        "a".repeat(256 * 1024 + 1),
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(Exclusions::load(root.path()).is_err());
    }
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
    let temp = TempDir::new();
    std::fs::write(temp.path().join(".raylocignore"), "").unwrap();
    assert!(
        Exclusions::load_named(
            temp.path(),
            ".raylocignore",
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
    std::fs::write(&path, "\\#literal\n\\!literal\n# comment\n \n").unwrap();
    let policy = Exclusions::load(temp.path()).unwrap();
    assert!(policy.excludes(&temp.path().join("#literal")));
    assert!(policy.excludes(&temp.path().join("!literal")));
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
    let temp = TempDir::new();
    let path = temp.path().join(".raylocignore");
    let huge = PolicyUsage {
        files: usize::MAX,
        ..PolicyUsage::default()
    };
    for content in ["", "a"] {
        std::fs::write(&path, content).unwrap();
        assert!(Exclusions::load_named(temp.path(), ".raylocignore", huge, ACTIVE_POLICY).is_err());
    }
}
