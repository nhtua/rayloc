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
