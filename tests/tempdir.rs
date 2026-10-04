mod support;
#[test]
fn temporary_directory_creation_preserves_an_existing_other_runner_directory() {
    let occupied = std::env::temp_dir().join(format!(
        "rayloc-test-{}-tempdir-support-0",
        std::process::id()
    ));
    std::fs::create_dir_all(&occupied).unwrap();
    std::fs::write(occupied.join("sentinel"), b"keep").unwrap();
    let directory = support::TempDir::new();
    assert_ne!(directory.path(), occupied);
    assert_eq!(std::fs::read(occupied.join("sentinel")).unwrap(), b"keep");
    std::fs::remove_dir_all(occupied).unwrap();
}
