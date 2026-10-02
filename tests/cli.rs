use std::process::Command;

#[test]
fn executable_entry_point_obeys_help_version_and_error_contracts() {
    for arguments in [
        vec![],
        vec!["--help"],
        vec!["-h"],
        vec!["--version"],
        vec!["-V"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let sentinel = "ghp_SyntheticCliSentinel0123456789";
    for arguments in [
        vec!["scan", sentinel],
        vec!["hook", "install"],
        vec![sentinel],
        vec!["--help", sentinel],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8(output.stderr).unwrap().contains(sentinel));
    }
}
#[path = "support/mod.rs"]
mod support;
#[test]
fn ci_can_disable_inline_ignores_without_leaking_passwords() {
    let directory = support::TempDir::new();
    let path = directory.path().join("source");
    std::fs::write(&path, b"password='aaaaaaaa' # rayloc:ignore\n").unwrap();
    for (arguments, expected) in [(vec!["scan"], 0), (vec!["scan", "--no-inline-ignores"], 1)] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(arguments)
            .arg(&path)
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("aaaaaaaa")
        );
        assert!(output.stderr.is_empty());
    }
}
