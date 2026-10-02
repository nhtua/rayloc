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
