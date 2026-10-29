use super::*;
use crate::redact::Summary;

#[test]
fn rejects_conflicting_and_incomplete_arguments() {
    for args in [
        vec!["--"],
        vec!["--config"],
        vec!["--config", "one", "--config", "two"],
        vec!["--stdout=false"],
        vec!["--stderr=invalid", "--", "cmd"],
        vec!["--stdout=invalid", "--", "cmd"],
        vec!["--stdout=true", "--stdout=false", "--", "cmd"],
        vec!["--stderr=true", "--stderr=false", "--", "cmd"],
        vec!["file", "other"],
        vec!["file", "--", "cmd"],
        vec!["--unknown"],
    ] {
        assert!(parse(args.into_iter().map(OsString::from).collect()).is_err());
    }
}

#[test]
fn parser_preserves_child_arguments_and_boolean_options() {
    let (input, config) = parse(
        [
            "--config",
            "policy",
            "--stdout=false",
            "--stderr=true",
            "--",
            "app",
            "--",
            "argument",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
    )
    .unwrap();
    assert_eq!(config, Some(PathBuf::from("policy")));
    match input {
        Input::Command(program, args, stdout, stderr) => {
            assert_eq!(program, "app");
            assert_eq!(args, ["--", "argument"]);
            assert!(!stdout && stderr);
        }
        _ => panic!("unexpected input mode"),
    }
}

#[test]
fn parser_accepts_paths_and_options_in_either_order() {
    let cases = [
        (
            vec!["--config", "policy", "input.txt"],
            "input.txt",
            Some("policy"),
        ),
        (
            vec!["input.txt", "--config", "policy"],
            "input.txt",
            Some("policy"),
        ),
        (vec!["./-name"], "./-name", None),
    ];
    for (args, path, config) in cases {
        let (input, found) = parse(args.into_iter().map(OsString::from).collect()).unwrap();
        match input {
            Input::File(file) => assert_eq!(file, PathBuf::from(path)),
            _ => panic!("expected file mode"),
        }
        assert_eq!(found, config.map(PathBuf::from));
    }
}

#[test]
fn invalid_and_missing_input_fail_without_child() {
    for args in [
        vec!["--unknown"],
        vec!["--config", "missing-policy-file"],
        vec!["missing-input-file"],
        vec!["."],
        vec!["--", "missing-rayloc-program"],
    ] {
        let mut summary = Summary::default();
        assert!(execute(args.into_iter().map(OsString::from).collect(), &mut summary).is_err());
        assert!(summary.error.is_some());
    }
}

#[test]
fn file_inputs_classify_open_and_regular_file_failures() {
    use std::os::unix::fs::PermissionsExt;
    let directory = crate::test_support::TempDir::new();

    let mut summary = Summary::default();
    assert!(
        execute(
            vec![directory.path().to_path_buf().into_os_string()],
            &mut summary
        )
        .is_err()
    );
    assert_eq!(summary.error, Some("not-regular-file"));

    let mut summary = Summary::default();
    assert!(
        execute(
            vec![directory.path().join("missing").into_os_string()],
            &mut summary
        )
        .is_err()
    );
    assert_eq!(summary.error, Some("open"));

    let path = directory.path().join("unreadable");
    std::fs::write(&path, b"clean\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .unwrap()
        .stdout;
    if uid.trim_ascii() != b"0" {
        let mut summary = Summary::default();
        assert!(execute(vec![path.into_os_string()], &mut summary).is_err());
        assert_eq!(summary.error, Some("open"));
    }
}

#[test]
fn fifo_input_is_rejected_as_nonregular() {
    let directory = crate::test_support::TempDir::new();
    let path = directory.path().join("fifo");
    std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert_eq!(
        open_regular(&path).unwrap_err().kind(),
        io::ErrorKind::InvalidInput,
        "reject a FIFO before opening it"
    );
    let mut summary = Summary::default();
    assert!(execute(vec![path.into_os_string()], &mut summary).is_err());
    assert_eq!(summary.error, Some("not-regular-file"));
}

#[test]
fn regular_file_validation_checks_before_and_after_open() {
    let directory = crate::test_support::TempDir::new();
    let path = directory.path().join("input");
    std::fs::write(&path, b"").unwrap();
    assert!(open_regular(&path).unwrap().metadata().unwrap().is_file());

    let missing = directory.path().join("missing");
    assert_eq!(
        open_regular(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}
