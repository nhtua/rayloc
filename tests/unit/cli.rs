use super::*;

#[test]
fn help_and_version_are_successful_and_extra_arguments_are_errors() {
    for args in [
        vec![],
        vec!["-h"],
        vec!["--help"],
        vec!["-V"],
        vec!["--version"],
    ] {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        assert_eq!(
            run_with_args(
                args.into_iter().map(OsString::from),
                &mut output,
                &mut errors
            ),
            0
        );
        assert!(!output.is_empty());
        assert!(errors.is_empty());
    }
    for command in [
        "-h",
        "--help",
        "-V",
        "--version",
        "scan",
        "hook",
        "unrecognized",
    ] {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let sentinel = "ghp_SyntheticArgumentSecret0123456789";
        assert_eq!(
            run_with_args(
                [command, sentinel].map(OsString::from),
                &mut output,
                &mut errors
            ),
            2
        );
        assert!(output.is_empty());
        assert!(!String::from_utf8(errors).unwrap().contains(sentinel));
    }
}

#[test]
fn unsupported_and_invalid_utf8_arguments_are_never_echoed() {
    for command in ["hook", "unknown-sensitive-input"] {
        let mut output = Vec::new();
        let mut errors = Vec::new();
        assert_eq!(
            run_with_args([OsString::from(command)], &mut output, &mut errors),
            2
        );
        assert!(
            !String::from_utf8(errors)
                .unwrap()
                .contains("unknown-sensitive-input")
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut errors = Vec::new();
        let argument = OsString::from_vec(b"\xffsecret-argument".to_vec());
        assert_eq!(run_with_args([argument], &mut Vec::new(), &mut errors), 2);
        assert!(
            !String::from_utf8(errors)
                .unwrap()
                .contains("secret-argument")
        );
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive-writer-diagnostic"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failures_return_safe_execution_errors() {
    for args in [vec![], vec!["--help"], vec!["--version"]] {
        let mut errors = Vec::new();
        assert_eq!(
            run_with_args(
                args.into_iter().map(OsString::from),
                &mut FailingWriter,
                &mut errors
            ),
            2
        );
        assert_eq!(errors, b"rayloc: cannot write command output\n");
    }
    assert_eq!(print_help(&mut FailingWriter, &mut FailingWriter), 2);
    assert_eq!(
        run_with_args(
            [OsString::from("scan"), OsString::from("--invalid")],
            &mut Vec::new(),
            &mut FailingWriter
        ),
        2
    );
}
#[test]
fn explicit_target_conflicts_symlinks_and_report_failure_are_safe() {
    let root = crate::test_support::TempDir::new();
    let file = root.path().join("file");
    std::fs::write(&file, "clean").unwrap();
    for options in [
        vec!["--config"],
        vec!["--config", "one", "--config", "two"],
        vec!["--staged", "--staged"],
        vec!["--diff", "HEAD", "--staged"],
        vec!["--glob"],
        vec!["first", "second"],
        vec!["--help", "file"],
    ] {
        let args =
            std::iter::once(OsString::from("scan")).chain(options.into_iter().map(OsString::from));
        assert_eq!(run_with_args(args, &mut Vec::new(), &mut Vec::new()), 2);
    }
    for help in ["--help", "-h"] {
        assert_eq!(
            run_with_args(
                ["scan", help].map(OsString::from),
                &mut Vec::new(),
                &mut Vec::new()
            ),
            0
        );
    }
    for selected in [root.path().join("missing"), {
        #[cfg(unix)]
        {
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            link
        }
        #[cfg(not(unix))]
        {
            root.path().to_path_buf()
        }
    }] {
        assert_eq!(
            run_with_args(
                [OsString::from("scan"), selected.into_os_string()],
                &mut Vec::new(),
                &mut Vec::new()
            ),
            2
        );
    }
    let args = [
        OsString::from("scan"),
        OsString::from("--"),
        file.as_os_str().into(),
    ];
    assert_eq!(
        run_with_args(args.clone(), &mut Vec::new(), &mut Vec::new()),
        0
    );
    let mut errors = Vec::new();
    assert_eq!(run_with_args(args, &mut FailingWriter, &mut errors), 2);
    assert_eq!(errors, b"rayloc: cannot write command output\n");
    std::fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\nrules: [{id: custom, regex: 'a*'}]",
    )
    .unwrap();
    assert_eq!(
        run_with_args(
            [OsString::from("scan"), file.into_os_string()],
            &mut Vec::new(),
            &mut Vec::new()
        ),
        2
    );
}
#[cfg(unix)]
#[test]
fn invalid_utf8_glob_is_rejected_without_echoing() {
    use std::os::unix::ffi::OsStringExt;
    let mut errors = Vec::new();
    assert_eq!(
        run_with_args(
            [
                OsString::from("scan"),
                OsString::from("--glob"),
                OsString::from_vec(b"\xffprivate".to_vec())
            ],
            &mut Vec::new(),
            &mut errors
        ),
        2
    );
    assert!(!String::from_utf8(errors).unwrap().contains("private"));
}
#[test]
fn staged_report_write_failure_is_safe() {
    let mut errors = Vec::new();
    assert_eq!(
        run_with_args(
            ["scan", "--staged"].map(OsString::from),
            &mut FailingWriter,
            &mut errors
        ),
        2
    );
    assert_eq!(errors, b"rayloc: cannot write command output\n");
}
