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
    for command in ["scan", "hook", "unknown-sensitive-input"] {
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
            [OsString::from("scan")],
            &mut Vec::new(),
            &mut FailingWriter
        ),
        2
    );
}
