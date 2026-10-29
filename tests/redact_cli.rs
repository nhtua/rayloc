use std::io::Write;
use std::process::{Command, Stdio};
mod support;

fn output_with_deadline(mut command: Command) -> std::process::Output {
    let dir = support::TempDir::new();
    let stdout_path = dir.path().join("stdout");
    let stderr_path = dir.path().join("stderr");
    let mut child = command
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("redaction command timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    std::process::Output {
        status,
        stdout: std::fs::read(stdout_path).unwrap(),
        stderr: std::fs::read(stderr_path).unwrap(),
    }
}

#[test]
fn stdin_redacts_secrets_without_changing_other_bytes() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    write!(child.stdin.take().unwrap(), "before {token} after\r\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"before [REDACTED] after\r\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn completed_lines_flush_before_eof_but_partial_tokens_wait() {
    use std::io::Read;
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut first = [0; 6];
        stdout.read_exact(&mut first).unwrap();
        sender.send(first.to_vec()).unwrap();
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap();
        sender.send(rest).unwrap();
    });
    stdin.write_all(b"clean\n").unwrap();
    let first = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("first line did not flush");
        });
    assert_eq!(first, b"clean\n");
    stdin
        .write_all(b"ghp_SyntheticToken0123456789abcdef") // rayloc:ignore
        .unwrap();
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
    drop(stdin);
    let rest = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("final line did not flush");
        });
    assert_eq!(rest, b"[REDACTED]");
    assert_eq!(child.wait().unwrap().code(), Some(1));
    reader.join().unwrap();
}

#[test]
fn file_input_matches_stdin_and_does_not_modify_file() {
    let dir = support::TempDir::new();
    let path = dir.path().join("input file.txt");
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let data = format!("prefix {token}\r\nlast");
    std::fs::write(&path, &data).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "input file.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"prefix [REDACTED]\r\nlast");
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read(path).unwrap(), data.as_bytes());
}

#[test]
fn unfinished_private_key_is_hidden_and_reported_as_error() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"-----BEGIN PRIVATE KEY-----\nprivate-body\n") // rayloc:ignore
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"[REDACTED]\n[REDACTED]\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn report_records_counts_without_leaking_input() {
    use std::os::unix::fs::PermissionsExt;
    let before: std::collections::HashSet<_> = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    writeln!(child.stdin.take().unwrap(), "key={token}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let suffix = format!("-{pid}-0.txt");
    let path = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            !before.contains(p)
                && p.file_name().is_some_and(|n| {
                    n.to_string_lossy().starts_with("rayloc-report-")
                        && n.to_string_lossy().ends_with(&suffix)
                })
        })
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let report = std::fs::read_to_string(&path).unwrap();
    assert!(report.contains("mode=stdio"));
    assert!(report.contains("source=stdin state=filtered"));
    assert!(report.contains("redactions=1"));
    assert!(!report.contains(&token));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn merged_stderr_pipe_stays_on_stdout() {
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let rayloc = env!("CARGO_BIN_EXE_rayloc");
    let inner = format!("printf 'out %s\\n' '{token}'; printf 'err %s\\n' '{token}' >&2");
    let script = format!("sh -c \"{inner}\" 2>&1 | '{rayloc}' redact");
    let mut command = Command::new("bash");
    command.args(["-c", &script]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"out [REDACTED]\nerr [REDACTED]\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn file_mode_never_consumes_stdin() {
    let dir = support::TempDir::new();
    std::fs::write(dir.path().join("input"), b"file-line\n").unwrap();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "input"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for _ in 0..1000 {
            if let Err(error) = writeln!(stdin, "{token}") {
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                break;
            }
        }
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"file-line\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn unreadable_file_reports_only_in_the_private_report() {
    use std::os::unix::fs::PermissionsExt;
    let uid = Command::new("id").arg("-u").output().unwrap().stdout;
    if uid.trim_ascii() == b"0" {
        // Privileged runners bypass file modes; the injected-open unit tests
        // cover this branch there instead.
        return;
    }
    let dir = support::TempDir::new();
    let path = dir.path().join("secret-input");
    std::fs::write(&path, b"clean\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.current_dir(dir.path()).arg("redact").arg(&path);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn redact_help_is_explicit_and_clean() {
    for option in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(["redact", option])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("Usage: rayloc redact")
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn bad_arguments_and_nonregular_paths_are_silent() {
    for args in [
        vec!["redact", "--bad"],
        vec!["redact", "--stdout=false"],
        vec!["redact", "--"],
        vec!["redact", "."],
        vec!["redact", "--", "rayloc-no-such-command"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn inline_ignore_does_not_disable_stream_redaction() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    writeln!(child.stdin.take().unwrap(), "{token} # rayloc:ignore").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"[REDACTED] # rayloc:ignore\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn large_file_redacts_more_than_ten_thousand_occurrences() {
    use std::io::{BufReader, BufWriter, Read};
    let dir = support::TempDir::new();
    let path = dir.path().join("large.txt");
    let result_path = dir.path().join("result.txt");
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let prefix = "x".repeat(80);
    let line = format!("{prefix} {token}\n");
    let expected = format!("{prefix} [REDACTED]\n");
    let count = 100_000;
    {
        let mut writer = BufWriter::new(std::fs::File::create(&path).unwrap());
        for _ in 0..count {
            writer.write_all(line.as_bytes()).unwrap();
        }
    }
    assert!(std::fs::metadata(&path).unwrap().len() > 10 * 1024 * 1024);
    let status = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "large.txt"])
        .stdout(std::fs::File::create(&result_path).unwrap())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
    let mut result = BufReader::new(std::fs::File::open(&result_path).unwrap());
    let mut actual = vec![0; expected.len()];
    for _ in 0..count {
        result.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected.as_bytes());
    }
    assert_eq!(result.read(&mut actual).unwrap(), 0);
    let stdin_result_path = dir.path().join("stdin-result.txt");
    let status = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .arg("redact")
        .stdin(std::fs::File::open(&path).unwrap())
        .stdout(std::fs::File::create(&stdin_result_path).unwrap())
        .stderr(Stdio::piped())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
    assert_eq!(
        std::fs::read(&stdin_result_path).unwrap(),
        std::fs::read(&result_path).unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bash_process_substitution_preserves_both_destinations() {
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let script = r#"
exec 3> >("$1" redact); out_pid=$!
exec 4> >("$1" redact >&2); err_pid=$!
printf 'out %s\n' "$2" >&3
printf 'err %s\n' "$2" >&4
exec 3>&- 4>&-
wait "$out_pid"; out_status=$?
wait "$err_pid"; err_status=$?
[ "$out_status" -eq 1 ] && [ "$err_status" -eq 1 ]
"#;
    let mut command = Command::new("bash");
    command.args(["-c", script, "test", env!("CARGO_BIN_EXE_rayloc"), &token]);
    let output = output_with_deadline(command);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"out [REDACTED]\n");
    assert_eq!(output.stderr, b"err [REDACTED]\n");
}

#[test]
fn explicit_policy_changes_detection_for_file_and_stdin() {
    let dir = support::TempDir::new();
    std::fs::write(
        dir.path().join("policy.yaml"),
        "version: '1'\nrules:\n  - id: internal\n    regex: 'corp_[A-Z]{8}'\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("input"), "data corp_ABCDEFGH\n").unwrap();
    let file = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "--config", "policy.yaml", "input"])
        .output()
        .unwrap();
    assert_eq!(file.status.code(), Some(1));
    assert_eq!(file.stdout, b"data [REDACTED]\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "--config", "policy.yaml"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"data corp_ABCDEFGH\n")
        .unwrap();
    let stdin = child.wait_with_output().unwrap();
    assert_eq!(stdin.status.code(), file.status.code());
    assert_eq!(stdin.stdout, file.stdout);
    assert!(stdin.stderr.is_empty());
}

#[test]
fn existing_file_scan_handles_anchored_custom_rule_on_long_record() {
    let dir = support::TempDir::new();
    std::fs::write(
        dir.path().join(".rayloc.yaml"),
        "version: '1'\nrules: [{id: anchored, regex: '^.*(corp_[A-Z]{8})', secret_group: 1}]\n",
    )
    .unwrap();
    let mut content = vec![b' '; 256 * 1024 + 10];
    content.extend_from_slice(b"corp_ABCDEFGH\n");
    std::fs::write(dir.path().join("input"), content).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["scan", "input", "--silent"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !output
            .stdout
            .windows(b"corp_ABCDEFGH".len())
            .any(|span| span == b"corp_ABCDEFGH")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn file_mode_accepts_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let dir = support::TempDir::new();
    let name = std::ffi::OsString::from_vec(b"raw-\xff.txt".to_vec());
    std::fs::write(dir.path().join(&name), b"clean\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .arg("redact")
        .arg(name)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"clean\n");
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn file_mode_follows_regular_symlink_and_rejects_fifo() {
    use std::os::unix::fs::symlink;
    let dir = support::TempDir::new();
    std::fs::write(dir.path().join("source"), b"clean\n").unwrap();
    symlink("source", dir.path().join("link")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .args(["redact", "link"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"clean\n");
    assert!(output.stderr.is_empty());
    assert!(
        Command::new("mkfifo")
            .arg(dir.path().join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.current_dir(dir.path()).args(["redact", "pipe"]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn parse_policy_and_filter_failures_are_silent_in_subprocesses() {
    let dir = support::TempDir::new();
    std::fs::write(dir.path().join("input"), b"clean\n").unwrap();
    for args in [
        vec!["redact", "input", "--", "cmd"],
        vec!["redact", "--config", "a", "--config", "b", "--", "cmd"],
        vec!["redact", "--stdout=true", "--stdout=false", "--", "cmd"],
        vec!["redact", "--stdout=bad", "--", "cmd"],
        vec!["redact", "--stderr=true", "--stderr=false", "--", "cmd"],
        vec!["redact", "--stderr=bad", "--", "cmd"],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
        command
            .current_dir(dir.path())
            .args(args)
            .stdin(Stdio::null());
        let output = output_with_deadline(command);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }

    std::fs::write(dir.path().join(".rayloc.yaml"), "rules: [").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command
        .current_dir(dir.path())
        .arg("redact")
        .stdin(Stdio::null());
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());

    std::fs::write(
        dir.path().join(".rayloc.yaml"),
        "version: \"1\"\nrules:\n  - id: broken\n    regex: \"(\"\n",
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command
        .current_dir(dir.path())
        .arg("redact")
        .stdin(Stdio::null());
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());

    std::fs::remove_file(dir.path().join(".rayloc.yaml")).unwrap();
    #[cfg(target_os = "linux")]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .current_dir(dir.path())
            .args(["redact", "input"])
            .stdin(Stdio::null())
            .stdout(std::fs::File::create("/dev/full").unwrap())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
    }

    let fifo_dir = support::TempDir::new();
    assert!(
        Command::new("mkfifo")
            .arg(fifo_dir.path().join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command
        .current_dir(fifo_dir.path())
        .args(["redact", "pipe"])
        .stdin(Stdio::null());
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
