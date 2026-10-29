use std::io::Write;
use std::process::{Command, Stdio};
mod support;

/// Every test in this binary spawns shell/process trees that inflate the
/// live per-user task count while they are alive. The spawn-limit tests
/// sample that count and pin rlimits against it, so concurrent siblings
/// make their measurements drift. Serializing all process launches keeps
/// the sampled counts steady.
static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialize_process_spawns() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
fn command_mode_keeps_channels_separate_and_allows_passthrough() {
    let _spawn_guard = serialize_process_spawns();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let script = format!("printf '%s\\n' '{token}'; printf '%s\\n' '{token}' >&2");
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args(["redact", "--stderr=false", "--", "sh", "-c", &script])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"[REDACTED]\n");
    assert_eq!(output.stderr, format!("{token}\n").as_bytes());
}

#[test]
fn every_channel_switch_preserves_the_selected_destination() {
    let _spawn_guard = serialize_process_spawns();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    let script = format!("printf '%s\\n' '{token}'; printf '%s\\n' '{token}' >&2");
    for stdout in [false, true] {
        for stderr in [false, true] {
            let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
                .args([
                    "redact",
                    &format!("--stdout={stdout}"),
                    &format!("--stderr={stderr}"),
                    "--",
                    "sh",
                    "-c",
                    &script,
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(if stdout || stderr { 1 } else { 0 })
            );
            assert_eq!(
                output.stdout,
                if stdout {
                    "[REDACTED]\n".to_owned()
                } else {
                    format!("{token}\n")
                }
                .as_bytes()
            );
            assert_eq!(
                output.stderr,
                if stderr {
                    "[REDACTED]\n".to_owned()
                } else {
                    format!("{token}\n")
                }
                .as_bytes()
            );
        }
    }
}

#[test]
fn both_large_child_channels_are_drained() {
    let _spawn_guard = serialize_process_spawns();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.args([
        "redact",
        "--",
        "sh",
        "-c",
        "i=0; while [ $i -lt 40000 ]; do printf 'out\\n'; printf 'err\\n' >&2; i=$((i+1)); done",
    ]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"out\n".repeat(40000));
    assert_eq!(output.stderr, b"err\n".repeat(40000));
}

#[test]
fn an_idle_channel_does_not_stall_the_active_channel() {
    let _spawn_guard = serialize_process_spawns();
    for stderr_active in [false, true] {
        let script = if stderr_active {
            "i=0; while [ $i -lt 20000 ]; do printf 'err\\n' >&2; i=$((i+1)); done"
        } else {
            "i=0; while [ $i -lt 20000 ]; do printf 'out\\n'; i=$((i+1)); done"
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
        command.args(["redact", "--", "sh", "-c", script]);
        let output = output_with_deadline(command);
        assert_eq!(output.status.code(), Some(0));
        if stderr_active {
            assert_eq!(output.stdout, b"");
            assert_eq!(output.stderr, b"err\n".repeat(20000));
        } else {
            assert_eq!(output.stdout, b"out\n".repeat(20000));
            assert_eq!(output.stderr, b"");
        }
    }
}

#[test]
fn one_channel_early_eof_leaves_the_other_channel_complete() {
    let _spawn_guard = serialize_process_spawns();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.args([
        "redact",
        "--",
        "sh",
        "-c",
        "exec 1>&-; printf 'kept\\n' >&2; printf 'kept\\n' >&2",
    ]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, b"kept\nkept\n");
}

#[test]
fn private_key_state_is_confined_to_its_channel() {
    let _spawn_guard = serialize_process_spawns();
    let script = [
        "printf -- '-----BEGIN PRIVATE KEY-----\\n'", // rayloc:ignore
        "printf 'body-line\\n' >&2",
        "printf 'body\\n'",
        "printf -- '-----END PRIVATE KEY-----\\n'", // rayloc:ignore
    ]
    .join("; ");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.args(["redact", "--", "sh", "-c", &script]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"[REDACTED]\n[REDACTED]\n[REDACTED]\n");
    assert_eq!(output.stderr, b"body-line\n");
}

#[test]
fn oversized_child_record_stops_and_reaps_producer() {
    let _spawn_guard = serialize_process_spawns();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.args([
        "redact",
        "--",
        "python3",
        "-c",
        "import os,time; os.write(1,b'x'*1048577); time.sleep(30)",
    ]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn worker_failure_keeps_earlier_safe_output_and_reaps_the_child() {
    let _spawn_guard = serialize_process_spawns();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
    command.args([
        "redact",
        "--",
        "python3",
        "-c",
        "import os,time; os.write(1,b'clean\\n'+b'x'*1048577); time.sleep(30)",
    ]);
    let output = output_with_deadline(command);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"clean\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn nonzero_child_drains_output_and_exits_two() {
    let _spawn_guard = serialize_process_spawns();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args([
            "redact",
            "--",
            "sh",
            "-c",
            "printf 'out\\n'; printf 'err\\n' >&2; exit 7",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
}

#[test]
fn child_inherits_stdin_and_redacts_its_output() {
    let _spawn_guard = serialize_process_spawns();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args(["redact", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = ["ghp_", "SyntheticToken0123456789abcdef"].concat();
    writeln!(child.stdin.take().unwrap(), "{token}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"[REDACTED]\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn child_inherits_environment_and_working_directory() {
    let _spawn_guard = serialize_process_spawns();
    let dir = support::TempDir::new();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(dir.path())
        .env("RAILOC_CHILD_PROBE", "inherited")
        .args([
            "redact",
            "--",
            "sh",
            "-c",
            "printf '%s %s\\n' \"$RAILOC_CHILD_PROBE\" \"$(pwd)\"",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let expected = format!(
        "inherited {}\n",
        std::fs::canonicalize(dir.path()).unwrap().display()
    );
    assert_eq!(output.stdout, expected.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn arguments_after_the_delimiter_reach_the_child_verbatim() {
    let _spawn_guard = serialize_process_spawns();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args(["redact", "--", "echo", "--", "--help", "--stdout=false"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"-- --help --stdout=false\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn closed_downstream_pipe_fails_without_hanging_child() {
    let _spawn_guard = serialize_process_spawns();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args([
            "redact",
            "--",
            "python3",
            "-c",
            "import os,time; os.write(1,b'line\\n'*100000); time.sleep(30)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("closed output did not stop child");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(2));
}

#[test]
fn signal_termination_is_recorded_in_private_report() {
    let _spawn_guard = serialize_process_spawns();
    let before: std::collections::HashSet<_> = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .args(["redact", "--", "sh", "-c", "kill -TERM $$"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let suffix = format!("-{}-0.txt", child.id());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let path = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            !before.contains(p)
                && p.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with("rayloc-report-")
                        && name.to_string_lossy().ends_with(&suffix)
                })
        })
        .unwrap();
    let report = std::fs::read_to_string(&path).unwrap();
    assert!(report.contains("child=signal:15"));
    assert!(report.contains("error=child"));
    std::fs::remove_file(path).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn child_process_spawn_failure_is_a_silent_exit_two() {
    let _spawn_guard = serialize_process_spawns();
    let program = env!("CARGO_BIN_EXE_rayloc");
    let directory = support::TempDir::new();
    let missing_command = directory.path().join("missing-command");
    let before: std::collections::HashSet<_> = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let child = Command::new(program)
        .current_dir("/")
        .arg("redact")
        .arg("--")
        .arg(missing_command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let suffix = format!("-{}-0.txt", child.id());
    let output = child.wait_with_output().unwrap();
    let path = std::fs::read_dir("/tmp")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| {
            !before.contains(p)
                && p.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with("rayloc-report-")
                        && name.to_string_lossy().ends_with(&suffix)
                })
        })
        .unwrap();
    let report = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(report.contains("error=spawn"));
    assert!(report.contains("status=failed"));
}
