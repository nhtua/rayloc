mod support;
use std::{
    fs,
    process::{Command, Output},
};
use support::TempDir;
fn run(root: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path())
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap()
}
#[test]
fn explicit_file_detects_builtin_and_custom_without_metadata_leaks() {
    let root = TempDir::new();
    fs::write(
        root.path().join("input"),
        "clean\ncorp_abcdefghijklmnop\nghp_abcdefghijklmnop\n",
    )
    .unwrap();
    fs::write(root.path().join(".rayloc.yaml"), "version: \"1\"\nrules:\n  - id: sensitive-rule-id\n    description: sensitive-description\n    regex: 'corp_([a-z]+)'\n    secret_group: 1\n    severity: Critical\n").unwrap();
    let output = run(&root, &["scan", "input"]);
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("2 finding(s)"));
    assert!(text.contains("Critical"));
    for private in [
        "abcdefghijklmnop",
        "sensitive-rule-id",
        "sensitive-description",
        "input",
    ] {
        assert!(!text.contains(private));
    }
    assert!(output.stderr.is_empty());
}
#[test]
fn clean_excluded_and_config_failure_have_correct_exits() {
    let root = TempDir::new();
    fs::write(root.path().join("input"), "ordinary text\n").unwrap();
    assert_eq!(run(&root, &["scan", "input"]).status.code(), Some(0));
    fs::write(root.path().join("input"), "ghp_abcdefghijklmnop\n").unwrap();
    fs::write(root.path().join(".raylocignore"), "input\n").unwrap();
    let excluded = run(&root, &["scan", "input"]);
    assert_eq!(excluded.status.code(), Some(0));
    assert!(
        String::from_utf8(excluded.stdout)
            .unwrap()
            .contains("EXCLUDED")
    );
    fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\nunknown: sensitive-diagnostic\n",
    )
    .unwrap();
    let invalid = run(&root, &["scan", "input"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(
        !String::from_utf8(invalid.stderr)
            .unwrap()
            .contains("sensitive-diagnostic")
    );
}
#[test]
fn merge_capture_entropy_and_disabled_rules_apply() {
    let root = TempDir::new();
    fs::write(
        root.path().join("input"),
        "prefixABCDEFGHIJKLMNOP=aaaa\nghp_abcdefghijklmnop\nnew_0123456789abcdef\n",
    )
    .unwrap();
    fs::write(root.path().join(".rayloc.yaml"), "version: \"1\"\nrules:\n - id: base\n   regex: 'prefix[A-Z]+=(.*)'\n   secret_group: 1\n   entropy: 1.0\n").unwrap();
    fs::write(root.path().join("extra"), "version: \"1\"\ndisabled_rules: [github-token]\nrules:\n - id: appended\n   regex: 'new_([a-f0-9]+)'\n   secret_group: 1\n   entropy: 3.0\n").unwrap();
    let output = run(&root, &["scan", "input", "--config", "extra"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 finding(s)")
    );
}
#[cfg(unix)]
#[test]
fn nonregular_policy_sources_fail_without_waiting_for_data() {
    use std::{
        thread,
        time::{Duration, Instant},
    };
    let root = TempDir::new();
    fs::write(root.path().join("input"), "clean").unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(root.path().join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path())
        .args(["scan", "input", "--config", "pipe"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > Duration::from_millis(500) {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.and_then(|s| s.code()), Some(2));
}
#[test]
fn git_root_policy_overrides_nested_policy_and_gitignore_does_not_hide_explicit_files() {
    let root = TempDir::new();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(root.path())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .unwrap()
            .success()
    );
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(root.path().join("nested/input"), "ghp_abcdefghijklmnop").unwrap();
    fs::write(root.path().join(".gitignore"), "nested/\n").unwrap();
    fs::write(root.path().join("nested/.rayloc.yaml"), "invalid syntax").unwrap();
    fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\ndisabled_rules: [github-token]",
    )
    .unwrap();
    assert_eq!(run(&root, &["scan", "nested/input"]).status.code(), Some(0));
    fs::write(root.path().join(".rayloc.yaml"), "version: \"1\"").unwrap();
    assert_eq!(run(&root, &["scan", "nested/input"]).status.code(), Some(1));
    fs::write(root.path().join(".git/synthetic"), "ghp_abcdefghijklmnop").unwrap();
    let excluded = run(&root, &["scan", ".git/synthetic"]);
    assert_eq!(excluded.status.code(), Some(0));
    assert!(
        String::from_utf8(excluded.stdout)
            .unwrap()
            .contains("EXCLUDED")
    );
}
#[cfg(unix)]
#[test]
fn native_files_and_non_git_symlink_parents_keep_policy() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new();
    let filename = "file-name";
    fs::write(root.path().join(filename), "ghp_abcdefghijklmnop").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path())
        .arg("scan")
        .arg(filename)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let alias = TempDir::new();
    symlink(root.path(), alias.path().join("linked")).unwrap();
    fs::write(root.path().join(".raylocignore"), "file*\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .arg("scan")
        .arg(alias.path().join("linked").join(filename))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
}
#[cfg(unix)]
#[test]
fn oversized_git_discovery_is_an_error_and_child_stderr_is_private() {
    use std::{
        os::unix::fs::PermissionsExt,
        thread,
        time::{Duration, Instant},
    };
    let root = TempDir::new();
    fs::write(root.path().join("input"), "clean").unwrap();
    fs::write(root.path().join("git"), "#!/usr/bin/python3\nimport sys\nsys.stderr.write('private-child-stderr')\nsys.stdout.write('x' * (3 * 1024 * 1024))\n").unwrap();
    fs::set_permissions(root.path().join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path())
        .args(["scan", "input"])
        .env("PATH", root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(2) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("discovery did not finish within its budget");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-child-stderr")
    );
}
#[test]
fn executable_target_conflicts_help_and_nonregular_paths_are_checked() {
    let root = TempDir::new();
    fs::write(root.path().join("input"), "clean").unwrap();
    for args in [
        vec!["scan", "--config"],
        vec!["scan", "--config", "one", "--config", "two"],
        vec!["scan", "--staged"],
        vec!["scan", "--diff", "main"],
        vec!["scan", "--glob"],
        vec!["scan", "one", "two"],
        vec!["scan", "--help", "input"],
    ] {
        assert_eq!(run(&root, &args).status.code(), Some(2));
    }
    for args in [
        vec!["scan", "--help"],
        vec!["scan", "-h"],
        vec!["scan", "--", "input"],
        vec!["scan", "."],
        vec!["scan", "--glob", "*"],
    ] {
        assert_eq!(run(&root, &args).status.code(), Some(0));
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.path().join("input"), root.path().join("link")).unwrap();
        assert_eq!(run(&root, &["scan", "link"]).status.code(), Some(2));
        let (output_socket, closed_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(closed_peer);
        let failing_output: std::os::fd::OwnedFd = output_socket.into();
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .current_dir(root.path())
            .args(["scan", "input"])
            .stdout(failing_output)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("cannot write command output")
        );
    }
    fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\nrules: [{id: custom, regex: 'a*'}]",
    )
    .unwrap();
    assert_eq!(run(&root, &["scan", "input"]).status.code(), Some(2));
    fs::write(root.path().join(".rayloc.yaml"), "version: \"1\"").unwrap();
    fs::write(root.path().join(".raylocignore"), "[z-a]").unwrap();
    assert_eq!(run(&root, &["scan", "input"]).status.code(), Some(2));
}
#[cfg(unix)]
#[test]
fn git_unavailable_bad_executable_and_invalid_root_output_are_safe() {
    use std::os::unix::fs::PermissionsExt;
    let root = TempDir::new();
    fs::write(root.path().join("input"), "clean").unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rayloc"));
        command
            .current_dir(root.path())
            .args(["scan", "input"])
            .env("PATH", root.path());
        command
    };
    assert_eq!(command().output().unwrap().status.code(), Some(0));
    assert_eq!(
        command()
            .env("GIT_DIR", "private-git-directory")
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        command()
            .env("GIT_WORK_TREE", "private-work-tree")
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    fs::write(root.path().join("git"), "not-executable").unwrap();
    assert_eq!(command().output().unwrap().status.code(), Some(2));
    fs::write(
        root.path().join("git"),
        "#!/bin/sh\nprintf sensitive-root-output\nprintf sensitive-child-error >&2\n",
    )
    .unwrap();
    fs::set_permissions(root.path().join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = command().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sensitive")
    );
}
#[test]
fn genuine_git_discovery_failure_never_switches_nested_policy_scope() {
    let root = TempDir::new();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(root.path())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .unwrap()
            .success()
    );
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(root.path().join("nested/input"), "corp_abcdefghijklmnop").unwrap();
    fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\nrules: [{id: corporate, regex: 'corp_[a-z]+'}]",
    )
    .unwrap();
    assert_eq!(run(&root, &["scan", "nested/input"]).status.code(), Some(1));
    for (key, value) in [
        // PARAMETERS predates the Git 2.30 floor; COUNT is ignored there.
        ("GIT_CONFIG_PARAMETERS", "private-invalid-config-parameters"),
        ("GIT_DIR", "private-missing-git-directory"),
        ("PATH", "/private-missing-git-executable-directory"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .current_dir(root.path())
            .args(["scan", "nested/input"])
            .env(key, value)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let errors = String::from_utf8(output.stderr).unwrap();
        assert_eq!(errors, "rayloc: cannot discover policy root\n");
        assert!(!errors.contains(value));
    }
}
#[cfg(unix)]
#[test]
fn both_git_pipes_finish_without_deadlock_and_oversized_stderr_fails_safely() {
    use std::{
        os::unix::fs::PermissionsExt,
        thread,
        time::{Duration, Instant},
    };
    let root = TempDir::new();
    fs::write(root.path().join("input"), "clean").unwrap();
    let script = format!(
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 1024 ]; do printf '%s' '{}' >&2; i=$((i + 1)); done\nprintf '%s\\n' \"$PWD\"\n",
        "x".repeat(1024)
    );
    fs::write(root.path().join("git"), script).unwrap();
    fs::set_permissions(root.path().join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path())
        .args(["scan", "input"])
        .env("PATH", root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(2) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Git pipes failed to drain concurrently");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stderr, b"rayloc: cannot discover policy root\n");
}
