use std::process::Command;

#[test]
fn parallel_directory_scan_streams_redacted_findings_and_finishes() {
    use std::time::{Duration, Instant};
    let directory = support::TempDir::new();
    let token = "ghp_ParallelDirScanToken0123456789";
    for i in 0..256 {
        let path = directory.path().join(format!("file_{i}.txt"));
        std::fs::write(&path, format!("key = {token}\n")).unwrap();
    }
    let output_dir = support::TempDir::new();
    let stdout_file = output_dir.path().join("stdout");
    let stderr_file = output_dir.path().join("stderr");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .env("RAYON_NUM_THREADS", "2")
        .current_dir(directory.path())
        .args(["scan"])
        .stdout(std::fs::File::create(&stdout_file).unwrap())
        .stderr(std::fs::File::create(&stderr_file).unwrap())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success() || status.code() == Some(1),
                    "unexpected exit code"
                );
                assert_eq!(status.code(), Some(1), "expected exit code 1 (findings)");
                break;
            }
            Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("scan timed out after 10 seconds");
            }
            Err(error) => panic!("failed to poll child: {error}"),
        }
    }
    let stdout = std::fs::read_to_string(&stdout_file).unwrap();
    let stderr = std::fs::read_to_string(&stderr_file).unwrap();
    assert!(!stdout.contains(token), "token leaked to stdout");
    assert!(!stderr.contains(token), "token leaked to stderr");
    let finding_count = stdout.matches("Rule:").count();
    assert_eq!(finding_count, 256, "expected 256 emitted finding records");
    assert!(
        stdout.contains("256 finding(s)"),
        "expected 256 finding summary"
    );
    assert!(
        stdout.contains("256 file(s)"),
        "expected all 256 files to be scanned"
    );
}

#[test]
fn parallel_directory_scan_completes_without_findings() {
    use std::time::{Duration, Instant};
    let directory = support::TempDir::new();
    for i in 0..256 {
        let path = directory.path().join(format!("file_{i}.txt"));
        std::fs::write(&path, "no secret here\n").unwrap();
    }
    let output_dir = support::TempDir::new();
    let stdout_file = output_dir.path().join("stdout");
    let stderr_file = output_dir.path().join("stderr");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .env("RAYON_NUM_THREADS", "2")
        .current_dir(directory.path())
        .args(["scan"])
        .stdout(std::fs::File::create(&stdout_file).unwrap())
        .stderr(std::fs::File::create(&stderr_file).unwrap())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert_eq!(status.code(), Some(0), "expected clean scan exit 0");
                break;
            }
            Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("scan timed out after 10 seconds");
            }
            Err(error) => panic!("failed to poll child: {error}"),
        }
    }
    let stdout = std::fs::read_to_string(&stdout_file).unwrap();
    let stderr = std::fs::read_to_string(&stderr_file).unwrap();
    assert!(
        stdout.contains("CLEAN"),
        "expected clean scan result: {stdout}"
    );
    assert!(
        stderr.is_empty() || stderr.contains("scanned 256/256 files"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stdout.contains("256 file(s)"),
        "expected all 256 files to be scanned"
    );
}

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
