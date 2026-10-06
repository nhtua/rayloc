use std::process::Command;

#[test]
fn parallel_directory_scan_streams_redacted_findings_and_finishes() {
    use std::time::{Duration, Instant};
    let directory = support::TempDir::new();
    let token = "ghp_ParallelDirScanToken0123456789"; // rayloc:ignore
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
fn parallel_chunk_output_is_deterministic() {
    use std::fs;
    use std::io::Write;

    const AWS: &str = concat!("AKIA0123", "456789AB", "CDEF");
    const GITHUB: &str = "ghp_ParallelDeterminismToken0123456789"; // rayloc:ignore
    let directory = support::TempDir::new();
    for file_index in 0..101 {
        let path = directory.path().join(format!("small_{file_index:03}.txt"));
        let mut file = fs::File::create(path).unwrap();
        for _ in 0..100 {
            writeln!(file, "key=\"{AWS}\"").unwrap();
        }
    }
    // Keep a >10 MiB single line in the same worker pool and include two
    // different rule matches on one line to exercise overlapping candidates.
    let mut large = fs::File::create(directory.path().join("large.js")).unwrap();
    let block = vec![b'x'; 256 * 1024];
    for _ in 0..41 {
        large.write_all(&block).unwrap();
    }
    writeln!(large, ",\"{AWS}\",\"{GITHUB}\"").unwrap();
    drop(large);

    let scope_root = rayloc::config::discover_scope_root(directory.path()).unwrap();
    let mut reference = None;
    for threads in [1, 8, 32] {
        let outcome = rayloc::scanner::scope::scan_directory_with_options(
            &scope_root,
            directory.path(),
            None,
            &rayloc::rules::BUILTINS,
            rayloc::scanner::scope::ScopeOptions {
                workers: threads,
                ..Default::default()
            },
        );
        assert_eq!(outcome.exit_code(), 2);
        assert_eq!(outcome.findings.len(), 10_000);
        assert_eq!(outcome.stats.findings_detected, 10_102);
        assert!(!format!("{outcome:?}").contains(AWS));
        assert!(!format!("{outcome:?}").contains(GITHUB));
        let mut findings: Vec<_> = outcome
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{}:{}:{}:{}:{}:{}:{}",
                    finding.source_id,
                    finding.line,
                    finding.start_column,
                    finding.end_column,
                    finding.rule.metadata().id,
                    finding.value,
                    finding.id
                )
            })
            .collect();
        findings.sort_unstable();
        let summary = (
            outcome.stats.files_attempted,
            outcome.stats.files_completed,
            outcome.stats.files_excluded,
            outcome.stats.bytes_read,
            outcome.stats.lines_scanned,
            outcome.stats.findings_detected,
            outcome
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
        let current = (findings, summary);
        if let Some(reference) = &reference {
            assert_eq!(
                &current, reference,
                "worker count {threads} changed results"
            );
        } else {
            reference = Some(current);
        }
    }
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
    let sentinel = "ghp_SyntheticCliSentinel0123456789"; // rayloc:ignore
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

#[test]
fn large_single_line_cli_contract() {
    use std::fs;

    const SECRET: &str = concat!("AKIA0123", "456789AB", "CDEF");
    let directory = support::TempDir::new();
    let root = directory.path();
    let large_path = root.join("minified.bundle");
    // Generate the fixture incrementally so the test itself does not need a
    // second 11 MiB allocation. Put the credential after the 10 MiB point.
    let mut file = fs::File::create(&large_path).unwrap();
    let block = vec![b'x'; 256 * 1024];
    for _ in 0..41 {
        std::io::Write::write_all(&mut file, &block).unwrap();
    }
    std::io::Write::write_all(&mut file, b",\"").unwrap();
    std::io::Write::write_all(&mut file, SECRET.as_bytes()).unwrap();
    std::io::Write::write_all(&mut file, b"\"").unwrap();
    drop(file);

    for arguments in [
        vec!["scan".to_owned(), large_path.display().to_string()],
        vec!["scan".to_owned(), root.display().to_string()],
        vec![
            "scan".to_owned(),
            "--glob".to_owned(),
            "*.bundle".to_owned(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .args(&arguments)
            .current_dir(root)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
        assert!(stdout.contains("minified.bundle:1:"), "{stdout}");
        assert!(stdout.contains("1 finding(s)"), "{stdout}");
        assert!(!stdout.contains(SECRET), "secret leaked to stdout");
        assert!(!stderr.contains(SECRET), "secret leaked to stderr");
    }
}
