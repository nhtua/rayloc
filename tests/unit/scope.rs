use super::*;
use crate::scanner::SourceError;
use crate::{rules::BUILTINS, test_support::TempDir};
fn root(temp: &TempDir) -> ScopeRoot {
    ScopeRoot {
        root: temp.path().to_path_buf(),
        git: false,
        administration: Vec::new(),
    }
}
fn scan(temp: &TempDir, limits: Limits) -> ScanOutcome {
    scan_scope(
        &root(temp),
        temp.path(),
        None,
        &BUILTINS,
        ScopeOptions {
            workers: 1,
            parallel_threshold: 1,
            parallel_bytes_threshold: 0,
        },
        limits,
    )
}
#[test]
fn bounded_scope_rejects_frontier_paths_depth_and_policy_overflow() {
    let temp = TempDir::new();
    fs::write(temp.path().join("key"), "ghp_abcdefghijklmnop").unwrap();
    for limits in [
        Limits {
            frontier: 255,
            ..LIMITS
        },
        Limits { paths: 1, ..LIMITS },
        Limits { depth: 0, ..LIMITS },
        Limits {
            directory: 0,
            ..LIMITS
        },
    ] {
        assert_eq!(
            scan(&temp, limits).errors,
            [SourceError::new(ScanError::ScopeLimit, None)]
        );
    }
    fs::write(temp.path().join(".gitignore"), "*.env").unwrap();
    for limits in [
        Limits {
            policy_files: 0,
            ..LIMITS
        },
        Limits {
            policy_bytes: 0,
            ..LIMITS
        },
        Limits {
            policy: PolicyUsage {
                patterns: 0,
                ..ACTIVE_POLICY
            },
            ..LIMITS
        },
    ] {
        assert_eq!(
            scan(&temp, limits).errors,
            [SourceError::new(ScanError::ScopeLimit, None)]
        );
    }
    fs::write(temp.path().join(".gitignore"), "[z-a]").unwrap();
    assert_eq!(
        scan(&temp, LIMITS).errors,
        [SourceError::new(ScanError::Policy, None)]
    );
    assert!(matches!(
        join(Path::new("/"), OsStr::new(&"x".repeat(MAX_PATH_BYTES))),
        Err(ScanError::ScopeLimit)
    ));
    let mut budget = Budget {
        entries: usize::MAX,
        paths: 0,
    };
    assert_eq!(budget.charge(1, 0, LIMITS), Err(ScanError::CounterOverflow));
    budget.entries = 0;
    budget.paths = usize::MAX;
    assert_eq!(budget.charge(0, 1, LIMITS), Err(ScanError::CounterOverflow));
}
#[test]
fn glob_input_limits_and_invalid_scopes_are_fixed_errors() {
    for pattern in ["x".repeat(16385), ",".repeat(1025), "{".repeat(17)] {
        assert!(matches!(compile_glob(&pattern), Err(ScanError::ScopeLimit)));
    }
    for pattern in ["", "/a", "../a", "}", "[z-a]"] {
        assert!(matches!(compile_glob(pattern), Err(ScanError::Discovery)));
    }
    assert!(compile_glob(r"./a\{b\}").unwrap().is_match("a{b}"));
    assert!(compile_glob("{a,b}").unwrap().is_match("b"));
    let temp = TempDir::new();
    for workers in [0, 65] {
        assert_eq!(
            scan_directory_with_options(
                &root(&temp),
                temp.path(),
                None,
                &BUILTINS,
                ScopeOptions {
                    workers,
                    parallel_threshold: 1,
                    parallel_bytes_threshold: 0
                }
            )
            .errors,
            [SourceError::new(ScanError::ScopeLimit, None)]
        );
    }
    assert_eq!(
        scan_directory(&root(&temp), &temp.path().join("missing"), None, &BUILTINS).errors,
        [SourceError::new(ScanError::Discovery, None)]
    );
    let other = TempDir::new();
    assert_eq!(
        scan_directory(&root(&temp), other.path(), None, &BUILTINS).errors,
        [SourceError::new(ScanError::Discovery, None)]
    );
}
#[test]
fn serial_parallel_many_files_and_global_overflow_agree() {
    let temp = TempDir::new();
    let line = b"ghp_abcdefghijklmnop\npassword=Ab3!Cd4@Ef5#\npassword=example\npassword=$TOKEN\nghp_abcdefghijklmnop # rayloc:ignore\n";
    for i in 0..300 {
        fs::write(temp.path().join(format!("{i:04}")), line.repeat(20)).unwrap();
    }
    let mut baseline = None;
    for workers in [1, 2, 8, 32] {
        let out = scan_directory_with_options(
            &root(&temp),
            temp.path(),
            None,
            &BUILTINS,
            ScopeOptions {
                workers,
                parallel_threshold: 1,
                parallel_bytes_threshold: 0,
            },
        );
        assert_eq!(
            out.errors,
            [SourceError::new(ScanError::FindingLimit, None)]
        );
        assert_eq!(out.stats.findings_detected, 12000);
        assert_eq!(out.findings.len(), 10000);
        assert_eq!(out.stats.files_completed, 300);
        let value = format!("{:?} {:?} {:?}", out.findings, out.stats, out.errors);
        if let Some(previous) = &baseline {
            assert_eq!(previous, &value);
        } else {
            baseline = Some(value);
        }
    }
}
#[test]
fn nested_repository_is_scanned_under_selected_policy() {
    let temp = TempDir::new();
    fs::create_dir(temp.path().join("nested")).unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(temp.path().join("nested"))
            .status()
            .unwrap()
            .success()
    );
    fs::write(temp.path().join("nested/key"), "ghp_abcdefghijklmnop").unwrap();
    let out = scan(&temp, LIMITS);
    assert_eq!(out.stats.findings_detected, 1);
    assert_eq!(out.stats.files_excluded, 1);
}
#[test]
fn depth_and_selected_ancestor_limits_fail_closed() {
    let temp = TempDir::new();
    fs::create_dir_all(temp.path().join("a/b")).unwrap();
    fs::write(temp.path().join("a/b/key"), "ghp_abcdefghijklmnop").unwrap();
    assert_eq!(
        scan(&temp, Limits { depth: 1, ..LIMITS }).errors,
        [SourceError::new(ScanError::ScopeLimit, None)]
    );
    assert_eq!(
        scan_scope(
            &root(&temp),
            &temp.path().join("a/b"),
            None,
            &BUILTINS,
            ScopeOptions {
                workers: 1,
                parallel_threshold: 1,
                parallel_bytes_threshold: 0
            },
            Limits { depth: 2, ..LIMITS }
        )
        .errors,
        [SourceError::new(ScanError::ScopeLimit, None)]
    );
    fs::write(temp.path().join("a/.gitignore"), "[z-a]").unwrap();
    let result = scan(&temp, LIMITS);
    assert_eq!(result.errors, [SourceError::new(ScanError::Policy, None)]);
}
#[cfg(unix)]
#[test]
fn permission_failures_preserve_partial_findings_even_in_ignored_trees() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new();
    fs::write(temp.path().join("a"), "ghp_abcdefghijklmnop").unwrap();
    fs::write(temp.path().join("b"), "clean").unwrap();
    fs::create_dir(temp.path().join("blocked")).unwrap();
    fs::write(temp.path().join(".gitignore"), "blocked/\n").unwrap();
    for name in ["b", "blocked"] {
        fs::set_permissions(temp.path().join(name), fs::Permissions::from_mode(0o0)).unwrap();
    }
    let result = scan(&temp, LIMITS);
    for name in ["b", "blocked"] {
        fs::set_permissions(temp.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(result.exit_code(), 2);
    assert_eq!(result.stats.findings_detected, 1);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.error == ScanError::Open && e.path.is_some())
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.error == ScanError::Discovery)
    );
}
fn runner(root: &ScopeRoot) -> Runner<'_> {
    Runner {
        registry: &BUILTINS,
        exclusions: Exclusions::load(&root.root).unwrap(),
        root,
        options: ScopeOptions {
            workers: 1,
            parallel_threshold: 1,
            parallel_bytes_threshold: 0,
        },
        limits: LIMITS,
        workers: vec![Worker::new()],
        pool: None,
        collector: Mutex::new(Collector::new(MAX_FINDINGS)),
        emitter: None,
        outcome: ScanOutcome::default(),
        budget: Budget::default(),
        frames: Vec::new(),
        batch: Vec::with_capacity(BATCH),
        batch_bytes: 0,
        matched: 0,
        scanned: 0,
        last_progress: None,
        total_policy: PolicyUsage::default(),
        administration: Vec::new(),
        repositories: 0,
        metadata_only: false,
    }
}

#[test]
fn scope_pool_is_lazy_and_uses_the_requested_private_thread_count() {
    let temp = TempDir::new();
    let root = root(&temp);
    let mut runner = runner(&root);
    runner.options.workers = 3;
    runner.options.parallel_threshold = 2;
    runner.options.parallel_bytes_threshold = 256 * 1024;
    assert!(runner.pool.is_none());
    runner.pool(1, 0).unwrap();
    assert!(runner.pool.is_none());
    runner.pool(2, 0).unwrap();
    assert_eq!(runner.workers.len(), 3);
    assert_eq!(runner.pool.as_ref().unwrap().current_num_threads(), 3);
    assert_eq!(
        runner
            .pool
            .as_ref()
            .unwrap()
            .install(rayon::current_num_threads),
        3
    );
}

#[test]
fn byte_heavy_small_file_batch_admits_workers_below_count_threshold() {
    let temp = TempDir::new();
    let root = root(&temp);
    let mut runner = runner(&root);
    runner.options.workers = 4;
    runner.options.parallel_threshold = 256;
    runner.options.parallel_bytes_threshold = 128 * 1024;
    let content = vec![b'x'; 16 * 1024];
    for index in 0..32 {
        let path = temp.path().join(format!("{index:02}.txt"));
        fs::write(&path, &content).unwrap();
        runner
            .regular(path.into_boxed_path(), true, true, None, &mut None)
            .unwrap();
    }
    assert!(runner.pool.is_none());
    runner.flush();
    assert_eq!(runner.pool.as_ref().unwrap().current_num_threads(), 4);
    assert_eq!(runner.outcome.stats.files_completed, 32);
    assert_eq!(runner.outcome.stats.bytes_read, (32 * content.len()) as u64);
}
#[test]
fn discovery_admission_failures_do_not_silently_skip_scope() {
    let temp = TempDir::new();
    let root = root(&temp);
    let mut runner = runner(&root);
    fs::write(temp.path().join("a"), "clean").unwrap();
    runner.limits.frontier = 0;
    assert!(matches!(
        runner.entries(temp.path()),
        Err(ScanError::ScopeLimit)
    ));
    runner.limits = LIMITS;
    runner.budget = Budget::default();
    runner.limits.paths = 0;
    assert!(matches!(
        runner.entries(temp.path()),
        Err(ScanError::ScopeLimit)
    ));
    runner.limits = LIMITS;
    runner.budget = Budget::default();
    assert_eq!(
        runner.regular(Path::new("/outside").into(), true, true, None, &mut None),
        Err(ScanError::Discovery)
    );
    runner.matched = u32::MAX;
    assert_eq!(
        runner.regular(temp.path().join("a").into(), true, true, None, &mut None),
        Err(ScanError::CounterOverflow)
    );
    runner.matched = 0;
    runner.limits.paths = 0;
    assert_eq!(
        runner.regular(temp.path().join("a").into(), true, true, None, &mut None),
        Err(ScanError::ScopeLimit)
    );
    runner.outcome.stats.files_excluded = u64::MAX;
    assert_eq!(runner.excluded(), Err(ScanError::CounterOverflow));
    fs::write(temp.path().join(".gitignore"), "a").unwrap();
    runner.total_policy.bytes = usize::MAX;
    assert!(matches!(
        runner.policy(temp.path(), true),
        Err(ScanError::ScopeLimit)
    ));
    runner.exclusions.usage.bytes = usize::MAX;
    runner.frames.push(Frame {
        directory: temp.path().into(),
        entries: Vec::new(),
        scanner: true,
        combined: true,
        policy: Some(
            Exclusions::load_named(
                temp.path(),
                ".gitignore",
                PolicyUsage::default(),
                ACTIVE_POLICY,
            )
            .unwrap(),
        ),
    });
    assert!(matches!(
        runner.policy(temp.path(), true),
        Err(ScanError::ScopeLimit)
    ));
    fs::write(temp.path().join(".raylocignore"), "[z-a]").unwrap();
    assert_eq!(
        scan(&temp, LIMITS).errors,
        [SourceError::new(ScanError::Policy, None)]
    );
}
#[test]
fn merge_errors_and_every_new_category_render_without_source_metadata() {
    for error in [
        ScanError::ScopeLimit,
        ScanError::GitMetadata,
        ScanError::Policy,
        ScanError::Pool,
    ] {
        let mut outcome = ScanOutcome::default();
        outcome.fail(error);
        let mut text = Vec::new();
        crate::report::terminal::render(&outcome, &mut text).unwrap();
        assert!(String::from_utf8(text).unwrap().contains("INCOMPLETE"));
        assert_eq!(outcome.exit_code(), 2);
    }
}
#[test]
fn selected_ancestors_and_pending_work_respect_path_budgets() {
    let temp = TempDir::new();
    fs::create_dir_all(temp.path().join("a/b")).unwrap();
    fs::write(temp.path().join("a/key"), "clean").unwrap();
    let root = root(&temp);
    let out = scan_scope(
        &root,
        &temp.path().join("a/b"),
        None,
        &BUILTINS,
        ScopeOptions {
            workers: 1,
            parallel_threshold: 1,
            parallel_bytes_threshold: 0,
        },
        Limits {
            paths: temp.path().as_os_str().len(),
            ..LIMITS
        },
    );
    assert_eq!(out.errors, [SourceError::new(ScanError::ScopeLimit, None)]);
    let mut runner = runner(&root);
    runner.limits.paths = temp.path().as_os_str().len() + 1;
    assert_eq!(
        runner.discover(temp.path(), None),
        Err(ScanError::ScopeLimit)
    );
    let long = std::path::PathBuf::from("x".repeat(MAX_PATH_BYTES + 1));
    assert_eq!(
        runner.enter(long.into(), true, true, false),
        Err(ScanError::ScopeLimit)
    );
}
#[cfg(unix)]
#[test]
fn metadata_failures_and_disappearing_files_remain_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new();
    let root = root(&temp);
    fs::write(temp.path().join("key"), "clean").unwrap();
    let mut first = runner(&root);
    first.enter(temp.path().into(), true, true, true).unwrap();
    fs::remove_file(temp.path().join("key")).unwrap();
    first.walk(None, &mut None).unwrap();
    first.flush();
    assert_eq!(first.outcome.errors[0].error, ScanError::Open);
    assert!(first.outcome.errors[0].path.is_some());
    fs::write(temp.path().join("key"), "clean").unwrap();
    let mut second = runner(&root);
    second.enter(temp.path().into(), true, true, false).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o400)).unwrap();
    let entries = second.entries(temp.path()).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        entries
            .iter()
            .all(|entry| matches!(entry.kind, Kind::Error))
    );
    second.frames.last_mut().unwrap().entries = entries;
    second.walk(None, &mut None).unwrap();
    assert_eq!(second.outcome.errors[0].error, ScanError::Discovery);
}
#[test]
fn discovered_scope_counter_and_pending_path_limits_propagate() {
    let temp = TempDir::new();
    let root = root(&temp);
    fs::write(temp.path().join("key"), "clean").unwrap();
    let mut regular = runner(&root);
    regular.enter(temp.path().into(), true, true, true).unwrap();
    regular.matched = u32::MAX;
    assert_eq!(
        regular.walk(None, &mut None),
        Err(ScanError::CounterOverflow)
    );
    fs::remove_file(temp.path().join("key")).unwrap();
    fs::create_dir(temp.path().join(".git")).unwrap();
    let mut admin = runner(&root);
    admin.enter(temp.path().into(), true, true, true).unwrap();
    admin.outcome.stats.files_excluded = u64::MAX;
    assert_eq!(admin.walk(None, &mut None), Err(ScanError::CounterOverflow));
    #[cfg(unix)]
    {
        fs::remove_dir(temp.path().join(".git")).unwrap();
        std::os::unix::fs::symlink("absent", temp.path().join("link")).unwrap();
        let mut link = runner(&root);
        link.enter(temp.path().into(), true, true, true).unwrap();
        link.outcome.stats.files_excluded = u64::MAX;
        assert_eq!(link.walk(None, &mut None), Err(ScanError::CounterOverflow));
    }
}
#[test]
fn generic_checksum_and_invalid_aws_candidates_keep_independent_counters() {
    let mut counters = crate::rules::context::Suppressions {
        checksum: usize::MAX,
        ..Default::default()
    };
    assert_eq!(
        BUILTINS.detect_line_with_suppressions(
            b"checksum_api_key=9f21c7ab6e40d835",
            &mut crate::rules::entropy::Histogram::new(),
            &mut counters,
            |_, _| panic!("checksum emitted")
        ),
        Err(ScanError::CounterOverflow)
    );
    let out = engine::scan_reader(
        &mut std::io::Cursor::new(
            b"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+//@",
        ),
        1,
    );
    assert_eq!(out.stats.findings_detected, 1);
    assert_eq!(
        out.findings[0].rule,
        crate::rules::builtin::RuleId::ContextSecret
    );
    assert_eq!(out.exit_code(), 1);
}
#[test]
fn a_discovered_path_above_the_path_cap_is_not_admitted() {
    let temp = TempDir::new();
    let root = root(&temp);
    let mut runner = runner(&root);
    let directory: Box<Path> = std::path::PathBuf::from("x".repeat(MAX_PATH_BYTES)).into();
    runner.budget.paths = MAX_PATH_BYTES + 1;
    runner.budget.entries = 1;
    runner.frames.push(Frame {
        directory,
        entries: vec![Entry {
            name: OsStr::new("a").into(),
            kind: Kind::Regular,
        }],
        scanner: true,
        combined: true,
        policy: None,
    });
    assert_eq!(runner.walk(None, &mut None), Err(ScanError::ScopeLimit));
}

#[test]
fn nested_administration_admission_checks_pointer_and_storage_budgets() {
    let temp = TempDir::new();
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["init", "--quiet", "--separate-git-dir=admin", "nested"])
            .status()
            .unwrap()
            .success()
    );
    let root = root(&temp);
    let directory = temp.path().join("nested");
    let mut limited = runner(&root);
    limited.repositories = NESTED_REPOSITORIES;
    assert_eq!(
        limited.nested_administration(&directory),
        Err(ScanError::ScopeLimit)
    );
    let mut entries = runner(&root);
    entries.limits.frontier = 0;
    assert_eq!(
        entries.nested_administration(&directory),
        Err(ScanError::ScopeLimit)
    );
    let mut paths = runner(&root);
    paths.limits.paths = 0;
    assert_eq!(
        paths.nested_administration(&directory),
        Err(ScanError::ScopeLimit)
    );
    let mut record = runner(&root);
    record.limits.administration_path = 1;
    assert_eq!(
        record.nested_administration(&directory),
        Err(ScanError::ScopeLimit)
    );
    assert!(record.administration.is_empty());
    let mut admitted = runner(&root);
    admitted.nested_administration(&directory).unwrap();
    assert_eq!(admitted.administration.len(), 1);
    let usage = (admitted.budget.entries, admitted.budget.paths);
    admitted.nested_administration(&directory).unwrap();
    assert_eq!(admitted.administration.len(), 1);
    assert_eq!((admitted.budget.entries, admitted.budget.paths), usage);
    let with_admin = ScopeRoot {
        administration: vec![temp.path().join("admin")],
        ..root
    };
    let mut known = runner(&with_admin);
    known.nested_administration(&directory).unwrap();
    assert!(known.administration.is_empty());
    assert_eq!(known.budget.paths, 0);
    let unknown = ScopeRoot {
        root: temp.path().to_path_buf(),
        git: false,
        administration: Vec::new(),
    };
    let mut spare = runner(&unknown);
    spare.administration = Vec::with_capacity(2);
    spare.budget.entries = 2;
    spare.nested_administration(&directory).unwrap();
    assert_eq!(spare.administration.len(), 1);
    assert_eq!(spare.budget.entries, 2);
}

#[test]
fn discovered_administration_exclusion_counter_is_checked() {
    let temp = TempDir::new();
    fs::create_dir(temp.path().join("admin")).unwrap();
    let root = root(&temp);
    let mut runner = runner(&root);
    runner.administration.push(temp.path().join("admin").into());
    runner.enter(temp.path().into(), true, true, true).unwrap();
    runner.outcome.stats.files_excluded = u64::MAX;
    assert_eq!(
        runner.walk(None, &mut None),
        Err(ScanError::CounterOverflow)
    );
}

#[test]
fn malformed_nested_pointer_fails_before_admitting_scan_work() {
    let temp = TempDir::new();
    fs::create_dir(temp.path().join("nested")).unwrap();
    fs::write(temp.path().join("nested/.git"), "gitdir: absent\n").unwrap();
    fs::write(temp.path().join("key"), "ghp_abcdefghijklmnop").unwrap();
    let outcome = scan(&temp, LIMITS);
    assert_eq!(
        outcome.errors,
        [SourceError::new(ScanError::Discovery, None)]
    );
    assert_eq!(outcome.exit_code(), 2);
    assert_eq!(outcome.stats.files_attempted, 0);
    assert!(outcome.findings.is_empty());
}

#[test]
fn pending_work_flushes_at_the_byte_limit_and_preserves_open_failures() {
    let temp = TempDir::new();
    fs::write(temp.path().join("key"), "clean").unwrap();
    let root = root(&temp);
    let mut runner = runner(&root);
    // 255 independently owned 4,112-byte paths leave 16 bytes of batch budget.
    // Their sources are unavailable by scan time; admission must retain the errors.
    let unavailable = temp
        .path()
        .join("x".repeat(4112 - temp.path().as_os_str().len() - 1));
    for source_id in 1..=255 {
        runner.batch.push(Work {
            path: unavailable.clone().into_boxed_path(),
            source_id,
            estimated_bytes: 0,
        });
    }
    runner.matched = 255;
    runner.batch_bytes = 1_048_560;
    runner.budget.paths = 1_048_560;
    runner
        .regular(temp.path().join("key").into(), true, true, None, &mut None)
        .unwrap();
    assert_eq!(runner.outcome.stats.files_attempted, 255);
    assert_eq!(runner.outcome.errors[0].error, ScanError::Open);
    assert!(runner.outcome.errors[0].path.is_some());
    assert_eq!(runner.batch.len(), 1);
    runner.flush();
    assert_eq!(runner.outcome.stats.files_attempted, 256);
    assert_eq!(runner.outcome.stats.files_completed, 1);
    assert_eq!(runner.outcome.exit_code(), 2);
    assert_eq!(runner.budget.paths, 0);
}

#[test]
fn directory_workers_preserve_prior_findings_on_app_header_budget_failure() {
    let temp = TempDir::new();
    fs::write(temp.path().join("a"), "ghp_abcdefghijklmnop").unwrap();
    let app = format!("ghs_1234_{}.e30.c2ln", "A".repeat(11000));
    fs::write(temp.path().join("z"), app).unwrap();
    let result = scan(&temp, LIMITS);
    assert_eq!(result.errors[0].error, ScanError::CandidateLimit);
    assert!(result.errors[0].path.is_some());
    assert_eq!(result.stats.files_attempted, 2);
    assert_eq!(result.stats.files_completed, 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].source_id, 1);
    assert_eq!(result.exit_code(), 2);
    assert!(!format!("{result:?}").contains("abcdefghijklmnop"));
}
