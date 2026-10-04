mod support;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use support::TempDir;

const SECRET: &str = concat!("AKIA0123", "456789AB", "CDEF");
fn isolated(command: &mut Command) -> &mut Command {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("LC_ALL", "C")
}
fn git(root: &Path, args: &[&str]) -> Output {
    let out = isolated(Command::new("git").current_dir(root))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git fixture failed: {args:?}");
    out
}
fn repo() -> TempDir {
    let dir = TempDir::new();
    git(dir.path(), &["init", "-q"]);
    for (key, value) in [
        ("user.name", "Fixture"),
        ("user.email", "fixture@example.invalid"),
        ("core.hooksPath", "/dev/null"),
        ("core.attributesFile", "/dev/null"),
        ("core.excludesFile", "/dev/null"),
    ] {
        git(dir.path(), &["config", key, value]);
    }
    dir
}
fn scan(root: &Path, options: &[&str]) -> Output {
    isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .args(["scan", "--diff", "HEAD"])
        .args(options)
        .output()
        .unwrap()
}
fn check(out: Output, code: i32, findings: usize) -> String {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.matches("[REDACTED]").count(), findings, "{text}");
    assert!(!text.contains(SECRET));
    assert!(!String::from_utf8(out.stderr).unwrap().contains(SECRET));
    text
}
#[test]
fn tracked_final_content_and_coordinates_exclude_untracked_deleted_and_context() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), format!("{SECRET}\nsafe\n")).unwrap();
    fs::write(root.join("deleted"), SECRET).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    check(scan(root, &[]), 0, 0);
    fs::write(root.join("entry"), format!("{SECRET}\nstaged\n")).unwrap();
    git(root, &["add", "entry"]);
    fs::write(root.join("entry"), format!("{SECRET}\nfinal\n{SECRET}\n")).unwrap();
    fs::write(root.join("new"), "staged\n").unwrap();
    git(root, &["add", "new"]);
    fs::write(root.join("new"), SECRET).unwrap();
    fs::write(root.join("untracked"), SECRET).unwrap();
    fs::remove_file(root.join("deleted")).unwrap();
    let text = check(scan(root, &[]), 1, 2);
    assert!(text.contains(":3:"));
}
#[test]
fn working_tree_policy_and_safe_reference_errors() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), "safe").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    fs::write(
        root.join(".rayloc.yaml"),
        "version: \"1\"\ndisabled_rules: [aws-access-key-id]\n",
    )
    .unwrap();
    check(scan(root, &[]), 0, 0);
    for reference in ["--help", "missing", "HEAD:entry", "HEAD;echo private"] {
        let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
            .args(["scan", "--diff", reference])
            .output()
            .unwrap();
        check(out, 2, 0);
    }
}
#[test]
fn modes_empty_sides_symlinks_and_sha256_preserve_strict_patch_contract() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for format in ["sha1", "sha256"] {
        let dir = repo();
        let root = dir.path();
        if format == "sha256" {
            fs::remove_dir_all(root.join(".git")).unwrap();
            git(root, &["init", "-q", "--object-format=sha256"]);
            git(root, &["config", "user.name", "Fixture"]);
            git(root, &["config", "user.email", "fixture@example.invalid"]);
        }
        for name in ["mode", "content-mode", "empty", "type"] {
            fs::write(root.join(name), "safe\n").unwrap();
        }
        symlink("safe", root.join("link")).unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "base"]);
        fs::set_permissions(root.join("mode"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(root.join("content-mode"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("content-mode"), SECRET).unwrap();
        fs::write(root.join("empty"), "").unwrap();
        fs::remove_file(root.join("type")).unwrap();
        symlink(SECRET, root.join("type")).unwrap();
        fs::remove_file(root.join("link")).unwrap();
        symlink(SECRET, root.join("link")).unwrap();
        fs::write(root.join(SECRET), "target contains no secret").unwrap();
        fs::write(root.join("added-empty"), "").unwrap();
        git(root, &["add", "added-empty"]);
        check(scan(root, &[]), 1, 3);
    }
}
#[test]
fn nested_conversion_uses_root_relative_attributes_and_alternate_index() {
    let dir = repo();
    let root = dir.path();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join(".gitattributes"), "entry text eol=lf\n").unwrap();
    fs::write(root.join("entry"), "safe\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    fs::write(root.join("entry"), format!("safe\r\n{SECRET}\r\n")).unwrap();
    fs::copy(root.join(".git/index"), root.join("alternate")).unwrap();
    check(scan(root, &[]), 1, 1);
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root.join("nested")))
        .env("GIT_INDEX_FILE", "alternate")
        .args(["scan", "--diff", "HEAD"])
        .output()
        .unwrap();
    check(out, 1, 1);
}
#[test]
fn direct_reference_diff_does_not_use_merge_base_or_history() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), "safe\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "ancestor"]);
    git(root, &["branch", "other"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "current"]);
    git(root, &["branch", "current"]);
    git(root, &["checkout", "-q", "other"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "independent"]);
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .args(["scan", "--diff", "current"])
        .output()
        .unwrap();
    check(out, 0, 0);
}
#[test]
fn clean_filters_match_diff_conversion_and_spaced_paths_are_safe() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join(".gitattributes"), "* filter=fixture\n").unwrap();
    git(root, &["config", "filter.fixture.clean", "tr X A"]);
    fs::write(root.join("entry"), "safe\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let name = "private name";
    fs::write(root.join(name), "XKIX0123456789XBCDEF\n").unwrap();
    let out = isolated(Command::new("git").current_dir(root))
        .arg("add")
        .arg(name)
        .output()
        .unwrap();
    assert!(out.status.success());
    check(scan(root, &[]), 1, 1);
}
fn wrapped_scan(root: &Path, script: &str) -> Output {
    use std::os::unix::fs::PermissionsExt;
    let wrapper = root.join("bin");
    fs::create_dir(&wrapper).unwrap();
    let original = std::env::var_os("PATH").unwrap();
    let real = std::env::split_paths(&original)
        .map(|p| p.join("git"))
        .find(|p| p.is_file())
        .unwrap();
    let code = format!(
        "#!/usr/bin/python3\nimport os, subprocess, sys\nreal = os.environ['REAL_GIT']\nargs = sys.argv[1:]\n{script}\nos.execv(real, [real] + args)\n"
    );
    fs::write(wrapper.join("git"), code).unwrap();
    fs::set_permissions(wrapper.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let paths = wrapper;
    isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .env("PATH", paths)
        .env("REAL_GIT", real)
        .args(["scan", "--diff", "HEAD"])
        .output()
        .unwrap()
}
fn changed_repo() -> TempDir {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), "safe\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    dir
}
#[test]
fn same_length_mutation_after_patch_is_detected_despite_identical_raw() {
    let dir = changed_repo();
    let script = "if '--patch' in args:\n    result = subprocess.run([real]+args, stdout=subprocess.PIPE)\n    before = subprocess.check_output([real, 'diff', '--raw', '-z', '--no-abbrev', 'HEAD'])\n    open('entry','w').write('BKIA0123456789ABCDEF')\n    after = subprocess.check_output([real, 'diff', '--raw', '-z', '--no-abbrev', 'HEAD'])\n    assert before == after\n    sys.stdout.buffer.write(result.stdout); sys.exit(result.returncode)";
    check(wrapped_scan(dir.path(), script), 2, 1);
}
#[test]
fn mutation_before_patch_disagrees_with_independent_identity() {
    let dir = changed_repo();
    check(
        wrapped_scan(
            dir.path(),
            "if '--patch' in args: open('entry','w').write('BKIA0123456789ABCDEF')",
        ),
        2,
        0,
    );
}
#[test]
fn mode_only_succeeds_but_truncated_content_mode_patch_fails() {
    use std::os::unix::fs::PermissionsExt;
    let dir = changed_repo();
    let root = dir.path();
    fs::set_permissions(root.join("entry"), fs::Permissions::from_mode(0o755)).unwrap();
    check(
        wrapped_scan(
            root,
            "if '--patch' in args:\n    result = subprocess.check_output([real]+args)\n    sys.stdout.buffer.write(b'\\n'.join(result.split(b'\\n')[:3])+b'\\n'); sys.exit(0)",
        ),
        2,
        0,
    );
    fs::write(root.join("entry"), "safe\n").unwrap();
    check(scan(root, &[]), 0, 0);
}
#[test]
fn late_policy_index_head_and_scope_mutations_have_error_precedence() {
    for mutation in [
        "open('.raylocignore','w').write('entry\\n')",
        "subprocess.check_call([real,'add','entry'])",
        "subprocess.check_call([real,'symbolic-ref','HEAD','refs/heads/replaced'])",
        "open('new','w').write('safe'); subprocess.check_call([real,'add','new'])",
        "os.unlink('entry')",
        concat!(
            "open('replacement','w').write('",
            "AKIA0123",
            "456789AB",
            "CDEF",
            "'); os.replace('replacement','entry')"
        ),
        "open('replacement','w').write('BKIA0123456789ABCDEF'); os.replace('replacement','entry')",
    ] {
        let dir = changed_repo();
        let script = format!(
            "if '--patch' in args:\n    result = subprocess.run([real]+args,stdout=subprocess.PIPE)\n    {mutation}\n    sys.stdout.buffer.write(result.stdout); sys.exit(result.returncode)"
        );
        check(wrapped_scan(dir.path(), &script), 2, 1);
    }
}
#[test]
fn empty_scope_is_rechecked_and_ref_is_pinned() {
    let dir = changed_repo();
    fs::write(dir.path().join("entry"), "safe\n").unwrap();
    check(
        wrapped_scan(
            dir.path(),
            "if '--patch' in args:\n    result = subprocess.check_output([real]+args)\n    open('entry','w').write('changed')\n    sys.stdout.buffer.write(result); sys.exit(0)",
        ),
        2,
        0,
    );
    let dir = changed_repo();
    let root = dir.path();
    git(root, &["branch", "pinned"]);
    // Changing the supplied branch cannot change the acquired commit endpoint.
    // HEAD mutation separately remains an incomplete-scan check.
    let script =
        "if '--patch' in args:\n    assert 'HEAD' not in args\n    assert len(args[-2]) in (40,64)";
    check(wrapped_scan(root, script), 1, 1);
}
#[test]
fn malformed_raw_hash_and_patch_processes_fail_safely() {
    for script in [
        "if '--raw' in args: sys.stdout.buffer.write(b'bad\\0entry\\0'); sys.exit(0)",
        "if '--raw' in args: sys.stdout.buffer.write(b'bad\\0'); sys.exit(0)",
        "if '--patch' in args: sys.exit(5)",
        "if '--path=entry' in args: sys.stdout.write('0'*40+'\\n'); sys.exit(0)",
        "if '--path=entry' in args: sys.stdout.write('x'*66); sys.exit(0)",
        "if '--path=entry' in args: sys.exit(5)",
        "if '--path=entry' in args: os.unlink('entry')",
        "if '--path=entry' in args: os.rename('entry','replacement'); open('entry','w').write('other')",
        "if '--raw' in args:\n    if os.path.exists('second'): sys.stdout.buffer.write(b'bad\\0'); sys.exit(0)\n    open('second','w').close()",
        "if '--raw' in args:\n    if os.path.exists('second'): sys.exit(0)\n    open('second','w').close()",
        "if '--path=entry' in args:\n    if os.path.exists('hashed'): sys.stdout.write('f'*40+'\\n'); sys.exit(0)\n    open('hashed','w').close()",
    ] {
        let dir = changed_repo();
        let out = wrapped_scan(dir.path(), script);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8(out.stdout).unwrap().contains(SECRET));
        assert!(!String::from_utf8(out.stderr).unwrap().contains(SECRET));
    }
    let dir = changed_repo();
    let script = format!("sys.stderr.write({SECRET:?} * 10000)\n");
    check(wrapped_scan(dir.path(), &script), 1, 1);
}
#[test]
fn policy_exclusions_explicit_merge_inline_and_invalid_policy_are_enforced() {
    let dir = changed_repo();
    let root = dir.path();
    fs::write(root.join("entry"), format!("{SECRET} # rayloc:ignore\n")).unwrap();
    check(scan(root, &[]), 0, 0);
    check(scan(root, &["--no-inline-ignores"]), 1, 1);
    fs::write(
        root.join("override"),
        "version: \"1\"\ndisabled_rules: [aws-access-key-id]\n",
    )
    .unwrap();
    check(
        scan(root, &["--config", "override", "--no-inline-ignores"]),
        0,
        0,
    );
    check(scan(root, &["--config", "missing"]), 2, 0);
    fs::write(root.join(".raylocignore"), "entry\n").unwrap();
    assert!(check(scan(root, &["--no-inline-ignores"]), 0, 0).contains("EXCLUDED"));
    fs::write(root.join(".rayloc.yaml"), "bad").unwrap();
    check(scan(root, &[]), 2, 0);
    fs::remove_file(root.join(".rayloc.yaml")).unwrap();
    std::os::unix::fs::symlink("entry", root.join(".rayloc.yaml")).unwrap();
    check(scan(root, &[]), 2, 0);
}
#[test]
fn changed_and_dirty_equal_identity_gitlinks_are_counted_as_excluded() {
    let dir = changed_repo();
    let root = dir.path();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    git(&sub, &["init", "-q"]);
    git(&sub, &["config", "user.name", "Fixture"]);
    git(&sub, &["config", "user.email", "fixture@example.invalid"]);
    fs::write(sub.join("file"), "safe").unwrap();
    git(&sub, &["add", "."]);
    git(&sub, &["commit", "-qm", "sub"]);
    git(root, &["add", "sub"]);
    git(root, &["commit", "-qm", "sub"]);
    fs::write(sub.join("file"), SECRET).unwrap();
    git(&sub, &["commit", "-qam", "change"]);
    let text = check(scan(root, &[]), 1, 1);
    assert!(text.contains("1 file(s) excluded"));
    git(root, &["add", "sub"]);
    git(root, &["commit", "-qm", "updated"]);
    fs::write(sub.join("file"), "dirty").unwrap();
    assert!(check(scan(root, &[]), 1, 1).contains("1 file(s) excluded"));
}
#[test]
fn raw_known_identity_must_match_file_and_large_sources_stream() {
    let dir = changed_repo();
    let root = dir.path();
    git(root, &["add", "entry"]);
    check(
        wrapped_scan(
            root,
            "if '--path=entry' in args: sys.stdout.write('f'*40+'\\n'); sys.exit(0)",
        ),
        2,
        0,
    );
    let dir = repo();
    let root = dir.path();
    git(root, &["commit", "--allow-empty", "-qm", "base"]);
    use std::io::Write;
    let mut file = fs::File::create(root.join("large")).unwrap();
    for _ in 0..11264 {
        file.write_all(&[b'x'; 1023]).unwrap();
        file.write_all(b"\n").unwrap();
    }
    writeln!(file, "{SECRET}").unwrap();
    drop(file);
    git(root, &["add", "large"]);
    check(scan(root, &[]), 1, 1);
    fs::write(root.join("large"), "x".repeat(1024 * 1024)).unwrap();
    check(scan(root, &[]), 2, 0);
}
#[test]
fn diff_scope_argument_conflicts_fail_without_echoing_values() {
    let dir = changed_repo();
    for args in [
        vec!["--diff"],
        vec!["--diff", "HEAD"],
        vec!["--staged"],
        vec!["--glob", "*"],
        vec!["entry"],
        vec!["--help"],
    ] {
        check(scan(dir.path(), &args), 2, 0);
    }
    for args in [
        vec!["scan", "--diff"],
        vec!["scan", "entry", "--diff", "HEAD"],
        vec!["scan", "--glob", "*", "--diff", "HEAD"],
        vec!["scan", "--diff", ""],
    ] {
        let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(dir.path()))
            .args(args)
            .output()
            .unwrap();
        check(out, 2, 0);
    }
}
#[test]
fn malformed_stream_framing_and_late_acquisition_errors_are_incomplete() {
    for script in [
        "if '--raw' in args: sys.stdout.buffer.write(b'partial'); sys.exit(0)",
        "if '--raw' in args: sys.stdout.buffer.write(b'header\\0partial'); sys.exit(0)",
        "if '--raw' in args:\n    if os.path.exists('second'): sys.stdout.buffer.write(b'partial'); sys.exit(0)\n    open('second','w').close()",
        "if '--raw' in args:\n    if os.path.exists('second'): sys.stdout.buffer.write(b'header\\0partial'); sys.exit(0)\n    open('second','w').close()",
        "if '--raw' in args:\n    if os.path.exists('second'): sys.exit(2)\n    open('second','w').close()",
        "if '--git-path' in args: sys.exit(2)",
        "if 'write-tree' in args: sys.exit(2)",
        "if '--verify' in args: sys.stdout.write('bad\\n');sys.exit(0)",
        "if '--path=entry' in args:\n    if os.path.exists('secondhash'):sys.exit(2)\n    open('secondhash','w').close()",
        "if 'hash-object' in args and not any(a.startswith('--path=') for a in args): os.unlink(sys.argv[0])",
        "if '--patch' in args:\n    sys.stdout.buffer.write(subprocess.check_output([real]+args));sys.exit(2)",
        "if '--patch' in args:\n    result=subprocess.check_output([real]+args)\n    os.symlink('entry','.rayloc.yaml')\n    sys.stdout.buffer.write(result);sys.exit(0)",
        "if '--git-path' in args:\n    os.makedirs('probe',exist_ok=True);sys.stdout.write('probe/index\\n');sys.exit(0)\nif '--patch' in args:\n    os.rmdir('probe');open('probe','w').close()",
        "if '--git-path' in args: sys.stdout.write('entry/child\\n'); sys.exit(0)",
        "if 'symbolic-ref' in args: sys.exit(2)",
        "if 'hash-object' in args and not any(a.startswith('--path=') for a in args): sys.exit(2)",
        "if 'hash-object' in args and not any(a.startswith('--path=') for a in args): sys.stdout.write('a'*64+'\\n');sys.exit(0)",
        "if '--raw' in args: os.unlink(sys.argv[0])",
        "if '--patch' in args: os.unlink(sys.argv[0])",
        "if '--path=entry' in args: os.unlink(sys.argv[0])",
        "if '--patch' in args:\n    result=subprocess.check_output([real]+args)\n    open('.rayloc.yaml','w').write('bad')\n    sys.stdout.buffer.write(result);sys.exit(0)",
        "if 'symbolic-ref' in args:\n    if os.path.exists('head'):sys.exit(2)\n    open('head','w').close()",
        "if 'write-tree' in args:\n    if os.path.exists('tree'):sys.exit(2)\n    open('tree','w').close()",
    ] {
        let dir = changed_repo();
        let out = wrapped_scan(dir.path(), script);
        assert_eq!(out.status.code(), Some(2), "script: {script}");
        assert!(!String::from_utf8(out.stdout).unwrap().contains(SECRET));
    }
}
#[test]
fn bad_worktree_policy_cannot_be_hidden_by_reference_diff() {
    for (file, bytes) in [
        (".raylocignore", "["),
        (
            ".rayloc.yaml",
            "version: \"1\"\nrules: [{id: c, regex: 'a*'}]\n",
        ),
        ("override", "bad"),
    ] {
        let dir = changed_repo();
        fs::write(
            dir.path().join(file),
            if file == ".raylocignore" {
                &[0xff]
            } else {
                bytes.as_bytes()
            },
        )
        .unwrap();
        check(
            scan(
                dir.path(),
                if file == "override" {
                    &["--config", "override"]
                } else {
                    &[]
                },
            ),
            2,
            0,
        );
    }
    let dir = changed_repo();
    let root = dir.path();
    fs::write(
        root.join(".rayloc.yaml"),
        "version: \"1\"\nrules: [{id: same,regex: 'foo'}]\n",
    )
    .unwrap();
    fs::write(
        root.join("override"),
        "version: \"1\"\nrules: [{id: same,regex: 'bar'}]\n",
    )
    .unwrap();
    check(scan(root, &["--config", "override"]), 2, 0);
}
#[test]
fn symlink_hash_failures_and_nonregular_secondary_policy_return_incomplete() {
    use std::os::unix::fs::symlink;
    for script in [
        "if 'hash-object' in args:\n    if os.path.exists('hashed'):sys.stdout.write('bad\\n');sys.exit(0)\n    open('hashed','w').close()",
        "if '--raw' in args:os.unlink(sys.argv[0])",
    ] {
        let dir = repo();
        let root = dir.path();
        symlink("safe", root.join("link")).unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "base"]);
        fs::remove_file(root.join("link")).unwrap();
        symlink(SECRET, root.join("link")).unwrap();
        check(wrapped_scan(root, script), 2, 0);
    }
    for policy in [".raylocignore", "override"] {
        let dir = changed_repo();
        fs::create_dir(dir.path().join(policy)).unwrap();
        check(
            scan(
                dir.path(),
                if policy == "override" {
                    &["--config", "override"]
                } else {
                    &[]
                },
            ),
            2,
            0,
        );
    }
}
#[test]
fn index_changes_cancelled_in_workspace_fail_closed_without_value_leak() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), format!("{SECRET}\n")).unwrap();
    git(root, &["add", "entry"]);
    git(root, &["commit", "-qm", "base"]);
    fs::write(root.join("entry"), "safe staged\n").unwrap();
    git(root, &["add", "entry"]);
    fs::write(root.join("entry"), format!("{SECRET}\n")).unwrap();
    let raw = git(root, &["diff", "--raw", "-z", "--no-abbrev", "HEAD", "--"]);
    assert!(raw.stdout.is_empty());
    assert!(
        git(root, &["diff", "--patch", "HEAD", "--"])
            .stdout
            .is_empty()
    );
    check(scan(root, &[]), 2, 0);
    // The incomplete scope must not be described as clean when another path changes.
    fs::write(root.join("added"), format!("{SECRET}\n")).unwrap();
    git(root, &["add", "added"]);
    let out = scan(root, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(SECRET));
}
