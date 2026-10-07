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
        .args(["scan", "--staged"])
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
    assert_eq!(text.matches("\nValue: ").count(), findings, "{text}");
    assert!(!text.contains(SECRET));
    assert!(!String::from_utf8(out.stderr).unwrap().contains(SECRET));
    text
}
#[test]
fn unborn_and_empty_index_and_partial_staging_scan_only_snapshot_additions() {
    let dir = repo();
    let root = dir.path();
    check(scan(root, &[]), 0, 0);
    fs::write(root.join("entry"), format!("safe\n{SECRET}\n")).unwrap();
    git(root, &["add", "entry"]);
    fs::write(root.join("entry"), "safe replacement\n").unwrap();
    let text = check(scan(root, &[]), 1, 1);
    assert!(text.contains(":2:"), "{text}");
    git(root, &["commit", "-qm", "initial"]);
    fs::write(root.join("entry"), "safe staged\n").unwrap();
    git(root, &["add", "entry"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    check(scan(root, &[]), 0, 0);
}
#[test]
fn staged_policy_ignores_unstaged_edits_and_gitignore_never_hides_forced_entries() {
    let dir = repo();
    let root = dir.path();
    fs::write(
        root.join(".rayloc.yaml"),
        "version: \"1\"\ndisabled_rules: [aws-access-key-id]\n",
    )
    .unwrap();
    fs::write(root.join(".raylocignore"), "excluded\n").unwrap();
    fs::write(root.join("excluded"), SECRET).unwrap();
    fs::write(root.join("visible"), SECRET).unwrap();
    git(root, &["add", "."]);
    fs::write(root.join(".rayloc.yaml"), "invalid").unwrap();
    fs::write(root.join(".raylocignore"), "visible\n").unwrap();
    check(scan(root, &[]), 0, 0);
    git(root, &["rm", "-f", "--cached", ".rayloc.yaml"]);
    fs::write(root.join(".gitignore"), "visible\n").unwrap();
    check(scan(root, &[]), 1, 1);
}
#[test]
fn staged_argument_conflicts_and_nonrepository_fail_safely() {
    let dir = repo();
    for args in [
        vec!["--staged"],
        vec!["."],
        vec!["--glob", "*"],
        vec!["--diff", "HEAD"],
        vec!["--help"],
    ] {
        check(scan(dir.path(), &args), 2, 0);
    }
    let outside = TempDir::new();
    check(scan(outside.path(), &[]), 2, 0);
}
#[test]
fn attributes_nul_quoted_paths_and_symlink_text_remain_visible() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let dir = repo();
    let root = dir.path();
    fs::write(root.join(".gitattributes"), "* -diff\n").unwrap();
    let names = [
        b"space b/name".to_vec(),
        b"quotes\"\\\t\n".to_vec(),
        b"binary".to_vec(),
    ];
    fs::create_dir(root.join("space b")).unwrap();
    for name in names {
        fs::write(
            root.join(std::ffi::OsString::from_vec(name)),
            format!("zero\0 {SECRET}\n"),
        )
        .unwrap();
    }
    symlink(SECRET, root.join("link")).unwrap();
    git(root, &["add", "."]);
    git(root, &["config", "diff.noprefix", "true"]);
    git(root, &["config", "diff.mnemonicPrefix", "true"]);
    git(root, &["config", "diff.context", "500"]);
    git(root, &["config", "diff.interHunkContext", "500"]);
    git(
        root,
        &["config", "diff.orderFile", "/nonexistent/private-path"],
    );
    git(
        root,
        &["config", "diff.external", "/nonexistent/private-helper"],
    );
    let text = check(scan(root, &[]), 1, 4);
    // Control characters withhold the path; printable paths are shown.
    assert!(!text.contains("quotes"));
    assert!(text.contains("\nFile: binary:1:"), "{text}");
    assert!(text.contains("\nFile: space b/name:1:"), "{text}");
    assert!(text.contains("\nFile: link:1:"), "{text}");
}
#[test]
fn rename_delete_mode_changes_and_type_changes_obey_added_lines() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let dir = repo();
    let root = dir.path();
    for name in ["rename", "delete", "mode", "type"] {
        fs::write(root.join(name), SECRET).unwrap();
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "initial"]);
    git(root, &["mv", "rename", "renamed"]);
    git(root, &["rm", "delete"]);
    fs::set_permissions(root.join("mode"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(root.join("type")).unwrap();
    symlink(SECRET, root.join("type")).unwrap();
    fs::write(root.join("empty"), "").unwrap();
    git(root, &["add", "."]);
    check(scan(root, &[]), 1, 2);
}
#[test]
fn submodule_short_format_is_excluded_but_gitlink_to_regular_scans() {
    let dir = repo();
    let root = dir.path();
    git(root, &["commit", "--allow-empty", "-qm", "base"]);
    let object = String::from_utf8(git(root, &["rev-parse", "HEAD"]).stdout).unwrap();
    git(
        root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},sub", object.trim()),
        ],
    );
    git(root, &["config", "diff.submodule", "log"]);
    git(root, &["config", "diff.ignoreSubmodules", "all"]);
    assert!(check(scan(root, &[]), 0, 0).contains("1 file(s) excluded"));
    git(root, &["config", "diff.ignoreSubmodules", "none"]);
    git(root, &["commit", "-qm", "sub"]);
    fs::write(root.join("sub"), SECRET).unwrap();
    git(root, &["add", "sub"]);
    check(scan(root, &[]), 1, 1);
    git(root, &["commit", "-qm", "regular"]);
    git(
        root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},sub", object.trim()),
        ],
    );
    assert!(check(scan(root, &[]), 0, 0).contains("1 file(s) excluded"));
    git(root, &["commit", "-qm", "gitlink"]);
    git(root, &["rm", "--cached", "sub"]);
    assert!(check(scan(root, &[]), 0, 0).contains("1 file(s) excluded"));
}
#[test]
fn alternate_index_and_linked_worktree_use_the_active_git_context() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), "safe\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let index = root.join("alternate");
    fs::copy(root.join(".git/index"), &index).unwrap();
    fs::write(root.join("entry"), SECRET).unwrap();
    assert!(
        isolated(Command::new("git").current_dir(root))
            .env("GIT_INDEX_FILE", "alternate")
            .args(["add", "entry"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .env("GIT_INDEX_FILE", "alternate")
        .args(["scan", "--staged"])
        .output()
        .unwrap();
    check(out, 1, 1);
    check(scan(root, &[]), 0, 0);
    let linked = root.join("linked");
    git(
        root,
        &["worktree", "add", "-qb", "linked", linked.to_str().unwrap()],
    );
    fs::write(linked.join("entry"), SECRET).unwrap();
    git(&linked, &["add", "entry"]);
    fs::create_dir(linked.join("nested")).unwrap();
    check(scan(&linked.join("nested"), &[]), 1, 1);
}
#[test]
fn unmerged_index_and_malformed_or_symlink_policy_return_error() {
    use std::os::unix::fs::symlink;
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), "base\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    git(root, &["checkout", "-qb", "other"]);
    fs::write(root.join("entry"), "other\n").unwrap();
    git(root, &["commit", "-qam", "other"]);
    git(root, &["checkout", "-q", "-"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    git(root, &["commit", "-qam", "ours"]);
    assert!(
        !isolated(Command::new("git").current_dir(root))
            .args(["merge", "other"])
            .output()
            .unwrap()
            .status
            .success()
    );
    check(scan(root, &[]), 2, 0);
    git(root, &["merge", "--abort"]);
    fs::write(root.join(".rayloc.yaml"), "bad").unwrap();
    git(root, &["add", ".rayloc.yaml"]);
    check(scan(root, &[]), 2, 0);
    fs::remove_file(root.join(".rayloc.yaml")).unwrap();
    symlink("entry", root.join(".rayloc.yaml")).unwrap();
    git(root, &["add", ".rayloc.yaml"]);
    check(scan(root, &[]), 2, 0);
}
#[test]
fn explicit_configuration_merges_and_inline_switch_applies_in_staged_mode() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), format!("{SECRET} # rayloc:ignore\n")).unwrap();
    git(root, &["add", "entry"]);
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
}
#[test]
fn detached_head_and_sha256_repositories_are_supported() {
    let dir = repo();
    let root = dir.path();
    git(root, &["commit", "--allow-empty", "-qm", "base"]);
    git(root, &["checkout", "--detach", "-q"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    git(root, &["add", "entry"]);
    check(scan(root, &[]), 1, 1);
    let sha = TempDir::new();
    let out = isolated(Command::new("git").current_dir(sha.path()))
        .args(["init", "-q", "--object-format=sha256"])
        .output()
        .unwrap();
    if !out.status.success() {
        return;
    }
    fs::write(sha.path().join("entry"), SECRET).unwrap();
    git(sha.path(), &["add", "entry"]);
    check(scan(sha.path(), &[]), 1, 1);
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
        .args(["scan", "--staged"])
        .output()
        .unwrap()
}
#[test]
fn concurrent_index_and_head_mutations_cannot_report_complete() {
    for mutation in [
        "open('entry', 'w').write('clean'); subprocess.run([real, 'add', 'entry'], check=True)",
        "subprocess.run([real, 'symbolic-ref', 'HEAD', 'refs/heads/other'], check=True)",
    ] {
        let dir = repo();
        let root = dir.path();
        git(root, &["commit", "--allow-empty", "-qm", "base"]);
        git(root, &["branch", "other"]);
        fs::write(root.join("entry"), SECRET).unwrap();
        git(root, &["add", "entry"]);
        let script = format!("if 'diff' in args and '--patch' in args:\n    {mutation}");
        check(wrapped_scan(root, &script), 2, 1);
    }
}
#[test]
fn child_failure_discards_large_stderr_and_preserves_error_precedence() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), SECRET).unwrap();
    git(root, &["add", "entry"]);
    let script = format!(
        "if 'diff' in args and '--patch' in args:\n    subprocess.run([real] + args, check=True)\n    sys.stderr.write('{SECRET}' * 100000)\n    sys.exit(23)"
    );
    check(wrapped_scan(root, &script), 2, 1);
}
#[test]
fn excluded_bindings_still_require_complete_patch_and_both_streams() {
    for script in [
        "if 'diff' in args and '--patch' in args:\n    sys.exit(0)",
        "if 'diff' in args and '--raw' in args:\n    sys.exit(0)",
        "if 'diff' in args and '--patch' in args:\n    subprocess.run([real] + args, check=True)\n    sys.stdout.write('invalid framing\\n')\n    sys.exit(0)",
    ] {
        let dir = repo();
        let root = dir.path();
        fs::write(root.join(".raylocignore"), "entry\n").unwrap();
        fs::write(root.join("entry"), SECRET).unwrap();
        git(root, &["add", "."]);
        check(wrapped_scan(root, script), 2, 0);
    }
}
#[test]
fn malformed_git_control_records_and_policy_objects_fail_safely() {
    // These replace only the external Git boundary. Every invocation otherwise
    // uses a real repository and real Git; malformed protocol must not pass.
    let cases = [
        ("'symbolic-ref' in args", "sys.exit(2)"),
        (
            "'symbolic-ref' in args",
            "sys.stdout.write('not-a-ref\\n'); sys.exit(0)",
        ),
        ("'HEAD^{commit}' in args", "sys.exit(2)"),
        (
            "'HEAD^{commit}' in args",
            "sys.stdout.write('bad\\n'); sys.exit(0)",
        ),
        ("'show-ref' in args", "sys.exit(2)"),
        ("'--git-path' in args", "sys.exit(2)"),
        (
            "'--show-toplevel' in args",
            "sys.stdout.write('bad'); sys.exit(0)",
        ),
        ("'mktree' in args", "sys.exit(2)"),
        ("'hash-object' in args", "sys.exit(2)"),
        (
            "'hash-object' in args",
            "sys.stdout.write('1' * 64 + '\\n'); sys.exit(0)",
        ),
        ("'ls-tree' in args", "sys.exit(2)"),
        (
            "'ls-tree' in args",
            "sys.stdout.write('no tab'); sys.exit(0)",
        ),
        (
            "'ls-tree' in args",
            "sys.stdout.write('100644 blob ' + '1'*40 + '\\twrong\\0'); sys.exit(0)",
        ),
        (
            "'ls-tree' in args",
            "sys.stdout.write('100644 blob\\t.rayloc.yaml\\0'); sys.exit(0)",
        ),
        (
            "'ls-tree' in args",
            "sys.stdout.write('100644 blob abc\\t.rayloc.yaml\\0'); sys.exit(0)",
        ),
        (
            "'ls-tree' in args",
            "sys.stdout.write('100644 blob ' + 'z'*40 + '\\t.rayloc.yaml\\0'); sys.exit(0)",
        ),
        ("'cat-file' in args", "sys.exit(2)"),
        (
            "'cat-file' in args",
            "sys.stdout.write('x' * (1024*1024+1)); sys.exit(0)",
        ),
        (
            "'ls-tree' in args and '.raylocignore' in args",
            "sys.exit(2)",
        ),
        (
            "'diff' in args and '--raw' in args",
            "subprocess.run([real]+args, check=True); sys.exit(2)",
        ),
    ];
    for (condition, action) in cases {
        let dir = repo();
        let root = dir.path();
        fs::write(root.join(".rayloc.yaml"), "version: \"1\"\n").unwrap();
        git(root, &["add", ".rayloc.yaml"]);
        check(
            wrapped_scan(root, &format!("if {condition}:\n    {action}")),
            2,
            0,
        );
    }
}
#[test]
fn force_added_ignored_file_and_bad_explicit_policies_obey_scope() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join(".gitignore"), "private\n").unwrap();
    fs::write(root.join("private"), SECRET).unwrap();
    git(root, &["add", "-f", "private"]);
    check(scan(root, &[]), 1, 1);
    for text in ["bad", "version: \"1\"\nrules: [{id: c, regex: 'a*'}]\n"] {
        fs::write(root.join("override"), text).unwrap();
        check(scan(root, &["--config", "override"]), 2, 0);
    }
    fs::write(
        root.join(".rayloc.yaml"),
        "version: \"1\"\nrules: [{id: c, regex: 'x'}]\n",
    )
    .unwrap();
    git(root, &["add", ".rayloc.yaml"]);
    fs::write(
        root.join("override"),
        "version: \"1\"\nrules: [{id: c, regex: 'y'}]\n",
    )
    .unwrap();
    check(scan(root, &["--config", "override"]), 2, 0);
    fs::write(root.join(".raylocignore"), b"\xff").unwrap();
    git(root, &["add", ".raylocignore"]);
    check(scan(root, &[]), 2, 0);
}
#[test]
fn control_record_overflow_and_late_acquisition_failure_are_incomplete() {
    for condition in [
        "'symbolic-ref' in args",
        "'HEAD^{commit}' in args",
        "'show-ref' in args",
    ] {
        let dir = repo();
        let script =
            format!("if {condition}:\n    sys.stdout.write('x' * (1024*1024+1)); sys.exit(0)");
        check(wrapped_scan(dir.path(), &script), 2, 0);
    }
    let dir = repo();
    let root = dir.path();
    git(root, &["commit", "--allow-empty", "-qm", "base"]);
    check(
        wrapped_scan(
            root,
            "if any(arg.endswith('^{tree}') for arg in args):\n    sys.exit(2)",
        ),
        2,
        0,
    );
    let dir = repo();
    let root = dir.path();
    check(
        wrapped_scan(
            root,
            "if 'ls-tree' in args and '.raylocignore' in args:\n    os.unlink(sys.argv[0])",
        ),
        2,
        0,
    );
    let dir = repo();
    let root = dir.path();
    check(
        wrapped_scan(
            root,
            "if 'write-tree' in args:\n    if os.path.exists('wrote-tree'): sys.exit(2)\n    open('wrote-tree', 'w').close()",
        ),
        2,
        0,
    );
    let dir = repo();
    let root = dir.path();
    check(
        wrapped_scan(
            root,
            "if 'symbolic-ref' in args:\n    if os.path.exists('read-head'): sys.exit(2)\n    open('read-head', 'w').close()",
        ),
        2,
        0,
    );
    let dir = repo();
    let root = dir.path();
    // A malformed Git-supplied index path must fail before scanning.
    check(
        wrapped_scan(
            root,
            "if '--git-path' in args:\n    sys.stdout.write('.git/HEAD/child\\n'); sys.exit(0)",
        ),
        2,
        0,
    );
}
#[test]
fn unchanged_secrets_and_all_excluded_diffs_are_not_scanned() {
    let dir = repo();
    let root = dir.path();
    fs::write(root.join("entry"), format!("{SECRET}\n")).unwrap();
    fs::write(root.join(".raylocignore"), "excluded\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    fs::write(root.join("entry"), format!("{SECRET}\nsafe addition\n")).unwrap();
    git(root, &["add", "entry"]);
    check(scan(root, &[]), 0, 0);
    git(root, &["commit", "-qm", "safe"]);
    fs::write(root.join("excluded"), SECRET).unwrap();
    git(root, &["add", "excluded"]);
    assert!(check(scan(root, &[]), 0, 0).contains("EXCLUDED"));
}
#[test]
fn large_files_and_single_line_records_are_scanned_completely() {
    let dir = repo();
    let root = dir.path();
    use std::io::Write;
    let mut file = fs::File::create(root.join("large")).unwrap();
    let line = format!("{}\n", "x".repeat(1023));
    for _ in 0..11264 {
        file.write_all(line.as_bytes()).unwrap();
    }
    writeln!(file, "{SECRET}").unwrap();
    drop(file);
    git(root, &["add", "large"]);
    check(scan(root, &[]), 1, 1);
    let mut file = fs::File::create(root.join("large-minified")).unwrap();
    let block = vec![b'x'; 256 * 1024];
    for _ in 0..41 {
        file.write_all(&block).unwrap();
    }
    writeln!(file, ",\"{SECRET}\"").unwrap();
    drop(file);
    git(root, &["add", "large-minified"]);
    let text = check(scan(root, &[]), 1, 2);
    assert!(text.contains("large:11265:1"), "{text}");
    assert!(text.contains("large-minified:1:"), "{text}");
}
#[test]
fn index_path_becoming_unreadable_during_acquisition_is_incomplete() {
    let dir = repo();
    let root = dir.path();
    fs::create_dir(root.join("probe")).unwrap();
    check(
        wrapped_scan(
            root,
            "if '--git-path' in args:\n    sys.stdout.write('probe/index\\n'); sys.exit(0)\nif 'diff' in args and '--patch' in args:\n    os.rmdir('probe'); open('probe', 'w').close()",
        ),
        2,
        0,
    );
}
fn nested_policy_repository(linked: bool) -> (TempDir, std::path::PathBuf) {
    let dir = repo();
    let root = if linked {
        git(dir.path(), &["commit", "--allow-empty", "-qm", "base"]);
        let root = dir.path().join("linked");
        git(
            dir.path(),
            &["worktree", "add", "-qb", "linked", root.to_str().unwrap()],
        );
        root
    } else {
        dir.path().to_path_buf()
    };
    fs::create_dir(root.join("nested")).unwrap();
    (dir, root)
}
fn assert_nested_root_policy(linked: bool, case: &str) {
    let (_dir, root) = nested_policy_repository(linked);
    let (status, findings) = match case {
        "custom" | "conflicting" => {
            fs::write(
                root.join(".rayloc.yaml"),
                "version: \"1\"\nrules: [{id: root-custom, regex: '^ROOT_CUSTOM_VALUE$'}]\n",
            )
            .unwrap();
            fs::write(root.join("visible"), "ROOT_CUSTOM_VALUE\n").unwrap();
            if case == "conflicting" {
                fs::write(root.join(".raylocignore"), "excluded\n").unwrap();
                fs::write(root.join("excluded"), SECRET).unwrap();
                fs::write(
                    root.join("nested/.rayloc.yaml"),
                    "version: \"1\"\ndisabled_rules: [aws-access-key-id]\n",
                )
                .unwrap();
                fs::write(root.join("nested/.raylocignore"), "visible\n").unwrap();
            }
            (1, 1)
        }
        "ignore" => {
            fs::write(root.join(".raylocignore"), "excluded\n").unwrap();
            fs::write(root.join("excluded"), SECRET).unwrap();
            (0, 0)
        }
        "invalid" => {
            fs::write(root.join(".rayloc.yaml"), "invalid root policy\n").unwrap();
            fs::write(root.join("nested/.rayloc.yaml"), "version: \"1\"\n").unwrap();
            (2, 0)
        }
        _ => unreachable!(),
    };
    git(&root, &["add", "."]);
    check(scan(&root, &[]), status, findings);
    let result = check(scan(&root.join("nested"), &[]), status, findings);
    if findings != 0 {
        assert!(result.contains("Custom rule #"), "{result}");
    }
}
#[test]
fn nested_ordinary_invocation_uses_root_custom_rule() {
    assert_nested_root_policy(false, "custom");
}
#[test]
fn nested_linked_invocation_uses_root_custom_rule() {
    assert_nested_root_policy(true, "custom");
}
#[test]
fn nested_ordinary_invocation_uses_root_ignore() {
    assert_nested_root_policy(false, "ignore");
}
#[test]
fn nested_linked_invocation_uses_root_ignore() {
    assert_nested_root_policy(true, "ignore");
}
#[test]
fn nested_ordinary_policy_cannot_replace_root_policy() {
    assert_nested_root_policy(false, "conflicting");
}
#[test]
fn nested_linked_policy_cannot_replace_root_policy() {
    assert_nested_root_policy(true, "conflicting");
}
#[test]
fn nested_ordinary_invocation_cannot_bypass_invalid_root_config() {
    assert_nested_root_policy(false, "invalid");
}
#[test]
fn nested_linked_invocation_cannot_bypass_invalid_root_config() {
    assert_nested_root_policy(true, "invalid");
}
