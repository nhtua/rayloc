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
        .env_remove("GIT_INDEX_FILE")
        .output()
        .unwrap()
}
fn git(root: &TempDir, args: &[&str]) {
    assert!(
        Command::new("git")
            .current_dir(root.path())
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .unwrap()
            .success()
    );
}
fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn secret(root: &TempDir, path: &str) {
    let path = root.path().join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "ghp_abcdefghijklmnop\n").unwrap();
}

#[test]
fn omitted_directory_and_brace_globs_include_hidden_and_lockfiles() {
    let root = TempDir::new();
    for path in [
        ".env",
        "Cargo.lock",
        "nested/a.rs",
        "nested/b.toml",
        "node_modules/key",
    ] {
        secret(&root, path);
    }
    for args in [vec!["scan"], vec!["scan", "."]] {
        let output = run(&root, &args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text(&output).contains("5 finding(s)"));
        assert!(!text(&output).contains("abcdefghijklmnop"));
    }
    for args in [
        vec!["scan", "--glob", "**/*.{rs,toml}"],
        vec!["scan", "**/*.{rs,toml}"],
    ] {
        let output = run(&root, &args);
        assert_eq!(output.status.code(), Some(1));
        assert!(text(&output).contains("2 finding(s)"));
    }
    fs::create_dir(root.path().join("empty")).unwrap();
    assert_eq!(run(&root, &["scan", "empty"]).status.code(), Some(0));
}

#[test]
fn git_tracked_exceptions_nested_policy_and_scanner_priority_are_preserved() {
    let root = TempDir::new();
    git(&root, &["init", "--quiet"]);
    for path in [
        ".env",
        "forced/key.env",
        "untracked.env",
        "nested/keep.env",
        "nested/drop.env",
        "Cargo.lock",
    ] {
        secret(&root, path);
    }
    fs::write(root.path().join(".gitignore"), "*.env\nforced/\n").unwrap();
    fs::write(root.path().join("nested/.gitignore"), "!keep.env\n").unwrap();
    git(&root, &["add", "--force", ".env", "forced/key.env"]);
    fs::write(root.path().join(".ignore"), "Cargo.lock\n").unwrap();
    fs::write(root.path().join(".git/info/exclude"), "Cargo.lock\n").unwrap();
    let output = run(&root, &["scan", "."]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).contains("4 finding(s)"), "{}", text(&output));
    fs::write(
        root.path().join(".raylocignore"),
        "!untracked.env\nforced/\n!forced/key.env\n",
    )
    .unwrap();
    let output = run(&root, &["scan", "."]);
    assert!(text(&output).contains("4 finding(s)"), "{}", text(&output));
    assert_eq!(
        run(&root, &["scan", "forced/key.env"]).status.code(),
        Some(0)
    );
    fs::write(
        root.path().join(".raylocignore"),
        "!forced/\n!untracked.env\n",
    )
    .unwrap();
    assert!(text(&run(&root, &["scan", "."])).contains("5 finding(s)"));
}

#[test]
fn scanner_whitelist_reopens_git_parent_only_when_parent_is_reincluded() {
    let root = TempDir::new();
    secret(&root, "private/key.env");
    fs::write(root.path().join(".gitignore"), "private/\n").unwrap();
    fs::write(root.path().join(".raylocignore"), "!private/key.env\n").unwrap();
    assert_eq!(run(&root, &["scan", "."]).status.code(), Some(0));
    fs::write(
        root.path().join(".raylocignore"),
        "!private/\n!private/key.env\n",
    )
    .unwrap();
    assert_eq!(run(&root, &["scan", "."]).status.code(), Some(1));
    // Explicit selection bypasses Git policy outside Git too.
    fs::write(root.path().join(".raylocignore"), "").unwrap();
    assert_eq!(
        run(&root, &["scan", "private/key.env"]).status.code(),
        Some(1)
    );
}

#[test]
fn glob_counts_regular_matches_before_exclusions_and_checks_conflicts() {
    let root = TempDir::new();
    secret(&root, "a.env");
    fs::write(root.path().join(".raylocignore"), "*.env\n").unwrap();
    let output = run(&root, &["scan", "--glob", "*.env"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output).contains("EXCLUDED"));
    assert!(text(&output).contains("0 of 0 file(s) completed"));
    for args in [
        vec!["scan", "--glob", "*.missing"],
        vec!["scan", "--glob", "[z-a]"],
        vec!["scan", "--glob", "../*"],
        vec!["scan", "--glob", "*", "."],
        vec!["scan", "--glob", "*", "--glob", "*"],
    ] {
        assert_eq!(run(&root, &args).status.code(), Some(2));
    }
    secret(&root, "literal*name");
    assert_eq!(run(&root, &["scan", "literal*name"]).status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn symlinks_admin_and_nonregular_entries_are_excluded_without_traversal() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new();
    let external = TempDir::new();
    secret(&external, "key");
    symlink(external.path(), root.path().join("linked")).unwrap();
    symlink(external.path().join("key"), root.path().join("key-link")).unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    // An empty .git is tolerated outside Git, but its contents are excluded.
    let output = run(&root, &["scan", "."]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output).contains("3 file(s) excluded"));
    assert_eq!(run(&root, &["scan", "linked/key"]).status.code(), Some(1));
    for target in ["linked", "key-link"] {
        assert_eq!(run(&root, &["scan", target]).status.code(), Some(2));
    }
    assert_eq!(
        run(&root, &["scan", "--glob", "*link*"]).status.code(),
        Some(2)
    );
}

#[test]
fn selected_git_subdirectory_keeps_root_config_and_inherited_ignores() {
    let root = TempDir::new();
    git(&root, &["init", "--quiet"]);
    secret(&root, "sub/.env");
    secret(&root, "sub/keep");
    secret(&root, "outside");
    fs::write(root.path().join(".gitignore"), "*.env\n").unwrap();
    fs::write(root.path().join("sub/.rayloc.yaml"), "invalid").unwrap();
    let output = run(&root, &["scan", "sub"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).contains("1 finding(s)"));
    fs::write(
        root.path().join(".rayloc.yaml"),
        "version: \"1\"\ndisabled_rules: [github-token]",
    )
    .unwrap();
    assert_eq!(run(&root, &["scan", "sub"]).status.code(), Some(0));
}

#[test]
fn source_numbers_follow_raw_path_bytes_including_directory_separator() {
    let root = TempDir::new();
    for path in ["a/x", "a.txt", "a0", "z"] {
        secret(&root, path);
    }
    fs::write(root.path().join(".raylocignore"), "a0\n").unwrap();
    let output = run(&root, &["scan", "."]);
    assert_eq!(output.status.code(), Some(1));
    let text = text(&output);
    // .raylocignore is #1, a.txt #2, a/x #3, excluded a0 #4, z #5.
    let positions =
        ["source #2:1:1", "source #3:1:1", "source #5:1:1"].map(|s| text.find(s).unwrap());
    assert!(positions[0] < positions[1] && positions[1] < positions[2]);
}
#[cfg(unix)]
#[test]
fn nonutf8_and_newline_paths_and_duplicate_index_stages_keep_raw_order() {
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;
    let root = TempDir::new();
    git(&root, &["init", "--quiet"]);
    for bytes in [b"a\nkey".as_slice(), b"z\xffkey"] {
        fs::write(
            root.path()
                .join(std::ffi::OsString::from_vec(bytes.to_vec())),
            "ghp_abcdefghijklmnop",
        )
        .unwrap();
    }
    git(&root, &["add", "."]);
    let hash = Command::new("git")
        .current_dir(root.path())
        .args(["hash-object", "-w", "--stdin"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let oid = String::from_utf8(hash.stdout).unwrap();
    let mut child = Command::new("git")
        .current_dir(root.path())
        .args(["update-index", "--index-info"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    write!(
        child.stdin.take().unwrap(),
        "100644 {} 1\tconflict\n100644 {} 2\tconflict\n",
        oid.trim(),
        oid.trim()
    )
    .unwrap();
    assert!(child.wait().unwrap().success());
    secret(&root, "conflict");
    fs::write(root.path().join(".gitignore"), "*\n").unwrap();
    let out = run(&root, &["scan", "."]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("3 finding(s)"));
    assert!(!text(&out).contains("key"));
}
#[test]
fn internal_git_administration_is_excluded_during_recursive_discovery() {
    let root = TempDir::new();
    git(&root, &["init", "--quiet", "--separate-git-dir=admin"]);
    secret(&root, "admin/secret");
    secret(&root, "key");
    let out = run(&root, &["scan", "."]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("1 finding(s)"));
    assert_eq!(run(&root, &["scan", "admin/secret"]).status.code(), Some(2));
}
#[cfg(unix)]
#[test]
fn malformed_child_metadata_and_admin_paths_fail_with_fixed_diagnostics() {
    use std::os::unix::fs::PermissionsExt;
    let root = TempDir::new();
    git(&root, &["init", "--quiet"]);
    secret(&root, "z");
    let real = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .unwrap();
    let real = String::from_utf8(real.stdout).unwrap();
    let shim = TempDir::new();
    let executable = shim.path().join("git");
    for script in [
        "case \"$*\" in *--git-common-dir*) /bin/rm \"$0\"; exec REAL \"$@\";; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *--show-toplevel*) /bin/rm \"$0\"; exec REAL \"$@\";; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *ls-files*) printf 'a\\000b\\000a\\000';; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *ls-files*) printf 'bad';; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *ls-files*) printf 'zz\\000yy\\000';; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *ls-files*) printf 'private-child-stderr' >&2; exit 1;; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *--git-dir*) printf 'private-child-stderr' >&2; exit 1;; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *--git-dir*) printf 'no-newline';; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *--git-dir*) i=0; while [ $i -lt 17000 ]; do printf x; i=$((i+1)); done;; *) exec REAL \"$@\";; esac",
        "case \"$*\" in *--show-toplevel*) printf 'relative\\n';; *) exec REAL \"$@\";; esac",
    ] {
        fs::write(
            &executable,
            format!("#!/bin/sh\n{}\n", script.replace("REAL", real.trim())),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_rayloc"))
            .current_dir(root.path())
            .args(["scan", "."])
            .env("PATH", shim.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(
            !String::from_utf8(out.stderr.clone())
                .unwrap()
                .contains("private-child-stderr")
        );
        assert!(!text(&out).contains("private-child-stderr"));
    }
}
#[cfg(unix)]
#[test]
fn deleted_current_directory_is_a_safe_discovery_error() {
    let root = TempDir::new();
    fs::create_dir(root.path().join("gone")).unwrap();
    let out = Command::new("sh")
        .current_dir(root.path())
        .args([
            "-c",
            "cd gone && rmdir ../gone && exec \"$1\" scan",
            "sh",
            env!("CARGO_BIN_EXE_rayloc"),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8(out.stderr).unwrap().contains("gone"));
}
#[test]
fn repository_globs_are_root_relative_and_ignore_only_selected_policy_sources() {
    let root = TempDir::new();
    git(&root, &["init", "--quiet"]);
    secret(&root, "key.env");
    fs::create_dir(root.path().join("sub")).unwrap();
    let external = TempDir::new();
    fs::write(external.path().join("global-ignore"), "*.env\n").unwrap();
    let status = Command::new("git")
        .current_dir(root.path())
        .args(["config", "core.excludesFile"])
        .arg(external.path().join("global-ignore"))
        .status()
        .unwrap();
    assert!(status.success());
    let out = Command::new(env!("CARGO_BIN_EXE_rayloc"))
        .current_dir(root.path().join("sub"))
        .args(["scan", "--glob", "*.env"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("1 finding(s)"));
}
