#![cfg(unix)]
mod support;
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
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
fn path() -> OsString {
    std::env::join_paths(
        std::iter::once(
            Path::new(env!("CARGO_BIN_EXE_rayloc"))
                .parent()
                .unwrap()
                .to_owned(),
        )
        .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap()
}
fn git(root: &Path, args: &[&str]) -> Output {
    isolated(Command::new("git").current_dir(root))
        .env("PATH", path())
        .args(args)
        .output()
        .unwrap()
}
fn ok_git(root: &Path, args: &[&str]) {
    assert!(git(root, args).status.success(), "fixture {args:?}");
}
fn repo() -> TempDir {
    let dir = TempDir::new();
    ok_git(dir.path(), &["init", "-q", "--template="]);
    for (key, value) in [
        ("user.name", "Fixture"),
        ("user.email", "fixture@example.invalid"),
        ("core.attributesFile", "/dev/null"),
        ("core.excludesFile", "/dev/null"),
    ] {
        ok_git(dir.path(), &["config", key, value]);
    }
    dir
}
fn install(root: &Path) -> Output {
    isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .env("PATH", path())
        .args(["hook", "install"])
        .output()
        .unwrap()
}
fn check(out: Output, code: i32) -> String {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains(SECRET));
    text
}
#[test]
fn managed_hook_is_executable_idempotent_and_propagates_actual_scan_status() {
    let dir = repo();
    let root = dir.path();
    check(install(root), 0);
    let hook = root.join(".git/hooks/pre-commit");
    assert_ne!(fs::metadata(&hook).unwrap().permissions().mode() & 0o111, 0);
    let inode = fs::metadata(&hook).unwrap().ino();
    check(install(root), 0);
    assert_eq!(fs::metadata(&hook).unwrap().ino(), inode);
    ok_git(root, &["commit", "--allow-empty", "-qm", "empty"]);
    fs::write(root.join("entry"), "safe\n").unwrap();
    ok_git(root, &["add", "entry"]);
    ok_git(root, &["commit", "-qm", "clean"]);
    fs::write(root.join("entry"), SECRET).unwrap();
    ok_git(root, &["add", "entry"]);
    let run_hook = || {
        isolated(Command::new(&hook).current_dir(root))
            .env("PATH", path())
            .output()
            .unwrap()
    };
    check(run_hook(), 1);
    assert!(!git(root, &["commit", "-qm", "finding"]).status.success());
    fs::write(root.join(".rayloc.yaml"), "invalid").unwrap();
    ok_git(root, &["add", ".rayloc.yaml"]);
    check(run_hook(), 2);
    assert!(!git(root, &["commit", "-qm", "error"]).status.success());
}

#[test]
fn long_line_hook_blocks_findings_and_incomplete_legacy_rules_then_allows_clean_commit() {
    use std::io::Write;

    const CUSTOM_VALUE: &str = "LEGACY_SECRET_SYNTHETIC_VALUE";
    let dir = repo();
    let root = dir.path();
    ok_git(root, &["commit", "--allow-empty", "-qm", "base"]);
    check(install(root), 0);

    let mut large = fs::File::create(root.join("minified.js")).unwrap();
    let block = vec![b'x'; 256 * 1024];
    for _ in 0..41 {
        large.write_all(&block).unwrap();
    }
    writeln!(large, ",\"{SECRET}\"").unwrap();
    drop(large);
    ok_git(root, &["add", "minified.js"]);
    check(git(root, &["commit", "-qm", "finding"]), 1);
    fs::remove_file(root.join("minified.js")).unwrap();
    ok_git(root, &["add", "-u", "minified.js"]);

    fs::write(
        root.join(".rayloc.yaml"),
        "version: \"1\"\nrules:\n  - id: legacy-rule\n    regex: 'LEGACY_SECRET_[A-Z_]+'\n",
    )
    .unwrap();
    let mut legacy = fs::File::create(root.join("legacy.js")).unwrap();
    for _ in 0..5 {
        legacy.write_all(&block).unwrap();
    }
    writeln!(legacy, ",\"{CUSTOM_VALUE}\"").unwrap();
    drop(legacy);
    ok_git(root, &["add", ".rayloc.yaml", "legacy.js"]);
    let hook = root.join(".git/hooks/pre-commit");
    let incomplete = isolated(Command::new(&hook).current_dir(root))
        .env("PATH", path())
        .output()
        .unwrap();
    check(incomplete, 2);
    assert!(
        !git(root, &["commit", "-qm", "incomplete custom rule"])
            .status
            .success()
    );

    fs::write(root.join(".rayloc.yaml"), "version: \"1\"\n").unwrap();
    let mut clean = fs::File::create(root.join("clean.js")).unwrap();
    for _ in 0..41 {
        clean.write_all(&block).unwrap();
    }
    clean.write_all(b",\"ordinary value\"\n").unwrap();
    drop(clean);
    ok_git(root, &["add", ".rayloc.yaml", "clean.js"]);
    check(git(root, &["commit", "-qm", "clean large line"]), 0);
}
#[test]
fn active_relative_absolute_and_linked_hooks_paths_are_used_from_nested_callers() {
    for linked in [false, true] {
        for custom in [None, Some("relative"), Some("absolute")] {
            let dir = repo();
            let original = dir.path();
            ok_git(original, &["commit", "--allow-empty", "-qm", "base"]);
            let root = if linked {
                let p = original.join("linked");
                ok_git(
                    original,
                    &["worktree", "add", "-qb", "linked", p.to_str().unwrap()],
                );
                p
            } else {
                original.to_owned()
            };
            let target = match custom {
                Some("relative") => {
                    ok_git(&root, &["config", "core.hooksPath", "custom hooks"]);
                    root.join("custom hooks")
                }
                Some(_) => {
                    let p = original.join("shared hooks");
                    ok_git(&root, &["config", "core.hooksPath", p.to_str().unwrap()]);
                    p
                }
                None => original.join(".git/hooks"),
            };
            fs::create_dir(root.join("nested")).unwrap();
            check(install(&root.join("nested")), 0);
            assert!(target.join("pre-commit").is_file());
            ok_git(&root, &["commit", "--allow-empty", "-qm", "clean"]);
            fs::write(root.join("entry"), SECRET).unwrap();
            ok_git(&root, &["add", "entry"]);
            assert!(!git(&root, &["commit", "-qm", "blocked"]).status.success());
            if custom.is_some() {
                assert!(!original.join(".git/hooks/pre-commit").exists());
            }
            if linked && custom == Some("absolute") {
                check(install(original), 0);
                ok_git(
                    original,
                    &["commit", "--allow-empty", "-qm", "shared clean"],
                );
                fs::write(original.join("other-entry"), SECRET).unwrap();
                ok_git(original, &["add", "other-entry"]);
                check(git(original, &["commit", "-qm", "shared blocked"]), 1);
            }
        }
    }
}
#[test]
fn unmanaged_and_symlink_hooks_are_preserved_with_safe_manual_guidance() {
    for kind in ["regular", "symlink", "directory", "large"] {
        let dir = repo();
        let root = dir.path();
        fs::create_dir_all(root.join(".git/hooks")).unwrap();
        let hook = root.join(".git/hooks/pre-commit");
        match kind {
            "symlink" => symlink("missing", &hook).unwrap(),
            "directory" => fs::create_dir(&hook).unwrap(),
            "large" => fs::write(&hook, vec![b'x'; 11 * 1024 * 1024]).unwrap(),
            _ => fs::write(&hook, SECRET).unwrap(),
        };
        let before = fs::symlink_metadata(&hook).unwrap();
        let text = check(install(root), 2);
        assert!(text.contains("rayloc scan --staged"));
        assert_eq!(fs::symlink_metadata(&hook).unwrap().ino(), before.ino());
        if kind == "regular" {
            assert_eq!(fs::read_to_string(&hook).unwrap(), SECRET);
        }
    }
}
#[test]
fn missing_scanner_nonrepository_invalid_args_and_unwritable_destination_fail_safely() {
    let dir = repo();
    let root = dir.path();
    let tools = root.join("tools");
    fs::create_dir(&tools).unwrap();
    let git_binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("git"))
        .find(|p| p.is_file())
        .unwrap();
    symlink(git_binary, tools.join("git")).unwrap();
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .env("PATH", &tools)
        .args(["hook", "install"])
        .output()
        .unwrap();
    assert!(check(out, 2).contains("PATH"));
    assert!(!root.join(".git/hooks/pre-commit").exists());
    fs::write(tools.join("rayloc"), "not executable").unwrap();
    check(
        isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
            .env("PATH", &tools)
            .args(["hook", "install"])
            .output()
            .unwrap(),
        2,
    );
    let outside = TempDir::new();
    check(install(outside.path()), 2);
    ok_git(root, &["config", "core.hooksPath", "/dev/null/child"]);
    check(install(root), 2);
    for args in [
        vec!["hook"],
        vec!["hook", "remove"],
        vec!["hook", "install", SECRET],
    ] {
        check(
            isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
                .args(args)
                .output()
                .unwrap(),
            2,
        );
    }
}

#[test]
fn relative_scanner_path_is_checked_in_hook_execution_directory() {
    let dir = repo();
    let root = dir.path();
    fs::create_dir(root.join("bin")).unwrap();
    symlink(env!("CARGO_BIN_EXE_rayloc"), root.join("bin/rayloc")).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let git_binary = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("git"))
        .find(|p| p.is_file())
        .unwrap();
    symlink(&git_binary, root.join("bin/git")).unwrap();
    symlink(&git_binary, root.join("nested/git")).unwrap();
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root.join("nested")))
        .env("PATH", "bin:.")
        .args(["hook", "install"])
        .output()
        .unwrap();
    check(out, 0);
    let out = isolated(Command::new(root.join(".git/hooks/pre-commit")).current_dir(root))
        .env("PATH", "bin:.")
        .output()
        .unwrap();
    check(out, 0);
    fs::remove_file(root.join("bin/rayloc")).unwrap();
    let out = isolated(Command::new(root.join(".git/hooks/pre-commit")).current_dir(root))
        .env("PATH", "bin:.")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !isolated(Command::new(git_binary).current_dir(root))
            .env("PATH", "bin:.")
            .args(["commit", "--allow-empty", "-qm", "missing scanner"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn failing_hook_directory_lookup_suppresses_child_diagnostics() {
    let dir = repo();
    let root = dir.path();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("git"))
        .find(|p| p.is_file())
        .unwrap();
    fs::write(bin.join("git"),"#!/usr/bin/python3\nimport os,sys\nif '--git-path' in sys.argv:\n sys.stderr.write('private-path' * 100000)\n sys.exit(2)\nos.execv(os.environ['REAL_GIT'], [os.environ['REAL_GIT']] + sys.argv[1:])\n").unwrap();
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
    let out = isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .env("PATH", &bin)
        .env("REAL_GIT", real)
        .args(["hook", "install"])
        .output()
        .unwrap();
    assert!(!check(out, 2).contains("private-path"));
}

#[test]
fn relative_git_routing_environment_is_preserved_when_installing_from_nested_cwd() {
    for custom in [false, true] {
        let dir = repo();
        let root = dir.path();
        fs::create_dir(root.join("nested")).unwrap();
        if custom {
            ok_git(root, &["config", "core.hooksPath", "custom"]);
        }
        let out =
            isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root.join("nested")))
                .env("PATH", path())
                .env("GIT_DIR", "../.git")
                .env("GIT_WORK_TREE", "..")
                .args(["hook", "install"])
                .output()
                .unwrap();
        check(out, 0);
        assert!(
            root.join(if custom {
                "custom/pre-commit"
            } else {
                ".git/hooks/pre-commit"
            })
            .is_file()
        );
        let out = isolated(Command::new("git").current_dir(root.join("nested")))
            .env("PATH", path())
            .env("GIT_DIR", "../.git")
            .env("GIT_WORK_TREE", "..")
            .args(["commit", "--allow-empty", "-qm", "installed"])
            .output()
            .unwrap();
        check(out, 0);
    }
}
