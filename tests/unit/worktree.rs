use super::*;
use crate::test_support::TempDir;

#[test]
fn allocation_admission_accounts_for_both_capacities_and_overflow() {
    let mut bytes = Vec::new();
    append(&mut bytes, b"abc", 3, 6).unwrap();
    assert_eq!(bytes, b"abc");
    assert!(append(&mut bytes, b"d", 3, 6).is_err());
    assert!(append(&mut bytes, b"d", usize::MAX, usize::MAX).is_err());
    let mut excess = Vec::with_capacity(20);
    assert!(append(&mut excess, b"a", 0, 1).is_err());
}
#[test]
fn scan_diff_wrapper_delegates_to_emitter_variant() {
    use std::ffi::OsStr;
    let dir = TempDir::new();
    let outcome = scan_diff(dir.path(), OsStr::new("HEAD"), None, false);
    assert_eq!(outcome.exit_code(), 2);
}
#[test]
fn opened_identity_and_policy_limits_reject_unsafe_inputs() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new();
    let root = dir.path();
    fs::write(root.join("file"), "safe").unwrap();
    fs::write(root.join("other"), "safe").unwrap();
    let before = metadata(&root.join("file")).unwrap();
    assert!(regular(&root.join("other"), &before).is_err());
    assert!(regular(&root.join("missing"), &before).is_err());
    assert!(regular(root, &metadata(root).unwrap()).is_err());
    assert!(identity(root, root, b"missing", 0o100644).is_err());
    assert!(identity(root, root, b"file", 0o120000).is_err());
    assert!(identity(root, root, b"file", 0o160000).is_err());
    assert!(identity(root, root, b"file", 0).is_err());
    symlink(root, root.join("link")).unwrap();
    assert!(identity(root, root, b"link/file", 0o100644).is_err());
    fs::write(root.join("large"), vec![b'x'; config::MAX_CONFIG_BYTES + 1]).unwrap();
    assert!(matches!(
        policy(&root.join("large")),
        Err(ScanError::Policy)
    ));
    assert!(policy(&root.join("file/child")).is_err());
    assert!(policy(&root.join("link")).is_err());
}
#[test]
fn unresolved_bindings_never_enter_strict_parser_and_deletion_is_unchanged() {
    for width in [40, 64] {
        let zero = "0".repeat(width);
        let known = "a".repeat(width);
        let raw = format!(":100644 100644 {known} {zero} M\0");
        assert!(RawBinding::parse(1, raw.as_bytes(), b"entry\0", width).is_err());
        assert!(RawBinding::parse_worktree(1, raw.as_bytes(), b"entry\0", width).is_ok());
        for (oldmode, newmode, oldoid, newoid, status) in [
            ("100644", "100644", zero.as_str(), zero.as_str(), "M"),
            ("100600", "100644", known.as_str(), zero.as_str(), "M"),
            ("100644", "000000", known.as_str(), known.as_str(), "D"),
            ("100644", "100644", known.as_str(), zero.as_str(), "R100"),
        ] {
            let raw = format!(":{oldmode} {newmode} {oldoid} {newoid} {status}\0");
            assert!(RawBinding::parse_worktree(1, raw.as_bytes(), b"entry\0", width).is_err());
        }
        let mut raw = format!(":100644 000000 {known} {zero} D\0").into_bytes();
        assert_eq!(
            resolve(
                Path::new("/missing"),
                Path::new("/missing"),
                &mut raw,
                b"entry\0",
                width
            )
            .unwrap(),
            [0; 64]
        );
    }
}
#[test]
fn hash_output_rejects_failed_and_malformed_children() {
    use std::process::Command;
    for body in ["exit 2", "printf invalid", "printf '%070d' 0"] {
        let mut command = Command::new("sh");
        command.args(["-c", body]);
        assert!(finish_hash(Process::start(&mut command).unwrap()).is_err());
    }
}
fn repository() -> TempDir {
    use std::process::Command;
    assert_isolated_git_environment();
    let dir = TempDir::new();
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.name", "Fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec!["config", "core.hooksPath", "/dev/null"],
        vec!["config", "core.attributesFile", "/dev/null"],
        vec!["config", "core.excludesFile", "/dev/null"],
    ] {
        let status = Command::new("git")
            .current_dir(dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }
    let root = dir.path();
    fs::write(root.join("entry"), "before\n").unwrap();
    assert!(
        Command::new("git")
            .current_dir(root)
            .args(["add", "."])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .current_dir(root)
            .args(["commit", "-qm", "base"])
            .status()
            .unwrap()
            .success()
    );
    fs::write(root.join("entry"), "after\n").unwrap();
    dir
}
#[test]
fn snapshot_budget_and_recheck_detect_missing_corrupted_and_changed_bindings() {
    if !in_isolated_git_child(
        "snapshot_budget_and_recheck_detect_missing_corrupted_and_changed_bindings",
    ) {
        return;
    }
    let dir = repository();
    let root = dir.path();
    let (original, resolved) = snapshot(root, root, "HEAD", 40, METADATA_CAP).unwrap();
    // One raw SHA-1 header is 99 bytes, pathname is 6 bytes, stat is 64 bytes.
    for cap in [0, 99, 105, 169, 268] {
        assert!(matches!(
            snapshot(root, root, "HEAD", 40, cap),
            Err(ScanError::ScopeLimit)
        ));
    }
    verify(root, root, "HEAD", 40, &original, &resolved).unwrap();
    for raw in [
        b"".as_slice(),
        b"partial",
        b"wrong\0",
        &original[..99],
        &original[..105],
    ] {
        assert!(verify(root, root, "HEAD", 40, raw, &resolved).is_err());
    }
    for normalized in [b"".as_slice(), b"partial", b"wrong\0", &resolved[..99]] {
        assert!(verify(root, root, "HEAD", 40, &original, normalized).is_err());
    }
    let mut extra = resolved.clone();
    extra.push(1);
    assert!(verify(root, root, "HEAD", 40, &original, &extra).is_err());
    // Keeping the current stat while restoring the earlier resolved identity
    // isolates the content-hash comparison from the stat comparison.
    fs::write(root.join("entry"), "other\n").unwrap();
    let (current, _) = snapshot(root, root, "HEAD", 40, METADATA_CAP).unwrap();
    assert!(verify(root, root, "HEAD", 40, &current, &resolved).is_err());
    assert!(snapshot(root, root, "missing", 40, METADATA_CAP).is_err());
    assert!(verify(root, root, "missing", 40, &[], &[]).is_err());
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), "safe").unwrap();
    assert!(identity(root, root, b"nested/file", 0o100644).is_ok());
    assert!(identity(root, root, b"missing/file", 0o100644).is_err());
    assert!(identity(root, root, b"nested", 0o100644).is_err());
}
#[test]
fn dirty_gitlink_variant_requires_exact_paths_and_single_line_change() {
    use crate::scanner::diff::{Event, Parser};
    let oid = "a".repeat(40);
    let empty = "b".repeat(40);
    let header = format!(":160000 160000 {oid} {oid} M\0");
    assert!(RawBinding::parse(1, header.as_bytes(), b"sub\0", 40).is_err());
    let valid = format!(
        "diff --git a/sub b/sub\n--- a/sub\n+++ b/sub\n@@ -1 +1 @@\n-Subproject commit {oid}\n+Subproject commit {oid}-dirty\n"
    );
    for patch in [
        valid.clone(),
        valid.replace("a/sub", "a/other"),
        valid.replace("+++ b/sub", "+++ b/other"),
        valid.replace("@@ -1 +1 @@", "@@ -1 +1,2 @@"),
        valid.replace("@@ -1 +1 @@", "@@ -1,1 +1,1 @@"),
        valid.replace(
            &format!("-Subproject commit {oid}"),
            "-Subproject commit bad",
        ),
        valid.replace("-dirty", "-other"),
        valid.lines().take(5).collect::<Vec<_>>().join("\n") + "\n",
        valid.clone() + "\\ No newline at end of file\n",
        valid.clone() + &format!("+Subproject commit {oid}-dirty\n"),
    ] {
        let binding =
            RawBinding::parse_worktree_resolved(1, header.as_bytes(), b"sub\0", 40).unwrap();
        let mut parser = Parser::new(binding, empty.as_bytes()).unwrap();
        let mut added = 0;
        let records = patch.split_inclusive('\n').try_for_each(|record| {
            parser.record(record.as_bytes(), |event| {
                if matches!(event, Event::Added { .. }) {
                    added += 1;
                }
            })
        });
        assert_eq!(
            records.and_then(|()| parser.finish()).is_ok(),
            patch == valid
        );
        assert_eq!(added, 0);
    }
}
#[test]
fn unresolved_worktree_identity_is_rejected() {
    if !in_isolated_git_child("unresolved_worktree_identity_is_rejected") {
        return;
    }
    let dir = repository();
    let root = dir.path();
    let (object, _) = identity(root, root, b"entry", 0o100644).unwrap();
    let mut header = format!(":100644 100644 {object} {} M\0", "0".repeat(40)).into_bytes();
    assert!(resolve(root, root, &mut header, b"entry\0", 40).is_err());
}
#[test]
fn link_and_submodule_identities_are_literal_and_policy_reads_are_bounded() {
    if !in_isolated_git_child(
        "link_and_submodule_identities_are_literal_and_policy_reads_are_bounded",
    ) {
        return;
    }
    use std::os::unix::fs::symlink;
    let dir = repository();
    let root = dir.path();
    symlink("missing-target", root.join("link")).unwrap();
    let (link_oid, _) = identity(root, root, b"link", 0o120000).unwrap();
    assert_eq!(link_oid.len(), 40);
    assert!(identity(root, root, b"link", 0o100644).is_err());
    assert!(identity(root, root, b"entry", 0o120000).is_err());
    assert!(identity(root, root, b"entry", 0o160000).is_err());
    assert!(identity(root, root, b"entry", 0).is_err());
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    for args in [
        vec!["init", "-q"],
        vec![
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-qm",
            "base",
        ],
    ] {
        assert!(
            std::process::Command::new("git")
                .current_dir(&sub)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let (commit, _) = identity(root, root, b"sub", 0o160000).unwrap();
    assert_eq!(commit.len(), 40);
    assert!(policy(&root.join("missing")).unwrap().bytes.is_none());
    assert_eq!(
        policy(&root.join("entry")).unwrap().bytes.unwrap(),
        b"after\n"
    );
}
#[test]
fn acquisition_and_hash_process_failures_cannot_complete_snapshots() {
    if !in_isolated_git_child("acquisition_and_hash_process_failures_cannot_complete_snapshots") {
        return;
    }
    use std::os::unix::fs::symlink;
    let dir = repository();
    let root = dir.path();
    let missing = root.join("missing");
    assert!(snapshot(&missing, root, "HEAD", 40, METADATA_CAP).is_err());
    assert!(snapshot(root, &missing, "HEAD", 40, METADATA_CAP).is_err());
    assert!(identity(&missing, root, b"entry", 0o100644).is_err());
    symlink("target", root.join("link")).unwrap();
    assert!(identity(&missing, root, b"link", 0o120000).is_err());
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    assert!(
        std::process::Command::new("git")
            .current_dir(&sub)
            .args(["init", "-q"])
            .status()
            .unwrap()
            .success()
    );
    assert!(identity(root, root, b"sub", 0o160000).is_err());
}

fn isolated_environment(command: &mut std::process::Command) -> &mut std::process::Command {
    for (key, _) in std::env::vars_os() {
        if key.as_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "4")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "core.attributesFile")
        .env("GIT_CONFIG_VALUE_1", "/dev/null")
        .env("GIT_CONFIG_KEY_2", "core.excludesFile")
        .env("GIT_CONFIG_VALUE_2", "/dev/null")
        .env("GIT_CONFIG_KEY_3", "commit.gpgSign")
        .env("GIT_CONFIG_VALUE_3", "false")
        .env("LC_ALL", "C")
}
fn tree_bytes(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut result = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    result
}
#[test]
fn inherited_git_routing_and_config_cannot_mutate_external_fixture_state() {
    use std::process::Command;
    let dir = TempDir::new();
    let root = dir.path();
    for args in [
        vec!["init", "-q"],
        vec![
            // Detached auto-maintenance can create objects/maintenance.lock
            // while the sentinel tree is compared.
            "-c",
            "maintenance.auto=false",
            "-c",
            "user.name=Sentinel",
            "-c",
            "user.email=sentinel@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "sentinel",
        ],
    ] {
        assert!(
            isolated_environment(Command::new("git").current_dir(root))
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    // Keep a separate real index with bytes that hostile GIT_INDEX_FILE can target.
    fs::write(root.join("sentinel"), "unchanged sentinel payload\n").unwrap();
    assert!(
        isolated_environment(Command::new("git").current_dir(root))
            .args(["add", "sentinel"])
            .status()
            .unwrap()
            .success()
    );
    fs::copy(root.join(".git/index"), root.join("external-index")).unwrap();
    fs::write(root.join("hostile.config"),"[commit]\n gpgSign = true\n[gpg]\n program = /nonexistent/rayloc-hostile-signing\n[core]\n hooksPath = /nonexistent/rayloc-hostile-hooks\n attributesFile = /nonexistent/rayloc-hostile-attributes\n excludesFile = /nonexistent/rayloc-hostile-excludes\n").unwrap();
    let before = tree_bytes(root);
    for name in [
        "snapshot_budget_and_recheck_detect_missing_corrupted_and_changed_bindings",
        "unresolved_worktree_identity_is_rejected",
        "link_and_submodule_identities_are_literal_and_policy_reads_are_bounded",
        "acquisition_and_hash_process_failures_cannot_complete_snapshots",
    ] {
        let target = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
        let child = isolated_environment(&mut Command::new(std::env::current_exe().unwrap()))
            .env("GIT_DIR", root.join(".git"))
            .env("GIT_WORK_TREE", root)
            .env("GIT_INDEX_FILE", root.join("external-index"))
            .env("GIT_CONFIG_GLOBAL", root.join("hostile.config"))
            .env("GIT_CONFIG_SYSTEM", root.join("hostile.config"))
            .env("GIT_CONFIG_NOSYSTEM", "0")
            .env("GIT_ATTR_NOSYSTEM", "0")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "commit.gpgSign")
            .env("GIT_CONFIG_VALUE_0", "true")
            .args(["--exact", &target, "--nocapture"])
            .output()
            .unwrap();
        let after = tree_bytes(root);
        let changed: Vec<_> = before
            .keys()
            .chain(after.keys())
            .filter(|path| before.get(*path) != after.get(*path))
            .collect();
        assert!(
            changed.is_empty(),
            "unit fixture modified external sentinel repository or index after {name}: {changed:?}"
        );
        assert!(
            child.status.success(),
            "isolated unit fixture failed: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert!(
            String::from_utf8_lossy(&child.stdout).contains("test result: ok. 1 passed;"),
            "hostile fixture selector must execute exactly one test"
        );
    }
}

// Production deliberately inherits Git environment. Isolate the entire unit-test
// process, including direct production calls, instead of modifying shared env in
// parallel test threads or changing the production command builder.
fn in_isolated_git_child(name: &str) -> bool {
    use std::process::Command;
    let target = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    if std::env::var("RAYLOC_ISOLATED_GIT_UNIT").as_deref() == Ok(target.as_str()) {
        assert_isolated_git_environment();
        return true;
    }
    let child = isolated_environment(&mut Command::new(std::env::current_exe().unwrap()))
        .env("RAYLOC_ISOLATED_GIT_UNIT", &target)
        .args(["--exact", &target, "--nocapture"])
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "isolated unit fixture failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        String::from_utf8_lossy(&child.stdout).contains("test result: ok. 1 passed;"),
        "isolated fixture selector must execute exactly one test"
    );
    false
}

fn assert_isolated_git_environment() {
    use std::process::Command;
    let mut command = Command::new("git");
    let expected: std::collections::BTreeMap<_, _> = isolated_environment(&mut command)
        .get_envs()
        .filter_map(|(key, value)| {
            value
                .filter(|_| key.as_bytes().starts_with(b"GIT_"))
                .map(|value| (key.to_os_string(), value.to_os_string()))
        })
        .collect();
    let actual: std::collections::BTreeMap<_, _> = std::env::vars_os()
        .filter(|(key, _)| key.as_bytes().starts_with(b"GIT_"))
        .collect();
    assert!(
        actual == expected,
        "isolated unit child inherited unsafe Git environment"
    );
}
