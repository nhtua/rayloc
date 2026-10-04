mod support;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use support::TempDir;

const LINE: &str = "Login expects {\"username\":\"testuser\",\"password\":\"password123\"}\n";
fn isolated(command: &mut Command) -> &mut Command {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
}
fn run(root: &Path, args: &[&str]) -> Output {
    isolated(Command::new(env!("CARGO_BIN_EXE_rayloc")).current_dir(root))
        .args(args)
        .output()
        .unwrap()
}
fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap() + &String::from_utf8_lossy(&output.stderr)
}
fn ids(output: &Output) -> Vec<String> {
    text(output)
        .lines()
        .filter_map(|line| line.strip_prefix("ID: "))
        .map(str::to_owned)
        .collect()
}
fn repo() -> TempDir {
    let dir = TempDir::new();
    let status = isolated(Command::new("git").current_dir(dir.path()))
        .args(["init", "-q"])
        .status()
        .unwrap();
    assert!(status.success());
    fs::create_dir(dir.path().join("docs")).unwrap();
    fs::write(dir.path().join("docs/plan.md"), LINE).unwrap();
    fs::write(dir.path().join("other.md"), LINE).unwrap();
    dir
}

#[test]
fn accepted_id_covers_one_value_in_one_file() {
    let dir = repo();
    let root = dir.path();
    let first = run(root, &["scan"]);
    assert_eq!(first.status.code(), Some(1), "{}", text(&first));
    let found = ids(&first);
    assert_eq!(found.len(), 2);
    assert_ne!(found[0], found[1], "same value, different files");
    assert!(text(&first).contains("rayloc accept <ID>"));

    // Accept the docs/plan.md finding from a subdirectory; the root policy is edited.
    let plan = ids(&run(root, &["scan", "docs/plan.md"])).remove(0);
    let accepted = run(&root.join("docs"), &["accept", &plan.to_uppercase()]);
    assert_eq!(accepted.status.code(), Some(0), "{}", text(&accepted));
    assert_eq!(
        text(&accepted),
        format!("rayloc: created .rayloc.yaml and accepted {plan}; stage it for --staged scans\n")
    );
    let other = found.iter().find(|id| **id != plan).unwrap();
    let added = run(root, &["accept", other]);
    assert_eq!(
        text(&added),
        format!("rayloc: accepted {other} in .rayloc.yaml; stage it for --staged scans\n")
    );
    let edit = fs::read_to_string(root.join(".rayloc.yaml")).unwrap();
    fs::write(
        root.join(".rayloc.yaml"),
        edit.replace(&format!("  - \"{other}\"\n"), ""),
    )
    .unwrap();
    let again = run(root, &["accept", &plan]);
    assert_eq!(
        text(&again),
        format!("rayloc: {plan} is already accepted\n")
    );

    let second = run(root, &["scan"]);
    assert_eq!(second.status.code(), Some(1));
    assert_eq!(
        ids(&second),
        [found.iter().find(|id| **id != plan).unwrap().clone()]
    );
    assert!(text(&second).contains("accepted=1"));

    // Repeating the accepted value is covered; a different value is not.
    fs::write(
        root.join("docs/plan.md"),
        format!("{LINE}{LINE}{{\"password\":\"realPass9x\"}}\n"),
    )
    .unwrap();
    let edited = run(root, &["scan", "docs/plan.md"]);
    assert_eq!(edited.status.code(), Some(1));
    assert_eq!(ids(&edited).len(), 1);
    assert!(text(&edited).contains("docs/plan.md:3:"));
    assert!(text(&edited).contains("accepted=2"));

    // Staged scans use the same repository-relative path.
    fs::write(root.join("docs/plan.md"), LINE).unwrap();
    let git_add = |path: &str| {
        let status = isolated(Command::new("git").current_dir(root))
            .args(["add", path])
            .status()
            .unwrap();
        assert!(status.success());
    };
    git_add("docs/plan.md");
    // Staged scans read the index policy, so an unstaged accept does not apply.
    assert_eq!(run(root, &["scan", "--staged"]).status.code(), Some(1));
    git_add(".rayloc.yaml");
    let staged = run(root, &["scan", "--staged"]);
    assert_eq!(staged.status.code(), Some(0), "{}", text(&staged));
    assert!(text(&staged).contains("accepted=1"));
}

#[test]
fn accept_rejects_invalid_ids_and_policies_without_echoing() {
    let dir = repo();
    let root = dir.path();
    let secret = "password123";
    for args in [
        vec!["accept"],
        vec!["accept", secret],
        vec!["accept", "abcde", "extra"],
    ] {
        let output = run(root, &args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!text(&output).contains(secret));
    }
    let help = run(root, &["accept", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(text(&help).contains("accept <id>"));

    fs::write(root.join(".rayloc.yaml"), "version: [\n").unwrap();
    let output = run(root, &["accept", "abcde"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(text(&output), "rayloc: invalid YAML policy\n");
}
