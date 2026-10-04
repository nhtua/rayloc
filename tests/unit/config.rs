use super::*;
use crate::test_support as support;
use support::TempDir;
#[test]
fn strict_yaml_rejects_ambiguous_unsupported_and_unknown_values() {
    let invalid = [
        "",
        "[1]",
        "version: 2",
        "version: [1]",
        "version: \"1\"\nversion: \"1\"",
        "version: \"1\"\nx: a",
        "version: &anchor 1",
        "version: !tag 1",
        "version: *missing",
        "version: \"1\"\n<<: {}",
        "version: \"1\"\n---\nversion: \"1\"",
        "version: {a: 1}",
        "version: \"1\"\nrules: {}",
        "version: \"1\"\nentropy_thresholds: []",
        "version: \"1\"\ndisabled_rules: {}",
        "version: \"1\"\nrules: [1]",
        "version: \"1\"\nrules: [{id: a}]",
        "version: \"1\"\nrules: [{regex: a}]",
        "version: \"1\"\nrules: [{id: '', regex: a}]",
        "version: \"1\"\nrules: [{id: a!, regex: a}]",
        "version: \"1\"\nrules: [{id: a, regex: a, secret_group: -1}]",
        "version: \"1\"\nrules: [{id: a, regex: a, severity: Bad}]",
        "version: \"1\"\nrules: [{id: a, regex: a, x: b}]",
        "version: \"1\"\nrules: [{id: a, regex: a, description: []}]",
        "version: \"1\"\nrules: [{id: a, regex: a}, {id: a, regex: b}]",
        "version: \"1\"\nrules: [{id: github-token, regex: a}]",
        "version: \"1\"\ndisabled_rules: [github-token, github-token]",
        "version: \"1\"\nentropy_thresholds: {unknown: 1}",
        "version: \"1\"\nrules: [",
        "? [a, b]\n: c",
    ];
    for text in invalid {
        assert!(parse(text.as_bytes()).is_err(), "{text}");
    }
    assert!(matches!(parse(b"\xff"), Err(ConfigError::Syntax)));
    for value in ["NaN", "inf", "-0.1", "8.1", "none", "[]"] {
        assert!(
            parse(format!("version: \"1\"\ndefault_entropy_threshold: {value}").as_bytes())
                .is_err()
        );
    }
    for (class, value) in [("hex", 4.1), ("alphanumeric", 6.0), ("base64", 6.1)] {
        assert!(
            parse(format!("version: \"1\"\nentropy_thresholds: {{{class}: {value}}}").as_bytes())
                .is_err()
        );
    }
    for text in [
        "version: \"1\"\nrules: &a []",
        "version: \"1\"\nrules: !a []",
        "version: \"1\"\nx: &a {}",
        "version: \"1\"\nx: !a {}",
        "version: \"1\"\nx: [*a]",
    ] {
        assert!(parse(text.as_bytes()).is_err());
    }
}
#[test]
fn merge_preserves_unspecified_policy_and_unions_disables() {
    let base = parse(b"version: \"1\"\ndefault_entropy_threshold: 4\nentropy_thresholds: {hex: 3, base64: 5}\nrules: [{id: base, regex: a}]\ndisabled_rules: [github-token]").unwrap();
    let extra = parse(b"version: \"1\"\nentropy_thresholds: {hex: 2, alphanumeric: 4}\nrules: [{id: extra, regex: b}]\ndisabled_rules: [github-token, base]").unwrap();
    let merged = base.merge(extra).unwrap();
    assert_eq!(merged.default_entropy_threshold, Some(4.0));
    assert_eq!(merged.entropy_thresholds.len(), 3);
    assert_eq!(merged.entropy_thresholds["hex"], 2.0);
    assert_eq!(merged.entropy_thresholds["base64"], 5.0);
    assert_eq!(
        merged
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["base", "extra"]
    );
    assert_eq!(merged.disabled, ["github-token", "base"]);
    let merged = merged
        .merge(parse(b"version: \"1\"\ndefault_entropy_threshold: 0").unwrap())
        .unwrap();
    assert_eq!(merged.default_entropy_threshold, Some(0.0));
    assert!(
        merged
            .merge(parse(b"version: \"1\"\nrules: [{id: base, regex: x}]").unwrap())
            .is_err()
    );
}
#[test]
fn parser_and_aggregate_budgets_bound_hostile_inputs() {
    assert!(matches!(
        parse(&vec![b' '; MAX_CONFIG_BYTES + 1]),
        Err(ConfigError::Limit)
    ));
    let nested = format!("version: \"1\"\nx: {}a{}", "[".repeat(18), "]".repeat(18));
    assert!(matches!(parse(nested.as_bytes()), Err(ConfigError::Limit)));
    let events = format!("version: \"1\"\nx: [{}]", "a,".repeat(8192));
    assert!(matches!(parse(events.as_bytes()), Err(ConfigError::Limit)));
    let rules = (0..257)
        .map(|n| format!("{{id: r{n}, regex: a}}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(matches!(
        parse(format!("version: \"1\"\nrules: [{rules}]").as_bytes()),
        Err(ConfigError::Limit)
    ));
    assert!(matches!(
        parse(
            format!(
                "version: \"1\"\nrules: [{{id: r, regex: '{}'}}]",
                "a".repeat(MAX_PATTERN_BYTES + 1)
            )
            .as_bytes()
        ),
        Err(ConfigError::Limit)
    ));
    assert!(
        parse(
            format!(
                "version: \"1\"\nrules: [{{id: {}, regex: a}}]",
                "r".repeat(129)
            )
            .as_bytes()
        )
        .is_err()
    );
    let text = (0..17)
        .map(|n| format!("{{id: r{n}, regex: '{}'}}", "a".repeat(MAX_PATTERN_BYTES)))
        .collect::<Vec<_>>()
        .join(",");
    assert!(matches!(
        parse(format!("version: \"1\"\nrules: [{text}]").as_bytes()),
        Err(ConfigError::Limit)
    ));
    let half = format!(
        "version: \"1\"\nrules: [{}]",
        (0..129)
            .map(|n| format!("{{id: a{n}, regex: a}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let other = half.replace("id: a", "id: b");
    assert!(matches!(
        parse(half.as_bytes())
            .unwrap()
            .merge(parse(other.as_bytes()).unwrap()),
        Err(ConfigError::Limit)
    ));
}
#[test]
fn bounded_policy_reads_root_discovery_and_loading() {
    let root = TempDir::new();
    let path = root.path().join("source");
    std::fs::write(&path, "clean").unwrap();
    assert_eq!(discover_root(&path).unwrap(), root.path());
    assert_eq!(discover_root(root.path()).unwrap(), root.path());
    assert!(discover_root(&root.path().join("missing")).is_err());
    assert!(read_policy(&root.path().join("missing")).is_err());
    assert!(read_policy(root.path()).is_err());
    assert!(load(root.path(), None).unwrap().rules.is_empty());
    assert!(load(root.path(), Some(&root.path().join("missing"))).is_err());
    std::fs::write(
        root.path().join(".rayloc.yaml"),
        include_bytes!("../../.rayloc.yaml"),
    )
    .unwrap();
    assert_eq!(
        load(root.path(), None).unwrap().default_entropy_threshold,
        Some(4.5)
    );
    std::fs::write(
        root.path().join("extra"),
        b"version: \"1\"\ndefault_entropy_threshold: 2",
    )
    .unwrap();
    assert_eq!(
        load(root.path(), Some(&root.path().join("extra")))
            .unwrap()
            .default_entropy_threshold,
        Some(2.0)
    );
    std::fs::write(root.path().join("huge"), vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
    assert!(matches!(
        read_policy(&root.path().join("huge")),
        Err(ConfigError::Limit)
    ));
    for category in [
        ConfigError::Read,
        ConfigError::Syntax,
        ConfigError::Schema,
        ConfigError::Limit,
        ConfigError::Pattern,
        ConfigError::Ignore,
        ConfigError::Discovery,
    ] {
        assert!(!category.to_string().is_empty());
        let error: &dyn std::error::Error = &category;
        assert!(error.source().is_none());
    }
}
#[test]
fn schema_enforces_yaml_scalar_types() {
    for text in [
        "version: 1",
        "version: true",
        "version: null",
        "version: \"1\"\ndefault_entropy_threshold: '4.5'",
        "version: \"1\"\nrules: [{id: 1, regex: abc}]",
        "version: \"1\"\nrules: [{id: abc, regex: true}]",
        "version: \"1\"\nrules: [{id: abc, regex: abc, description: null}]",
        "version: \"1\"\nrules: [{id: abc, regex: abc, secret_group: '1'}]",
    ] {
        assert!(parse(text.as_bytes()).is_err());
    }
}
#[test]
fn wrong_container_types_missing_fields_and_yaml_numeric_forms_are_checked() {
    for text in [
        "version: \"1\"\nrules: [{id: [], regex: a}]",
        "version: \"1\"\nrules: [{id: a, regex: []}]",
        "version: \"1\"\nrules: [{id: a, regex: a, entropy: []}]",
        "version: \"1\"\nrules: [{id: a, regex: a, severity: []}]",
        "version: \"1\"\nrules: [{id: a, regex: a, secret_group: []}]",
        "version: \"1\"\ndisabled_rules: [[]]",
        "version: \"1\"\ndefault_entropy_threshold: .nan",
        "version: \"1\"\nrules: [{id: a, regex: a, description: NULL}]",
        "version: \"1\"\nx: [abc",
        "version: \"1\"\nx: {y: [abc",
    ] {
        assert!(parse(text.as_bytes()).is_err());
    }
    assert_eq!(parse(b"version: '1'\ndefault_entropy_threshold: 0x4\nrules: [{id: a, regex: a, secret_group: 0o0}]").unwrap().default_entropy_threshold, Some(4.0));
}
#[test]
fn nonrepository_classification_requires_complete_fixed_diagnostics() {
    let ordinary = b"fatal: not a git repository (or any of the parent directories): .git\n";
    assert!(outside_git(ordinary));
    assert!(outside_git(b"fatal: not a git repository (or any parent up to mount point /mnt)\nStopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).\n"));
    for diagnostic in [b"".as_slice(), b"not a git repository", b"fatal: not a git repository: private-git-path\n", b"fatal: not a git repository (or any parent up to mount point relative)\nStopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).\n"] { assert!(!outside_git(diagnostic)); }
    for diagnostic in [
        [b"warning: private-input\n".as_slice(), ordinary].concat(),
        [ordinary.as_slice(), b"private-tail\n"].concat(),
    ] {
        assert!(!outside_git(&diagnostic));
    }
}
struct DiagnosticReadError {
    remaining: usize,
}
impl std::io::Read for DiagnosticReadError {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("private-reader-diagnostic"));
        }
        let count = bytes.len().min(self.remaining);
        bytes[..count].fill(b'x');
        self.remaining -= count;
        Ok(count)
    }
}
#[test]
fn child_diagnostics_are_bounded_drained_and_reader_errors_are_fixed() {
    let exact = vec![b'x'; MAX_GIT_DIAGNOSTIC_BYTES];
    assert_eq!(
        read_git_diagnostic(exact.as_slice()).unwrap().len(),
        MAX_GIT_DIAGNOSTIC_BYTES
    );
    let mut oversized = std::io::Cursor::new(vec![b'x'; MAX_GIT_DIAGNOSTIC_BYTES * 20]);
    assert_eq!(
        read_git_diagnostic(&mut oversized),
        Err(ConfigError::Discovery)
    );
    assert_eq!(oversized.position(), (MAX_GIT_DIAGNOSTIC_BYTES * 20) as u64);
    for remaining in [0, MAX_GIT_DIAGNOSTIC_BYTES + 1] {
        assert_eq!(
            read_git_diagnostic(DiagnosticReadError { remaining }),
            Err(ConfigError::Discovery)
        );
    }
}
#[test]
fn schema_version_and_partial_document_fail_closed() {
    for bytes in [
        b"version: '2'".as_slice(),
        b"version: []",
        b"%YAML invalid",
        b"---\n[",
        b"version: '1'\n...\n%YAML invalid",
        b"version: '1'\nx: {x: a, ?}",
    ] {
        assert!(parse(bytes).is_err());
    }
    let root = TempDir::new();
    std::fs::write(root.path().join(".rayloc.yaml"), "invalid").unwrap();
    assert!(load(root.path(), None).is_err());
    std::fs::remove_file(root.path().join(".rayloc.yaml")).unwrap();
    std::fs::write(root.path().join("extra"), "invalid").unwrap();
    assert!(load(root.path(), Some(&root.path().join("extra"))).is_err());
}
#[cfg(unix)]
#[test]
fn unreadable_policy_and_git_administration_fail_closed_without_git_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let root = TempDir::new();
    let admin = root.path().join(".git");
    std::fs::write(&admin, "gitdir: missing").unwrap();
    assert!(outside_without_git(root.path()).is_err());
    std::fs::remove_file(&admin).unwrap();
    std::fs::create_dir(&admin).unwrap();
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o0)).unwrap();
    let result = outside_without_git(root.path());
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o0)).unwrap();
    let result = load(root.path(), None);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    #[cfg(target_os = "linux")]
    assert_eq!(
        read_policy(Path::new("/proc/self/mem")),
        Err(ConfigError::Read)
    );
}
#[cfg(unix)]
#[test]
fn broken_discovered_policy_link_is_an_error() {
    let root = TempDir::new();
    std::os::unix::fs::symlink("missing", root.path().join(".rayloc.yaml")).unwrap();
    assert!(load(root.path(), None).is_err());
}
#[test]
fn malformed_document_boundaries_and_version_containers_are_rejected() {
    for text in [
        "---\n\tbad",
        "version: '1'\n\tbad",
        "version: {}",
        "version: '1'\n...\n\tbad",
        "version: '1'\n{",
        "version: '1'\n[",
        "---\n%TAG",
        "---\n%YAML invalid",
    ] {
        assert!(parse(text.as_bytes()).is_err());
    }
    let mut document = Document {
        parser: Parser::new_from_str(""),
        events: MAX_EVENTS,
    };
    assert!(matches!(
        document.value(Event::MappingStart(0, None), 0),
        Err(ConfigError::Limit)
    ));
}
#[test]
fn accepted_ids_are_validated_deduplicated_bounded_and_merged() {
    let config = parse(b"version: \"1\"\naccepted: [s3e9k, ABCDE]").unwrap();
    assert_eq!(
        config.accepted,
        ["s3e9k", "abcde"].map(|id| FindingId::parse(id).unwrap())
    );
    for text in [
        "version: \"1\"\naccepted: {}",
        "version: \"1\"\naccepted: [[]]",
        "version: \"1\"\naccepted: [abcd]",
        "version: \"1\"\naccepted: [abcdi]",
        "version: \"1\"\naccepted: [abcde, ABCDE]",
        "version: \"1\"\naccepted: [12345]",
    ] {
        assert_eq!(
            parse(text.as_bytes()).err(),
            Some(ConfigError::Schema),
            "{text}"
        );
    }
    let mut unique = std::collections::BTreeSet::new();
    for n in 0.. {
        if unique.len() == MAX_ACCEPTED + 2 {
            break;
        }
        unique.insert(FindingId::new(b"", n.to_string().as_bytes()));
    }
    let quoted: Vec<String> = unique.iter().map(|id| format!("'{id}'")).collect();
    let text = format!("version: \"1\"\naccepted: [{}]", quoted.join(", "));
    assert_eq!(parse(text.as_bytes()).err(), Some(ConfigError::Limit));
    let half = |range: std::ops::Range<usize>| {
        parse(format!("version: \"1\"\naccepted: [{}]", quoted[range].join(", ")).as_bytes())
            .unwrap()
    };
    let merged = half(0..2).merge(half(1..3)).unwrap();
    assert_eq!(merged.accepted.len(), 3);
    let split = MAX_ACCEPTED / 2 + 1;
    assert_eq!(
        half(0..split).merge(half(split..2 * split)).err(),
        Some(ConfigError::Limit)
    );
}
#[test]
fn accepting_edits_block_lists_and_preserves_comments() {
    let id = FindingId::parse("s3e9k").unwrap();
    for (before, after) in [
        ("", "accepted:\n  - \"s3e9k\"\n"),
        ("version: '1'", "version: '1'\naccepted:\n  - \"s3e9k\"\n"),
        ("a: 1\r\n", "a: 1\r\naccepted:\r\n  - \"s3e9k\"\r\n"),
        ("accepted: []\nb: 2\n", "accepted:\n  - \"s3e9k\"\nb: 2\n"),
        ("accepted:", "accepted:\n  - \"s3e9k\"\n"),
        (
            "accepted: # why\n\n# note\n- abcde\n",
            "accepted: # why\n- \"s3e9k\"\n\n# note\n- abcde\n",
        ),
        (
            "accepted:\n    - abcde\n",
            "accepted:\n    - \"s3e9k\"\n    - abcde\n",
        ),
        ("accepted:\nb: 2\n", "accepted:\n  - \"s3e9k\"\nb: 2\n"),
    ] {
        assert_eq!(
            insert_accepted(before, id).as_deref(),
            Some(after),
            "{before}"
        );
    }
    assert_eq!(insert_accepted("accepted: [abcde]\n", id), None);
}
#[test]
fn accepting_creates_updates_and_reports_policy_failures() {
    let id = FindingId::parse("s3e9k").unwrap();
    let root = TempDir::new();
    let policy = root.path().join(".rayloc.yaml");
    assert_eq!(accept(root.path(), id), Ok(Acceptance::Created));
    assert_eq!(
        std::fs::read_to_string(&policy).unwrap(),
        "version: \"1\"\naccepted:\n  - \"s3e9k\"\n"
    );
    assert_eq!(accept(root.path(), id), Ok(Acceptance::Already));
    assert_eq!(
        accept(root.path(), FindingId::parse("abcde").unwrap()),
        Ok(Acceptance::Added)
    );
    for (text, error) in [
        (
            b"version: '1'\naccepted: [abcde]\n".as_slice(),
            ConfigError::Update,
        ),
        (b"version: '1'\naccepted: \"x\"\n", ConfigError::Schema),
        (
            b"version: '1'\n\"accepted\": [abcde]\n",
            ConfigError::Update,
        ),
        (b"\xff", ConfigError::Syntax),
    ] {
        std::fs::write(&policy, text).unwrap();
        assert_eq!(accept(root.path(), id), Err(error));
        assert_eq!(std::fs::read(&policy).unwrap(), text);
    }
    std::fs::remove_file(&policy).unwrap();
    std::fs::create_dir(&policy).unwrap();
    assert_eq!(accept(root.path(), id), Err(ConfigError::Read));
    assert_eq!(accept(&policy.join("x"), id), Err(ConfigError::Write));
    assert_eq!(
        accept(&root.path().join("file/x"), id).err(),
        Some(ConfigError::Write)
    );
    std::fs::write(root.path().join("file"), b"").unwrap();
    assert_eq!(
        accept(&root.path().join("file"), id),
        Err(ConfigError::Read)
    );
    for error in [ConfigError::Update, ConfigError::Write] {
        assert!(!error.to_string().is_empty());
    }
}
