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
    assert!(discover_root(Path::new("/")).is_err());
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
