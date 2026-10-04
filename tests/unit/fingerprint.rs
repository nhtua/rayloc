use super::*;

#[test]
fn ids_are_stable_short_and_bound_to_path_and_value() {
    let id = FindingId::new(b"plan.md", b"password123");
    assert_eq!(id.to_string(), "s3e9k");
    assert_eq!(id.to_string().len(), ID_LENGTH);
    assert_ne!(id, FindingId::new(b"docs/other.md", b"password123"));
    assert_ne!(id, FindingId::new(b"plan.md", b"password124"));
    // The separator keeps path/value boundaries distinct.
    assert_ne!(FindingId::new(b"ab", b"c"), FindingId::new(b"a", b"bc"));
    assert_eq!(
        FindingId::new(b"docs/plan.md", b"x"),
        FindingId::new(b"docs\\plan.md", b"x")
    );
}

#[test]
fn parsing_accepts_report_ids_only() {
    let id = FindingId::new(b"plan.md", b"password123");
    assert_eq!(FindingId::parse("s3e9k"), Some(id));
    assert_eq!(FindingId::parse("S3E9K"), Some(id));
    for text in ["", "s3e9", "s3e9kk", "s3e9i", "s3e9u", "s3e9-", "s3é9"] {
        assert_eq!(FindingId::parse(text), None, "{text}");
    }
    assert_eq!(format!("{id:?}"), format!("FindingId({:?})", *b"s3e9k"));
}
