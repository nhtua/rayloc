//! Bounded byte classifiers shared by assignment detectors.
#![allow(dead_code)] // Both context lexers consume these helpers in Task 2.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSyntax {
    Text,
    Code,
}

impl SourceSyntax {
    pub fn from_path(path: &[u8]) -> Self {
        const CODE_SUFFIXES: [&[u8]; 11] = [
            b".py", b".pyi", b".rs", b".js", b".jsx", b".mjs", b".cjs", b".ts", b".tsx", b".mts",
            b".cts",
        ];
        if CODE_SUFFIXES.iter().any(|suffix| {
            path.len() >= suffix.len()
                && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        }) {
            Self::Code
        } else {
            Self::Text
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AssociationKind {
    Assignment,
    Pair,
    Equality,
    NonAssociation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Association {
    pub kind: AssociationKind,
    pub operator_len: usize,
}

const fn association(kind: AssociationKind, operator_len: usize) -> Association {
    Association { kind, operator_len }
}

pub(crate) fn classify_association(
    syntax: SourceSyntax,
    before_name: Option<u8>,
    operator_prefix: &[u8],
) -> Association {
    let Some(&first) = operator_prefix.first() else {
        return association(AssociationKind::NonAssociation, 0);
    };
    if syntax == SourceSyntax::Text {
        return match first {
            b'=' => association(AssociationKind::Assignment, 1),
            b':' => association(AssociationKind::Pair, 1),
            _ => association(AssociationKind::NonAssociation, 0),
        };
    }
    match first {
        b'=' if operator_prefix.starts_with(b"===") => association(AssociationKind::Equality, 3),
        b'=' if operator_prefix.starts_with(b"==") => association(AssociationKind::Equality, 2),
        b'=' if operator_prefix.get(1) == Some(&b'>') => {
            association(AssociationKind::NonAssociation, 2)
        }
        b'=' => association(AssociationKind::Assignment, 1),
        b':' if operator_prefix
            .get(1)
            .is_some_and(|b| matches!(b, b':' | b'=')) =>
        {
            association(AssociationKind::NonAssociation, 2)
        }
        b':' if before_name == Some(b'?') => association(AssociationKind::NonAssociation, 1),
        b':' => association(AssociationKind::Pair, 1),
        _ => association(AssociationKind::NonAssociation, 0),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReferenceKind {
    None,
    Template,
    Code,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FieldEvidence {
    pub password: bool,
    pub aws: bool,
    pub authorization: bool,
    pub checksum: bool,
    pub generic: bool,
}

const GENERIC_FIELDS: [&[u8]; 30] = [
    b"api_key",
    b"access_token",
    b"client_secret",
    b"credential",
    b"credentials",
    b"auth_token",
    b"secret_key",
    b"datadog_api_key",
    b"datadog_app_key",
    b"azure_ad_client_secret",
    b"npm_token",
    b"nuget_api_key",
    b"pagerduty_key",
    b"pagerduty_integration_key",
    b"snyk_token",
    b"sonar_token",
    b"newrelic_license_key",
    b"newrelic_insights_key",
    b"splunk_observability_token",
    b"intercom_api_key",
    b"vultr_api_key",
    b"trello_api_key",
    b"postman_api_key",
    b"unsplash_api_key",
    b"sumologic_access_id",
    b"sumologic_access_key",
    b"grafana_service_account",
    b"honeycomb_api_key",
    b"logdna_api_key",
    b"zoom_oauth_client_secret",
];

fn field(tail: &[u8], full_len: usize, suffix: &[u8]) -> bool {
    tail.ends_with(suffix)
        && (full_len == suffix.len() && tail.len() == full_len
            || tail.get(tail.len().saturating_sub(suffix.len() + 1)) == Some(&b'_'))
}

pub(crate) fn classify_fields(
    normalized_tail: &[u8],
    full_len: usize,
    checksum: bool,
) -> FieldEvidence {
    FieldEvidence {
        password: field(normalized_tail, full_len, b"password")
            || field(normalized_tail, full_len, b"passwd"),
        aws: (full_len == b"aws_secret_access_key".len()
            && normalized_tail == b"aws_secret_access_key")
            || (full_len == b"secret_access_key".len() && normalized_tail == b"secret_access_key"),
        authorization: full_len == b"authorization".len() && normalized_tail == b"authorization",
        checksum,
        generic: GENERIC_FIELDS
            .iter()
            .any(|suffix| field(normalized_tail, full_len, suffix)),
    }
}

const LEGACY_REFERENCE_PREFIXES: [&[u8]; 8] = [
    b"process.env",
    b"os.getenv",
    b"os.environ",
    b"env(",
    b"getenv(",
    b"config.",
    b"settings.",
    b"ENV[",
];

pub(crate) fn classify_reference(
    value: &[u8],
    quoted: bool,
    syntax: SourceSyntax,
) -> ReferenceKind {
    if value.starts_with(b"$") || value.starts_with(b"{{") || value.starts_with(b"<") {
        return ReferenceKind::Template;
    }
    if !quoted
        && LEGACY_REFERENCE_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
    {
        return ReferenceKind::Template;
    }
    if !quoted && syntax == SourceSyntax::Code && qualified_identifier(value) {
        return ReferenceKind::Code;
    }
    ReferenceKind::None
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit()
}

fn qualified_identifier(value: &[u8]) -> bool {
    let mut i = 0;
    if !value.first().is_some_and(|&b| identifier_start(b)) {
        return false;
    }
    while value.get(i).is_some_and(|&b| identifier_continue(b)) {
        i += 1;
    }
    let mut qualified = false;
    while i < value.len() {
        let op_len = if value[i..].starts_with(b"::")
            || value[i..].starts_with(b"->")
            || value[i..].starts_with(b"?.")
        {
            2
        } else if value[i] == b'.' {
            1
        } else {
            return false;
        };
        i += op_len;
        if !value.get(i).is_some_and(|&b| identifier_start(b)) {
            return false;
        }
        while value.get(i).is_some_and(|&b| identifier_continue(b)) {
            i += 1;
        }
        qualified = true;
    }
    qualified
}

#[cfg(test)]
#[path = "../../tests/unit/assignment.rs"]
mod tests;
