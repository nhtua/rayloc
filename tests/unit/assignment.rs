use super::*;

#[test]
fn source_syntax_uses_only_supported_code_suffixes() {
    for path in [
        b"/tmp/nonutf8-\xff/example.py".as_slice(),
        b"source.pyi",
        b"source.rs",
        b"source.js",
        b"source.jsx",
        b"source.mjs",
        b"source.cjs",
        b"source.ts",
        b"source.tsx",
        b"source.mts",
        b"source.cts",
        b"SOURCE.PY",
    ] {
        assert_eq!(
            SourceSyntax::from_path(path),
            SourceSyntax::Code,
            "{path:?}"
        );
    }
    for path in [
        b"source.env".as_slice(),
        b"source.sh",
        b"source.ps1",
        b"source.yaml",
        b"source.json",
        b"source.md",
        b"" as &[u8],
        b"source.ts.bak",
    ] {
        assert_eq!(
            SourceSyntax::from_path(path),
            SourceSyntax::Text,
            "{path:?}"
        );
    }
}

#[test]
fn association_evidence_preserves_values_and_rejects_ternary_labels() {
    let cases = [
        (
            SourceSyntax::Code,
            None,
            b"=".as_slice(),
            AssociationKind::Assignment,
            1,
        ),
        (
            SourceSyntax::Code,
            None,
            b"==",
            AssociationKind::Equality,
            2,
        ),
        (
            SourceSyntax::Code,
            None,
            b"===",
            AssociationKind::Equality,
            3,
        ),
        (
            SourceSyntax::Code,
            None,
            b"=>",
            AssociationKind::NonAssociation,
            2,
        ),
        (SourceSyntax::Code, None, b":", AssociationKind::Pair, 1),
        (
            SourceSyntax::Code,
            None,
            b"::",
            AssociationKind::NonAssociation,
            2,
        ),
        (
            SourceSyntax::Code,
            None,
            b":=",
            AssociationKind::NonAssociation,
            2,
        ),
        (
            SourceSyntax::Code,
            Some(b'?'),
            b":",
            AssociationKind::NonAssociation,
            1,
        ),
        (
            SourceSyntax::Code,
            Some(b'{'),
            b":",
            AssociationKind::Pair,
            1,
        ),
        (
            SourceSyntax::Code,
            Some(b','),
            b"=",
            AssociationKind::Assignment,
            1,
        ),
        (
            SourceSyntax::Code,
            None,
            b"=x",
            AssociationKind::Assignment,
            1,
        ),
        (
            SourceSyntax::Text,
            None,
            b"==",
            AssociationKind::Assignment,
            1,
        ),
        (SourceSyntax::Text, None, b":", AssociationKind::Pair, 1),
        (
            SourceSyntax::Code,
            None,
            b"x",
            AssociationKind::NonAssociation,
            0,
        ),
    ];
    for (syntax, before, op, kind, length) in cases {
        let actual = classify_association(syntax, before, op);
        assert_eq!(actual.kind, kind, "{syntax:?} {before:?} {op:?}");
        assert_eq!(actual.operator_len, length, "{syntax:?} {before:?} {op:?}");
    }
}

#[test]
fn reference_classification_respects_quotes_and_source() {
    let members: [&[u8]; 13] = [
        b"args.vllm_api_key",
        b"self.allow_credentials",
        b"self.DUMMY_API_KEY",
        b"args.allow_credentials",
        b"auth.accessToken",
        b"deps.completeCredential",
        b"input.credential",
        b"row.externalCredential",
        b"input.configPath",
        b"grantRef.configPath",
        b"input.env.COGNEE_API_KEY",
        b"credentials.accessToken",
        b"credentials.clientSecret",
    ];
    for value in members {
        assert_eq!(
            classify_reference(value, false, SourceSyntax::Code),
            ReferenceKind::Code,
            "{value:?}"
        );
        assert_eq!(
            classify_reference(value, true, SourceSyntax::Code),
            ReferenceKind::None,
            "quoted {value:?}"
        );
        assert_eq!(
            classify_reference(value, false, SourceSyntax::Text),
            ReferenceKind::None,
            "text {value:?}"
        );
    }
    for value in [b"${PASSWORD}".as_slice(), b"{{ PASSWORD }}", b"<secret>"] {
        for quoted in [false, true] {
            for syntax in [SourceSyntax::Text, SourceSyntax::Code] {
                assert_eq!(
                    classify_reference(value, quoted, syntax),
                    ReferenceKind::Template,
                    "{value:?}, quoted={quoted}, syntax={syntax:?}"
                );
            }
        }
    }
    assert_eq!(
        classify_reference(b"config.password", false, SourceSyntax::Text),
        ReferenceKind::Template
    );
    assert_eq!(
        classify_reference(b"config.password", true, SourceSyntax::Text),
        ReferenceKind::None
    );
    for value in [
        b"process.env.KEY".as_slice(),
        b"os.getenv(NAME)",
        b"os.environ[NAME]",
        b"env(NAME)",
        b"getenv(NAME)",
        b"settings.key",
        b"ENV[NAME]",
    ] {
        assert_eq!(
            classify_reference(value, false, SourceSyntax::Text),
            ReferenceKind::Template,
            "legacy text reference {value:?}"
        );
        assert_eq!(
            classify_reference(value, true, SourceSyntax::Code),
            ReferenceKind::None,
            "quoted literal {value:?}"
        );
    }
}

#[test]
fn reference_grammar_requires_qualification_and_complete_components() {
    for value in [
        b"args.api_key".as_slice(),
        b"input.env.KEY",
        b"crate::KEY",
        b"node->secret",
        b"client?.credential",
    ] {
        assert_eq!(
            classify_reference(value, false, SourceSyntax::Code),
            ReferenceKind::Code,
            "{value:?}"
        );
    }
    for value in [
        b"TOKEN".as_slice(),
        b"ANTHROPIC_AUTH_TOKEN",
        b"Q7v2n9B4x6M1z8K3",
        b".field",
        b"args.",
        b"a..b",
        b"2token",
        b"abc-def",
        b"api.key!",
        b"args::",
        b"a:::b",
        b"args.\xff",
    ] {
        assert_eq!(
            classify_reference(value, false, SourceSyntax::Code),
            ReferenceKind::None,
            "{value:?} stays eligible"
        );
    }
}

#[test]
fn field_evidence_preserves_all_existing_suffixes() {
    let fields: [&[u8]; 31] = [
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
        b"allow_credentials",
    ];
    for suffix in fields {
        let mut name = b"prefix_".to_vec();
        name.extend_from_slice(suffix);
        let evidence = classify_fields(&name, name.len(), false);
        assert!(evidence.generic, "{suffix:?}");
    }
    assert!(classify_fields(b"service_password", 16, false).password);
    assert!(classify_fields(b"service_passwd", 14, false).password);
    assert!(classify_fields(b"aws_secret_access_key", 21, false).aws);
    assert!(classify_fields(b"secret_access_key", 17, false).aws);
    assert!(classify_fields(b"authorization", 13, false).authorization);
    assert!(classify_fields(b"api_key", 7, true).checksum);

    let long = [b"x".repeat(70), b"_api_key".to_vec()].concat();
    let tail = &long[long.len() - 64..];
    assert!(classify_fields(tail, long.len(), false).generic);
    assert!(!classify_fields(b"api_key", 71, false).generic);
}

#[cfg(test)]
fn normalized_test_name(raw: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(raw.len());
    for (index, &byte) in raw.iter().enumerate() {
        if index > 0
            && byte.is_ascii_uppercase()
            && (raw[index - 1].is_ascii_lowercase()
                || (raw[index - 1].is_ascii_uppercase()
                    && raw.get(index + 1).is_some_and(u8::is_ascii_lowercase)))
        {
            normalized.push(b'_');
        }
        normalized.push(byte.to_ascii_lowercase());
    }
    normalized
}

#[test]
fn normalized_camel_fields_and_long_name_checksum_are_preserved() {
    let name = normalized_test_name(b"appPassword");
    assert!(classify_fields(&name, name.len(), false).password);
    let name = normalized_test_name(b"clientSecret");
    assert!(classify_fields(&name, name.len(), false).generic);

    let tail = [b"x".repeat(48), b"_client_secret".to_vec()].concat();
    let evidence = classify_fields(&tail, 80, true);
    assert!(evidence.generic);
    assert!(evidence.checksum);
    assert!(!classify_fields(b"client_secret", 80, false).aws);
}
