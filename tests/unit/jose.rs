use super::*;
#[test]
fn encoding_is_canonical_urlsafe_and_not_padded() {
    for token in [b"A".as_slice(), b"AB", b"AAB", b"@@", b"AA=", b"AA+"] {
        assert!(!encoded(token));
        assert!(!decode(token, &mut Vec::new()));
    }
    let mut output = Vec::new();
    assert!(decode(b"_-8", &mut output));
    assert_eq!(output, [255, 239]);
}
fn encode(bytes: &[u8]) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = String::new();
    for b in bytes {
        bits.push_str(&format!("{b:08b}"));
    }
    while bits.len() % 6 != 0 {
        bits.push('0');
    }
    bits.as_bytes()
        .chunks(6)
        .map(|chunk| {
            alphabet[chunk
                .iter()
                .fold(0, |value, b| value * 2 + usize::from(*b == b'1'))]
        })
        .collect()
}
fn token(header: &[u8], suffix: &[u8]) -> Vec<u8> {
    [encode(header), suffix.to_vec()].concat()
}
#[test]
fn unknown_members_are_valid_json_even_when_they_have_alg_named_children() {
    assert!(accepted(&token(
        br#"{"alg":"HS256","meta":{"alg":42,"enc":null}}"#,
        b".e30.AAAA"
    )));
}
#[test]
fn complete_json_header_grammar_and_security_field_types_are_checked() {
    let suffix = b".e30.AAAA";
    for header in [
        r#"{"alg":"HS256","meta":[true,false,null,0,-12,1.25e+2,1E-2,[],{}],"text":"\"\\\/\b\f\n\r\t\u0041\uD83D\uDE00é"}"#.as_bytes(),
        br#"{"\u0061lg":"HS256","enc":"something"}"#,
    ] { assert!(accepted(&token(header, suffix)), "positive header"); }
    for header in [
        b"".as_slice(),
        b"[]",
        b"true",
        b"null",
        b"{}",
        b"{",
        b"{\"alg\"",
        b"{\"alg\":",
        b"{\"alg\":\"HS256\"} trailing",
        br#"{"alg":"HS256","alg":"none"}"#,
        br#"{"alg":"HS256","enc":3}"#,
        br#"{"alg":null}"#,
        br#"{"alg":""}"#,
        br#"{"alg":"HS256","x":"\x"}"#,
        br#"{"alg":"HS256","x":"\uD800"}"#,
        br#"{"alg":"HS256","x":"\uDC00"}"#,
        br#"{"alg":"HS256","x":"\uD800\u0000"}"#,
        br#"{"alg":"HS256","x":"\uXYZZ"}"#,
        br#"{"alg":"HS256","x":"\u123"}"#,
        br#"{"alg":"HS256","x":"unterminated}"#,
        b"{\"alg\":\"HS256\",\"x\":\"\x01\"}",
        b"{\"alg\":\"HS256\",\"x\":\"\xff\"}",
        br#"{"alg":"HS256","x":01}"#,
        br#"{"alg":"HS256","x":-}"#,
        br#"{"alg":"HS256","x":1.}"#,
        br#"{"alg":"HS256","x":1e}"#,
        br#"{"alg":"HS256","x":1e+}"#,
        br#"{"alg":"HS256","x":tru}"#,
        br#"{"alg":"HS256","x":nul}"#,
        br#"{"alg":"HS256","x":fals}"#,
        br#"{"alg":"HS256","x":!}"#,
        br#"{"alg":"HS256","x":[1,]}"#,
        br#"{"alg":"HS256","x":[1 2]}"#,
        br#"{"alg":"HS256" "x":1}"#,
        br#"{"alg":"HS256",}"#,
    ] {
        assert!(!accepted(&token(header, suffix)), "negative header");
    }
}
#[test]
fn jose_budgets_and_segment_boundaries_are_enforced() {
    assert!(!accepted(b""));
    assert!(!accepted(&vec![b'A'; MAX_CANDIDATE_BYTES + 1]));
    assert!(!accepted(
        &[vec![b'A'; HEADER_BYTES + 1], b".e30.AAAA".to_vec()].concat()
    ));
    for suffix in [
        b".e30.AAAA.extra".as_slice(),
        b".e30.AAAA.extra.extra.extra",
        b".e30.AAAA=",
        b".e30.A",
        b".e30.AA+",
        b"..AAAA",
    ] {
        assert!(!accepted(&token(br#"{"alg":"HS256"}"#, suffix)));
    }
    for suffix in [
        b"..AAAA.AAAA.AAAA".as_slice(),
        b".AAAA.AAAA.AAAA.",
        b".AAAA..AAAA.AAAA",
    ] {
        assert!(!accepted(&token(
            br#"{"alg":"none","enc":"A256GCM"}"#,
            suffix
        )));
    }
    let header = format!(
        "{{\"alg\":\"HS256\",\"x\":{}{}}}",
        "[".repeat(JSON_DEPTH + 1),
        "]".repeat(JSON_DEPTH + 1)
    );
    assert_eq!(
        valid(&token(header.as_bytes(), b".e30.AAAA")),
        Err(ScanError::CandidateLimit)
    );
    let header = format!(
        "{{\"alg\":\"HS256\",\"x\":[{}]}}",
        vec!["0"; JSON_VALUES].join(",")
    );
    assert_eq!(
        valid(&token(header.as_bytes(), b".e30.AAAA")),
        Err(ScanError::CandidateLimit)
    );
    let input = [
        b"AA.".as_slice(),
        &vec![b'A'; MAX_CANDIDATE_BYTES],
        b".AAAA",
    ]
    .concat();
    assert_eq!(
        detect(&input, |_, _| panic!("oversize")),
        Err(ScanError::CandidateLimit)
    );
}

fn accepted(bytes: &[u8]) -> bool {
    valid(bytes).unwrap_or(false)
}
#[test]
fn jwe_direct_and_key_wrapping_segment_contracts_are_distinct() {
    for (header, suffix, want) in [
        (
            br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#.as_slice(),
            b".AAAA.AAAA.AAAA.AAAA".as_slice(),
            true,
        ),
        (
            br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#,
            b"..AAAA.AAAA.AAAA",
            false,
        ),
        (
            br#"{"alg":"ECDH-ES","enc":"A256GCM"}"#,
            b"..AAAA.AAAA.AAAA",
            true,
        ),
        (
            br#"{"alg":"dir","enc":"A256GCM"}"#,
            b".AAAA.AAAA.AAAA.AAAA",
            false,
        ),
        (br#"{"alg":"dir","enc":"A256GCM"}"#, b"..AAAA..AAAA", false),
        (br#"{"alg":"dir","enc":"A256GCM"}"#, b"...AAAA.AAAA", false),
        (br#"{"alg":"dir","enc":"A256GCM"}"#, b"..AAAA.AAAA.", false),
    ] {
        assert_eq!(accepted(&token(header, suffix)), want);
    }
    for header in [
        b"{\"alg\":\"HS256\",\"x\":\"\\".as_slice(),
        b"{\"alg\":\"HS256\",\"x\":\"\\u1",
        b"{\"alg\":\"HS256\",\"x\":\"\\uD800\\u1",
        b"{\"alg\":\"HS256\",\"x\":\"\\uD800x",
        b"-",
    ] {
        assert!(!accepted(&token(header, b".e30.AAAA")));
    }
}
