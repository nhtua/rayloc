use super::*;

const OLD: &str = "1111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222";
const EMPTY: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
const ZERO: &str = "0000000000000000000000000000000000000000";

fn raw(old_mode: &str, new_mode: &str, old: &str, new: &str, status: &str) -> Vec<u8> {
    format!(":{old_mode} {new_mode} {old} {new} {status}\0").into_bytes()
}

#[test]
fn raw_metadata_preserves_paths_and_rejects_protocol_disagreement() {
    let header = raw("100644", "100755", OLD, NEW, "M");
    let binding = RawBinding::parse(7, &header, b"space b/name\xff\0", 40).unwrap();
    assert_eq!(binding.source_id(), 7);
    assert_eq!(binding.path(), b"space b/name\xff");
    assert_eq!(binding.old_mode(), 0o100644);
    assert_eq!(binding.new_mode(), 0o100755);
    assert_eq!(binding.status(), b'M');
    for (om, nm, old, new, status) in [
        ("000000", "100644", ZERO, NEW, "A"),
        ("100644", "000000", OLD, ZERO, "D"),
        ("120000", "100644", OLD, NEW, "T"),
        ("160000", "120000", OLD, NEW, "T"),
        ("100644", "100755", OLD, OLD, "M"),
    ] {
        assert!(RawBinding::parse(0, &raw(om, nm, old, new, status), b"x\0", 40).is_ok());
    }
    for (om, nm, old, new, status) in [
        ("000000", "100644", OLD, NEW, "A"),
        ("100644", "000000", OLD, NEW, "D"),
        ("100644", "100755", OLD, NEW, "T"),
        ("120000", "100644", OLD, NEW, "M"),
        ("100644", "100644", OLD, OLD, "M"),
        ("100644", "100644", OLD, NEW, "R100"),
        ("100644", "100644", OLD, NEW, "C"),
        ("100644", "100644", OLD, NEW, "U"),
        ("100644", "100644", ZERO, NEW, "M"),
        ("100600", "100644", OLD, NEW, "M"),
        ("100648", "100644", OLD, NEW, "M"),
        ("10064", "100644", OLD, NEW, "M"),
    ] {
        assert!(RawBinding::parse(0, &raw(om, nm, old, new, status), b"x\0", 40).is_err());
    }
    for path in [
        b"".as_slice(),
        b"x",
        b"\0",
        b"a\0b\0",
        b"/x\0",
        b"../x\0",
        b"a//b\0",
        b"a/./b\0",
        b"x/\0",
    ] {
        assert!(RawBinding::parse(0, &header, path, 40).is_err());
    }
    for bad in [
        b"".as_slice(),
        b":x\0",
        &header[..header.len() - 1],
        b"::100644 100644 a b M\0",
    ] {
        assert!(RawBinding::parse(0, bad, b"x\0", 40).is_err());
    }
    assert!(RawBinding::parse(0, &header, b"x\0", 41).is_err());
    let sha256 = raw("100644", "100644", &"a".repeat(64), &"b".repeat(64), "M");
    assert!(RawBinding::parse(0, &sha256, b"x\0", 64).is_ok());
    let mut path = vec![b'x'; MAX_RECORD_BYTES];
    path[MAX_RECORD_BYTES - 1] = 0;
    assert!(RawBinding::parse(0, &header, &path, 40).is_ok());
    path.insert(0, b'x');
    assert!(matches!(
        RawBinding::parse(0, &header, &path, 40),
        Err(DiffError::Limit)
    ));
    assert!(matches!(
        RawBinding::parse(0, &path, b"x\0", 40),
        Err(DiffError::Limit)
    ));
}

fn section(path: &str, om: &str, nm: &str, old: &str, new: &str, body: &str) -> String {
    let mut text = format!("diff --git a/{path} b/{path}\n");
    if om == "000000" {
        text += &format!("new file mode {nm}\n");
    } else if nm == "000000" {
        text += &format!("deleted file mode {om}\n");
    } else if om != nm {
        text += &format!("old mode {om}\nnew mode {nm}\n");
    }
    if old != new {
        text += &format!(
            "index {old}..{new}{}\n",
            if om == nm {
                format!(" {om}")
            } else {
                String::new()
            }
        );
    }
    if !body.is_empty() {
        text += &format!(
            "--- {}\n+++ {}\n",
            if om == "000000" {
                "/dev/null".into()
            } else {
                format!("a/{path}")
            },
            if nm == "000000" {
                "/dev/null".into()
            } else {
                format!("b/{path}")
            }
        );
        text += body;
    }
    text
}

type Added = (u32, u64, Vec<u8>, bool);
fn parse_patch(header: &[u8], path: &[u8], patch: &[u8]) -> Result<Vec<Added>, DiffError> {
    parse_binding(RawBinding::parse(7, header, path, 40)?, patch)
}
fn parse_binding(binding: RawBinding<'_>, patch: &[u8]) -> Result<Vec<Added>, DiffError> {
    let mut parser = Parser::new(binding, EMPTY.as_bytes())?;
    let mut added = vec![];
    for line in patch.split_inclusive(|&b| b == b'\n') {
        parser.record(line, |event| match event {
            Event::Added {
                source_id,
                new_line,
                payload,
                starts_run,
            } => added.push((source_id, new_line, payload.to_vec(), starts_run)),
            Event::AddedFragment {
                source_id,
                new_line,
                payload,
                starts_run,
                ends_line: true,
                ..
            } => added.push((source_id, new_line, payload.to_vec(), starts_run)),
            Event::AddedFragment { .. } => {}
            Event::Boundary => {}
        })?;
    }
    parser.finish()?;
    Ok(added)
}

fn parse_fragmented(binding: RawBinding<'_>, patch: &[u8]) -> Result<(usize, usize), DiffError> {
    let mut parser = Parser::new(binding, EMPTY.as_bytes())?;
    let mut fragments = 0;
    let mut bytes = 0;
    let mut start = 0;
    while start < patch.len() {
        let end = patch[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| start + n + 1)
            .ok_or(DiffError::Invalid)?;
        let mut at = start;
        while at < end {
            let next = (at + crate::scanner::chunk::CHUNK_BYTES).min(end);
            let final_fragment = next == end;
            parser.fragment(&patch[at..next], final_fragment, |event| {
                if let Event::AddedFragment { payload, .. } = event {
                    assert!(payload.len() <= crate::scanner::chunk::CHUNK_BYTES);
                    fragments += 1;
                    bytes += payload.len();
                }
            })?;
            at = next;
        }
        start = end;
    }
    parser.finish()?;
    Ok((fragments, bytes))
}

#[test]
fn huge_added_deleted_and_context_records_stream_only_added_payload() {
    let payload = format!(
        "{}diff --git fake @@ +++ \\\\",
        "x".repeat(10 * 1024 * 1024)
    );
    let add_header = raw("000000", "100644", ZERO, NEW, "A");
    let add = section(
        "x",
        "000000",
        "100644",
        ZERO,
        NEW,
        &format!("@@ -0,0 +1 @@\n+{payload}\n"),
    );
    let (fragments, bytes) = parse_fragmented(
        RawBinding::parse(9, &add_header, b"x\0", 40).unwrap(),
        add.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        fragments,
        payload.len().div_ceil(crate::scanner::chunk::CHUNK_BYTES)
    );
    assert_eq!(bytes, payload.len());

    let modify_header = raw("100644", "100644", OLD, NEW, "M");
    for (prefix, hunk) in [
        (b"-", b"@@ -1 +0,0 @@\n".as_slice()),
        (b" ", b"@@ -1 +1 @@\n".as_slice()),
    ] {
        let line = [prefix, payload.as_bytes(), b"\n"].concat();
        let body = [hunk, &line].concat();
        let patch = section(
            "x",
            "100644",
            "100644",
            OLD,
            NEW,
            std::str::from_utf8(&body).unwrap(),
        );
        assert_eq!(
            parse_fragmented(
                RawBinding::parse(9, &modify_header, b"x\0", 40).unwrap(),
                patch.as_bytes()
            )
            .unwrap(),
            (0, 0)
        );
    }
}

#[test]
fn fragmented_record_framing_and_partial_eof_fail_closed() {
    let header = raw("000000", "100644", ZERO, NEW, "A");
    let mut parser = Parser::new(
        RawBinding::parse(1, &header, b"x\0", 40).unwrap(),
        EMPTY.as_bytes(),
    )
    .unwrap();
    assert!(
        parser
            .fragment(b"diff --git a/x b/x\n", true, |_| {})
            .is_ok()
    );
    assert!(
        parser
            .fragment(b"new file mode 100644", false, |_| {})
            .is_ok()
    );
    assert!(parser.fragment(b"", true, |_| {}).is_err());
    assert!(parser.fragment(b"index", false, |_| {}).is_err());

    let mut parser = Parser::new(
        RawBinding::parse(1, &header, b"x\0", 40).unwrap(),
        EMPTY.as_bytes(),
    )
    .unwrap();
    let index = format!("index {ZERO}..{NEW}\n");
    for record in [
        b"diff --git a/x b/x\n".as_slice(),
        b"new file mode 100644\n",
        index.as_bytes(),
        b"--- /dev/null\n",
        b"+++ b/x\n",
        b"@@ -0,0 +1 @@\n",
    ] {
        parser.record(record, |_| {}).unwrap();
    }
    parser.fragment(b"+partial", false, |_| {}).unwrap();
    assert!(parser.finish().is_err());
}

#[test]
fn fragmented_parser_matches_complete_records_at_every_byte_split() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let binding = RawBinding::parse(7, &header, b"x\0", 40).unwrap();
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        "@@ -1,2 +1,3 @@\n-old\n+first\n context\n+last\n\\ No newline at end of file\n",
    );
    let expected = parse_binding(binding, patch.as_bytes()).unwrap();
    for chunk_size in 1..=17 {
        let mut parser = Parser::new(binding, EMPTY.as_bytes()).unwrap();
        let mut actual: Vec<Added> = Vec::new();
        let mut at = 0;
        while at < patch.len() {
            let record_end = patch.as_bytes()[at..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|n| at + n + 1)
                .unwrap();
            let mut record_added: Option<Added> = None;
            while at < record_end {
                let next = (at + chunk_size).min(record_end);
                let final_fragment = next == record_end;
                parser
                    .fragment(&patch.as_bytes()[at..next], final_fragment, |event| {
                        if let Event::AddedFragment {
                            source_id,
                            new_line,
                            payload,
                            starts_run,
                            ..
                        } = event
                        {
                            if let Some((last_id, last_line, last_payload, _last_run)) =
                                record_added.as_mut()
                            {
                                if *last_id == source_id && *last_line == new_line {
                                    last_payload.extend_from_slice(payload);
                                    return;
                                }
                            }
                            record_added =
                                Some((source_id, new_line, payload.to_vec(), starts_run));
                        }
                    })
                    .unwrap();
                at = next;
            }
            if let Some(added) = record_added {
                actual.push(added);
            }
        }
        parser.finish().unwrap();
        assert_eq!(actual, expected, "fragment size {chunk_size}");
    }
}

#[test]
fn only_added_payload_is_emitted_with_coordinates_and_run_boundaries() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        "@@ -1,4 +1,7 @@ arbitrary heading\n-deleted-secret\n+first\n++++ header-content\n context-secret\n+@@ content\n+diff --git content\n-delete-again\n+raw\0bytes\r\n context-again\n@@ -9,0 +13 @@\n+last\n",
    );
    let added = parse_patch(&header, b"x\0", patch.as_bytes()).unwrap();
    assert_eq!(
        added,
        vec![
            (7, 1, b"first".to_vec(), true),
            (7, 2, b"+++ header-content".to_vec(), false),
            (7, 4, b"@@ content".to_vec(), true),
            (7, 5, b"diff --git content".to_vec(), false),
            (7, 6, b"raw\0bytes\r".to_vec(), true),
            (7, 13, b"last".to_vec(), true),
        ]
    );
}

#[test]
fn validates_section_headers_empty_objects_modes_and_type_change_pairs() {
    for (om, nm, old, new, status, body) in [
        ("000000", "100644", ZERO, NEW, "A", "@@ -0,0 +1 @@\n+one\n"),
        ("100644", "000000", OLD, ZERO, "D", "@@ -1 +0,0 @@\n-one\n"),
        ("000000", "100644", ZERO, EMPTY, "A", ""),
        ("100644", "000000", EMPTY, ZERO, "D", ""),
        ("100644", "100755", OLD, OLD, "M", ""),
        (
            "100644",
            "100755",
            OLD,
            NEW,
            "M",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
    ] {
        let patch = section("x", om, nm, old, new, body);
        assert!(parse_patch(&raw(om, nm, old, new, status), b"x\0", patch.as_bytes()).is_ok());
        if !body.is_empty() {
            let truncated = section("x", om, nm, old, new, "");
            assert!(
                parse_patch(&raw(om, nm, old, new, status), b"x\0", truncated.as_bytes()).is_err()
            );
        }
    }
    for (om, nm) in [
        ("120000", "100644"),
        ("100644", "120000"),
        ("160000", "100644"),
        ("100644", "160000"),
    ] {
        let header = raw(om, nm, OLD, NEW, "T");
        let first = section("x", om, "000000", OLD, ZERO, "@@ -1 +0,0 @@\n-old\n");
        let second = section("x", "000000", nm, ZERO, NEW, "@@ -0,0 +1 @@\n+new\n");
        let binding = RawBinding::parse(7, &header, b"x\0", 40).unwrap();
        let mut parser = Parser::new(binding, EMPTY.as_bytes()).unwrap();
        assert!(!parser.needs_second_section());
        for line in first.as_bytes().split_inclusive(|&b| b == b'\n') {
            parser.record(line, |_| {}).unwrap();
        }
        assert!(parser.needs_second_section());
        assert!(parser.finish().is_err());
        let added = parse_patch(&header, b"x\0", (first.clone() + &second).as_bytes()).unwrap();
        assert_eq!(added.len(), usize::from(nm != "160000"));
        assert!(parse_patch(&header, b"x\0", (second + &first).as_bytes()).is_err());
    }
}

#[test]
fn malformed_sections_and_every_incomplete_prefix_fail_closed() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        "@@ -1 +1 @@\n-old\n+new\n",
    );
    for prefix in patch
        .as_bytes()
        .split_inclusive(|&b| b == b'\n')
        .scan(0, |n, line| {
            *n += line.len();
            Some(*n)
        })
        .filter(|&n| n < patch.len())
    {
        assert!(parse_patch(&header, b"x\0", &patch.as_bytes()[..prefix]).is_err());
    }
    for changed in [
        patch.replace("a/x b/x", "a/x b/y"),
        patch.replace("--- a/x", "--- a/y"),
        patch.replace("+++ b/x", "+++ b/y"),
        patch.replace(OLD, NEW),
        patch.replace(" 100644\n", " 100755\n"),
        patch.replace("--- a/x\n", ""),
        patch.replace("+++ b/x\n", ""),
        patch.replace("@@ -1 +1 @@", "@@@ -1 +1 @@@"),
        patch.replace("index", "unknown"),
        patch.replace("diff --git", "diff --cc"),
        patch.replace("diff --git", "diff --combined"),
        patch.replace("--- a/x", "new file mode 100644\n--- a/x"),
        patch.clone() + "+extra\n",
        patch.clone() + "\n",
        patch.clone() + &patch,
        format!("preamble\n{patch}"),
        patch.trim_end().to_owned(),
    ] {
        assert!(parse_patch(&header, b"x\0", changed.as_bytes()).is_err());
    }
}

#[test]
fn hunks_validate_counts_ranges_and_no_newline_markers() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    for body in [
        "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n",
        "@@ -1,0 +2 @@\n+one\n@@ -2 +2,0 @@\n-two\n",
        "@@ -1 +1 @@\n same\n\\ No newline at end of file\n",
    ] {
        assert!(
            parse_patch(
                &header,
                b"x\0",
                section("x", "100644", "100644", OLD, NEW, body).as_bytes()
            )
            .is_ok()
        );
    }
    for body in [
        "@@ -0 +1 @@\n-old\n+new\n",
        "@@ -1 +0 @@\n-old\n+new\n",
        "@@ -0,0 +0,0 @@\n",
        "@@ -1, +1 @@\n",
        "@@ -1 -1 @@\n",
        "@@ -1 +1 @@@\n",
        "@@ -1 +1 @@junk\n",
        "@@ -18446744073709551616 +1 @@\n",
        "@@ -18446744073709551615,2 +1 @@\n",
        "@@ -1 +18446744073709551615,2 @@\n",
        "@@ -1 +1 @@\n-old\n",
        "@@ -1 +1 @@\n+new\n",
        "@@ -1 +1 @@\n context\n+extra\n",
        "@@ -1 +1 @@\n\\ No newline at end of file\n-old\n+new\n",
        "@@ -1 +1 @@\n-old\n\\ unknown\n+new\n",
        "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n\\ No newline at end of file\n+new\n",
        "@@ -1,2 +1 @@\n-old\n\\ No newline at end of file\n-more\n+new\n",
        "@@ -1 +1,2 @@\n-old\n+new\n\\ No newline at end of file\n+more\n",
        "@@ -2 +2 @@\n-old\n+new\n@@ -1 +3 @@\n-old\n+new\n",
        "@@ -2 +2 @@\n-old\n+new\n@@ -3 +1 @@\n-old\n+new\n",
        "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n@@ -2 +2 @@\n-more\n+more\n",
        "@@ -1 +1 @@\n-old\n+new\n--- a/x\n",
    ] {
        assert!(
            parse_patch(
                &header,
                b"x\0",
                section("x", "100644", "100644", OLD, NEW, body).as_bytes()
            )
            .is_err(),
            "body accepted"
        );
    }
}

#[test]
fn quoted_bytes_and_unquoted_space_framing_match_authoritative_paths() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    for (path, encoded) in [
        (b"x\x07".as_slice(), "x\\a"),
        (b"x\x08", "x\\b"),
        (b"x\t", "x\\t"),
        (b"x\n", "x\\n"),
        (b"x\x0b", "x\\v"),
        (b"x\x0c", "x\\f"),
        (b"x\r", "x\\r"),
        (b"x\"", "x\\\""),
        (b"x\\", "x\\\\"),
        (b"x\xff", "x\\377"),
    ] {
        let path = [path, b"\0"].concat();
        let patch = section(
            "x",
            "100644",
            "100644",
            OLD,
            NEW,
            "@@ -1 +1 @@\n-old\n+new\n",
        )
        .replace("a/x", &format!("\"a/{encoded}\""))
        .replace("b/x", &format!("\"b/{encoded}\""));
        assert_eq!(
            parse_patch(&header, &path, patch.as_bytes()).unwrap(),
            vec![(7, 1, b"new".to_vec(), true)]
        );
    }
    for path in [
        "space name",
        "space b/name",
        "dev/null",
        " leading trailing ",
    ] {
        let mut patch = section(
            path,
            "100644",
            "100644",
            OLD,
            NEW,
            "@@ -1 +1 @@\n-old\n+new\n",
        );
        if path.contains(' ') {
            patch = patch
                .replace(&format!("--- a/{path}\n"), &format!("--- a/{path}\t\n"))
                .replace(&format!("+++ b/{path}\n"), &format!("+++ b/{path}\t\n"));
        }
        assert!(parse_patch(&header, format!("{path}\0").as_bytes(), patch.as_bytes()).is_ok());
    }
}

#[test]
fn rejects_bad_quoting_and_path_trailers_without_recovery() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        "@@ -1 +1 @@\n-old\n+new\n",
    );
    for bad in [
        "\"a/x",
        "\"a/x\\\"",
        "\"a/\\q\"",
        "\"a/\\00\"",
        "\"a/\\000\"",
        "\"a/\\400\"",
        "\"a/\\999\"",
        "\"a/\\x78\"",
        "\"a/\\u0078\"",
        "\"a/y\"",
        "\"a/\"",
        "\"a/xxx\"",
        "a/xjunk",
    ] {
        assert!(parse_patch(&header, b"x\0", patch.replacen("a/x", bad, 1).as_bytes()).is_err());
    }
    for bad in [
        "--- a/x\t",
        "--- a/x timestamp",
        "+++ b/x\t",
        "+++ b/x timestamp",
    ] {
        let original = if bad.starts_with("---") {
            "--- a/x"
        } else {
            "+++ b/x"
        };
        assert!(parse_patch(&header, b"x\0", patch.replace(original, bad).as_bytes()).is_err());
    }
}

#[test]
fn errors_are_fixed_categories() {
    for error in [DiffError::Invalid, DiffError::Limit, DiffError::Overflow] {
        assert!(!format!("{error}").is_empty());
        assert!(!format!("{error:?}").is_empty());
        let _: &dyn std::error::Error = &error;
    }
}

#[test]
fn absent_and_empty_sides_cannot_consume_source_lines() {
    for (om, nm, old, new, status, body) in [
        (
            "000000",
            "100644",
            ZERO,
            NEW,
            "A",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
        (
            "100644",
            "000000",
            OLD,
            ZERO,
            "D",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
        (
            "100644",
            "100644",
            EMPTY,
            NEW,
            "M",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
        (
            "100644",
            "100644",
            OLD,
            EMPTY,
            "M",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
        ("000000", "100644", ZERO, NEW, "A", "@@ -9,0 +1 @@\n+new\n"),
        ("100644", "000000", OLD, ZERO, "D", "@@ -1 +9,0 @@\n-old\n"),
    ] {
        assert!(
            parse_patch(
                &raw(om, nm, old, new, status),
                b"x\0",
                section("x", om, nm, old, new, body).as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn records_are_single_lf_framed_and_exactly_bounded_and_errors_are_sticky() {
    let header = raw("000000", "100644", ZERO, NEW, "A");
    let binding = RawBinding::parse(7, &header, b"x\0", 40).unwrap();
    let framing = section("x", "000000", "100644", ZERO, NEW, "@@ -0,0 +1 @@\n");
    for length in [MAX_RECORD_BYTES, MAX_RECORD_BYTES + 1] {
        let mut parser = Parser::new(binding, EMPTY.as_bytes()).unwrap();
        for line in framing.as_bytes().split_inclusive(|&b| b == b'\n') {
            parser.record(line, |_| {}).unwrap();
        }
        let mut line = vec![b'x'; length];
        line[0] = b'+';
        line[length - 1] = b'\n';
        let mut bytes = 0;
        let result = parser.record(&line, |event| {
            if let Event::Added { payload, .. } = event {
                bytes = payload.len();
            }
        });
        if length == MAX_RECORD_BYTES {
            assert!(result.is_ok());
            assert_eq!(bytes, MAX_RECORD_BYTES - 2);
            assert!(parser.finish().is_ok());
        } else {
            assert_eq!(result, Err(DiffError::Limit));
            assert_eq!(bytes, 0);
            assert!(parser.record(b"+x\n", |_| {}).is_err());
            assert!(parser.finish().is_err());
        }
    }
    let mut parser = Parser::new(binding, EMPTY.as_bytes()).unwrap();
    for line in framing.as_bytes().split_inclusive(|&b| b == b'\n') {
        parser.record(line, |_| {}).unwrap();
    }
    assert!(parser.record(b"+one\n+hidden\n", |_| {}).is_err());
    assert!(parser.finish().is_err());
}

#[test]
fn exhaustive_short_bodies_emit_only_added_records_and_reject_wrong_counts() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    for encoded in 0..729u32 {
        let mut value = encoded;
        let mut body = String::new();
        let (mut old_count, mut new_count) = (0, 0);
        let mut expected = vec![];
        let mut previous_added = false;
        for _ in 0..6 {
            let indicator = b"+- "[(value % 3) as usize];
            value /= 3;
            if indicator != b'+' {
                old_count += 1;
            }
            if indicator != b'-' {
                new_count += 1;
            }
            if indicator == b'+' {
                expected.push((7, new_count, b"added".to_vec(), !previous_added));
            }
            previous_added = indicator == b'+';
            body += if indicator == b'+' {
                "+added\n"
            } else if indicator == b'-' {
                "-deleted\n"
            } else {
                " context\n"
            };
        }
        let hunk = format!(
            "@@ -{},{} +{},{} @@\n",
            u64::from(old_count > 0),
            old_count,
            u64::from(new_count > 0),
            new_count
        );
        let patch = section("x", "100644", "100644", OLD, NEW, &(hunk + &body));
        assert_eq!(
            parse_patch(&header, b"x\0", patch.as_bytes()).unwrap(),
            expected
        );
        let wrong = format!(
            "@@ -{},{} +1,{} @@\n",
            u64::from(old_count > 0),
            old_count,
            new_count + 1
        );
        assert!(
            parse_patch(
                &header,
                b"x\0",
                section("x", "100644", "100644", OLD, NEW, &(wrong + &body)).as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn random_bounded_protocol_bytes_never_panic_or_recover_after_failure() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let binding = RawBinding::parse(7, &header, b"x\0", 40).unwrap();
    let framing = section("x", "100644", "100644", OLD, NEW, "@@ -1,10 +1,10 @@\n");
    let mut seed = 0xc0ffeefu64;
    for _ in 0..2048 {
        let mut bytes = vec![];
        for _ in 0..128 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((seed >> 32) as u8);
        }
        let _ = RawBinding::parse(0, &bytes[..64], &bytes[64..], 40);
        let mut parser = Parser::new(binding, EMPTY.as_bytes()).unwrap();
        for line in framing.as_bytes().split_inclusive(|&b| b == b'\n') {
            parser.record(line, |_| {}).unwrap();
        }
        for chunk in bytes.chunks(16) {
            let record = [chunk, b"\n"].concat();
            let result = parser.record(&record, |event| {
                if let Event::Added { payload, .. } = event {
                    assert_eq!(record[0], b'+');
                    assert_eq!(payload, &record[1..record.len() - 1]);
                }
            });
            if result.is_err() {
                assert!(parser.record(b"+otherwise-valid\n", |_| {}).is_err());
                break;
            }
        }
        assert!(parser.finish().is_err());
    }
}

#[test]
fn deleted_and_context_secrets_never_reach_detector_or_retained_findings() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let marker = "-----BEGIN PRIVATE KEY-----";
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        &format!("@@ -1,2 +1,2 @@\n-{marker}\n {marker}\n+clean\n"),
    );
    let added = parse_patch(&header, b"x\0", patch.as_bytes()).unwrap();
    let mut findings = vec![];
    for (source_id, line, payload, _) in added {
        crate::rules::builtin::detect_line(&payload, |rule, span| {
            findings.push(crate::scanner::Finding {
                source_id,
                line,
                start_column: span.start + 1,
                end_column: span.end + 1,
                rule,
                value: crate::scanner::redaction::RedactedString::new(&payload[span.clone()]),
                id: crate::scanner::fingerprint::FindingId::new(b"", &payload[span]),
            })
        })
        .unwrap();
    }
    assert!(findings.is_empty());
    let mut hits = 0;
    crate::rules::builtin::detect_line(marker.as_bytes(), |_, _| hits += 1).unwrap();
    assert_eq!(hits, 1);
}

#[test]
fn overflow_empty_bindings_sha256_and_extended_header_errors_are_rejected() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let binding = RawBinding::parse(7, &header, b"x\0", 40).unwrap();
    assert!(Parser::new(binding, b"bad").is_err());
    assert!(Parser::new(binding, ZERO.as_bytes()).is_err());
    assert!(
        Parser::new(binding, EMPTY.as_bytes())
            .unwrap()
            .finish()
            .is_err()
    );
    for body in [
        "@@ -18446744073709551615 +1 @@\n-old\n+new\n",
        "@@ -1 +18446744073709551615 @@\n-old\n+new\n",
        "@@ -1 +1 @@\n\n",
        "@@ -1 +1 @@\n?invalid\n",
        "@@ -1,0 +1 @@\n-old\n+new\n",
        "@@ -1 +1,0 @@\n+new\n-old\n",
        "@@ -1 +1 @@\n-old\n+new\n@@ -2 +2 @@\n-old\n+new\n\\ No newline at end of file\n",
    ] {
        let result = parse_patch(
            &header,
            b"x\0",
            section("x", "100644", "100644", OLD, NEW, body).as_bytes(),
        );
        if body.ends_with("\\ No newline at end of file\n") {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
    for (om, nm, old, new, status) in [
        ("100644", "100755", OLD, NEW, "M"),
        ("100644", "100755", OLD, OLD, "M"),
        ("000000", "100644", ZERO, EMPTY, "A"),
        ("100644", "000000", EMPTY, ZERO, "D"),
    ] {
        let body = if new == NEW {
            "@@ -1 +1 @@\n-old\n+new\n"
        } else {
            ""
        };
        let patch = section("x", om, nm, old, new, body);
        let header = raw(om, nm, old, new, status);
        for bad in [
            patch.clone() + "index unexpected\n",
            patch.replace("mode 100644", "mode 100755"),
            patch.replace("mode 100755", "mode 100644"),
        ] {
            if bad != patch {
                assert!(parse_patch(&header, b"x\0", bad.as_bytes()).is_err());
            }
        }
    }
    let old = "a".repeat(64);
    let new = "b".repeat(64);
    let empty = "e".repeat(64);
    let zero = "0".repeat(64);
    let header = raw("120000", "100644", &old, &new, "T");
    let patch = section(
        "x",
        "120000",
        "000000",
        &old,
        &zero,
        "@@ -1 +0,0 @@\n-old\n",
    ) + &section(
        "x",
        "000000",
        "100644",
        &zero,
        &new,
        "@@ -0,0 +1 @@\n+new\n",
    );
    let mut parser = Parser::new(
        RawBinding::parse(0, &header, b"x\0", 64).unwrap(),
        empty.as_bytes(),
    )
    .unwrap();
    for line in patch.as_bytes().split_inclusive(|&b| b == b'\n') {
        parser.record(line, |_| {}).unwrap();
    }
    assert!(!parser.needs_second_section());
    assert!(parser.finish().is_ok());
}

#[test]
fn individual_header_field_and_quoted_token_truncations_fail() {
    for header in [
        b":100644\0".as_slice(),
        b":100644 100644\0",
        b":100644 100644 old\0",
        b":100644 100644 old new\0",
        b":100644 invalid old new M\0",
        b":100644 100644 old new M extra\0",
    ] {
        assert!(RawBinding::parse(0, header, b"x\0", 40).is_err());
    }
    let header = raw("100644", "100644", OLD, NEW, "M");
    let patch = section(
        "x",
        "100644",
        "100644",
        OLD,
        NEW,
        "@@ -1 +1 @@\n-old\n+new\n",
    );
    for bad in [
        patch.replace("b/x\n", "b/x junk\n"),
        patch.replacen("a/x b/x", "\"", 1),
        patch.replacen("a/x b/x", "\"a/\\", 1),
        patch.replace("+1 @@", "+ @@"),
        patch.replace("+1 @@", "+1 @ @"),
    ] {
        assert!(parse_patch(&header, b"x\0", bad.as_bytes()).is_err());
    }
    for path in [
        b"control\t\0".as_slice(),
        b"high\xff\0",
        b"quote\"\0",
        b"back\\\0",
    ] {
        let mut parser = Parser::new(
            RawBinding::parse(0, &header, path, 40).unwrap(),
            EMPTY.as_bytes(),
        )
        .unwrap();
        let record = [
            b"diff --git a/".as_slice(),
            &path[..path.len() - 1],
            b" b/",
            &path[..path.len() - 1],
            b"\n",
        ]
        .concat();
        assert!(parser.record(&record, |_| {}).is_err());
    }
    for (om, nm, old, new, status) in [
        ("000000", "100644", ZERO, NEW, "A"),
        ("100644", "000000", OLD, ZERO, "D"),
        ("100644", "100755", OLD, NEW, "M"),
    ] {
        let header = raw(om, nm, old, new, status);
        let body = if status == "A" {
            "@@ -0,0 +1 @@\n+new\n"
        } else if status == "D" {
            "@@ -1 +0,0 @@\n-old\n"
        } else {
            "@@ -1 +1 @@\n-old\n+new\n"
        };
        let patch = section("x", om, nm, old, new, body);
        for bad in [
            patch.replace("/dev/null", "wrong"),
            patch.replace(&format!("{new}\n"), &format!("{new} 100644\n")),
            patch.replace("file mode", "wrong mode"),
            patch.replace("old mode", "wrong mode"),
            patch.replace("new mode", "wrong mode"),
        ] {
            if bad != patch {
                assert!(parse_patch(&header, b"x\0", bad.as_bytes()).is_err());
            }
        }
    }
}

#[test]
fn mismatched_hunk_gaps_cannot_invent_new_coordinates() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    for body in [
        "@@ -1 +10 @@\n-old\n+new\n",
        "@@ -10 +1 @@\n-old\n+new\n",
        "@@ -1 +1 @@\n-old\n+new\n@@ -3 +4 @@\n-old\n+new\n",
        "@@ -1,0 +2 @@\n+one\n@@ -2 +3,0 @@\n-two\n",
    ] {
        assert!(
            parse_patch(
                &header,
                b"x\0",
                section("x", "100644", "100644", OLD, NEW, body).as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn absent_and_empty_side_anchors_cannot_skip_missing_source() {
    for (om, nm, old, new, status, body) in [
        (
            "000000",
            "100644",
            ZERO,
            NEW,
            "A",
            "@@ -0,0 +9 @@\n+clean\n",
        ),
        (
            "100644",
            "000000",
            OLD,
            ZERO,
            "D",
            "@@ -9 +0,0 @@\n-clean\n",
        ),
        (
            "100644",
            "100644",
            EMPTY,
            NEW,
            "M",
            "@@ -9,0 +10 @@\n+clean\n",
        ),
        (
            "100644",
            "100644",
            OLD,
            EMPTY,
            "M",
            "@@ -10 +9,0 @@\n-clean\n",
        ),
    ] {
        assert!(
            parse_patch(
                &raw(om, nm, old, new, status),
                b"x\0",
                section("x", om, nm, old, new, body).as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn no_newline_eof_forbids_later_zero_count_anchor_gaps_and_failure_stays_sticky() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    for body in [
        "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n@@ -2,0 +3 @@\n+later\n",
        "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n@@ -3 +2,0 @@\n-later\n",
    ] {
        let patch = section("x", "100644", "100644", OLD, NEW, body);
        let mut parser = Parser::new(
            RawBinding::parse(7, &header, b"x\0", 40).unwrap(),
            EMPTY.as_bytes(),
        )
        .unwrap();
        let mut rejected = false;
        for line in patch.as_bytes().split_inclusive(|&b| b == b'\n') {
            if parser.record(line, |_| {}).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(parser.record(b"+otherwise-valid\n", |_| {}).is_err());
        assert!(parser.finish().is_err());
    }
}

#[test]
fn equal_nonzero_gaps_and_exact_eof_anchors_preserve_valid_coordinates() {
    let header = raw("100644", "100644", OLD, NEW, "M");
    let body = "@@ -10 +10 @@\n-old\n+first\n@@ -13 +13 @@\n-old\n+second\n";
    assert_eq!(
        parse_patch(
            &header,
            b"x\0",
            section("x", "100644", "100644", OLD, NEW, body).as_bytes()
        )
        .unwrap(),
        vec![
            (7, 10, b"first".to_vec(), true),
            (7, 13, b"second".to_vec(), true),
        ]
    );
    for body in [
        "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+first\n@@ -1,0 +2 @@\n+second\n",
        "@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n@@ -2 +1,0 @@\n-later\n",
    ] {
        assert!(
            parse_patch(
                &header,
                b"x\0",
                section("x", "100644", "100644", OLD, NEW, body).as_bytes()
            )
            .is_ok()
        );
    }
}

#[test]
fn dirty_worktree_gitlink_uses_bound_no_index_variant() {
    let header = raw("160000", "160000", OLD, OLD, "M");
    let valid = format!(
        "diff --git a/sub b/sub\n--- a/sub\n+++ b/sub\n@@ -1 +1 @@\n-Subproject commit {OLD}\n+Subproject commit {OLD}-dirty\n"
    );
    for patch in [
        valid.clone(),
        valid.replace("a/sub", "a/wrong"),
        valid.replace("+++ b/sub", "+++ b/wrong"),
        valid.replace("@@ -1 +1 @@", "@@ -1 +1,2 @@"),
        valid.replace("-dirty", "-other"),
        valid.replace("-Subproject commit ", "-Incorrect "),
        valid.clone() + "extra\n",
    ] {
        let binding = RawBinding::parse_worktree_resolved(7, &header, b"sub\0", 40).unwrap();
        let result = parse_binding(binding, patch.as_bytes());
        assert_eq!(result.is_ok(), patch == valid);
        if let Ok(added) = result {
            assert!(added.is_empty());
        }
    }
}
