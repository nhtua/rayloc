use super::*;
use std::io::Cursor;
#[test]
fn records_validate_framing_order_duplicates_and_budgets() {
    let mut records = Records::new(
        io::BufReader::with_capacity(1, Cursor::new(b"a\0a\0b\0")),
        LIMITS,
    );
    assert!(records.next().unwrap());
    assert_eq!(records.current, b"a");
    assert!(records.next().unwrap());
    assert_eq!(records.current, b"b");
    assert!(!records.next().unwrap());
    for input in [
        b"a".as_slice(),
        b"\0",
        b"/a\0",
        b"a/../b\0",
        b"./a\0",
        b"a//b\0",
        b"b\0a\0",
    ] {
        let mut records = Records::new(Cursor::new(input), LIMITS);
        while let Ok(true) = records.next() {}
        let mut records = Records::new(Cursor::new(input), LIMITS);
        let result = loop {
            match records.next() {
                Ok(true) => {}
                result => break result,
            }
        };
        assert_eq!(result, Err(ScanError::GitMetadata));
    }
    for limits in [
        MetadataLimits {
            records: 0,
            ..LIMITS
        },
        MetadataLimits { bytes: 0, ..LIMITS },
        MetadataLimits { path: 0, ..LIMITS },
    ] {
        assert_eq!(
            Records::new(Cursor::new(b"a\0"), limits).next(),
            Err(ScanError::ScopeLimit)
        );
    }
    let mut records = Records::new(Cursor::new(b"a\0"), LIMITS);
    records.count = u64::MAX;
    assert_eq!(records.next(), Err(ScanError::CounterOverflow));
    let mut records = Records::new(Cursor::new(b"a\0"), LIMITS);
    records.bytes = u64::MAX;
    assert_eq!(records.next(), Err(ScanError::CounterOverflow));
}
struct InterruptedThenError(bool);
impl Read for InterruptedThenError {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        if self.0 {
            self.0 = false;
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Err(io::Error::other("sensitive diagnostic"))
        }
    }
}
#[test]
fn io_errors_are_fixed_and_drain_consumes_large_diagnostics() {
    assert!(drain(InterruptedThenError(true)).is_err());
    assert_eq!(
        Records::new(BufReader::new(InterruptedThenError(true)), LIMITS).next(),
        Err(ScanError::GitMetadata)
    );
    let mut bytes = Cursor::new(vec![b'x'; 65536]);
    drain(&mut bytes).unwrap();
    assert_eq!(bytes.position(), 65536);
}
#[test]
fn real_cursor_tracks_removed_paths_subtrees_and_reaps_early() {
    let temp = crate::test_support::TempDir::new();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(temp.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        )
    };
    git(&["init", "--quiet"]);
    std::fs::create_dir(temp.path().join("sub")).unwrap();
    for name in ["a", "sub/b", "z"] {
        std::fs::write(temp.path().join(name), "clean").unwrap();
    }
    git(&["add", "."]);
    std::fs::remove_file(temp.path().join("a")).unwrap();
    let mut cursor = Tracked::start(temp.path(), &temp.path().join("sub")).unwrap();
    assert!(!cursor.contains(b"a").unwrap());
    assert!(cursor.contains(b"sub/b").unwrap());
    cursor.finish().unwrap();
    let mut cursor = Tracked::start(temp.path(), temp.path()).unwrap();
    assert!(cursor.contains(b"sub/b").unwrap());
    assert!(!cursor.contains(b"x").unwrap());
    assert!(cursor.contains(b"z").unwrap());
    cursor.finish().unwrap();
    drop(Tracked::start(temp.path(), temp.path()).unwrap());
    assert!(Tracked::start(temp.path(), Path::new("/outside")).is_err());
    let outside = crate::test_support::TempDir::new();
    let mut cursor = Tracked::start(outside.path(), outside.path()).unwrap();
    assert_eq!(cursor.finish(), Err(ScanError::GitMetadata));
}
#[cfg(unix)]
#[test]
fn cursor_read_failures_propagate_during_membership_and_final_drain() {
    fn cursor() -> Tracked {
        let mut child = Command::new("sh")
            .args(["-c", "printf 'a\\000b\\000a\\000'"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let records = Records::new(BufReader::new(child.stdout.take().unwrap()), LIMITS);
        let stderr = child.stderr.take().unwrap();
        let diagnostic = Some(std::thread::spawn(move || drain(stderr)));
        let mut cursor = Tracked {
            child,
            diagnostic,
            records,
            present: false,
            finished: false,
        };
        cursor.present = cursor.records.next().unwrap();
        cursor
    }
    let mut membership = cursor();
    assert_eq!(membership.contains(b"z"), Err(ScanError::GitMetadata));
    let mut finishing = cursor();
    assert_eq!(finishing.finish(), Err(ScanError::GitMetadata));
    let mut diagnostic = cursor();
    diagnostic.records.limits.records = 0;
    assert_eq!(diagnostic.finish(), Err(ScanError::ScopeLimit));
}
#[test]
fn failed_diagnostic_drainers_make_an_otherwise_successful_child_incomplete() {
    let temp = crate::test_support::TempDir::new();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(temp.path())
            .args(["init", "--quiet"])
            .status()
            .unwrap()
            .success()
    );
    for panics in [false, true] {
        let mut cursor = Tracked::start(temp.path(), temp.path()).unwrap();
        cursor.diagnostic.take().unwrap().join().unwrap().unwrap();
        cursor.diagnostic = Some(std::thread::spawn(move || {
            assert!(!panics, "test drain failure");
            Err(io::Error::other("test read failure"))
        }));
        assert_eq!(cursor.finish(), Err(ScanError::GitMetadata));
    }
}
#[test]
fn unavailable_diagnostic_thread_kills_and_reaps_the_piped_child() {
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let result = attach_diagnostic(
        &mut child,
        Err(io::Error::other("synthetic thread startup error")),
    );
    assert!(matches!(result, Err(ScanError::GitMetadata)));
    assert!(child.try_wait().unwrap().is_some());
}
