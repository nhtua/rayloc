use super::*;
#[test]
fn record_is_bounded_and_requires_terminators() {
    let mut bytes = Vec::new();
    assert!(record(&mut &b"a\0"[..], 0, &mut bytes).unwrap());
    assert_eq!(bytes, b"a\0");
    assert!(record(&mut &b"partial"[..], 0, &mut bytes).is_err());
    assert!(!record(&mut &b""[..], 0, &mut bytes).unwrap());
    let mut exact = vec![b'x'; MAX_LINE_BYTES];
    exact[MAX_LINE_BYTES - 1] = b'\n';
    assert!(record(&mut exact.as_slice(), b'\n', &mut bytes).unwrap());
    exact.push(b'\n');
    exact[MAX_LINE_BYTES - 1] = b'x';
    assert!(record(&mut exact.as_slice(), b'\n', &mut bytes).is_err());
}
struct Errors {
    interrupted: bool,
}
impl Read for Errors {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        if std::mem::take(&mut self.interrupted) {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Err(io::Error::other("private diagnostic"))
        }
    }
}
impl BufRead for Errors {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if std::mem::take(&mut self.interrupted) {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Err(io::Error::other("private diagnostic"))
        }
    }
    fn consume(&mut self, _: usize) {}
}
#[test]
fn io_errors_are_safe_and_interrupted_reads_retry() {
    assert!(drain(Errors { interrupted: true }).is_err());
    assert!(record(&mut Errors { interrupted: true }, 0, &mut Vec::new()).is_err());
    assert!(Process::start(&mut Command::new("/nonexistent/rayloc-test-process")).is_err());
}
#[test]
fn output_overflow_and_early_drop_reap_children() {
    let mut command = Command::new("sh");
    command.args(["-c", "printf abcdef; exec sleep 60"]);
    assert!(matches!(
        capture(&mut command, 3),
        Err(ScanError::ScopeLimit)
    ));
    let mut command = Command::new("sh");
    command.args(["-c", "exec sleep 60"]);
    let process = Process::start(&mut command).unwrap();
    let id = process.child.id();
    drop(process);
    assert!(!Path::new(&format!("/proc/{id}")).exists());
}
#[test]
fn diagnostic_failure_and_panic_cannot_complete_successfully() {
    for panic in [false, true] {
        let mut process = Process::start(&mut Command::new("true")).unwrap();
        process.diagnostic.take().unwrap().join().unwrap().unwrap();
        process.diagnostic = Some(std::thread::spawn(move || {
            if panic {
                panic!("fixture panic");
            }
            Err(io::Error::other("private diagnostic"))
        }));
        assert!(process.finish().is_err());
    }
}
#[test]
fn failed_drainer_start_reaps_the_already_started_child() {
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();
    assert!(attach_diagnostic(&mut child, Err(io::Error::other("thread limit"))).is_err());
    assert!(child.try_wait().unwrap().is_some());
    assert!(capture(&mut Command::new("/nonexistent/rayloc-fixture"), 10).is_err());
}
#[test]
fn successful_requires_nonzero_exit_and_fails_on_error() {
    let mut ok = Command::new("sh");
    ok.args(["-c", "printf output"]);
    assert_eq!(successful(&mut ok, 64).unwrap(), b"output");
    let mut fail = Command::new("sh");
    fail.args(["-c", "printf output; exit 2"]);
    assert!(matches!(
        successful(&mut fail, 64),
        Err(ScanError::GitMetadata)
    ));
}
