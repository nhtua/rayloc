use super::*;
use crate::redact::Stats;
use crate::rules::Registry;
use std::io::{Cursor, Write};

struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive diagnostic"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("sensitive diagnostic"))
    }
}

struct PanicWriter;
impl Write for PanicWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("synthetic private diagnostic");
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn worker_panics_and_io_errors_are_reported_as_fixed_failures() {
    let _lock = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let _hook = PanicHookGuard(Some(std::panic::take_hook()));
    std::panic::set_hook(Box::new(|_| {}));
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut stats = Stats::default();
    assert!(
        worker(
            &mut BufReader::new(Cursor::new(b"clean\n")),
            &mut PanicWriter,
            &registry,
            &mut stats
        )
        .is_err()
    );
    assert!(
        worker(
            &mut BufReader::new(Cursor::new(b"clean\n")),
            &mut BrokenWriter,
            &registry,
            &mut stats
        )
        .is_err()
    );
    assert!(
        !worker(
            &mut BufReader::new(Cursor::new(b"clean\n")),
            &mut Vec::new(),
            &registry,
            &mut stats
        )
        .unwrap()
    );
}
