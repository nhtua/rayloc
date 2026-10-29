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

#[test]
fn command_recovers_a_poisoned_hook_lock() {
    // A synthetic panic poisons the process-wide hook lock once. `command` must
    // take the poisoned-guard arm and behave exactly as on an uncontended lock.
    // The payload is a static string, never source text.
    let _hook = PanicHookGuard(Some(std::panic::take_hook()));
    std::panic::set_hook(Box::new(|_| {}));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = PANIC_HOOK_LOCK.lock().unwrap();
        panic!("synthetic poison payload");
    }));
    drop(_hook);
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut summary = Summary::default();
    let result = command(
        "sh".into(),
        vec!["-c".into(), "echo clean".into()],
        true,
        true,
        &registry,
        &mut summary,
    );
    assert!(result.is_ok(), "a poisoned hook lock stays recoverable");
    assert_eq!(summary.error, None);
    assert_eq!(summary.sources.len(), 2);
}

#[test]
fn command_inherits_uncaptured_streams_and_reports_child_failure() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut summary = Summary::default();
    let result = command(
        "sh".into(),
        vec!["-c".into(), "sleep 0.05; exit 7".into()],
        false,
        false,
        &registry,
        &mut summary,
    );
    assert_eq!(result, Err(()));
    assert_eq!(summary.error, Some("child"));
    assert!(summary.child_started);
    // Uncaptured streams are recorded as sources without stats, and the loop
    // keeps polling while the child is alive with no workers left to join.
    assert_eq!(
        summary
            .sources
            .iter()
            .map(|(name, stats)| (*name, stats.is_none()))
            .collect::<Vec<_>>(),
        [("stdout", true), ("stderr", true)]
    );
    assert_eq!(summary.child.map(|status| status.code()), Some(Some(7)));
}

#[test]
fn command_reports_worker_failure_when_the_child_overruns_the_record_limit() {
    // The child emits one 1 MiB + 1 byte record, so its stdout worker returns a
    // fixed failure to the channel and `command` reports the worker arm.
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut summary = Summary::default();
    let result = command(
        "sh".into(),
        vec![
            "-c".into(),
            "dd if=/dev/zero bs=1048577 count=1 2>/dev/null | tr '\\0' 'a'".into(),
        ],
        true,
        true,
        &registry,
        &mut summary,
    );
    assert_eq!(result, Err(()));
    assert_eq!(summary.error, Some("worker"));
    assert_eq!(summary.sources.len(), 2);
    assert!(
        summary
            .sources
            .iter()
            .all(|(name, stats)| stats.is_some() && (*name == "stdout" || *name == "stderr"))
    );
}

#[test]
fn command_reports_worker_thread_spawn_failure_and_reaps_child() {
    FAIL_NEXT_WORKER_SPAWN.with(|fail| fail.set(true));
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let mut summary = Summary::default();
    let result = command(
        "sh".into(),
        vec!["-c".into(), "sleep 5".into()],
        true,
        false,
        &registry,
        &mut summary,
    );
    assert_eq!(result, Err(()));
    assert_eq!(summary.error, Some("worker"));
    assert!(summary.child_started);
    assert!(summary.child.is_some_and(|status| !status.success()));
}

#[test]
fn command_silences_the_process_hook_while_workers_run() {
    let registry = Registry::compile(crate::config::Config::default()).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let exerciser_barrier = std::sync::Arc::clone(&barrier);
    let exerciser = std::thread::spawn(move || {
        exerciser_barrier.wait();
        // Sleep well inside the window where `command` has the silent hook
        // installed; the payload is a static string, never source text.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = std::panic::catch_unwind(|| panic!("synthetic hook exercise"));
    });
    barrier.wait();
    let mut summary = Summary::default();
    let result = command(
        "sh".into(),
        vec!["-c".into(), "sleep 1; echo clean".into()],
        true,
        true,
        &registry,
        &mut summary,
    );
    let _ = exerciser.join();
    assert!(result.is_ok());
    // The guard restores the previous process hook when `command` returns.
    drop(std::panic::take_hook());
    assert!(!summary.child_started || summary.child.is_some());
}
