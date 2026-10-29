//! Child capture with concurrent per-channel workers and cleanup.

use std::{
    ffi::OsString,
    io::{self, BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::{Mutex, mpsc},
    time::Duration,
};

use crate::rules::Registry;

use super::{Stats, Summary, filter::filter};

static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;
struct PanicHookGuard(Option<PanicHook>);
impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if let Some(hook) = self.0.take() {
            std::panic::set_hook(hook);
        }
    }
}

pub(super) fn command(
    program: OsString,
    args: Vec<OsString>,
    stdout: bool,
    stderr: bool,
    registry: &Registry,
    summary: &mut Summary,
) -> Result<bool, ()> {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(if stdout {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stderr(if stderr {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            summary.error = Some("spawn");
            return Err(());
        }
    };
    summary.child_started = true;
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();
    // Worker panic payloads may contain source text; suppress the process-wide
    // hook while workers run and convert unwinds to fixed errors.
    // Match arms, not `unwrap_or_else(|error| ...)`: a closure here only runs on
    // a poisoned lock, so the arm is exercised directly by the poison test.
    let _hook_lock = match PANIC_HOOK_LOCK.lock() {
        Ok(guard) => guard,
        Err(error) => error.into_inner(),
    };
    let _hook_guard = PanicHookGuard(Some(std::panic::take_hook()));
    std::panic::set_hook(Box::new(|_| {}));
    std::thread::scope(|scope| {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (tx, rx) = mpsc::sync_channel(2);
            let mut remaining = 0;
            let mut failed = false;
            if !stdout {
                summary.sources.push(("stdout", None));
            }
            if !stderr {
                summary.sources.push(("stderr", None));
            }
            if let Some(input) = child_stdout {
                let tx = tx.clone();
                if std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        let mut stats = Stats::default();
                        let result = worker(
                            &mut BufReader::with_capacity(256 * 1024, input),
                            &mut io::stdout(),
                            registry,
                            &mut stats,
                        );
                        let _ = tx.send(("stdout", stats, result));
                    })
                    .is_ok()
                {
                    remaining += 1;
                } else {
                    failed = true;
                }
            }
            if let Some(input) = child_stderr {
                let tx = tx.clone();
                if std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        let mut stats = Stats::default();
                        let result = worker(
                            &mut BufReader::with_capacity(256 * 1024, input),
                            &mut io::stderr(),
                            registry,
                            &mut stats,
                        );
                        let _ = tx.send(("stderr", stats, result));
                    })
                    .is_ok()
                {
                    remaining += 1;
                } else {
                    failed = true;
                }
            }
            drop(tx);
            let mut found = false;
            if failed {
                let _ = child.kill();
            }
            let mut status = None;
            while remaining > 0 || status.is_none() {
                if status.is_none() {
                    match child.try_wait() {
                        Ok(s) => status = s,
                        Err(_) => {
                            failed = true;
                            let _ = child.kill();
                            status = child.wait().ok();
                            if status.is_none() {
                                break;
                            }
                        }
                    }
                }
                if remaining > 0 {
                    match rx.recv_timeout(Duration::from_millis(10)) {
                        Ok((source, stats, Ok(detected))) => {
                            summary.sources.push((source, Some(stats)));
                            found |= detected;
                            remaining -= 1;
                        }
                        Ok((source, stats, Err(()))) => {
                            summary.sources.push((source, Some(stats)));
                            failed = true;
                            remaining -= 1;
                            let _ = child.kill();
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            failed = true;
                            let _ = child.kill();
                            remaining = 0;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                } else if status.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            summary.child = status;
            if failed || !status.is_some_and(|s| s.success()) {
                summary.error = Some(if failed { "worker" } else { "child" });
                Err(())
            } else {
                Ok(found)
            }
        }));
        match result {
            Ok(result) => result,
            Err(_) => {
                let _ = child.kill();
                summary.child = child.wait().ok();
                summary.error = Some("worker");
                Err(())
            }
        }
    })
}

fn worker(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    registry: &Registry,
    stats: &mut Stats,
) -> Result<bool, ()> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        filter(input, output, registry, stats)
    })) {
        Ok(Ok(detected)) => Ok(detected),
        Ok(Err(_)) => Err(()),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/redact_command.rs"]
mod tests;
