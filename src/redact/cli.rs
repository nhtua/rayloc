//! Strict argument parsing, policy setup, and stdio/file dispatch.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use crate::rules::Registry;

use super::{Stats, Summary, filter::filter, report::write_summary};

pub(super) enum Input {
    Stdin,
    File(PathBuf),
    Command(OsString, Vec<OsString>, bool, bool),
}

fn parse(args: Vec<OsString>) -> Result<(Input, Option<PathBuf>), ()> {
    let mut args = args.into_iter();
    let mut file = None;
    let mut config = None;
    let mut stdout = None;
    let mut stderr = None;
    while let Some(arg) = args.next() {
        if arg == "--" {
            if file.is_some() {
                return Err(());
            }
            let program = args.next().ok_or(())?;
            return Ok((
                Input::Command(
                    program,
                    args.collect(),
                    stdout.unwrap_or(true),
                    stderr.unwrap_or(true),
                ),
                config,
            ));
        }
        if arg == "--config" {
            if config.is_some() {
                return Err(());
            }
            config = Some(PathBuf::from(args.next().ok_or(())?));
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--stdout=")) {
            if stdout.is_some() {
                return Err(());
            }
            stdout = Some(match value {
                "true" => true,
                "false" => false,
                _ => return Err(()),
            });
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--stderr=")) {
            if stderr.is_some() {
                return Err(());
            }
            stderr = Some(match value {
                "true" => true,
                "false" => false,
                _ => return Err(()),
            });
        } else if arg.to_str().is_some_and(|s| s.starts_with('-')) || file.is_some() {
            return Err(());
        } else {
            file = Some(PathBuf::from(arg));
        }
    }
    if stdout.is_some() || stderr.is_some() {
        return Err(());
    }
    Ok((file.map_or(Input::Stdin, Input::File), config))
}

pub(crate) fn run(args: Vec<OsString>) -> u8 {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        return if writeln!(io::stdout(), "Usage: rayloc redact [--config <file>] [<file> | -- <command>...]\nCommand options: --stdout=true|false --stderr=true|false").is_ok() { 0 } else { 2 };
    }
    run_with_report(args, super::report::report())
}

pub(super) fn run_with_report(args: Vec<OsString>, report: io::Result<impl Write>) -> u8 {
    let Ok(mut report) = report else {
        return 2;
    };
    let started = Instant::now();
    let mut summary = Summary {
        mode: "invalid",
        ..Summary::default()
    };
    let result = execute(args, &mut summary);
    summary.sources.sort_unstable_by_key(|(source, _)| *source);
    let code = match result {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(()) => 2,
    };
    if write_summary(&mut report, &summary, started.elapsed(), code).is_err() {
        return 2;
    }
    code
}

fn execute(args: Vec<OsString>, summary: &mut Summary) -> Result<bool, ()> {
    let (input, config) = parse(args).map_err(|_| {
        summary.error = Some("arguments");
    })?;
    summary.mode = match &input {
        Input::Stdin => "stdio",
        Input::File(_) => "file",
        Input::Command(..) => "command",
    };
    let root = crate::config::discover_root(Path::new(".")).map_err(|_| {
        summary.error = Some("policy");
    })?;
    let policy = crate::config::load(&root, config.as_deref()).map_err(|_| {
        summary.error = Some("policy");
    })?;
    let mut registry = Registry::compile(policy).map_err(|_| {
        summary.error = Some("policy");
    })?;
    summary.policy = true;
    registry.inline_ignores = false;
    match input {
        Input::Stdin => {
            let mut stats = Stats::default();
            let result = filter(
                &mut BufReader::with_capacity(256 * 1024, io::stdin()),
                &mut io::stdout(),
                &registry,
                &mut stats,
            );
            summary.sources.push(("stdin", Some(stats)));
            result.map_err(|_| {
                summary.error = Some("filter");
            })
        }
        Input::File(path) => {
            if !fs::metadata(&path)
                .map_err(|_| {
                    summary.error = Some("open");
                })?
                .is_file()
            {
                summary.error = Some("not-regular-file");
                return Err(());
            }
            let file = open_regular(&path).map_err(|_| {
                summary.error = Some("open");
            })?;
            if !file
                .metadata()
                .map_err(|_| {
                    summary.error = Some("open");
                })?
                .is_file()
            {
                summary.error = Some("not-regular-file");
                return Err(());
            }
            let mut stats = Stats::default();
            let result = filter(
                &mut BufReader::with_capacity(256 * 1024, file),
                &mut io::stdout(),
                &registry,
                &mut stats,
            );
            summary.sources.push(("file", Some(stats)));
            result.map_err(|_| {
                summary.error = Some("filter");
            })
        }
        Input::Command(program, args, stdout, stderr) => {
            super::command::command(program, args, stdout, stderr, &registry, summary)
        }
    }
}

/// Open a validated regular file without a race window on the final path
/// component: `O_NONBLOCK` prevents a path swapped to a FIFO from blocking.
fn open_regular(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const NONBLOCK: i32 = 0x800;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const NONBLOCK: i32 = 0x4;
    OpenOptions::new()
        .read(true)
        .custom_flags(NONBLOCK)
        .open(path)
}

#[cfg(test)]
#[path = "../../tests/unit/redact_cli.rs"]
mod tests;
