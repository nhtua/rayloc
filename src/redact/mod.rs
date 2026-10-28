//! Bounded record processing for stream redaction.
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::rules::{Registry, entropy::Histogram};

const MAX_RECORD: usize = 1024 * 1024;
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

#[derive(Default)]
struct Stats {
    bytes_read: u64,
    bytes_written: u64,
    records: u64,
    detections: u64,
    redactions: u64,
    private_key_blocks: u64,
    unterminated_blocks: u64,
}

fn increment(counter: &mut u64, amount: usize) -> io::Result<()> {
    *counter = counter
        .checked_add(u64::try_from(amount).map_err(|_| io::Error::other("counter overflow"))?)
        .ok_or_else(|| io::Error::other("counter overflow"))?;
    Ok(())
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    bytes: &'a mut u64,
}
impl Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        increment(self.bytes, count)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Default)]
struct Summary {
    mode: &'static str,
    policy: bool,
    sources: Vec<(&'static str, Option<Stats>)>,
    child_started: bool,
    child: Option<std::process::ExitStatus>,
    error: Option<&'static str>,
}

enum Input {
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

fn report() -> io::Result<fs::File> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("clock"))?;
    report_in(Path::new("/tmp"), std::process::id(), now)
}

fn report_in(directory: &Path, pid: u32, now: Duration) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    for collision in 0..64 {
        let path = directory.join(format!(
            "rayloc-report-{}-{}-{}-{collision}.txt",
            now.as_secs(),
            now.subsec_nanos(),
            pid
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut file) => {
                writeln!(
                    file,
                    "rayloc report v1\npid={}\nstarted={}.{:09}\nstatus=running",
                    pid,
                    now.as_secs(),
                    now.subsec_nanos()
                )?;
                file.flush()?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("report collision"))
}

pub(crate) fn run(args: Vec<OsString>) -> u8 {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        return if writeln!(io::stdout(), "Usage: rayloc redact [--config <file>] [<file> | -- <command>...]\nCommand options: --stdout=true|false --stderr=true|false").is_ok() { 0 } else { 2 };
    }
    run_with_report(args, report())
}

fn run_with_report(args: Vec<OsString>, report: io::Result<impl Write>) -> u8 {
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

fn write_summary(
    report: &mut dyn Write,
    summary: &Summary,
    elapsed: Duration,
    code: u8,
) -> io::Result<()> {
    let status = if code == 2 { "failed" } else { "complete" };
    let completed = SystemTime::now().duration_since(UNIX_EPOCH).ok();
    let child = summary
        .child
        .map(|status| {
            use std::os::unix::process::ExitStatusExt;
            match (status.code(), status.signal()) {
                (Some(code), _) => format!("exit:{code}"),
                (_, Some(signal)) => format!("signal:{signal}"),
                _ => "unavailable".to_owned(),
            }
        })
        .unwrap_or_else(|| {
            if summary.child_started {
                "unavailable"
            } else {
                "not-started"
            }
            .to_owned()
        });
    writeln!(
        report,
        "mode={}\npolicy={}\nelapsed_ns={}\nfinished={}\nchild={}\nerror={}",
        summary.mode,
        summary.policy,
        elapsed.as_nanos(),
        completed.map_or_else(
            || "unavailable".to_owned(),
            |time| format!("{}.{:09}", time.as_secs(), time.subsec_nanos())
        ),
        child,
        summary.error.unwrap_or("none")
    )?;
    for (source, stats) in &summary.sources {
        match stats {
            Some(stats) => writeln!(
                report,
                "source={source} state=filtered bytes_read={} bytes_written={} records={} detections={} redactions={} private_key_blocks={} unterminated_blocks={}",
                stats.bytes_read,
                stats.bytes_written,
                stats.records,
                stats.detections,
                stats.redactions,
                stats.private_key_blocks,
                stats.unterminated_blocks
            )?,
            None => writeln!(report, "source={source} state=passthrough counts=unknown")?,
        }
    }
    writeln!(report, "status={status}\nexit={code}")?;
    report.flush()
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
            use std::os::unix::fs::OpenOptionsExt;
            if !fs::metadata(&path)
                .map_err(|_| {
                    summary.error = Some("open");
                })?
                .is_file()
            {
                summary.error = Some("not-regular-file");
                return Err(());
            }
            // O_NONBLOCK prevents a path swapped to a FIFO from blocking open.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            const NONBLOCK: i32 = 0x800;
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            const NONBLOCK: i32 = 0x4;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(NONBLOCK)
                .open(path)
                .map_err(|_| {
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
            command(program, args, stdout, stderr, &registry, summary)
        }
    }
}

fn command(
    program: OsString,
    args: Vec<OsString>,
    stdout: bool,
    stderr: bool,
    registry: &Registry,
    summary: &mut Summary,
) -> Result<bool, ()> {
    let mut child = Command::new(program)
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
        .map_err(|_| {
            summary.error = Some("spawn");
        })?;
    summary.child_started = true;
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();
    // Worker panic payloads may contain source text; suppress the process-wide
    // hook while workers run and convert unwinds to fixed errors.
    let _hook_lock = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
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
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        filter(input, output, registry, stats)
    }))
    .map_err(|_| ())
    .and_then(|result| result.map_err(|_| ()))
}

/// Filter one input without retaining it beyond a single physical record.
fn filter(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    registry: &Registry,
    stats: &mut Stats,
) -> io::Result<bool> {
    let mut record = Vec::new();
    let mut histogram = Histogram::new();
    let mut found = false;
    let mut pem = None;
    loop {
        let buffer = match input.fill_buf() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if buffer.is_empty() {
            if !record.is_empty() {
                found |= write_record(&record, output, registry, &mut histogram, &mut pem, stats)?;
            }
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .flush()?;
            if !record.is_empty() {
                increment(&mut stats.records, 1)?;
            }
            if pem.is_some() {
                increment(&mut stats.unterminated_blocks, 1)?;
                return Err(io::Error::other("unterminated private key"));
            }
            return Ok(found);
        }
        let newline = buffer.iter().position(|&b| b == b'\n');
        let count = newline.unwrap_or(buffer.len());
        let consumed = count + usize::from(newline.is_some());
        increment(&mut stats.bytes_read, consumed)?;
        if count > MAX_RECORD.saturating_sub(record.len()) {
            return Err(io::Error::other("record limit"));
        }
        record.extend_from_slice(&buffer[..count]);
        input.consume(consumed);
        if newline.is_some() {
            let crlf = record.last() == Some(&b'\r');
            if crlf {
                record.pop();
            }
            found |= write_record(&record, output, registry, &mut histogram, &mut pem, stats)?;
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .write_all(if crlf { b"\r\n" } else { b"\n" })?;
            CountingWriter {
                inner: output,
                bytes: &mut stats.bytes_written,
            }
            .flush()?;
            increment(&mut stats.records, 1)?;
            record.clear();
        }
    }
}

fn write_record(
    record: &[u8],
    output: &mut dyn Write,
    registry: &Registry,
    histogram: &mut Histogram,
    pem: &mut Option<usize>,
    stats: &mut Stats,
) -> io::Result<bool> {
    let mut spans = Vec::new();
    if registry.private_key_enabled() {
        let markers = crate::rules::builtin::PRIVATE_KEY_MARKERS;
        let mut cursor = 0;
        while cursor < record.len() {
            if let Some(index) = *pem {
                let marker = markers[index];
                let mut end_marker = b"-----END ".to_vec();
                end_marker.extend_from_slice(&marker[b"-----BEGIN ".len()..]);
                let end = record[cursor..]
                    .windows(end_marker.len())
                    .position(|window| window == end_marker)
                    .map(|offset| cursor + offset + end_marker.len());
                spans.push(cursor..end.unwrap_or(record.len()));
                match end {
                    Some(end) => {
                        *pem = None;
                        cursor = end;
                    }
                    None => break,
                }
            } else {
                const BEGIN: &[u8] = b"-----BEGIN ";
                let Some(offset) = record[cursor..]
                    .windows(BEGIN.len())
                    .position(|window| window == BEGIN)
                else {
                    break;
                };
                let start = cursor + offset;
                match markers
                    .iter()
                    .position(|marker| record[start..].starts_with(marker))
                {
                    Some(index) => {
                        increment(&mut stats.private_key_blocks, 1)?;
                        *pem = Some(index);
                        cursor = start;
                    }
                    None => cursor = start + BEGIN.len(),
                }
            }
            if spans.len() > crate::scanner::engine::MAX_FINDINGS {
                return Err(io::Error::other("finding limit"));
            }
        }
    }
    if !record.is_empty() && spans.len() == 1 && spans[0] == (0..record.len()) {
        CountingWriter {
            inner: output,
            bytes: &mut stats.bytes_written,
        }
        .write_all(b"[REDACTED]")?;
        increment(&mut stats.redactions, 1)?;
        return Ok(true);
    }
    let pem_intervals = spans.len();
    let detection = registry.detect_line(record, histogram, |_, span| spans.push(span));
    increment(&mut stats.detections, spans.len() - pem_intervals)?;
    detection.map_err(|_| io::Error::other("detection failed"))?;
    if spans.len() > crate::scanner::engine::MAX_FINDINGS {
        return Err(io::Error::other("finding limit"));
    }
    if spans
        .iter()
        .any(|span| span.start >= span.end || span.end > record.len())
    {
        return Err(io::Error::other("invalid span"));
    }
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let found = !spans.is_empty();
    let mut position = 0;
    let mut index = 0;
    while index < spans.len() {
        let span = &spans[index];
        let start = span.start;
        let mut end = span.end;
        index += 1;
        while index < spans.len() && spans[index].start <= end {
            end = end.max(spans[index].end);
            index += 1;
        }
        let mut writer = CountingWriter {
            inner: output,
            bytes: &mut stats.bytes_written,
        };
        writer.write_all(&record[position..start])?;
        writer.write_all(b"[REDACTED]")?;
        increment(&mut stats.redactions, 1)?;
        position = end;
    }
    CountingWriter {
        inner: output,
        bytes: &mut stats.bytes_written,
    }
    .write_all(&record[position..])?;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn preserves_bytes_and_redacts_across_read_boundaries() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let input = [
            b"before ghp_".as_slice(),
            b"SyntheticToken0123456789abcdef after\r\n\xff\0",
        ]
        .concat();
        for size in 1..=input.len() {
            let mut output = Vec::new();
            let mut reader = BufReader::with_capacity(size, Cursor::new(&input));
            assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
            assert_eq!(output, b"before [REDACTED] after\r\n\xff\0");
        }
    }

    #[test]
    fn oversized_records_are_never_emitted() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let input = vec![b'x'; MAX_RECORD + 1];
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        let mut stats = Stats::default();
        assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
        assert!(output.is_empty());
        assert_eq!(stats.detections, 0);
        assert_eq!(stats.bytes_read, (MAX_RECORD + 1) as u64);
    }

    #[test]
    fn maximum_record_and_crlf_boundary_are_preserved() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let mut input = vec![b'x'; MAX_RECORD - 1];
        input.extend_from_slice(b"\r\n");
        let mut reader = BufReader::with_capacity(13, Cursor::new(&input));
        let mut output = Vec::new();
        assert!(!filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, input);
        let mut input = vec![b'x'; MAX_RECORD];
        input.extend_from_slice(b"\r\n");
        let mut reader = BufReader::with_capacity(13, Cursor::new(&input));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn masks_private_key_body_until_matching_end() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let input =
            b"prefix -----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY----- suffix\n"; // rayloc:ignore
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(
            output,
            b"prefix [REDACTED]\n[REDACTED]\n[REDACTED] suffix\n"
        );
    }

    #[test]
    fn unrelated_begin_prefix_does_not_hide_a_later_private_key() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let input = b"-----BEGIN PUBLIC KEY----- -----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY----- tail\n"; // rayloc:ignore
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, b"-----BEGIN PUBLIC KEY----- [REDACTED] tail\n");
    }

    #[test]
    fn rejects_conflicting_and_incomplete_arguments() {
        for args in [
            vec!["--"],
            vec!["--config"],
            vec!["--config", "one", "--config", "two"],
            vec!["--stdout=false"],
            vec!["--stderr=invalid", "--", "cmd"],
            vec!["--stdout=invalid", "--", "cmd"],
            vec!["--stdout=true", "--stdout=false", "--", "cmd"],
            vec!["--stderr=true", "--stderr=false", "--", "cmd"],
            vec!["file", "other"],
            vec!["file", "--", "cmd"],
            vec!["--unknown"],
        ] {
            assert!(parse(args.into_iter().map(OsString::from).collect()).is_err());
        }
    }

    #[test]
    fn parser_preserves_child_arguments_and_boolean_options() {
        let (input, config) = parse(
            [
                "--config",
                "policy",
                "--stdout=false",
                "--stderr=true",
                "--",
                "app",
                "--",
                "argument",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        )
        .unwrap();
        assert_eq!(config, Some(PathBuf::from("policy")));
        match input {
            Input::Command(program, args, stdout, stderr) => {
                assert_eq!(program, "app");
                assert_eq!(args, ["--", "argument"]);
                assert!(!stdout && stderr);
            }
            _ => panic!("unexpected input mode"),
        }
    }

    #[test]
    fn invalid_and_missing_input_fail_without_child() {
        for args in [
            vec!["--unknown"],
            vec!["--config", "missing-policy-file"],
            vec!["missing-input-file"],
            vec!["."],
            vec!["--", "missing-rayloc-program"],
        ] {
            let mut summary = Summary::default();
            assert!(execute(args.into_iter().map(OsString::from).collect(), &mut summary).is_err());
            assert!(summary.error.is_some());
        }
    }

    #[test]
    fn private_key_variants_and_unterminated_blocks_are_safe() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        for begin in crate::rules::builtin::PRIVATE_KEY_MARKERS {
            let mut end = b"-----END ".to_vec();
            end.extend_from_slice(&begin[b"-----BEGIN ".len()..]);
            let input = [
                b"prefix ".as_slice(),
                begin,
                b"\nbody\n",
                end.as_slice(),
                b" suffix\n",
            ]
            .concat();
            let mut output = Vec::new();
            let mut reader = BufReader::new(Cursor::new(&input));
            let mut stats = Stats::default();
            assert!(filter(&mut reader, &mut output, &registry, &mut stats).unwrap());
            assert_eq!(
                output,
                b"prefix [REDACTED]\n[REDACTED]\n[REDACTED] suffix\n"
            );
            assert_eq!(stats.private_key_blocks, 1);
            assert_eq!(stats.redactions, 3);
            assert_eq!(stats.bytes_read, input.len() as u64);
            assert_eq!(stats.bytes_written, output.len() as u64);
        }
        let mut output = Vec::new();
        let mut stats = Stats::default();
        let mut reader = BufReader::new(Cursor::new(b"-----BEGIN PRIVATE KEY-----\nbody")); // rayloc:ignore
        assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
        assert_eq!(stats.unterminated_blocks, 1);
        assert_eq!(output, b"[REDACTED]\n[REDACTED]");
    }

    #[test]
    fn disabled_key_rule_passes_marker_and_body_unchanged() {
        let policy =
            crate::config::parse(b"version: '1'\ndisabled_rules: [private-key-marker]\n").unwrap();
        let registry = Registry::compile(policy).unwrap();
        let input = b"-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----\n"; // rayloc:ignore
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        assert!(!filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, input);
    }

    #[test]
    fn wrong_end_label_does_not_release_body() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let input =
            b"-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END EC PRIVATE KEY-----\nstill-private\n"; // rayloc:ignore
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
        assert_eq!(output, b"[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]\n");
    }

    #[test]
    fn counters_fail_closed_and_empty_content_is_preserved() {
        let mut max = u64::MAX;
        assert!(increment(&mut max, 1).is_err());
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let mut reader = BufReader::new(Cursor::new(b"\n\r\n\xff\0\r"));
        let mut output = Vec::new();
        let mut stats = Stats::default();
        assert!(!filter(&mut reader, &mut output, &registry, &mut stats).unwrap());
        assert_eq!(output, b"\n\r\n\xff\0\r");
        assert_eq!(stats.records, 3);
    }

    #[test]
    fn overlapping_and_adjacent_custom_matches_are_merged() {
        let config = crate::config::parse(b"version: '1'\nrules:\n  - id: first\n    regex: 'abcde'\n  - id: second\n    regex: 'cdefg'\n  - id: third\n    regex: 'hi'\n").unwrap();
        let registry = Registry::compile(config).unwrap();
        let mut reader = BufReader::new(Cursor::new(b"prefix abcdefghi suffix\n"));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, b"prefix [REDACTED] suffix\n");
    }

    #[test]
    fn detector_failure_after_a_match_withholds_entire_record() {
        let config = crate::config::parse(b"version: '1'\nrules:\n  - id: first\n    regex: 'abc'\n  - id: large\n    regex: 'D+'\n").unwrap();
        let registry = Registry::compile(config).unwrap();
        let mut input = b"abc ".to_vec();
        input.extend(std::iter::repeat_n(b'D', 65537));
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        let mut stats = Stats::default();
        assert!(filter(&mut reader, &mut output, &registry, &mut stats).is_err());
        assert!(output.is_empty());
        assert_eq!(stats.detections, 1);
    }

    #[test]
    fn too_many_matches_on_one_record_are_withheld() {
        let config =
            crate::config::parse(b"version: '1'\nrules: [{id: single, regex: 'x'}]").unwrap();
        let registry = Registry::compile(config).unwrap();
        let mut reader = BufReader::new(Cursor::new(vec![b'x'; 10001]));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn excessive_private_key_blocks_fail_without_emitting_a_partial_record() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let block = b"-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----"; // rayloc:ignore
        let input = block.repeat(10_001);
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        assert!(filter(&mut reader, &mut output, &registry, &mut Stats::default()).is_err());
        assert!(output.is_empty());
    }

    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("sensitive diagnostic"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("sensitive diagnostic"))
        }
    }

    #[test]
    fn writer_failures_propagate_without_source_text() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        for input in [b"clean\n".as_slice(), b"".as_slice()] {
            let mut reader = BufReader::new(Cursor::new(input));
            assert!(
                filter(
                    &mut reader,
                    &mut BrokenWriter,
                    &registry,
                    &mut Stats::default()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn summary_write_and_flush_failures_are_reported() {
        struct FlushFailure(Vec<u8>);
        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("sensitive diagnostic"))
            }
        }
        let summary = Summary {
            mode: "stdio",
            ..Summary::default()
        };
        assert!(write_summary(&mut BrokenWriter, &summary, Duration::ZERO, 0).is_err());
        assert!(write_summary(&mut FlushFailure(Vec::new()), &summary, Duration::ZERO, 0).is_err());
        let mut report = Vec::new();
        let summary = Summary {
            mode: "command",
            child_started: true,
            ..Summary::default()
        };
        write_summary(&mut report, &summary, Duration::ZERO, 2).unwrap();
        assert!(
            String::from_utf8(report)
                .unwrap()
                .contains("child=unavailable")
        );
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let mut stats = Stats::default();
        assert!(
            filter(
                &mut BufReader::new(Cursor::new(b"clean")),
                &mut FlushFailure(Vec::new()),
                &registry,
                &mut stats
            )
            .is_err()
        );
        assert_eq!(stats.records, 0);
    }

    #[test]
    fn report_creation_and_finalization_errors_return_two() {
        assert_eq!(
            run_with_report(
                Vec::new(),
                Err::<BrokenWriter, _>(io::Error::other("private"))
            ),
            2
        );
        assert_eq!(
            run_with_report(vec![OsString::from("--invalid")], Ok(BrokenWriter)),
            2
        );
        let mut report = Vec::new();
        assert_eq!(
            run_with_report(vec![OsString::from("--invalid")], Ok(&mut report)),
            2
        );
        let report = String::from_utf8(report).unwrap();
        assert!(report.contains("error=arguments"));
        assert!(!report.contains("--invalid"));
    }

    #[test]
    fn worker_panics_and_io_errors_are_reported_as_fixed_failures() {
        struct PanicWriter;
        impl Write for PanicWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("synthetic private diagnostic")
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
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

    struct InterruptedReader {
        interrupted: bool,
        data: Cursor<&'static [u8]>,
    }
    impl io::Read for InterruptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.data.read(buf)
        }
    }

    #[test]
    fn interrupted_reads_are_retried() {
        let registry = Registry::compile(crate::config::Config::default()).unwrap();
        let mut reader = BufReader::new(InterruptedReader {
            interrupted: false,
            data: Cursor::new(b"clean\n"),
        });
        let mut output = Vec::new();
        assert!(!filter(&mut reader, &mut output, &registry, &mut Stats::default()).unwrap());
        assert_eq!(output, b"clean\n");
    }

    #[test]
    fn read_failures_and_counter_overflows_stop_without_raw_output() {
        struct FailedReader;
        impl io::Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private diagnostic"))
            }
        }
        let config =
            crate::config::parse(b"version: '1'\nrules: [{id: token, regex: 'sensitive'}]")
                .unwrap();
        let registry = Registry::compile(config).unwrap();
        let mut output = Vec::new();
        assert!(
            filter(
                &mut BufReader::new(FailedReader),
                &mut output,
                &registry,
                &mut Stats::default()
            )
            .is_err()
        );
        assert!(output.is_empty());
        let mut stats = Stats {
            detections: u64::MAX,
            ..Stats::default()
        };
        assert!(
            filter(
                &mut BufReader::new(Cursor::new(b"sensitive\n")),
                &mut output,
                &registry,
                &mut stats
            )
            .is_err()
        );
        assert!(output.is_empty());
    }

    #[test]
    fn report_creation_refuses_collisions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = crate::test_support::TempDir::new();
        let target = directory.path().join("sentinel");
        std::fs::write(&target, b"unchanged").unwrap();
        let first = directory.path().join("rayloc-report-10-0-42-0.txt");
        symlink(&target, &first).unwrap();
        let mut file = report_in(directory.path(), 42, Duration::from_secs(10)).unwrap();
        writeln!(file, "test").unwrap();
        let created = directory.path().join("rayloc-report-10-0-42-1.txt");
        assert_eq!(
            std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        for index in 2..64 {
            std::fs::write(
                directory
                    .path()
                    .join(format!("rayloc-report-10-0-42-{index}.txt")),
                b"occupied",
            )
            .unwrap();
        }
        assert!(report_in(directory.path(), 42, Duration::from_secs(10)).is_err());
        assert!(
            report_in(
                &directory.path().join("missing"),
                42,
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
}
