//! Secure report creation and bounded aggregate summaries.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::Summary;

pub(super) fn report() -> io::Result<fs::File> {
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

pub(super) fn write_summary(
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

#[cfg(test)]
#[path = "../../tests/unit/redact_report.rs"]
mod tests;
