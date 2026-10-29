//! Secure report creation and bounded aggregate summaries.

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::Summary;

pub(super) fn report() -> io::Result<fs::File> {
    // A pre-epoch system clock cannot be represented; treat it as zero time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    report_in(Path::new("/tmp"), std::process::id(), now)
}

fn report_in(directory: &Path, pid: u32, now: Duration) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    for collision in 0..64 {
        let path = directory.join(format!(
            "rayloc-report-{}-{collision}.txt",
            format_datetime(now)
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
                    "rayloc report v1\npid={}\nstarted_at={}Z\nstatus=running",
                    pid,
                    format_datetime(now)
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

fn format_datetime(time: Duration) -> String {
    let seconds = i64::try_from(time.as_secs()).unwrap_or(i64::MAX);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    }
    .div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
}

pub(super) fn sanitized_program_name(program: &OsStr) -> Option<String> {
    let name = Path::new(program).file_name()?.to_str()?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return None;
    }
    Some(name.to_owned())
}

pub(super) fn write_summary(
    report: &mut dyn Write,
    summary: &Summary,
    elapsed: Duration,
    code: u8,
) -> io::Result<()> {
    let status = if code == 2 { "failed" } else { "complete" };
    use std::os::unix::process::ExitStatusExt;
    let child = match summary.child {
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit:{code}"),
            (_, Some(signal)) => format!("signal:{signal}"),
            _ => "unavailable".to_owned(),
        },
        None if summary.child_started => "unavailable".to_owned(),
        None => "not-started".to_owned(),
    };
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let duration_seconds = format!("{}.{:09}", elapsed.as_secs(), elapsed.subsec_nanos());
    writeln!(
        report,
        "invocation=rayloc redact\nmode={}\npolicy={}\nduration_seconds={}\nfinished_at={}Z\nchild_program={}\nchild={}\nerror={}",
        summary.mode,
        summary.policy,
        duration_seconds,
        format_datetime(time),
        summary.child_program.as_deref().unwrap_or("none"),
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
