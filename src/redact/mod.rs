//! Bounded record processing for stream redaction.

mod cli;
mod command;
pub(crate) mod filter;
mod pem;
mod report;

use std::io;

pub(crate) use cli::run;

#[derive(Default)]
pub(super) struct Stats {
    pub(super) bytes_read: u64,
    pub(super) bytes_written: u64,
    pub(super) records: u64,
    pub(super) detections: u64,
    pub(super) redactions: u64,
    pub(super) private_key_blocks: u64,
    pub(super) unterminated_blocks: u64,
}

pub(super) fn increment(counter: &mut u64, amount: usize) -> io::Result<()> {
    *counter = counter
        .checked_add(u64::try_from(amount).map_err(|_| io::Error::other("counter overflow"))?)
        .ok_or_else(|| io::Error::other("counter overflow"))?;
    Ok(())
}

#[derive(Default)]
pub(super) struct Summary {
    pub(super) mode: &'static str,
    pub(super) policy: bool,
    pub(super) sources: Vec<(&'static str, Option<Stats>)>,
    pub(super) child_started: bool,
    pub(super) child: Option<std::process::ExitStatus>,
    pub(super) error: Option<&'static str>,
}
