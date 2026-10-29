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
    // `usize` widens losslessly into `u64` on every supported platform.
    match counter.checked_add(amount as u64) {
        Some(value) => {
            *counter = value;
            Ok(())
        }
        None => Err(io::Error::other("counter overflow")),
    }
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
