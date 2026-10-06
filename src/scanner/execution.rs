//! Explicit thread selection and private Rayon execution for scope scans.
use super::ScanError;
use std::ffi::OsStr;

pub(crate) const MAX_SCAN_THREADS: usize = 64;

pub(crate) fn resolve_threads(
    requested: Option<usize>,
    environment: Option<&OsStr>,
    available: usize,
) -> Result<usize, ScanError> {
    let value = if let Some(requested) = requested {
        requested
    } else if let Some(environment) = environment {
        environment
            .to_str()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ScanError::ScopeLimit)?
    } else {
        available.clamp(1, 8)
    };
    if !(1..=MAX_SCAN_THREADS).contains(&value) {
        return Err(ScanError::ScopeLimit);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../../tests/unit/execution.rs"]
mod tests;
