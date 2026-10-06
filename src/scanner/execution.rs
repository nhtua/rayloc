//! Explicit thread selection and private Rayon execution for scope scans.
use super::ScanError;
use std::ffi::OsStr;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const MAX_SCAN_THREADS: usize = 64;

pub(crate) fn build_pool(
    threads: usize,
    builder: impl FnOnce(usize) -> Result<rayon::ThreadPool, ()>,
) -> Result<rayon::ThreadPool, ScanError> {
    builder(threads).map_err(|_| ScanError::Pool)
}

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

pub(crate) fn dynamic_claim<W, T, R, F>(
    pool: &rayon::ThreadPool,
    workers: &mut [W],
    jobs: &[T],
    process: F,
) -> Vec<R>
where
    W: Send,
    T: Sync,
    R: Default + Send,
    F: Fn(&mut W, &T, &mut R) + Sync,
{
    let next = AtomicUsize::new(0);
    use rayon::prelude::*;
    pool.install(|| {
        workers
            .par_iter_mut()
            .map(|worker| {
                let mut result = R::default();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(job) = jobs.get(index) else { break };
                    process(worker, job, &mut result);
                }
                result
            })
            .collect()
    })
}

#[cfg(test)]
#[path = "../../tests/unit/execution.rs"]
mod tests;
