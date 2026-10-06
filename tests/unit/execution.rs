use super::*;
use std::ffi::OsStr;

#[test]
fn private_pool_creation_failures_map_to_a_fixed_scan_error() {
    assert!(matches!(build_pool(4, |_| Err(())), Err(ScanError::Pool)));
}

#[test]
fn thread_resolution_obeys_precedence_and_bounds() {
    for threads in [1, 8, 32, 64] {
        assert_eq!(
            resolve_threads(Some(threads), Some(OsStr::new("2")), 16),
            Ok(threads)
        );
        assert_eq!(
            resolve_threads(Some(threads), Some(OsStr::new("invalid")), 16),
            Ok(threads)
        );
        assert_eq!(
            resolve_threads(None, Some(OsStr::new(&threads.to_string())), 16),
            Ok(threads)
        );
    }
    assert_eq!(resolve_threads(None, None, 32), Ok(8));
    assert_eq!(resolve_threads(None, None, 2), Ok(2));
    for value in [0, 65, usize::MAX] {
        assert_eq!(
            resolve_threads(Some(value), None, 8),
            Err(ScanError::ScopeLimit)
        );
    }
    for value in ["", "0", "65", "abc"] {
        assert_eq!(
            resolve_threads(None, Some(OsStr::new(value)), 8),
            Err(ScanError::ScopeLimit)
        );
    }
}

#[test]
fn dynamic_claiming_finishes_later_jobs_while_the_first_job_is_blocked() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let mut workers = vec![(), ()];
    let jobs: Vec<usize> = (0..32).collect();
    let started = std::sync::mpsc::channel();
    let (release_send, release_recv) = std::sync::mpsc::channel();
    let release_recv = std::sync::Mutex::new(release_recv);
    let finished = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            dynamic_claim(&pool, &mut workers, &jobs, |_, job, _: &mut ()| {
                if *job == 0 {
                    started.0.send(()).unwrap();
                    release_recv.lock().unwrap().recv().unwrap();
                } else {
                    finished.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
        });
        started
            .1
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while finished.load(std::sync::atomic::Ordering::Relaxed) < 2
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        let later_finished = finished.load(std::sync::atomic::Ordering::Relaxed) >= 2;
        release_send.send(()).unwrap();
        worker.join().unwrap();
        assert!(
            later_finished,
            "later jobs must be claimable while job zero is blocked"
        );
    });
}

#[cfg(unix)]
#[test]
fn non_utf8_thread_environment_is_a_fixed_error() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        resolve_threads(None, Some(OsStr::from_bytes(b"\xff")), 8),
        Err(ScanError::ScopeLimit)
    );
}
