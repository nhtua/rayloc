use super::*;
use std::ffi::OsStr;

#[test]
fn thread_resolution_obeys_precedence_and_bounds() {
    for threads in [1, 8, 32, 64] {
        assert_eq!(
            resolve_threads(Some(threads), Some(OsStr::new("2")), 16),
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

#[cfg(unix)]
#[test]
fn non_utf8_thread_environment_is_a_fixed_error() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        resolve_threads(None, Some(OsStr::from_bytes(b"\xff")), 8),
        Err(ScanError::ScopeLimit)
    );
}
