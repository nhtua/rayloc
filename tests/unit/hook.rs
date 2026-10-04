use super::*;
use crate::test_support::TempDir;

#[test]
fn identical_managed_hook_with_lost_permissions_is_repaired() {
    let dir = TempDir::new();
    let path = dir.path().join("pre-commit");
    fs::write(&path, SCRIPT).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    install_at(dir.path()).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn concurrent_installations_publish_one_complete_executable_hook() {
    let dir = TempDir::new();
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        let barrier = &barrier;
        let directory = dir.path();
        for _ in 0..16 {
            scope.spawn(move || {
                barrier.wait();
                install_at(directory).unwrap();
            });
        }
    });
    let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(fs::read(dir.path().join("pre-commit")).unwrap(), SCRIPT);
}

#[test]
fn permission_failures_preserve_existing_bytes_and_leave_no_partial_hook() {
    let dir = TempDir::new();
    let path = dir.path().join("pre-commit");
    fs::write(&path, SCRIPT).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    assert_eq!(install_at(dir.path()), Err(MANUAL));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), SCRIPT);
    fs::remove_file(&path).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(install_at(dir.path()), Err(WRITE));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!path.exists());
}

#[test]
fn missing_hooks_directory_cannot_be_created_in_read_only_parent() {
    let dir = TempDir::new();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(install_at(&dir.path().join("hooks")), Err(WRITE));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!dir.path().join("hooks").exists());
}

#[test]
fn failed_publication_never_claims_installation_or_changes_unmanaged_content() {
    let dir = TempDir::new();
    let path = dir.path().join("pre-commit");
    let exists = || Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
    assert_eq!(installed(exists(), &path), Err(WRITE));
    fs::write(&path, "unmanaged hook").unwrap();
    assert_eq!(installed(exists(), &path), Err(MANUAL));
    assert_eq!(
        installed(
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            &path
        ),
        Err(WRITE)
    );
    assert_eq!(fs::read(&path).unwrap(), b"unmanaged hook");
}

#[test]
fn hook_preparation_requires_writable_owned_synchronizable_file() {
    let dir = TempDir::new();
    let path = dir.path().join("candidate");
    fs::write(&path, "existing").unwrap();
    assert!(write_hook(&mut File::open(&path).unwrap()).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"existing");
    // /dev/null accepts bytes, but an ordinary user cannot change its mode.
    let mut null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    assert_eq!(
        write_hook(&mut null).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    // A socket accepts writes and permissions but cannot synchronize to disk.
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let owned: std::os::fd::OwnedFd = socket.into();
    let mut socket_file = File::from(owned);
    assert!(write_hook(&mut socket_file).is_err());
}
