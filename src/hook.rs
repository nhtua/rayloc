//! Atomic, no-clobber installation into Git's active pre-commit directory.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const SCRIPT: &[u8] = b"#!/bin/sh\n# Managed by rayloc.\nexec rayloc scan --staged\n";
const MANUAL: &str = "existing hook preserved; manually integrate rayloc scan --staged into the active pre-commit hook and propagate its nonzero status";
const WRITE: &str = "cannot install executable hook";
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn install(cwd: &Path) -> Result<(), &'static str> {
    // Hooks run at the worktree root. Resolve both relative core.hooksPath and
    // relative PATH entries there, even when installation starts in a subdirectory.
    let root = crate::scanner::staged::git_path(cwd, &["rev-parse", "--show-toplevel"])
        .map_err(|_| "cannot resolve Git worktree")?;
    let directory = crate::scanner::staged::git_path(&root, &["rev-parse", "--git-path", "hooks"])
        .map_err(|_| "cannot resolve active Git hooks directory")?;
    let available = Command::new("/bin/sh")
        .current_dir(&root)
        .args(["-c", "command -v rayloc >/dev/null 2>&1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !available.is_ok_and(|status| status.success()) {
        return Err(
            "rayloc is unavailable on PATH; install the scanner before installing its hook",
        );
    }
    install_at(&directory)
}

fn write_error(_: std::io::Error) -> &'static str {
    WRITE
}

fn preserve_error(_: std::io::Error) -> &'static str {
    MANUAL
}

fn existing(path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Ok(metadata) if metadata.is_file() => {}
        _ => return Err(MANUAL),
    }
    let file = File::open(path).map_err(preserve_error)?;
    let mut bytes = Vec::new();
    (&file)
        .take(SCRIPT.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(preserve_error)?;
    if bytes != SCRIPT {
        return Err(MANUAL);
    }
    let mode = file.metadata().map_err(write_error)?.permissions().mode();
    if mode & 0o111 != 0o111 {
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(write_error)?;
    }
    Ok(true)
}

fn install_at(directory: &Path) -> Result<(), &'static str> {
    let destination = directory.join("pre-commit");
    if existing(&destination)? {
        return Ok(());
    }
    fs::create_dir_all(directory).map_err(write_error)?;
    let temporary = directory.join(format!(
        ".rayloc-hook-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(write_error)?;
    let result = write_hook(&mut file).and_then(|()| {
        // Linking a completed inode publishes atomically and never replaces an
        // existing directory entry, including a concurrently installed hook.
        fs::hard_link(&temporary, &destination)
    });
    drop(file);
    let cleanup = fs::remove_file(temporary).map_err(write_error);
    let result = installed(result, &destination);
    result.and(cleanup)
}

// Keep file preparation separate from publication: any write, permission, or
// synchronization failure must leave the destination untouched.
fn write_hook(file: &mut File) -> std::io::Result<()> {
    file.write_all(SCRIPT)?;
    file.set_permissions(fs::Permissions::from_mode(0o755))?;
    file.sync_all()
}

fn installed(result: std::io::Result<()>, destination: &Path) -> Result<(), &'static str> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if existing(destination)? {
                Ok(())
            } else {
                Err(WRITE)
            }
        }
        Err(_) => Err(WRITE),
    }
}

#[cfg(test)]
#[path = "../tests/unit/hook.rs"]
mod tests;
