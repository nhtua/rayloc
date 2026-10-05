//! Direct pinned-commit-to-tracked-working-tree scans, with independent identities.
use super::{
    ScanError, ScanOutcome,
    diff::RawBinding,
    engine::{Collector, MAX_FINDINGS, MAX_LINE_BYTES},
    git::{self, Process},
    staged,
};
use crate::{
    config::{
        self,
        ignore::{ACTIVE_POLICY, Exclusions, PolicyUsage},
    },
    rules::Registry,
};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::Instant,
};

// Combined original and resolved metadata, including allocated capacities. Source
// content is never retained. Exceeding the cap is an incomplete scan (exit 2).
const METADATA_CAP: usize = 64 * 1024 * 1024;
type Stamp = (u64, u64, u32, u64, i64, i64, i64, i64);
fn stamp(metadata: &fs::Metadata) -> Stamp {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
fn metadata(path: &Path) -> Result<fs::Metadata, ScanError> {
    fs::symlink_metadata(path).map_err(|_| ScanError::GitMetadata)
}
fn regular(path: &Path, before: &fs::Metadata) -> Result<File, ScanError> {
    if !before.is_file() {
        return Err(ScanError::GitMetadata);
    }
    let file = File::open(path).map_err(|_| ScanError::GitMetadata)?;
    if stamp(before) != stamp(&file.metadata().map_err(|_| ScanError::GitMetadata)?) {
        return Err(ScanError::GitMetadata);
    }
    Ok(file)
}
fn finish_hash(mut process: Process) -> Result<String, ScanError> {
    let mut bytes = Vec::new();
    (&mut process.output)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(|_| ScanError::GitMetadata)?;
    if bytes.len() > 65 {
        return Err(ScanError::ScopeLimit);
    }
    process.finish_success()?;
    staged::oid(bytes)
}
fn identity(
    cwd: &Path,
    root: &Path,
    pathname: &[u8],
    mode: u32,
) -> Result<(String, Stamp), ScanError> {
    let relative = staged::path(pathname.to_vec());
    let path = root.join(&relative);
    // Refuse substituted symlink ancestors as well as nonregular leaf files.
    let mut ancestor = root.to_path_buf();
    for component in relative
        .parent()
        .expect("relative path has parent")
        .components()
    {
        ancestor.push(component);
        if !metadata(&ancestor)?.is_dir() {
            return Err(ScanError::GitMetadata);
        }
    }
    let before = metadata(&path)?;
    let object = match mode {
        0o100644 | 0o100755 => {
            let file = regular(&path, &before)?;
            let mut arg = OsString::from("--path=");
            arg.push(relative.as_os_str());
            let mut command = git::command(cwd);
            command.args(["hash-object", "--stdin"]).arg(arg);
            finish_hash(Process::start_input(&mut command, Stdio::from(file))?)?
        }
        0o120000 => {
            if !before.file_type().is_symlink() {
                return Err(ScanError::GitMetadata);
            }
            let link = fs::read_link(&path).map_err(|_| ScanError::GitMetadata)?;
            let bytes = link.as_os_str().as_bytes();
            if bytes.len() > MAX_LINE_BYTES {
                return Err(ScanError::ScopeLimit);
            }
            let mut process = Process::start_input(
                git::command(cwd).args(["hash-object", "--stdin"]),
                Stdio::piped(),
            )?;
            process.write_input(bytes)?;
            finish_hash(process)?
        }
        0o160000 => {
            if !before.is_dir() {
                return Err(ScanError::GitMetadata);
            }
            // A submodule has its own repository; clear only the outer index
            // override, which must still be preserved for the parent acquisition.
            let mut command = git::command(cwd);
            command
                .arg("-C")
                .arg(&path)
                .args(["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"])
                .env_remove("GIT_INDEX_FILE");
            staged::oid(git::successful(&mut command, 65)?)?
        }
        _ => return Err(ScanError::GitMetadata),
    };
    if stamp(&before) != stamp(&metadata(&path)?) {
        return Err(ScanError::GitMetadata);
    }
    Ok((object, stamp(&before)))
}
fn diff(cwd: &Path, base: &str, patch: bool) -> Result<Process, ScanError> {
    let mut command = git::command(cwd);
    command.arg("diff").args(staged::DIFF_FLAGS);
    if patch {
        command.args(["--patch", "--full-index", "--unified=0"]);
    } else {
        command.args(["--raw", "-z", "--no-abbrev"]);
    }
    Process::start(command.args([base, "--"]))
}
fn append(target: &mut Vec<u8>, bytes: &[u8], other: usize, cap: usize) -> Result<(), ScanError> {
    let total = target
        .len()
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(other))
        .ok_or(ScanError::ScopeLimit)?;
    if total > cap {
        return Err(ScanError::ScopeLimit);
    }
    target.reserve_exact(bytes.len());
    if target.capacity() > cap - other {
        return Err(ScanError::ScopeLimit);
    }
    target.extend_from_slice(bytes);
    Ok(())
}
fn resolve(
    cwd: &Path,
    root: &Path,
    header: &mut [u8],
    pathname: &[u8],
    width: usize,
) -> Result<[u8; 64], ScanError> {
    let mut fingerprint = [0; 64];
    let binding = RawBinding::parse_worktree(1, header, pathname, width)
        .map_err(|_| ScanError::GitMetadata)?;
    if binding.new_mode() != 0 {
        let (object, s) = identity(cwd, root, binding.path(), binding.new_mode())?;
        for (chunk, number) in fingerprint.chunks_exact_mut(8).zip([
            s.0,
            s.1,
            u64::from(s.2),
            s.3,
            s.4 as u64,
            s.5 as u64,
            s.6 as u64,
            s.7 as u64,
        ]) {
            chunk.copy_from_slice(&number.to_ne_bytes());
        }
        let offset = 16 + width;
        let old = &header[offset..offset + width];
        if object.len() != width || (!old.iter().all(|&b| b == b'0') && old != object.as_bytes()) {
            return Err(ScanError::GitMetadata);
        }
        header[offset..offset + width].copy_from_slice(object.as_bytes());
    }
    RawBinding::parse_worktree_resolved(1, header, pathname, width)
        .map_err(|_| ScanError::GitMetadata)?;
    Ok(fingerprint)
}
fn snapshot(
    cwd: &Path,
    root: &Path,
    base: &str,
    width: usize,
    cap: usize,
) -> Result<(Vec<u8>, Vec<u8>), ScanError> {
    let mut process = diff(cwd, base, false)?;
    let (mut original, mut resolved, mut header, mut pathname) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    while git::record(&mut process.output, 0, &mut header)? {
        if !git::record(&mut process.output, 0, &mut pathname)? {
            return Err(ScanError::GitMetadata);
        }
        append(&mut original, &header, resolved.capacity(), cap)?;
        append(&mut original, &pathname, resolved.capacity(), cap)?;
        let fingerprint = resolve(cwd, root, &mut header, &pathname, width)?;
        append(&mut original, &fingerprint, resolved.capacity(), cap)?;
        append(&mut resolved, &header, original.capacity(), cap)?;
        append(&mut resolved, &pathname, original.capacity(), cap)?;
    }
    process.finish_success()?;
    Ok((original, resolved))
}
// Recheck streams against retained metadata without allocating a second snapshot.
fn verify(
    cwd: &Path,
    root: &Path,
    base: &str,
    width: usize,
    original: &[u8],
    resolved: &[u8],
) -> Result<(), ScanError> {
    let mut process = diff(cwd, base, false)?;
    let (mut raw, mut normalized) = (original, resolved);
    let (mut header, mut pathname, mut expected) = (Vec::new(), Vec::new(), Vec::new());
    while git::record(&mut process.output, 0, &mut header)? {
        if !git::record(&mut process.output, 0, &mut pathname)? {
            return Err(ScanError::GitMetadata);
        }
        for bytes in [&header, &pathname] {
            if !git::record(&mut raw, 0, &mut expected)? || &expected != bytes {
                return Err(ScanError::GitMetadata);
            }
        }
        let fingerprint = resolve(cwd, root, &mut header, &pathname, width)?;
        raw = raw
            .strip_prefix(&fingerprint)
            .ok_or(ScanError::GitMetadata)?;
        for bytes in [&header, &pathname] {
            if !git::record(&mut normalized, 0, &mut expected)? || &expected != bytes {
                return Err(ScanError::GitMetadata);
            }
        }
    }
    process.finish_success()?;
    if !raw.is_empty() || !normalized.is_empty() {
        return Err(ScanError::GitMetadata);
    }
    Ok(())
}
#[derive(PartialEq)]
struct Policy {
    bytes: Option<Vec<u8>>,
    stamp: Option<Stamp>,
}
fn policy(path: &Path) -> Result<Policy, ScanError> {
    let before = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Policy {
                bytes: None,
                stamp: None,
            });
        }
        Err(_) => return Err(ScanError::Policy),
    };
    let file = regular(path, &before).map_err(|_| ScanError::Policy)?;
    let mut bytes = Vec::new();
    file.take(config::MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ScanError::Policy)?;
    if bytes.len() > config::MAX_CONFIG_BYTES || stamp(&before) != stamp(&metadata(path)?) {
        return Err(ScanError::Policy);
    }
    Ok(Policy {
        bytes: Some(bytes),
        stamp: Some(stamp(&before)),
    })
}
/// Scan final tracked working-tree additions directly against one pinned commit.
pub fn scan_diff(
    cwd: &Path,
    reference: &OsStr,
    explicit: Option<&Path>,
    no_inline: bool,
) -> ScanOutcome {
    scan_diff_with_emitter(cwd, reference, explicit, no_inline, None)
}

pub fn scan_diff_with_emitter(
    cwd: &Path,
    reference: &OsStr,
    explicit: Option<&Path>,
    no_inline: bool,
    emitter: Option<crate::report::emitter::SharedEmitter>,
) -> ScanOutcome {
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    let collector = match emitter {
        Some(e) => Mutex::new(Collector::with_emitter(MAX_FINDINGS, e)),
        None => Mutex::new(Collector::new(MAX_FINDINGS)),
    };
    if let Err(error) = acquire(
        cwd,
        reference,
        explicit,
        no_inline,
        &mut outcome,
        &collector,
    ) {
        outcome.fail(error);
    }
    collector
        .into_inner()
        .expect("collector lock is not poisoned")
        .finish(&mut outcome);
    outcome.elapsed = started.elapsed();
    outcome
}
fn acquire(
    cwd: &Path,
    reference: &OsStr,
    explicit: Option<&Path>,
    no_inline: bool,
    outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    // Option-like refs are invalid even if a specially named revision exists.
    if reference.as_bytes().starts_with(b"-") || reference.is_empty() {
        return Err(ScanError::GitMetadata);
    }
    let root = staged::git_path(cwd, &["rev-parse", "--show-toplevel"])?;
    let mut reference = reference.to_os_string();
    reference.push("^{commit}");
    let base = staged::oid(git::successful(
        git::command(cwd)
            .args(["rev-parse", "--verify", "--end-of-options"])
            .arg(reference),
        65,
    )?)?;
    let index_path = staged::git_path(cwd, &["rev-parse", "--git-path", "index"])?;
    let head = staged::head(cwd)?;
    let index = staged::git_oid(cwd, &["write-tree"])?;
    let index_stamp = staged::index_stamp(&index_path)?;
    let empty = staged::git_oid(cwd, &["hash-object", "--stdin"])?;
    if base.len() != index.len() || base.len() != empty.len() {
        return Err(ScanError::GitMetadata);
    }
    let paths = [
        root.join(".rayloc.yaml"),
        root.join(".raylocignore"),
        explicit.map_or_else(|| root.join(".rayloc.yaml"), PathBuf::from),
    ];
    let policies = [policy(&paths[0])?, policy(&paths[1])?, policy(&paths[2])?];
    let (registry, exclusions) = (|| {
        let mut config = policies[0]
            .bytes
            .as_deref()
            .map(config::parse)
            .transpose()?
            .unwrap_or_default();
        if explicit.is_some() {
            config = config.merge(config::parse(
                policies[2]
                    .bytes
                    .as_deref()
                    .ok_or(config::ConfigError::Read)?,
            )?)?;
        }
        let mut registry = Registry::compile(config)?;
        registry.inline_ignores = !no_inline;
        Ok::<_, config::ConfigError>((
            registry,
            Exclusions::from_bytes(
                &root,
                policies[1].bytes.clone(),
                PolicyUsage::default(),
                ACTIVE_POLICY,
            )?,
        ))
    })()
    .map_err(|_| ScanError::Policy)?;
    let (original, resolved) = snapshot(cwd, &root, &base, base.len(), METADATA_CAP)?;
    let mut patch = diff(cwd, &base, true)?;
    staged::consume_resolved(
        &mut resolved.as_slice(),
        &mut patch.output,
        &root,
        &empty,
        &registry,
        &exclusions,
        outcome,
        collector,
        true,
    )?;
    patch.finish_success()?;
    verify(cwd, &root, &base, base.len(), &original, &resolved)?;
    for (path, before) in paths.iter().zip(policies) {
        if policy(path)? != before {
            return Err(ScanError::Policy);
        }
    }
    if head != staged::head(cwd)?
        || index_stamp != staged::index_stamp(&index_path)?
        || index != staged::git_oid(cwd, &["write-tree"])?
    {
        return Err(ScanError::GitMetadata);
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../tests/unit/worktree.rs"]
mod tests;
