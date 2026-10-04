//! Pinned index-tree scanning. Raw and patch streams are consumed in lockstep.
use super::{
    ScanError, ScanOutcome,
    diff::{Event, Parser, RawBinding},
    engine::{self, Collector, MAX_FINDINGS, MAX_LINE_BYTES},
    git::{self, Process},
};
use crate::{
    config::{
        self,
        ignore::{ACTIVE_POLICY, Exclusions, PolicyUsage},
    },
    rules::{Registry, entropy::Histogram},
};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

const OID_CAP: usize = 65;
// Everything except output format is shared. --unified=0 ALSO enables patches
// with --raw on Git 2.30, so it belongs only to the patch command.
pub(super) const DIFF_FLAGS: &[&str] = &[
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--text",
    "--inter-hunk-context=0",
    "--diff-algorithm=myers",
    "--no-indent-heuristic",
    "--no-function-context",
    "--no-relative",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--output-indicator-new=+",
    "--output-indicator-old=-",
    "--output-indicator-context= ",
    "--submodule=short",
    "--ignore-submodules=none",
    "-O/dev/null",
];
pub(super) fn path(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(OsString::from_vec(bytes))
}
pub(super) fn oid(bytes: Vec<u8>) -> Result<String, ScanError> {
    let value = bytes.strip_suffix(b"\n").ok_or(ScanError::GitMetadata)?;
    if !matches!(value.len(), 40 | 64)
        || !value
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || value.iter().all(|&b| b == b'0')
    {
        return Err(ScanError::GitMetadata);
    }
    Ok(String::from_utf8(value.to_vec()).expect("validated ASCII object ID"))
}
pub(super) fn git_oid(cwd: &Path, args: &[&str]) -> Result<String, ScanError> {
    oid(git::successful(git::command(cwd).args(args), OID_CAP)?)
}
#[derive(PartialEq)]
pub(super) struct Head {
    symbolic: Vec<u8>,
    commit: Option<String>,
}
pub(super) fn head(cwd: &Path) -> Result<Head, ScanError> {
    let (status, symbolic) = git::capture(
        git::command(cwd).args(["symbolic-ref", "-q", "HEAD"]),
        MAX_LINE_BYTES,
    )?;
    if !status.success() && (status.code() != Some(1) || !symbolic.is_empty()) {
        return Err(ScanError::GitMetadata);
    }
    let (status, commit) = git::capture(
        git::command(cwd).args([
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            "HEAD^{commit}",
        ]),
        OID_CAP,
    )?;
    let commit = if status.success() {
        Some(oid(commit)?)
    } else {
        if status.code() != Some(1) || !commit.is_empty() {
            return Err(ScanError::GitMetadata);
        }
        let reference = symbolic
            .strip_suffix(b"\n")
            .filter(|v| v.starts_with(b"refs/heads/"))
            .ok_or(ScanError::GitMetadata)?;
        let (status, bytes) = git::capture(
            git::command(cwd)
                .args(["show-ref", "--verify", "--quiet", "--"])
                .arg(path(reference.to_vec())),
            OID_CAP,
        )?;
        if status.code() != Some(1) || !bytes.is_empty() {
            return Err(ScanError::GitMetadata);
        }
        None
    };
    Ok(Head { symbolic, commit })
}
#[derive(PartialEq)]
pub(super) struct IndexStamp {
    size: u64,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
pub(super) fn index_stamp(file: &Path) -> Result<Option<IndexStamp>, ScanError> {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(file) {
        Ok(m) => Ok(Some(IndexStamp {
            size: m.len(),
            dev: m.dev(),
            ino: m.ino(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ScanError::GitMetadata),
    }
}
pub(crate) fn git_path(cwd: &Path, args: &[&str]) -> Result<PathBuf, ScanError> {
    let bytes = git::successful(git::command(cwd).args(args), MAX_LINE_BYTES)?;
    let value = bytes
        .strip_suffix(b"\n")
        .filter(|b| !b.is_empty() && !b.contains(&0))
        .ok_or(ScanError::GitMetadata)?;
    Ok(cwd.join(path(value.to_vec())))
}
fn policy_blob(cwd: &Path, tree: &str, name: &str) -> Result<Option<Vec<u8>>, ScanError> {
    let bytes = git::successful(
        git::command(cwd).args(["ls-tree", "--full-tree", "-z", tree, "--", name]),
        MAX_LINE_BYTES,
    )?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let tab = bytes
        .iter()
        .position(|&b| b == b'\t')
        .ok_or(ScanError::GitMetadata)?;
    let (metadata, filename) = (&bytes[..tab], &bytes[tab + 1..]);
    if filename != [name.as_bytes(), b"\0"].concat() {
        return Err(ScanError::GitMetadata);
    }
    let mut fields = metadata.split(|&b| b == b' ');
    if !matches!(fields.next(), Some(b"100644" | b"100755")) || fields.next() != Some(b"blob") {
        return Err(ScanError::Policy);
    }
    let object = fields.next().ok_or(ScanError::GitMetadata)?;
    if object.len() != tree.len() || fields.next().is_some() {
        return Err(ScanError::GitMetadata);
    }
    let object = oid([object, b"\n"].concat())?;
    Ok(Some(git::successful(
        git::command(cwd).args(["cat-file", "blob", &object]),
        config::MAX_CONFIG_BYTES,
    )?))
}
fn diff(cwd: &Path, base: &str, index: &str, patch: bool) -> Result<Process, ScanError> {
    let mut command = git::command(cwd);
    command.arg("diff").args(DIFF_FLAGS);
    if patch {
        command.args(["--patch", "--full-index", "--unified=0"]);
    } else {
        command.args(["--raw", "-z", "--no-abbrev"]);
    }
    Process::start(command.args([base, index, "--"]))
}
/// Staged mode never reads source or discovered policy from working-tree files.
pub fn scan_staged(cwd: &Path, explicit: Option<&Path>, no_inline: bool) -> ScanOutcome {
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    let collector = Mutex::new(Collector::new(MAX_FINDINGS));
    if let Err(error) = acquire(cwd, explicit, no_inline, &mut outcome, &collector) {
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
    explicit: Option<&Path>,
    no_inline: bool,
    outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    let root = git_path(cwd, &["rev-parse", "--show-toplevel"])?;
    let index_path = git_path(cwd, &["rev-parse", "--git-path", "index"])?;
    let original_head = head(cwd)?;
    let index = git_oid(cwd, &["write-tree"])?;
    let stamp = index_stamp(&index_path)?;
    let base = match &original_head.commit {
        Some(commit) => git_oid(
            cwd,
            &[
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{commit}^{{tree}}"),
            ],
        )?,
        None => git_oid(cwd, &["mktree"])?,
    };
    let empty_blob = git_oid(cwd, &["hash-object", "--stdin"])?;
    if base.len() != index.len() || empty_blob.len() != index.len() {
        return Err(ScanError::GitMetadata);
    }
    let config = policy_blob(cwd, &index, ".rayloc.yaml")?;
    let exclusions = policy_blob(cwd, &index, ".raylocignore")?;
    let (registry, exclusions) = (|| {
        let base = config
            .as_deref()
            .map(config::parse)
            .transpose()?
            .unwrap_or_default();
        let config = match explicit {
            Some(file) => base.merge(config::parse(&config::read_policy(file)?)?)?,
            None => base,
        };
        let mut registry = Registry::compile(config)?;
        registry.inline_ignores = !no_inline;
        Ok::<_, config::ConfigError>((
            registry,
            Exclusions::from_bytes(&root, exclusions, PolicyUsage::default(), ACTIVE_POLICY)?,
        ))
    })()
    .map_err(|_| ScanError::Policy)?;
    let mut raw = diff(cwd, &base, &index, false)?;
    let mut patch = diff(cwd, &base, &index, true)?;
    consume(
        &mut raw.output,
        &mut patch.output,
        &root,
        &empty_blob,
        &registry,
        &exclusions,
        outcome,
        collector,
    )?;
    raw.finish_success()?;
    patch.finish_success()?;
    if original_head != head(cwd)?
        || stamp != index_stamp(&index_path)?
        || index != git_oid(cwd, &["write-tree"])?
    {
        return Err(ScanError::GitMetadata);
    }
    Ok(())
}
fn next_source(source: &mut u32) -> Result<(), ScanError> {
    *source = source.checked_add(1).ok_or(ScanError::CounterOverflow)?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn consume(
    raw: &mut impl std::io::BufRead,
    patch: &mut impl std::io::BufRead,
    root: &Path,
    empty_blob: &str,
    registry: &Registry,
    exclusions: &Exclusions,
    outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>,
) -> Result<(), ScanError> {
    consume_resolved(
        raw, patch, root, empty_blob, registry, exclusions, outcome, collector, false,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn consume_resolved(
    raw: &mut impl std::io::BufRead,
    patch: &mut impl std::io::BufRead,
    root: &Path,
    empty_blob: &str,
    registry: &Registry,
    exclusions: &Exclusions,
    outcome: &mut ScanOutcome,
    collector: &Mutex<Collector>,
    worktree: bool,
) -> Result<(), ScanError> {
    let (mut header, mut pathname, mut previous, mut line) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut lookahead = git::record(patch, b'\n', &mut line)?;
    let mut source_id = 0u32;
    let mut histogram = Histogram::new();
    while git::record(raw, 0, &mut header)? {
        if !git::record(raw, 0, &mut pathname)? {
            return Err(ScanError::GitMetadata);
        }
        next_source(&mut source_id)?;
        let binding = if worktree {
            RawBinding::parse_worktree_resolved(source_id, &header, &pathname, empty_blob.len())
        } else {
            RawBinding::parse(source_id, &header, &pathname, empty_blob.len())
        }
        .map_err(|_| ScanError::GitMetadata)?;
        if binding.path() <= previous.as_slice() {
            return Err(ScanError::GitMetadata);
        }
        previous.clear();
        previous.extend_from_slice(binding.path());
        let excluded = binding.new_mode() == 0o160000
            || (binding.new_mode() == 0 && binding.old_mode() == 0o160000)
            || binding.path().split(|&b| b == b'/').any(|c| c == b".git")
            || exclusions.excludes(&root.join(path(binding.path().to_vec())));
        if excluded {
            engine::add(&mut outcome.stats.files_excluded, 1)?;
        } else {
            engine::add(&mut outcome.stats.files_attempted, 1)?;
        }
        let mut parser =
            Parser::new(binding, empty_blob.as_bytes()).map_err(|_| ScanError::GitMetadata)?;
        let mut first = true;
        while lookahead {
            if !first && line.starts_with(b"diff --git ") && !parser.needs_second_section() {
                break;
            }
            first = false;
            let mut error = None;
            parser
                .record(&line, |event| {
                    if let Event::Added {
                        source_id,
                        new_line,
                        payload,
                        ..
                    } = event
                    {
                        if !excluded && error.is_none() {
                            error = (|| {
                                engine::add(&mut outcome.stats.bytes_read, payload.len())?;
                                engine::add(&mut outcome.stats.lines_scanned, 1)?;
                                engine::detect_record(
                                    payload,
                                    source_id,
                                    new_line,
                                    outcome,
                                    engine::LIMITS,
                                    registry,
                                    &mut histogram,
                                    collector,
                                )
                            })()
                            .err();
                        }
                    }
                    // The current detector is strictly per physical line: no state
                    // survives Boundary, non-additions, hunks or different files.
                })
                .map_err(|_| ScanError::GitMetadata)?;
            if let Some(error) = error {
                return Err(error);
            }
            lookahead = git::record(patch, b'\n', &mut line)?;
        }
        parser.finish().map_err(|_| ScanError::GitMetadata)?;
        if !excluded {
            engine::add(&mut outcome.stats.files_completed, 1)?;
        }
    }
    if lookahead {
        return Err(ScanError::GitMetadata);
    }
    Ok(())
}
#[cfg(test)]
#[path = "../../tests/unit/staged.rs"]
mod tests;
