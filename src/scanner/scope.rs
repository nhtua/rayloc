//! Sorted, bounded recursive scope with serial policy and one private Rayon pool.
use super::{
    ScanError, ScanOutcome,
    engine::{self, Collector, MAX_FINDINGS, Worker},
    tracked::{MAX_PATH_BYTES, Tracked},
};
use crate::{
    config::{
        ScopeRoot,
        ignore::{ACTIVE_POLICY, Decision, Exclusions, PolicyUsage},
    },
    rules::Registry,
};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{IsTerminal, Write},
    path::Path,
    sync::Mutex,
    time::Instant,
};

const MAX_FRONTIER: usize = 65_536;
const MAX_PATH_STORAGE: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
const BATCH: usize = 256;
const BATCH_BYTES: usize = 1024 * 1024;
const POLICY_FILES: usize = 4096;
const POLICY_BYTES: usize = 64 * 1024 * 1024;
const NESTED_REPOSITORIES: usize = 4096;
#[derive(Clone, Copy)]
struct Limits {
    frontier: usize,
    paths: usize,
    depth: usize,
    directory: usize,
    policy: PolicyUsage,
    policy_files: usize,
    policy_bytes: usize,
    administration_path: usize,
}
const LIMITS: Limits = Limits {
    frontier: MAX_FRONTIER,
    paths: MAX_PATH_STORAGE,
    depth: MAX_DEPTH,
    directory: MAX_FRONTIER,
    policy: ACTIVE_POLICY,
    policy_files: POLICY_FILES,
    policy_bytes: POLICY_BYTES,
    administration_path: MAX_PATH_BYTES,
};
/// Benchmark/test controls; hard worker/resource ceilings still apply.
#[derive(Clone, Copy)]
pub struct ScopeOptions {
    pub workers: usize,
    pub parallel_threshold: usize,
    pub parallel_bytes_threshold: u64,
}
impl Default for ScopeOptions {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
            parallel_threshold: 256,
            parallel_bytes_threshold: 256 * 1024,
        }
    }
}
#[derive(Default)]
struct Budget {
    entries: usize,
    paths: usize,
}
impl Budget {
    fn charge(&mut self, entries: usize, paths: usize, limits: Limits) -> Result<(), ScanError> {
        let next_entries = self
            .entries
            .checked_add(entries)
            .ok_or(ScanError::CounterOverflow)?;
        let next_paths = self
            .paths
            .checked_add(paths)
            .ok_or(ScanError::CounterOverflow)?;
        if next_entries > limits.frontier || next_paths > limits.paths {
            return Err(ScanError::ScopeLimit);
        }
        self.entries = next_entries;
        self.paths = next_paths;
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Kind {
    Directory,
    Regular,
    Other,
    Error,
}
struct Entry {
    name: Box<OsStr>,
    kind: Kind,
}
struct Frame {
    directory: Box<Path>,
    entries: Vec<Entry>,
    scanner: bool,
    combined: bool,
    policy: Option<Exclusions>,
}
struct Work {
    path: Box<Path>,
    source_id: u32,
    estimated_bytes: u64,
}
struct Runner<'a> {
    registry: &'a Registry,
    exclusions: Exclusions,
    root: &'a ScopeRoot,
    options: ScopeOptions,
    limits: Limits,
    workers: Vec<Worker>,
    pool: Option<rayon::ThreadPool>,
    helpers: Option<super::batch::HelperPool>,
    collector: Mutex<Collector>,
    emitter: Option<crate::report::emitter::SharedEmitter>,
    outcome: ScanOutcome,
    budget: Budget,
    frames: Vec<Frame>,
    batch: Vec<Work>,
    batch_bytes: usize,
    matched: u32,
    scanned: u32,
    last_progress: Option<std::time::Instant>,
    total_policy: PolicyUsage,
    administration: Vec<Box<Path>>,
    repositories: usize,
    metadata_only: bool,
}
/// Scan an existing directory, optionally intersecting a repository-relative glob.
pub fn scan_directory(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
) -> ScanOutcome {
    scan_directory_with_options(root, selected, pattern, registry, ScopeOptions::default())
}

pub fn scan_directory_with_emitter(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
    emitter: crate::report::emitter::SharedEmitter,
) -> ScanOutcome {
    scan_scope_with_emitter(
        root,
        selected,
        pattern,
        registry,
        ScopeOptions::default(),
        LIMITS,
        Some(emitter),
    )
}
pub fn scan_directory_with_options_and_emitter(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
    options: ScopeOptions,
    emitter: crate::report::emitter::SharedEmitter,
) -> ScanOutcome {
    scan_scope_with_emitter(
        root,
        selected,
        pattern,
        registry,
        options,
        LIMITS,
        Some(emitter),
    )
}
pub fn scan_directory_with_options(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
    options: ScopeOptions,
) -> ScanOutcome {
    scan_scope(root, selected, pattern, registry, options, LIMITS)
}
fn scan_scope(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
    options: ScopeOptions,
    limits: Limits,
) -> ScanOutcome {
    scan_scope_with_emitter(root, selected, pattern, registry, options, limits, None)
}

fn scan_scope_with_emitter(
    root: &ScopeRoot,
    selected: &Path,
    pattern: Option<&str>,
    registry: &Registry,
    options: ScopeOptions,
    limits: Limits,
    emitter: Option<crate::report::emitter::SharedEmitter>,
) -> ScanOutcome {
    let started = Instant::now();
    let result = (|| {
        if options.workers == 0 || options.workers > super::execution::MAX_SCAN_THREADS {
            return Err(ScanError::ScopeLimit);
        }
        let inclusion = pattern.map(compile_glob).transpose()?;
        let exclusions = Exclusions::load_named(
            &root.root,
            ".raylocignore",
            PolicyUsage::default(),
            limits.policy,
        )
        .map_err(policy_error)?;
        let collector = Mutex::new(Collector::new(MAX_FINDINGS));
        let mut runner = Runner {
            registry,
            total_policy: exclusions.usage,
            exclusions,
            root,
            options,
            limits,
            workers: vec![Worker::new()],
            pool: None,
            helpers: None,
            collector,
            emitter,
            outcome: ScanOutcome::default(),
            budget: Budget::default(),
            frames: Vec::new(),
            batch: Vec::with_capacity(BATCH),
            batch_bytes: 0,
            matched: 0,
            scanned: 0,
            last_progress: None,
            administration: Vec::new(),
            repositories: 0,
            metadata_only: false,
        };
        runner.budget.charge(runner.batch.capacity(), 0, limits)?;
        let selected = fs::canonicalize(selected).map_err(|_| ScanError::Discovery)?;
        let execution = runner
            .discover_administration(&selected)
            .and_then(|()| runner.discover(&selected, inclusion.as_ref()));
        if let Err(error) = execution {
            runner.outcome.fail(error);
        }
        runner.flush();
        // Print final newline after progress output
        let mut stderr = std::io::stderr();
        if runner.last_progress.is_some() && stderr.is_terminal() {
            writeln!(stderr, "\r").ok();
        }
        if pattern.is_some() && runner.matched == 0 && runner.outcome.errors.is_empty() {
            runner.outcome.fail(ScanError::NoGlobMatches);
        }
        runner
            .collector
            .into_inner()
            .expect("collector lock is not poisoned")
            .finish(&mut runner.outcome);
        Ok(runner.outcome)
    })();
    let mut outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut outcome = ScanOutcome::default();
            outcome.fail(error);
            outcome
        }
    };
    outcome.elapsed = started.elapsed();
    outcome
}
fn policy_error(error: crate::config::ConfigError) -> ScanError {
    if error == crate::config::ConfigError::Limit {
        ScanError::ScopeLimit
    } else {
        ScanError::Policy
    }
}
fn raw(path: &OsStr) -> &[u8] {
    path.as_encoded_bytes()
}
fn join(parent: &Path, name: &OsStr) -> Result<Box<Path>, ScanError> {
    if parent
        .as_os_str()
        .len()
        .saturating_add(name.len())
        .saturating_add(1)
        > MAX_PATH_BYTES
    {
        return Err(ScanError::ScopeLimit);
    }
    Ok(parent.join(name).into_boxed_path())
}
fn compile_glob(pattern: &str) -> Result<GlobSet, ScanError> {
    if pattern.len() > 16 * 1024 || pattern.bytes().filter(|&b| b == b',').count() > 1024 {
        return Err(ScanError::ScopeLimit);
    }
    let mut depth = 0usize;
    let mut escaped = false;
    for byte in pattern.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'{' => {
                depth += 1;
                if depth > 16 {
                    return Err(ScanError::ScopeLimit);
                }
            }
            b'}' => {
                depth = depth.checked_sub(1).ok_or(ScanError::Discovery)?;
            }
            _ => {}
        }
    }
    if pattern.is_empty()
        || Path::new(pattern).is_absolute()
        || pattern.split('/').any(|p| p == "..")
    {
        return Err(ScanError::Discovery);
    }
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map_err(|_| ScanError::Discovery)?;
    GlobSetBuilder::new()
        .add(glob)
        .build()
        .map_err(|_| ScanError::ScopeLimit)
}
impl Runner<'_> {
    fn pool(&mut self, count: usize, estimated_bytes: u64) -> Result<(), ScanError> {
        if self.workers.len() == 1
            && self.options.workers > 1
            && (count >= self.options.parallel_threshold
                || estimated_bytes >= self.options.parallel_bytes_threshold)
        {
            let pool = super::execution::build_pool(self.options.workers, |threads| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .map_err(|_| ())
            })?;
            self.workers
                .extend((1..self.options.workers).map(|_| Worker::new()));
            self.pool = Some(pool);
            // Create shared helper pool for parallel line batching
            self.helpers = Some(super::batch::HelperPool::new(
                self.options.workers,
                super::batch::BATCH_LIMITS,
            ));
        }
        Ok(())
    }
    fn active_policy(&self) -> Result<PolicyUsage, ScanError> {
        self.frames
            .iter()
            .filter_map(|frame| frame.policy.as_ref())
            .try_fold(self.exclusions.usage, |usage, policy| {
                usage.add(policy.usage).map_err(policy_error)
            })
    }
    fn policy(&mut self, directory: &Path, enabled: bool) -> Result<Option<Exclusions>, ScanError> {
        if !enabled {
            return Ok(None);
        }
        let policy = Exclusions::load_named(
            directory,
            ".gitignore",
            self.active_policy()?,
            self.limits.policy,
        )
        .map_err(policy_error)?;
        self.total_policy = self.total_policy.add(policy.usage).map_err(policy_error)?;
        if self.total_policy.files > self.limits.policy_files
            || self.total_policy.bytes > self.limits.policy_bytes
        {
            return Err(ScanError::ScopeLimit);
        }
        Ok(Some(policy))
    }
    fn decisions(
        &self,
        path: &Path,
        directory: bool,
        parent_scanner: bool,
        parent_combined: bool,
    ) -> (bool, bool) {
        let scanner = self.exclusions.decision(path, directory);
        let git = self
            .frames
            .iter()
            .rev()
            .filter_map(|frame| frame.policy.as_ref())
            .map(|policy| policy.decision(path, directory))
            .find(|decision| *decision != Decision::None)
            .unwrap_or(Decision::None);
        let effective = if scanner == Decision::None {
            git
        } else {
            scanner
        };
        (
            parent_scanner && scanner != Decision::Ignore,
            parent_combined && effective != Decision::Ignore,
        )
    }
    fn enter(
        &mut self,
        directory: Box<Path>,
        scanner: bool,
        combined: bool,
        enumerate: bool,
    ) -> Result<(), ScanError> {
        if self.frames.len() >= self.limits.depth || directory.as_os_str().len() > MAX_PATH_BYTES {
            return Err(ScanError::ScopeLimit);
        }
        self.budget
            .charge(0, directory.as_os_str().len(), self.limits)?;
        let policy = if self.metadata_only {
            None
        } else {
            self.policy(&directory, combined)?
        };
        let entries = if enumerate {
            self.entries(&directory)?
        } else {
            Vec::new()
        };
        self.frames.push(Frame {
            directory,
            entries,
            scanner,
            combined,
            policy,
        });
        Ok(())
    }
    fn entries(&mut self, directory: &Path) -> Result<Vec<Entry>, ScanError> {
        let mut entries: Vec<Entry> = Vec::new();
        let iterator = fs::read_dir(directory).map_err(|_| ScanError::Discovery)?;
        for entry in iterator {
            let entry = entry.map_err(|_| ScanError::Discovery)?;
            if entries.len() >= self.limits.directory {
                return Err(ScanError::ScopeLimit);
            }
            if entries.len() == entries.capacity() {
                let desired = entries
                    .capacity()
                    .saturating_mul(2)
                    .max(16)
                    .min(self.limits.directory);
                self.budget
                    .charge(desired - entries.capacity(), 0, self.limits)?;
                let old = entries.capacity();
                entries.reserve_exact(desired - entries.len());
                self.budget
                    .charge(entries.capacity() - desired, 0, self.limits)?;
                debug_assert!(entries.capacity() >= old);
            }
            let name = entry.file_name().into_boxed_os_str();
            let kind = match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => Kind::Directory,
                Ok(file_type) if file_type.is_file() => Kind::Regular,
                Ok(_) => Kind::Other,
                Err(_) => Kind::Error,
            };
            self.budget.charge(0, name.len(), self.limits)?;
            entries.push(Entry { name, kind });
        }
        // '/' belongs to directory sorting keys; component order would misorder a.txt vs a/x.
        entries.sort_unstable_by(|a, b| {
            raw(&a.name)
                .iter()
                .copied()
                .chain(matches!(a.kind, Kind::Directory).then_some(b'/'))
                .cmp(
                    raw(&b.name)
                        .iter()
                        .copied()
                        .chain(matches!(b.kind, Kind::Directory).then_some(b'/')),
                )
        });
        entries.reverse();
        Ok(entries)
    }
    fn excluded(&mut self) -> Result<(), ScanError> {
        engine::add(&mut self.outcome.stats.files_excluded, 1)
    }
    fn regular(
        &mut self,
        path: Box<Path>,
        parent_scanner: bool,
        parent_combined: bool,
        inclusion: Option<&GlobSet>,
        tracked: &mut Option<Tracked>,
    ) -> Result<(), ScanError> {
        let relative = path
            .strip_prefix(&self.root.root)
            .map_err(|_| ScanError::Discovery)?;
        let tracked = match tracked {
            Some(cursor) => cursor.contains(raw(relative.as_os_str()))?,
            None => false,
        };
        if inclusion.is_some_and(|set| !set.is_match(relative)) {
            return Ok(());
        }
        self.matched = self
            .matched
            .checked_add(1)
            .ok_or(ScanError::CounterOverflow)?;
        let (scanner, combined) = self.decisions(&path, false, parent_scanner, parent_combined);
        if !(if tracked { scanner } else { combined }) {
            return self.excluded();
        }
        if self.batch.len() == BATCH || self.batch_bytes + path.as_os_str().len() > BATCH_BYTES {
            self.flush();
        }
        self.budget.charge(0, path.as_os_str().len(), self.limits)?;
        self.batch_bytes += path.as_os_str().len();
        let estimated_bytes = fs::metadata(&path).map_or(u64::MAX, |metadata| metadata.len());
        self.batch.push(Work {
            path,
            source_id: self.matched,
            estimated_bytes,
        });
        Ok(())
    }
    fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let estimated_bytes = self.batch.iter().fold(0_u64, |total, item| {
            total.saturating_add(item.estimated_bytes)
        });
        if let Err(error) = self.pool(self.batch.len(), estimated_bytes) {
            self.outcome.fail(error);
        }
        let collector = &self.collector;
        let registry = self.registry;
        let root = self.root;
        let emitter = self.emitter.as_ref();
        let process = |(worker, work): (&mut Worker, &[Work])| {
            let mut outcome = ScanOutcome::default();
            for item in work {
                engine::merge(
                    &mut outcome,
                    worker.file(
                        &item.path,
                        item.path.strip_prefix(&root.root).unwrap_or(&item.path),
                        item.source_id,
                        registry,
                        collector,
                        emitter,
                    ),
                );
            }
            outcome
        };
        let parallel = self.pool.is_some()
            && self.options.workers > 1
            && (self.batch.len() >= self.options.parallel_threshold
                || estimated_bytes >= self.options.parallel_bytes_threshold);
        let results: Vec<_> = if parallel {
            let pool = self.pool.as_ref().expect("pool initialized with lanes");
            let helpers = self.helpers.as_ref();
            super::execution::dynamic_claim(
                pool,
                &mut self.workers,
                &self.batch,
                |worker, item, outcome| {
                    // Use parallel line batching for eligible large files
                    if let Some(helpers) = helpers {
                        let run = worker.file_with_batches(
                            &item.path,
                            item.path.strip_prefix(&root.root).unwrap_or(&item.path),
                            item.source_id,
                            registry,
                            helpers,
                            super::batch::BATCH_LIMITS,
                            collector,
                            emitter,
                        );
                        engine::merge(outcome, run.outcome);
                    } else {
                        engine::merge(
                            outcome,
                            worker.file(
                                &item.path,
                                item.path.strip_prefix(&root.root).unwrap_or(&item.path),
                                item.source_id,
                                registry,
                                collector,
                                emitter,
                            ),
                        );
                    }
                },
            )
        } else {
            vec![process((&mut self.workers[0], &self.batch))]
        };
        for outcome in results {
            engine::merge(&mut self.outcome, outcome);
        }
        let batch_size = self.batch.len() as u32;
        self.scanned = self.scanned.saturating_add(batch_size);
        // Throttle progress output: only print if stderr is a terminal and
        // at least 100ms has elapsed since the last progress message.
        let now = std::time::Instant::now();
        let should_print = self.last_progress.is_none()
            || now.duration_since(self.last_progress.unwrap())
                >= std::time::Duration::from_millis(100);
        if should_print {
            // Use \r to overwrite previous progress line (only when terminal)
            let mut stderr = std::io::stderr();
            let is_terminal = stderr.is_terminal();
            if is_terminal {
                write!(stderr, "\r").ok();
            }
            eprint!("rayloc: scanned {}/{} files", self.scanned, self.matched);
            self.last_progress = Some(now);
        }
        self.budget.paths -= self.batch_bytes;
        self.batch_bytes = 0;
        self.batch.clear();
    }
    fn discover(&mut self, selected: &Path, inclusion: Option<&GlobSet>) -> Result<(), ScanError> {
        let relative = selected
            .strip_prefix(&self.root.root)
            .map_err(|_| ScanError::Discovery)?;
        let mut tracked = if self.root.git {
            Some(Tracked::start(&self.root.root, selected)?)
        } else {
            None
        };
        let components: Vec<OsString> = relative.iter().map(OsStr::to_os_string).collect();
        if components.len() >= self.limits.depth {
            return Err(ScanError::ScopeLimit);
        }
        self.enter(
            self.root.root.clone().into_boxed_path(),
            true,
            true,
            components.is_empty(),
        )?;
        for (index, component) in components.iter().enumerate() {
            let parent = self.frames.last().expect("root frame exists");
            let path = join(&parent.directory, component)?;
            let (scanner, combined) = self.decisions(&path, true, parent.scanner, parent.combined);
            self.enter(path, scanner, combined, index + 1 == components.len())?;
        }
        self.walk(inclusion, &mut tracked)?;
        if let Some(cursor) = &mut tracked {
            cursor.finish()?;
        }
        Ok(())
    }
    fn discover_administration(&mut self, selected: &Path) -> Result<(), ScanError> {
        // A pointer can identify administration that sorts before the worktree.
        // Resolve all encountered pointers before admitting any scan work.
        self.metadata_only = true;
        self.enter(selected.into(), true, true, true)?;
        self.walk(None, &mut None)?;
        self.metadata_only = false;
        Ok(())
    }
    fn nested_administration(&mut self, directory: &Path) -> Result<(), ScanError> {
        if self.repositories == NESTED_REPOSITORIES {
            return Err(ScanError::ScopeLimit);
        }
        self.repositories += 1;
        for path in
            crate::config::nested_administration(directory).map_err(|_| ScanError::Discovery)?
        {
            if path.as_os_str().len() > self.limits.administration_path {
                return Err(ScanError::ScopeLimit);
            }
            if self.root.administration.contains(&path)
                || self
                    .administration
                    .iter()
                    .any(|known| known.as_ref() == path)
            {
                continue;
            }
            if self.administration.len() == self.administration.capacity() {
                let old = self.administration.capacity();
                self.administration.reserve_exact(1);
                self.budget
                    .charge(self.administration.capacity() - old, 0, self.limits)?;
            }
            self.budget.charge(0, path.as_os_str().len(), self.limits)?;
            self.administration.push(path.into_boxed_path());
        }
        Ok(())
    }
    fn walk(
        &mut self,
        inclusion: Option<&GlobSet>,
        tracked: &mut Option<Tracked>,
    ) -> Result<(), ScanError> {
        while !self.frames.is_empty() {
            let frame = self.frames.last_mut().expect("frame exists");
            let Some(entry) = frame.entries.pop() else {
                let frame = self.frames.pop().expect("frame exists");
                self.budget.entries -= frame.entries.capacity();
                self.budget.paths -= frame.directory.as_os_str().len();
                continue;
            };
            self.budget.paths -= entry.name.len();
            let path = join(&frame.directory, &entry.name)?;
            let parent_scanner = frame.scanner;
            let parent_combined = frame.combined;
            if entry.name.as_ref() == OsStr::new(".git") {
                if self.metadata_only && matches!(entry.kind, Kind::Regular) {
                    self.nested_administration(path.parent().expect("entry has a parent"))?;
                }
                if !self.metadata_only {
                    self.excluded()?;
                }
                continue;
            }
            if self
                .root
                .administration
                .iter()
                .any(|admin| path.starts_with(admin))
                || self
                    .administration
                    .iter()
                    .any(|admin| path.starts_with(admin))
            {
                if !self.metadata_only {
                    self.excluded()?;
                }
                continue;
            }
            match entry.kind {
                Kind::Directory => {
                    let (scanner, combined) =
                        self.decisions(&path, true, parent_scanner, parent_combined);
                    if let Err(error) = self.enter(path, scanner, combined, true) {
                        if error == ScanError::ScopeLimit || error == ScanError::CounterOverflow {
                            return Err(error);
                        }
                        self.outcome.fail(error);
                    }
                }
                Kind::Regular if !self.metadata_only => {
                    self.regular(path, parent_scanner, parent_combined, inclusion, tracked)?
                }
                Kind::Other if !self.metadata_only => self.excluded()?,
                Kind::Regular | Kind::Other => {}
                Kind::Error => self.outcome.fail(ScanError::Discovery),
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "../../tests/unit/scope.rs"]
mod tests;
