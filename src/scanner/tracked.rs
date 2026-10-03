//! Bounded, validated monotonic Git index path cursor. Git 2.30 needs no deduplicate flag.
use super::{ScanError, engine::READ_BUFFER_BYTES};
use std::{
    io::{self, BufRead, BufReader, Read},
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
    thread::JoinHandle,
};
pub(super) const MAX_PATH_BYTES: usize = 16 * 1024;
#[derive(Clone, Copy)]
pub(super) struct MetadataLimits {
    pub records: u64,
    pub bytes: u64,
    pub path: usize,
}
const LIMITS: MetadataLimits = MetadataLimits {
    records: 1_000_000,
    bytes: 64 * 1024 * 1024,
    path: MAX_PATH_BYTES,
};
struct Records<R> {
    reader: R,
    current: Vec<u8>,
    previous: Vec<u8>,
    count: u64,
    bytes: u64,
    limits: MetadataLimits,
}
impl<R: BufRead> Records<R> {
    fn new(reader: R, limits: MetadataLimits) -> Self {
        Self {
            reader,
            current: Vec::new(),
            previous: Vec::new(),
            count: 0,
            bytes: 0,
            limits,
        }
    }
    fn next(&mut self) -> Result<bool, ScanError> {
        loop {
            self.current.clear();
            loop {
                let input = match self.reader.fill_buf() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result.map_err(|_| ScanError::GitMetadata)?,
                };
                if input.is_empty() {
                    return if self.current.is_empty() {
                        Ok(false)
                    } else {
                        Err(ScanError::GitMetadata)
                    };
                }
                let nul = input.iter().position(|&byte| byte == 0);
                let length = nul.unwrap_or(input.len());
                if length > self.limits.path - self.current.len() {
                    return Err(ScanError::ScopeLimit);
                }
                self.current.reserve_exact(length);
                self.current.extend_from_slice(&input[..length]);
                self.reader.consume(length + usize::from(nul.is_some()));
                if nul.is_some() {
                    break;
                }
            }
            self.count = self
                .count
                .checked_add(1)
                .ok_or(ScanError::CounterOverflow)?;
            self.bytes = self
                .bytes
                .checked_add(self.current.len() as u64)
                .ok_or(ScanError::CounterOverflow)?;
            if self.count > self.limits.records || self.bytes > self.limits.bytes {
                return Err(ScanError::ScopeLimit);
            }
            validate_path(&self.current)?;
            if !self.previous.is_empty() {
                match self.current.cmp(&self.previous) {
                    std::cmp::Ordering::Less => return Err(ScanError::GitMetadata),
                    std::cmp::Ordering::Equal => continue,
                    std::cmp::Ordering::Greater => {}
                }
            }
            self.previous.clear();
            self.previous.reserve_exact(self.current.len());
            self.previous.extend_from_slice(&self.current);
            return Ok(true);
        }
    }
}
fn validate_path(path: &[u8]) -> Result<(), ScanError> {
    if path
        .split(|&byte| byte == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(ScanError::GitMetadata);
    }
    Ok(())
}
fn drain(mut reader: impl Read) -> io::Result<()> {
    let mut buffer = [0; 8 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}
pub(super) struct Tracked {
    child: Child,
    diagnostic: Option<JoinHandle<io::Result<()>>>,
    records: Records<BufReader<ChildStdout>>,
    present: bool,
    finished: bool,
}
impl Tracked {
    pub(super) fn start(root: &Path, subtree: &Path) -> Result<Self, ScanError> {
        let mut command = Command::new("git");
        command.arg("-C").arg(root).args([
            "--literal-pathspecs",
            "ls-files",
            "--cached",
            "--full-name",
            "-z",
            "--",
        ]);
        let relative = subtree
            .strip_prefix(root)
            .map_err(|_| ScanError::GitMetadata)?;
        if !relative.as_os_str().is_empty() {
            command.arg(relative);
        }
        let mut child = command
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| ScanError::GitMetadata)?;
        let stdout = child.stdout.take().expect("Git stdout is piped");
        let stderr = child.stderr.take().expect("Git stderr is piped");
        let diagnostic = attach_diagnostic(
            &mut child,
            std::thread::Builder::new().spawn(move || drain(stderr)),
        )?;
        let mut cursor = Self {
            child,
            diagnostic: Some(diagnostic),
            records: Records::new(BufReader::with_capacity(READ_BUFFER_BYTES, stdout), LIMITS),
            present: false,
            finished: false,
        };
        cursor.present = cursor.records.next()?;
        Ok(cursor)
    }
    pub(super) fn contains(&mut self, relative: &[u8]) -> Result<bool, ScanError> {
        while self.present && self.records.current.as_slice() < relative {
            self.present = self.records.next()?;
        }
        Ok(self.present && self.records.current == relative)
    }
    pub(super) fn finish(&mut self) -> Result<(), ScanError> {
        while self.present {
            self.present = self.records.next()?;
        }
        let status = self.child.wait().map_err(|_| ScanError::GitMetadata)?;
        self.finished = true;
        self.diagnostic
            .take()
            .expect("drain thread is owned")
            .join()
            .map_err(|_| ScanError::GitMetadata)?
            .map_err(|_| ScanError::GitMetadata)?;
        if status.success() {
            Ok(())
        } else {
            Err(ScanError::GitMetadata)
        }
    }
}
// If a diagnostic drainer cannot start, never leave the piped child running.
fn attach_diagnostic(
    child: &mut Child,
    result: io::Result<JoinHandle<io::Result<()>>>,
) -> Result<JoinHandle<io::Result<()>>, ScanError> {
    match result {
        Ok(thread) => Ok(thread),
        Err(_) => {
            terminate(child);
            Err(ScanError::GitMetadata)
        }
    }
}
fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
impl Drop for Tracked {
    fn drop(&mut self) {
        if !self.finished {
            terminate(&mut self.child);
        }
        if let Some(thread) = self.diagnostic.take() {
            let _ = thread.join();
        }
    }
}
#[cfg(test)]
#[path = "../../tests/unit/tracked.rs"]
mod tests;
