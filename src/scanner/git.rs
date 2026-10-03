//! Reaped Git children with bounded stdout and concurrently discarded diagnostics.
use super::{
    ScanError,
    engine::{MAX_LINE_BYTES, READ_BUFFER_BYTES},
};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    thread::JoinHandle,
};

pub(super) struct Process {
    child: Child,
    pub(super) output: BufReader<ChildStdout>,
    diagnostic: Option<JoinHandle<io::Result<()>>>,
    waited: bool,
}
pub(super) fn command(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(cwd).env("LC_ALL", "C").args([
        "--literal-pathspecs",
        "-c",
        "core.quotePath=true",
    ]);
    command
}
fn drain(mut input: impl Read) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}
impl Process {
    pub(super) fn start(command: &mut Command) -> Result<Self, ScanError> {
        Self::start_input(command, Stdio::null())
    }
    pub(super) fn start_input(command: &mut Command, input: Stdio) -> Result<Self, ScanError> {
        let mut child = command
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| ScanError::GitMetadata)?;
        let output = BufReader::with_capacity(
            READ_BUFFER_BYTES,
            child.stdout.take().expect("stdout is piped"),
        );
        let stderr = child.stderr.take().expect("stderr is piped");
        let diagnostic = attach_diagnostic(
            &mut child,
            std::thread::Builder::new().spawn(move || drain(stderr)),
        )?;
        Ok(Self {
            child,
            output,
            diagnostic: Some(diagnostic),
            waited: false,
        })
    }
    pub(super) fn write_input(&mut self, bytes: &[u8]) -> Result<(), ScanError> {
        self.child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(bytes)
            .map_err(|_| ScanError::GitMetadata)
    }
    pub(super) fn finish_success(&mut self) -> Result<(), ScanError> {
        if self.finish()?.success() {
            Ok(())
        } else {
            Err(ScanError::GitMetadata)
        }
    }
    pub(super) fn finish(&mut self) -> Result<ExitStatus, ScanError> {
        let status = self.child.wait().map_err(|_| ScanError::GitMetadata)?;
        self.waited = true;
        self.diagnostic
            .take()
            .expect("diagnostic thread is owned")
            .join()
            .map_err(|_| ScanError::GitMetadata)?
            .map_err(|_| ScanError::GitMetadata)?;
        Ok(status)
    }
}
// Own the child before starting the drainer, so thread-resource exhaustion
// has the same kill/wait guarantee as later scanner errors.
fn attach_diagnostic(
    child: &mut Child,
    result: io::Result<JoinHandle<io::Result<()>>>,
) -> Result<JoinHandle<io::Result<()>>, ScanError> {
    match result {
        Ok(thread) => Ok(thread),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(ScanError::GitMetadata)
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(thread) = self.diagnostic.take() {
            let _ = thread.join();
        }
    }
}
pub(super) fn capture(
    command: &mut Command,
    cap: usize,
) -> Result<(ExitStatus, Vec<u8>), ScanError> {
    capture_input(command, cap, Stdio::null())
}
pub(super) fn capture_input(
    command: &mut Command,
    cap: usize,
    input: Stdio,
) -> Result<(ExitStatus, Vec<u8>), ScanError> {
    let mut process = Process::start_input(command, input)?;
    let mut bytes = Vec::new();
    // Take bounds allocation even for hostile or malfunctioning child output.
    (&mut process.output)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ScanError::GitMetadata)?;
    if bytes.len() > cap {
        return Err(ScanError::ScopeLimit);
    }
    Ok((process.finish()?, bytes))
}
pub(super) fn successful(command: &mut Command, cap: usize) -> Result<Vec<u8>, ScanError> {
    let (status, bytes) = capture(command, cap)?;
    if !status.success() {
        return Err(ScanError::GitMetadata);
    }
    Ok(bytes)
}
/// Terminator is retained inside the cap; partial EOF always fails.
pub(super) fn record(
    reader: &mut impl BufRead,
    separator: u8,
    bytes: &mut Vec<u8>,
) -> Result<bool, ScanError> {
    bytes.clear();
    loop {
        let input = match reader.fill_buf() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(|_| ScanError::GitMetadata)?,
        };
        if input.is_empty() {
            return if bytes.is_empty() {
                Ok(false)
            } else {
                Err(ScanError::GitMetadata)
            };
        }
        let delimiter = input.iter().position(|&b| b == separator);
        let count = delimiter.map_or(input.len(), |index| index + 1);
        if count > MAX_LINE_BYTES - bytes.len() {
            return Err(ScanError::LineLimit);
        }
        bytes.reserve_exact(count);
        bytes.extend_from_slice(&input[..count]);
        reader.consume(count);
        if delimiter.is_some() {
            return Ok(true);
        }
    }
}
#[cfg(test)]
#[path = "../../tests/unit/git.rs"]
mod tests;
