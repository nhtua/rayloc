//! Strict bounded YAML policy loading. Diagnostics never retain input text.

use crate::rules::builtin::Severity;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use yaml_rust2::{
    Yaml,
    parser::{Event, Parser},
    scanner::TScalarStyle,
};
pub mod ignore;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 8192;
const MAX_DEPTH: usize = 16;
pub const MAX_RULES: usize = 256;
pub const MAX_PATTERN_BYTES: usize = 16 * 1024;
pub const MAX_TOTAL_PATTERN_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Read,
    Syntax,
    Schema,
    Limit,
    Pattern,
    Ignore,
    Discovery,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "cannot read policy",
            Self::Syntax => "invalid YAML policy",
            Self::Schema => "invalid policy fields",
            Self::Limit => "policy exceeds resource limit",
            Self::Pattern => "invalid custom rule pattern",
            Self::Ignore => "invalid scanner ignore policy",
            Self::Discovery => "cannot discover policy root",
        })
    }
}
impl std::error::Error for ConfigError {}

pub struct CustomRule {
    pub(crate) id: String,
    pub(crate) pattern: String,
    pub(crate) group: usize,
    pub(crate) entropy: Option<f64>,
    pub(crate) severity: Severity,
}
#[derive(Default)]
pub struct Config {
    pub default_entropy_threshold: Option<f64>,
    pub entropy_thresholds: BTreeMap<String, f64>,
    pub(crate) rules: Vec<CustomRule>,
    pub(crate) disabled: Vec<String>,
}

enum Value {
    Scalar(String),
    Number(Yaml),
    Other,
    Map(BTreeMap<String, Value>),
    List(Vec<Value>),
}
struct Document<'a> {
    parser: Parser<std::str::Chars<'a>>,
    events: usize,
}
impl Document<'_> {
    fn next(&mut self) -> Result<Event, ConfigError> {
        self.events += 1;
        if self.events > MAX_EVENTS {
            return Err(ConfigError::Limit);
        }
        self.parser
            .next_token()
            .map(|(event, _)| event)
            .map_err(|_| ConfigError::Syntax)
    }
    fn value(&mut self, event: Event, depth: usize) -> Result<Value, ConfigError> {
        if depth > MAX_DEPTH {
            return Err(ConfigError::Limit);
        }
        match event {
            Event::Scalar(s, style, 0, None) => Ok(if style != TScalarStyle::Plain {
                Value::Scalar(s)
            } else {
                match s.as_str() {
                    "Null" | "NULL" => Value::Other,
                    _ => match Yaml::from_str(&s) {
                        Yaml::String(_) => Value::Scalar(s),
                        number @ (Yaml::Integer(_) | Yaml::Real(_)) => Value::Number(number),
                        _ => Value::Other,
                    },
                }
            }),
            Event::MappingStart(0, None) => {
                let mut map = BTreeMap::new();
                loop {
                    match self.next()? {
                        Event::MappingEnd => return Ok(Value::Map(map)),
                        Event::Scalar(key, _, 0, None) if key != "<<" => {
                            let event = self.next()?;
                            let value = self.value(event, depth + 1)?;
                            if map.insert(key, value).is_some() {
                                return Err(ConfigError::Schema);
                            }
                        }
                        _ => return Err(ConfigError::Syntax),
                    }
                }
            }
            Event::SequenceStart(0, None) => {
                let mut list = Vec::new();
                loop {
                    let event = self.next()?;
                    if event == Event::SequenceEnd {
                        return Ok(Value::List(list));
                    }
                    list.push(self.value(event, depth + 1)?);
                }
            }
            _ => Err(ConfigError::Syntax),
        }
    }
}
fn scalar(value: Value) -> Result<String, ConfigError> {
    if let Value::Scalar(s) = value {
        Ok(s)
    } else {
        Err(ConfigError::Schema)
    }
}
fn map(value: Value) -> Result<BTreeMap<String, Value>, ConfigError> {
    if let Value::Map(m) = value {
        Ok(m)
    } else {
        Err(ConfigError::Schema)
    }
}
fn list(value: Value) -> Result<Vec<Value>, ConfigError> {
    if let Value::List(l) = value {
        Ok(l)
    } else {
        Err(ConfigError::Schema)
    }
}
fn class_maximum(class: &str) -> Result<f64, ConfigError> {
    match class {
        "hex" => Ok(4.0),
        "alphanumeric" => Ok(62_f64.log2()),
        "base64" => Ok(6.0),
        _ => Err(ConfigError::Schema),
    }
}
fn threshold(value: Value, max: f64) -> Result<f64, ConfigError> {
    let n = match value {
        Value::Number(Yaml::Integer(n)) => n as f64,
        Value::Number(Yaml::Real(s)) => s.parse::<f64>().map_err(|_| ConfigError::Schema)?,
        _ => return Err(ConfigError::Schema),
    };
    if n.is_finite() && (0.0..=max).contains(&n) {
        Ok(n)
    } else {
        Err(ConfigError::Schema)
    }
}
fn rule(value: Value) -> Result<CustomRule, ConfigError> {
    let mut fields = map(value)?;
    let id = scalar(fields.remove("id").ok_or(ConfigError::Schema)?)?;
    let pattern = scalar(fields.remove("regex").ok_or(ConfigError::Schema)?)?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(ConfigError::Schema);
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(ConfigError::Limit);
    }
    if let Some(description) = fields.remove("description") {
        scalar(description)?;
    }
    let group = match fields.remove("secret_group") {
        None => 0,
        Some(Value::Number(Yaml::Integer(n))) => {
            usize::try_from(n).map_err(|_| ConfigError::Schema)?
        }
        Some(_) => return Err(ConfigError::Schema),
    };
    let entropy = fields
        .remove("entropy")
        .map(|v| threshold(v, 8.0))
        .transpose()?;
    let severity = match fields
        .remove("severity")
        .map(scalar)
        .transpose()?
        .as_deref()
        .unwrap_or("High")
    {
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        _ => return Err(ConfigError::Schema),
    };
    if !fields.is_empty() {
        return Err(ConfigError::Schema);
    }
    Ok(CustomRule {
        id,
        pattern,
        group,
        entropy,
        severity,
    })
}
/// Parse one ordinary YAML document under explicit byte/depth/event budgets.
pub fn parse(bytes: &[u8]) -> Result<Config, ConfigError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Limit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::Syntax)?;
    let mut document = Document {
        parser: Parser::new_from_str(text),
        events: 0,
    };
    if document.next()? != Event::StreamStart || document.next()? != Event::DocumentStart {
        return Err(ConfigError::Syntax);
    }
    let event = document.next()?;
    let mut fields = map(document.value(event, 0)?)?;
    if document.next()? != Event::DocumentEnd || document.next()? != Event::StreamEnd {
        return Err(ConfigError::Syntax);
    }
    if scalar(fields.remove("version").ok_or(ConfigError::Schema)?)? != "1" {
        return Err(ConfigError::Schema);
    }
    let mut config = Config {
        default_entropy_threshold: fields
            .remove("default_entropy_threshold")
            .map(|v| threshold(v, 8.0))
            .transpose()?,
        ..Config::default()
    };
    if let Some(value) = fields.remove("entropy_thresholds") {
        for (key, value) in map(value)? {
            let max = class_maximum(&key)?;
            config
                .entropy_thresholds
                .insert(key, threshold(value, max)?);
        }
    }
    if let Some(value) = fields.remove("rules") {
        for value in list(value)? {
            if config.rules.len() == MAX_RULES {
                return Err(ConfigError::Limit);
            }
            config.rules.push(rule(value)?);
        }
    }
    if let Some(value) = fields.remove("disabled_rules") {
        for value in list(value)? {
            let id = scalar(value)?;
            if config.disabled.contains(&id) {
                return Err(ConfigError::Schema);
            }
            config.disabled.push(id);
        }
    }
    if !fields.is_empty() {
        return Err(ConfigError::Schema);
    }
    config.validate()?;
    Ok(config)
}
impl Config {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self
            .default_entropy_threshold
            .is_some_and(|gate| !gate.is_finite() || !(0.0..=8.0).contains(&gate))
        {
            return Err(ConfigError::Schema);
        }
        for (class, gate) in &self.entropy_thresholds {
            if !gate.is_finite() || !(0.0..=class_maximum(class)?).contains(gate) {
                return Err(ConfigError::Schema);
            }
        }

        if self.rules.len() > MAX_RULES
            || self.rules.iter().map(|r| r.pattern.len()).sum::<usize>() > MAX_TOTAL_PATTERN_BYTES
        {
            return Err(ConfigError::Limit);
        }
        let mut ids = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if crate::rules::builtin_id(&rule.id).is_some() || !ids.insert(&rule.id) {
                return Err(ConfigError::Schema);
            }
        }
        Ok(())
    }
    /// Explicit scalars override, class maps merge, rules append, disables union.
    pub fn merge(mut self, explicit: Config) -> Result<Self, ConfigError> {
        if explicit.default_entropy_threshold.is_some() {
            self.default_entropy_threshold = explicit.default_entropy_threshold;
        }
        self.entropy_thresholds.extend(explicit.entropy_thresholds);
        self.rules.extend(explicit.rules);
        for id in explicit.disabled {
            if !self.disabled.contains(&id) {
                self.disabled.push(id);
            }
        }
        self.validate()?;
        Ok(self)
    }
}
/// Read at most the configuration budget plus one overflow sentinel byte.
pub fn read_policy(path: &Path) -> Result<Vec<u8>, ConfigError> {
    if !std::fs::metadata(path)
        .map_err(|_| ConfigError::Read)?
        .is_file()
    {
        return Err(ConfigError::Read);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| ConfigError::Read)?
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Read)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        Err(ConfigError::Limit)
    } else {
        Ok(bytes)
    }
}
const MAX_GIT_DIAGNOSTIC_BYTES: usize = 8 * 1024;

fn read_git_diagnostic(mut reader: impl Read) -> Result<Vec<u8>, ConfigError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_GIT_DIAGNOSTIC_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Discovery)?;
    // Drain concurrently even after the retained budget is reached, so a child
    // writing diagnostics cannot block while its stdout is being consumed.
    std::io::copy(&mut reader, &mut std::io::sink()).map_err(|_| ConfigError::Discovery)?;
    if bytes.len() > MAX_GIT_DIAGNOSTIC_BYTES {
        Err(ConfigError::Discovery)
    } else {
        Ok(bytes)
    }
}

fn outside_git(diagnostic: &[u8]) -> bool {
    if diagnostic == b"fatal: not a git repository (or any of the parent directories): .git\n" {
        return true;
    }
    diagnostic
        .strip_prefix(b"fatal: not a git repository (or any parent up to mount point ")
        .and_then(|text| {
            text.strip_suffix(
                b")\nStopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).\n",
            )
        })
        .is_some_and(|path| path.starts_with(b"/"))
}

fn outside_without_git(directory: &Path) -> Result<PathBuf, ConfigError> {
    if std::env::var_os("GIT_DIR").is_some() || std::env::var_os("GIT_WORK_TREE").is_some() {
        return Err(ConfigError::Discovery);
    }
    for ancestor in directory.ancestors() {
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(metadata) if metadata.is_dir() => {
                let mut entries =
                    std::fs::read_dir(ancestor.join(".git")).map_err(|_| ConfigError::Discovery)?;
                if entries.next().is_some() {
                    return Err(ConfigError::Discovery);
                }
            }
            _ => return Err(ConfigError::Discovery),
        }
    }
    Ok(directory.to_path_buf())
}

/// Root discovery uses Git when available; no parent policy is inherited outside Git.
pub fn discover_root(selected: &Path) -> Result<PathBuf, ConfigError> {
    let selected = if selected.is_absolute() {
        selected.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ConfigError::Discovery)?
            .join(selected)
    };
    let directory = std::fs::canonicalize(selected.parent().ok_or(ConfigError::Discovery)?)
        .map_err(|_| ConfigError::Discovery)?;
    let directory = directory
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == ".git"))
        .and_then(Path::parent)
        .unwrap_or(&directory);
    let mut child = match Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["rev-parse", "--show-toplevel"])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return outside_without_git(directory);
        }
        Err(_) => return Err(ConfigError::Discovery),
    };
    let stdout = child.stdout.take().expect("Git stdout is piped");
    let stderr = child.stderr.take().expect("Git stderr is piped");
    let (mut bytes, diagnostic, status) = std::thread::scope(|scope| {
        let diagnostic = scope.spawn(|| read_git_diagnostic(stderr));
        let mut bytes = Vec::new();
        let read = stdout
            .take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > MAX_CONFIG_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            let _ = diagnostic.join();
            return Err(ConfigError::Discovery);
        }
        let status = child.wait().map_err(|_| ConfigError::Discovery)?;
        let diagnostic = diagnostic.join().map_err(|_| ConfigError::Discovery)??;
        Ok((bytes, diagnostic, status))
    })?;
    if !status.success() {
        if status.code() == Some(128) && bytes.is_empty() && outside_git(&diagnostic) {
            return Ok(directory.to_path_buf());
        }
        return Err(ConfigError::Discovery);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(ConfigError::Discovery);
    }
    bytes.pop();
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| ConfigError::Discovery)?);
    Ok(path)
}
pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Config, ConfigError> {
    let base_path = root.join(".rayloc.yaml");
    let base = match std::fs::symlink_metadata(&base_path) {
        Ok(_) => parse(&read_policy(&base_path)?)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(_) => return Err(ConfigError::Read),
    };
    match explicit {
        Some(path) => base.merge(parse(&read_policy(path)?)?),
        None => Ok(base),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/config.rs"]
mod tests;
