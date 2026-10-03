//! Root-scoped tri-state ignore grammar. Input and aggregate compiler admission are bounded.
use super::{ConfigError, read_policy};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    None,
    Ignore,
    Whitelist,
}
#[derive(Clone, Copy, Default)]
pub(crate) struct PolicyUsage {
    pub bytes: usize,
    pub lines: usize,
    pub patterns: usize,
    pub complexity: usize,
    pub files: usize,
}
impl PolicyUsage {
    pub(crate) fn add(self, other: Self) -> Result<Self, ConfigError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(ConfigError::Limit)?,
            lines: self
                .lines
                .checked_add(other.lines)
                .ok_or(ConfigError::Limit)?,
            patterns: self
                .patterns
                .checked_add(other.patterns)
                .ok_or(ConfigError::Limit)?,
            complexity: self
                .complexity
                .checked_add(other.complexity)
                .ok_or(ConfigError::Limit)?,
            files: self
                .files
                .checked_add(other.files)
                .ok_or(ConfigError::Limit)?,
        })
    }
    pub(crate) fn fits(self, cap: Self) -> bool {
        self.bytes <= cap.bytes
            && self.lines <= cap.lines
            && self.patterns <= cap.patterns
            && self.complexity <= cap.complexity
            && self.files <= cap.files
    }
}
pub(crate) const ACTIVE_POLICY: PolicyUsage = PolicyUsage {
    bytes: 256 * 1024,
    lines: 1024,
    patterns: 256,
    complexity: 4096,
    files: 32,
};
pub struct Exclusions {
    matcher: Gitignore,
    pub(crate) usage: PolicyUsage,
}
impl Exclusions {
    pub fn load(root: &Path) -> Result<Self, ConfigError> {
        Self::load_named(root, ".raylocignore", PolicyUsage::default(), ACTIVE_POLICY)
    }
    pub(crate) fn load_named(
        root: &Path,
        name: &str,
        active: PolicyUsage,
        cap: PolicyUsage,
    ) -> Result<Self, ConfigError> {
        let path = root.join(name);
        let mut builder = GitignoreBuilder::new(root);
        let mut usage = PolicyUsage::default();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(ConfigError::Read);
                }
                let bytes = read_policy(&path)?;
                usage.bytes = bytes.capacity();
                usage.files = 1;
                let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Ignore)?;
                for line in text.lines() {
                    usage.lines = usage.lines.checked_add(1).ok_or(ConfigError::Limit)?;
                    if line.len() > super::MAX_PATTERN_BYTES {
                        return Err(ConfigError::Limit);
                    }
                    if !line.trim_end().is_empty() && !line.starts_with('#') {
                        usage.patterns = usage.patterns.checked_add(1).ok_or(ConfigError::Limit)?;
                        usage.complexity = usage
                            .complexity
                            .checked_add(
                                line.bytes()
                                    .filter(|b| {
                                        matches!(b, b'*' | b'?' | b'[' | b'{' | b',' | b'\\')
                                    })
                                    .count(),
                            )
                            .ok_or(ConfigError::Limit)?;
                    }
                    if !active.add(usage)?.fits(cap) {
                        return Err(ConfigError::Limit);
                    }
                    builder
                        .add_line(None, line)
                        .map_err(|_| ConfigError::Ignore)?;
                }
                if !active.add(usage)?.fits(cap) {
                    return Err(ConfigError::Limit);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ConfigError::Read),
        }
        Ok(Self {
            matcher: builder.build().map_err(|_| ConfigError::Ignore)?,
            usage,
        })
    }
    pub fn decision(&self, path: &Path, directory: bool) -> Decision {
        if !path.starts_with(self.matcher.path()) || path == self.matcher.path() {
            return Decision::None;
        }
        match self.matcher.matched(path, directory) {
            ignore::Match::None => Decision::None,
            ignore::Match::Ignore(_) => Decision::Ignore,
            ignore::Match::Whitelist(_) => Decision::Whitelist,
        }
    }
    pub fn excludes(&self, path: &Path) -> bool {
        path.ancestors()
            .any(|ancestor| self.decision(ancestor, ancestor != path) == Decision::Ignore)
    }
}
#[cfg(test)]
#[path = "../../tests/unit/ignore.rs"]
mod tests;
