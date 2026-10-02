//! Root-scoped Git ignore grammar for explicit scanner exclusions.
use super::{ConfigError, read_policy};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;
pub struct Exclusions {
    matcher: Gitignore,
}
impl Exclusions {
    pub fn load(root: &Path) -> Result<Self, ConfigError> {
        let path = root.join(".raylocignore");
        let mut builder = GitignoreBuilder::new(root);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = read_policy(&path)?;
                if bytes.len() > super::MAX_TOTAL_PATTERN_BYTES {
                    return Err(ConfigError::Limit);
                }
                let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Ignore)?;
                for (index, line) in text.lines().enumerate() {
                    if index >= 1024 || line.len() > super::MAX_PATTERN_BYTES {
                        return Err(ConfigError::Limit);
                    }
                    builder
                        .add_line(None, line)
                        .map_err(|_| ConfigError::Ignore)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ConfigError::Read),
        }
        Ok(Self {
            matcher: builder.build().map_err(|_| ConfigError::Ignore)?,
        })
    }
    pub fn excludes(&self, path: &Path) -> bool {
        path.ancestors().any(|ancestor| {
            if ancestor == self.matcher.path() || !ancestor.starts_with(self.matcher.path()) {
                return false;
            }
            self.matcher.matched(ancestor, ancestor != path).is_ignore()
        })
    }
}
#[cfg(test)]
#[path = "../../tests/unit/ignore.rs"]
mod tests;
