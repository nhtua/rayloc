use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rayloc-test-{}-{}-{}",
            std::process::id(),
            module_path!().replace("::", "-"),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
