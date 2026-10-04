//! Reproducible warm-filesystem scope crossover, including worker startup per scan.
use rayloc::{
    config::ScopeRoot,
    rules::{BUILTINS, Registry},
    scanner::scope::{ScopeOptions, scan_directory_with_options},
};
use std::{fs, time::Instant};
#[path = "../tests/support/mod.rs"]
mod support;
fn main() {
    let counts = std::env::var("RAYLOC_BENCH_FILES")
        .map_or(vec![8, 32, 128, 256, 4096], |v| vec![v.parse().unwrap()]);
    let sizes: Vec<usize> =
        std::env::var("RAYLOC_BENCH_BYTES").map_or(vec![256, 16384], |v| vec![v.parse().unwrap()]);
    let lanes =
        std::env::var("RAYLOC_BENCH_WORKERS").map_or(vec![1, 2, 8], |v| vec![v.parse().unwrap()]);
    let dense = std::env::var_os("RAYLOC_BENCH_DENSE").is_some();
    let complex = std::env::var_os("RAYLOC_BENCH_POLICY").is_some();
    let custom = complex.then(|| {
        let patterns = (0..256)
            .map(|i| format!("{{id: rule{i}, regex: 'never{i}[a-zA-Z0-9]{{128}}'}}"))
            .collect::<Vec<_>>()
            .join(",");
        Registry::compile(
            rayloc::config::parse(format!("version: '1'\nrules: [{patterns}]").as_bytes()).unwrap(),
        )
        .unwrap()
    });
    let registry = custom.as_ref().unwrap_or(&BUILTINS);
    for bytes in sizes {
        for &count in &counts {
            let temp = support::TempDir::new();
            let content = if dense {
                b"ghp_abcdefghijklmnop\n".repeat(100)
            } else {
                let mut content = b"ordinary code line\n".repeat(bytes.div_ceil(19));
                content.extend_from_slice(&[
                    65, 75, 73, 65, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70,
                    10,
                ]);
                content
            };
            let policy_bytes = if complex {
                let policy = (0..256)
                    .map(|i| format!("**/{}{}never{i}.rs\n", "a".repeat(64), "?*".repeat(4)))
                    .collect::<String>();
                fs::write(temp.path().join(".gitignore"), &policy).unwrap();
                policy.len()
            } else {
                0
            };
            for i in 0..count {
                fs::write(temp.path().join(format!("{i:08}")), &content).unwrap();
            }
            let root = ScopeRoot {
                root: temp.path().to_path_buf(),
                git: false,
                administration: Vec::new(),
            };
            for &workers in &lanes {
                let mut times = Vec::new();
                for _ in 0..5 {
                    let started = Instant::now();
                    let out = scan_directory_with_options(
                        &root,
                        temp.path(),
                        None,
                        registry,
                        ScopeOptions {
                            workers,
                            parallel_threshold: 1,
                        },
                    );
                    assert_eq!(
                        out.exit_code(),
                        if dense {
                            if count * 100 > 10000 { 2 } else { 1 }
                        } else {
                            1
                        }
                    );
                    assert_eq!(
                        out.stats.findings_detected,
                        (count * if dense { 100 } else { 1 }) as u64
                    );
                    assert_eq!(out.stats.files_completed, count as u64 + u64::from(complex));
                    assert_eq!(
                        out.stats.bytes_read,
                        (content.len() * count + policy_bytes) as u64
                    );
                    times.push(started.elapsed().as_secs_f64());
                }
                times.sort_by(f64::total_cmp);
                let seconds = times[2];
                println!(
                    "scope: files={count} bytes_each={} workers={workers} samples=5 median_ms={:.3} p95_ms={:.3} p99_ms={:.3} MB/s={:.2}",
                    content.len(),
                    seconds * 1000.0,
                    times[4] * 1000.0,
                    times[4] * 1000.0,
                    content.len() as f64 * count as f64 / seconds / 1e6
                );
            }
        }
    }
}
