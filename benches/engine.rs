use std::{io::Cursor, time::Instant};

use rayloc::scanner::engine::scan_reader;

fn main() {
    // Each record exercises byte reading, signatures, findings, and full masks.
    // Synthetic bytes remain internal; the benchmark prints measurements only.
    let record = b"ordinary content\nkey=ghp_SyntheticBenchmark0123456789\n";
    let input = record.repeat(1024);
    let iterations = 40;
    let started = Instant::now();
    let mut detected = 0;
    for _ in 0..iterations {
        let outcome = std::hint::black_box(scan_reader(&mut Cursor::new(&input), 1));
        assert_eq!(outcome.exit_code(), 1);
        assert_eq!(outcome.stats.findings_detected, 1024);
        assert_eq!(outcome.stats.bytes_read, input.len() as u64);
        detected += outcome.findings.len();
    }
    let elapsed = started.elapsed().as_secs_f64();
    let megabytes = (input.len() * iterations) as f64 / 1_000_000.0;
    println!(
        "engine: {megabytes:.3} MB in {elapsed:.4} s; {:.2} MB/s; {detected} findings (synthetic, 1 thread)",
        megabytes / elapsed
    );
}
