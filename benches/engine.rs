//! Precompiled complete detection pipeline, including accepted/rejected branches.
use rayloc::{config, rules::Registry, scanner::engine::scan_reader_with_registry};
use std::{io::Cursor, time::Instant};

fn main() {
    let policy = config::parse(
        b"version: '1'\nrules:\n  - id: corporate\n    regex: 'corp_[A-Za-z0-9]{16}'\n    entropy: 3.0\n",
    )
    .unwrap();
    let registry = Registry::compile(policy).unwrap();
    let record = b"ordinary content\nkey=ghp_SyntheticBenchmark0123456789\npassword='aaaaaaaa'\napi_key=Q7v2n9B4x6M1z8K3\ncorp_0123456789AbCdEf\ntoken='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln'\npassword=${PASSWORD}\npassword_sha256=9f21c7ab6e40d835\nkey=ghp_abcdefghijklmnop # rayloc:ignore\n";
    let input = record.repeat(1024);
    let mut samples = Vec::new();
    let mut detected = 0;
    // Compile all policy before timing; warm reader/allocator with an untimed pass.
    let warm = scan_reader_with_registry(&mut Cursor::new(&input), 1, &registry);
    assert_eq!(warm.stats.findings_detected, 5120);
    for _ in 0..40 {
        let started = Instant::now();
        let outcome = std::hint::black_box(scan_reader_with_registry(
            &mut Cursor::new(&input),
            1,
            &registry,
        ));
        samples.push(started.elapsed().as_secs_f64());
        assert_eq!(outcome.exit_code(), 1);
        assert_eq!(outcome.stats.findings_detected, 5120);
        assert_eq!(outcome.stats.bytes_read, input.len() as u64);
        detected += outcome.findings.len();
    }
    samples.sort_by(f64::total_cmp);
    let median = (samples[19] + samples[20]) / 2.0;
    println!(
        "engine: bytes={} samples=40 workers=1 median_ms={:.3} p95_ms={:.3} p99_ms={:.3} MB/s={:.2} findings={detected}; precompiled 10 built-ins + custom, warm cache",
        input.len(),
        median * 1000.0,
        samples[37] * 1000.0,
        samples[39] * 1000.0,
        input.len() as f64 / median / 1_000_000.0
    );
}
