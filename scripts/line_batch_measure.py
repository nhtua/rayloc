#!/usr/bin/env python3
"""Benchmark parallel line batch scanning vs baseline."""
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

BASELINE = Path("/tmp/opencode/rayloc-line-batch-baseline")
CANDIDATE = Path("/tmp/opencode/rayloc-line-batch-candidate")
FIXTURES = Path("/tmp/opencode/rayloc-line-batch-fixtures")

def create_fixture(parent: Path, case: str, size_mb: int = 10, lines: int = 50000) -> dict:
    """Create a test fixture."""
    fixture_dir = parent / case
    fixture_dir.mkdir(exist_ok=True)
    
    # Create a large file with some secrets
    file_path = fixture_dir / "large.txt"
    with open(file_path, 'w') as f:
        for i in range(lines):
            if i % 1000 == 0:
                # Insert a secret every 1000 lines
                f.write(f"api_key = \"sk_live_{i:016x}\"\n")
            else:
                f.write(f"let x = {i};\n")
    
    return {
        "path": str(file_path),
        "mode": "file",
        "expected_lines": lines,
        "expected_findings": lines // 1000,
    }

def measure_once(binary: Path, fixture: dict, threads: int = None) -> dict:
    """Measure scan time."""
    cmd = [str(binary), "scan"]
    if threads:
        cmd.extend(["--threads", str(threads)])
    cmd.append(fixture["path"])
    
    start = time.perf_counter()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    
    return {
        "elapsed": elapsed,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

def main():
    # Build candidate
    print("Building candidate...")
    subprocess.run(
        ["cargo", "build", "--locked", "--release"],
        cwd="/home/liam/Dev/github.com/nhtua/rayloc/.worktrees/parallel-line-batches",
        check=True,
    )
    shutil.copy(
        "/home/liam/Dev/github.com/nhtua/rayloc/.worktrees/parallel-line-batches/target/release/rayloc",
        CANDIDATE,
    )
    
    # Create fixtures
    print("Creating fixtures...")
    if FIXTURES.exists():
        shutil.rmtree(FIXTURES)
    FIXTURES.mkdir()
    
    fixture = create_fixture(FIXTURES, "file_clean", lines=500000)
    
    # Warm up
    print("Warming up...")
    measure_once(BASELINE, fixture)
    measure_once(CANDIDATE, fixture)
    if shutil.which("sync"):
        subprocess.run(["sync"])
    
    # Measure baseline (always serial)
    print("Measuring baseline...")
    baseline_times = []
    for _ in range(5):
        result = measure_once(BASELINE, fixture)
        baseline_times.append(result["elapsed"])
    baseline_median = sorted(baseline_times)[len(baseline_times) // 2]
    print(f"  Baseline median: {baseline_median:.3f}s")
    
    # Measure candidate with different thread counts
    print("Measuring candidate...")
    results = {}
    for threads in [1, 2, 4]:
        candidate_times = []
        for _ in range(5):
            result = measure_once(CANDIDATE, fixture, threads)
            candidate_times.append(result["elapsed"])
        candidate_median = sorted(candidate_times)[len(candidate_times) // 2]
        speedup = baseline_median / candidate_median
        results[threads] = {
            "median": candidate_median,
            "speedup": speedup,
        }
        print(f"  Threads {threads}: {candidate_median:.3f}s ({speedup:.2f}x)")
    
    # Summary
    print("\nSummary:")
    print(f"  Baseline: {baseline_median:.3f}s")
    for threads, result in results.items():
        print(f"  Threads {threads}: {result['median']:.3f}s ({result['speedup']:.2f}x)")
    
    # Save results
    output = {
        "baseline_median": baseline_median,
        "results": results,
        "fixture": fixture,
    }
    with open("/tmp/opencode/rayloc-line-batches-results.json", "w") as f:
        json.dump(output, f, indent=2)
    print("Results saved to /tmp/opencode/rayloc-line-batches-results.json")

if __name__ == "__main__":
    main()