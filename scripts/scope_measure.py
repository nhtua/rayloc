#!/usr/bin/env python3
"""Measure scope benchmark peak RSS per process on Linux/macOS (stdlib only).
Build first: cargo bench --bench scope --no-run
Run: python3 scripts/scope_measure.py target/release/deps/scope-<hash>
RSS includes fixture construction and compilation of the optional custom policy.
The benchmark reports warm medians including each scope's pool construction.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def measure(command, environment=None):
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(command, stdout=output, stderr=output, env=environment)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        output.seek(0)
        print(output.read().decode(), end="")
        if child.returncode:
            raise SystemExit(child.returncode)
        # Darwin reports bytes, Linux reports KiB.
        rss = usage.ru_maxrss / 1024 if sys.platform == "darwin" else usage.ru_maxrss
        print(f"peak_rss_kib={rss:.0f}", flush=True)


benchmark = str(Path(sys.argv[1]).resolve())
for label, count, size, option in [
    ("tiny", 20000, 256, None),
    ("throughput", 4096, 16384, None),
    ("policy", 256, 16384, "RAYLOC_BENCH_POLICY"),
    ("dense", 256, 256, "RAYLOC_BENCH_DENSE"),
]:
    for threshold in [256, 1]:
        for workers in [1, 8]:
            environment = dict(os.environ, RAYLOC_BENCH_FILES=str(count),
                               RAYLOC_BENCH_BYTES=str(size), RAYLOC_BENCH_WORKERS=str(workers),
                               RAYLOC_BENCH_THRESHOLD=str(threshold))
            if option:
                environment[option] = "1"
            print(f"case={label} workers={workers} threshold={threshold}", flush=True)
            measure([benchmark], environment)

# Git's index allocation is separate from rayloc's bounded metadata cursor.
with tempfile.TemporaryDirectory(prefix="rayloc-scope-measure-") as directory:
    subprocess.run(["git", "-C", directory, "init", "--quiet"], check=True)
    for index in range(20000):
        Path(directory, f"{index:08}").touch()
    subprocess.run(["git", "-C", directory, "add", "."], check=True)
    # Discard names rather than retaining or printing metadata measurements.
    print("case=git_metadata_20000", flush=True)
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(["git", "-C", directory, "ls-files", "--cached", "--full-name", "-z"], stdout=output)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        assert child.returncode == 0
        rss = usage.ru_maxrss / 1024 if sys.platform == "darwin" else usage.ru_maxrss
        print(f"peak_rss_kib={rss:.0f}", flush=True)
