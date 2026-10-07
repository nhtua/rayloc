#!/usr/bin/env python3
"""Measure whole-scope thread scaling without retaining scanner output.

Example: python3 scripts/parallel_measure.py --case 32_large --threads 1 2 8 32
The fixture is warmed with one untimed scan; cache state is never changed.
For single-file minified-line sizes and cap-versus-chunk comparisons, use
scripts/longline_measure.py; those cases are serial and should not imply that
adding directory worker threads accelerates one file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import statistics
import subprocess
import sys
import tempfile
import time


SUMMARY = re.compile(
    rb"([\d,]+) finding\(s\); ([\d,]+) retained; ([\d,]+) of ([\d,]+) file\(s\) completed; "
    rb"([\d,]+) line\(s\); ([\d,]+) byte\(s\) read"
)
EXCLUDED = re.compile(rb"([\d,]+) file\(s\) excluded")
VALUE_MARKER = b"\nValue: "
BLOCK = b"ordinary benchmark content\n"
TOKEN = b"ghp_" + b"abcdefgh" + b"ijklmnop"
CASES = (
    "32_large", "boundary_255", "boundary_256", "boundary_257", "uniform",
    "clustered", "single_large", "tiny_directories", "excluded_tree",
    "git_tracked_exceptions", "dense",
)


def parse_summary(report):
    """Extract counters only; callers must not retain report contents."""
    match = SUMMARY.search(report)
    if match is None:
        raise ValueError("scanner summary missing")
    excluded = EXCLUDED.search(report)
    if excluded is None:
        raise ValueError("scanner exclusion counter missing")
    findings, _, completed, attempted, lines, byte_count = (
        int(value.replace(b",", b"")) for value in match.groups()
    )
    return {
        "findings": findings,
        "files_completed": completed,
        "files_attempted": attempted,
        "files_excluded": int(excluded.group(1).replace(b",", b"")),
        "lines_scanned": lines,
        "bytes_read": byte_count,
    }


def _write_repeated(path, record, size):
    repeats, tail = divmod(size, len(record))
    block_count = 4096
    with path.open("wb") as output:
        while repeats >= block_count:
            output.write(record * block_count)
            repeats -= block_count
        if repeats:
            output.write(record * repeats)
        if tail:
            output.write(record[:tail])


def _fixture(root, name, paths, expected_findings=0, needles=(), expected_excluded=0):
    expected_bytes = sum(path.stat().st_size for path in paths)
    return {
        "case": name,
        "root": root,
        "selected": root,
        "expected_files": len(paths),
        "expected_bytes": expected_bytes,
        "expected_findings": expected_findings,
        "expected_excluded": expected_excluded,
        "expected_exit_code": int(expected_findings > 0),
        "_needles": tuple(needles),
    }


def create_fixture(parent, name, scale=1):
    """Create a known scan scope and return counters, never file contents."""
    if name not in CASES or scale < 1:
        raise ValueError("unsupported fixture")
    root = Path(parent) / name
    root.mkdir(parents=True)
    paths = []
    findings = 0
    needles = ()
    if name == "32_large":
        sizes = [4 * 1024 * 1024 * scale] * 32
        paths = [root / f"{i:04}.txt" for i in range(32)]
        for path, size in zip(paths, sizes):
            _write_repeated(path, BLOCK, size)
    elif name.startswith("boundary_"):
        count = int(name.rsplit("_", 1)[1])
        paths = [root / f"{i:04}.txt" for i in range(count)]
        for path in paths:
            _write_repeated(path, BLOCK, 64 * 1024 * scale)
    elif name == "uniform":
        paths = [root / f"{i:04}.txt" for i in range(256)]
        for path in paths:
            _write_repeated(path, BLOCK, 512 * 1024 * scale)
    elif name == "clustered":
        paths = [root / f"{i:04}.txt" for i in range(256)]
        for i, path in enumerate(paths):
            _write_repeated(path, BLOCK, (4 * 1024 * 1024 if i < 32 else 1024) * scale)
    elif name == "single_large":
        path = root / "large.txt"
        _write_repeated(path, BLOCK, 64 * 1024 * 1024 * scale)
        paths.append(path)
    elif name == "tiny_directories":
        for directory in range(32):
            child = root / f"{directory:04}"
            child.mkdir()
            for index in range(8):
                path = child / f"{index:04}.txt"
                _write_repeated(path, BLOCK, 256 * scale)
                paths.append(path)
    elif name == "excluded_tree":
        policy = root / ".raylocignore"
        policy.write_text("cache/\n")
        for index in range(256):
            path = root / f"{index:04}.txt"
            _write_repeated(path, BLOCK, 1024 * scale)
            paths.append(path)
        cache = root / "cache"
        cache.mkdir()
        for directory in range(128):
            child = cache / f"{directory:04}"
            child.mkdir()
            for index in range(64):
                path = child / f"{index:04}.txt"
                _write_repeated(path, BLOCK, 256)
        paths.append(policy)
    elif name == "git_tracked_exceptions":
        ignored = root / "ignored"
        ignored.mkdir()
        ignore_file = root / ".gitignore"
        ignore_file.write_text("ignored/\n")
        tracked = ignored / "tracked.env"
        tracked.write_bytes(TOKEN + b"\n")
        subprocess.run(["git", "init", "--quiet", "--template="], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "add", "-f", ".gitignore", "ignored/tracked.env"], cwd=root,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ignored_untracked = ignored / "untracked.env"
        ignored_untracked.write_bytes(TOKEN + b"\n")
        paths = [ignore_file, tracked]
        findings = 1
        needles = (TOKEN,)
    elif name == "dense":
        paths = [root / f"{i:04}.txt" for i in range(8)]
        record = TOKEN + b"\n"
        for path in paths:
            path.write_bytes(record * 100)
        findings = 800
        needles = (TOKEN,)
    expected_excluded = {"excluded_tree": 8192, "git_tracked_exceptions": 2}.get(name, 0)
    return _fixture(root, name, paths, findings, needles, expected_excluded)


def _append_tail(target, data, cap=32768):
    target.extend(data)
    if len(target) > cap:
        del target[:-cap]


def measure_once(binary, fixture, threads, sink_delay_ms=0):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_ATTR_NOSYSTEM="1", LC_ALL="C")
    if threads is None:
        environment.pop("RAYON_NUM_THREADS", None)
    else:
        environment.pop("RAYON_NUM_THREADS", None)
    command = [str(binary), "scan", str(fixture["selected"])]
    if threads is not None:
        command.extend(["--threads", str(threads)])
    started = time.perf_counter_ns()
    child = subprocess.Popen(command, cwd=fixture["root"], env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    try:
        tails = {"stdout": bytearray(), "stderr": bytearray()}
        overlap = b""
        finding_values = 0
        leaked = False
        overlap_bytes = max([len(VALUE_MARKER), *(len(needle) for needle in fixture["_needles"])])
        while selector.get_map():
            for key, _ in selector.select():
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    if sink_delay_ms:
                        time.sleep(sink_delay_ms / 1000)
                    combined = overlap + chunk
                    finding_values += sum(
                        match.end() > len(overlap) for match in re.finditer(VALUE_MARKER, combined)
                    )
                    leaked |= any(needle in combined for needle in fixture["_needles"])
                    overlap = combined[-overlap_bytes:]
                _append_tail(tails[key.data], chunk)
    finally:
        selector.close()
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    child.stdout.close()
    child.stderr.close()
    elapsed_ms = (time.perf_counter_ns() - started) / 1e6
    returncode = os.waitstatus_to_exitcode(status)
    if leaked:
        raise AssertionError("scanner printed a complete fixture credential")
    summary = parse_summary(bytes(tails["stdout"]))
    if returncode != fixture["expected_exit_code"]:
        raise AssertionError("scanner exit status changed for the fixture")
    if summary["findings"] != fixture["expected_findings"] or finding_values != fixture["expected_findings"]:
        raise AssertionError("scanner findings changed for the fixture")
    if summary["files_completed"] != fixture["expected_files"]:
        raise AssertionError("scanner completed-file count changed for the fixture")
    if summary["files_attempted"] != fixture["expected_files"]:
        raise AssertionError("scanner attempted-file count changed for the fixture")
    if summary["files_excluded"] != fixture["expected_excluded"]:
        raise AssertionError(
            f"scanner exclusion count changed: {summary['files_excluded']} != {fixture['expected_excluded']}"
        )
    if summary["bytes_read"] != fixture["expected_bytes"]:
        raise AssertionError("scanner byte count changed for the fixture")
    if any(needle in tails["stderr"] for needle in fixture["_needles"]):
        raise AssertionError("scanner wrote a complete fixture credential to stderr")
    rss_kib = usage.ru_maxrss / 1024 if sys.platform == "darwin" else usage.ru_maxrss
    return {
        "wall_ms": elapsed_ms,
        "user_ms": (usage.ru_utime) * 1000,
        "system_ms": (usage.ru_stime) * 1000,
        "peak_rss_kib": rss_kib,
        **summary,
        "exit_code": returncode,
    }


def measure_fixture(binary, fixture, threads, samples, sink_delay_ms=0):
    if samples < 1:
        raise ValueError("at least one timed sample is required")
    measure_once(binary, fixture, threads, sink_delay_ms)  # untimed warm-cache pass
    results = [measure_once(binary, fixture, threads, sink_delay_ms) for _ in range(samples)]
    wall = sorted(result["wall_ms"] for result in results)
    median = statistics.median(wall)
    tail = wall[min(len(wall) - 1, int(len(wall) * 0.95))]
    configured_threads = threads if threads is not None else min(os.cpu_count() or 1, 8)
    parallel_admitted = (
        fixture["expected_files"] >= 256 or fixture["expected_bytes"] >= 256 * 1024
    ) and configured_threads > 1
    aggregate = {
        "case": fixture["case"],
        "threads_requested": threads if threads is not None else "default",
        "thread_control": "--threads for directory/glob scans",
        "configured_pool_threads": configured_threads if parallel_admitted else 0,
        "active_lane_upper_bound": min(configured_threads, fixture["expected_files"])
        if parallel_admitted
        else 1,
        "admission_basis": "files_or_estimated_bytes" if parallel_admitted else "serial",
        "sink_delay_ms": sink_delay_ms,
        "cache": "warm after fixture creation and one untimed scan; OS caches not flushed",
        "samples": samples,
        "median_wall_ms": median,
        "p95_wall_ms": tail,
        "median_user_ms": statistics.median(result["user_ms"] for result in results),
        "median_system_ms": statistics.median(result["system_ms"] for result in results),
        "peak_rss_kib": max(result["peak_rss_kib"] for result in results),
        "files_completed": fixture["expected_files"],
        "bytes_read": fixture["expected_bytes"],
        "findings": fixture["expected_findings"],
        "files_excluded": fixture["expected_excluded"],
        "exit_code": fixture["expected_exit_code"],
    }
    return aggregate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parent.parent / "target/release/rayloc")
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", choices=CASES, action="append", default=[])
    parser.add_argument("--threads", type=int, nargs="+", default=[1, 2, 8, 16, 32])
    parser.add_argument("--include-default", action="store_true",
                        help="also measure without a thread-count override")
    parser.add_argument("--scale", type=int, default=1)
    parser.add_argument("--sink-delay-ms", type=int, default=0,
                        help="pause while draining each output chunk to simulate a slow sink")
    args = parser.parse_args()
    if (args.samples < 1 or args.scale < 1 or not 0 <= args.sink_delay_ms <= 1000
            or any(not 1 <= item <= 64 for item in args.threads)):
        parser.error("samples, scale, and requested thread counts must be positive and bounded")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error("scanner binary is missing; build the release binary first")
    cases = args.case or list(CASES)
    rows = []
    with tempfile.TemporaryDirectory(prefix="rayloc-parallel-") as directory:
        parent = Path(directory)
        for case in cases:
            fixture = create_fixture(parent, case, args.scale)
            requests = ([None] if args.include_default else []) + args.threads
            for threads in requests:
                row = measure_fixture(binary, fixture, threads, args.samples, args.sink_delay_ms)
                rows.append(row)
                print(json.dumps(row, sort_keys=True), flush=True)
    result = {
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "binary_bytes": binary.stat().st_size,
        "hardware": next((line.split(":", 1)[1].strip() for line in
                           Path("/proc/cpuinfo").read_text().splitlines()
                           if line.startswith("model name")), platform.processor() or platform.machine())
        if Path("/proc/cpuinfo").exists() else platform.processor() or platform.machine(),
        "os": platform.platform(),
        "cache_policy": "warm; no cache flush",
        "measurements": rows,
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
