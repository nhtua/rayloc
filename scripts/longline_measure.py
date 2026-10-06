#!/usr/bin/env python3
"""Compare complete scans of minified single-line fixtures across binaries.

Inputs are generated with bounded writes. Each binary gets one untimed warm run
and repeated timed runs. The harness validates exit status, finding count,
redaction, and reported bytes before accepting a timing.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile

from e2e_measure import measure

SECRET = b"AKIA0123456789ABCDEF"  # rayloc:ignore
PREFIX = b'{"bundle":"'
MID = b'","api":"'
TAIL = b'","pad":"'
SUFFIX = b'","note":"ordinary"}'
FILL = b"x" * (256 * 1024)


def fixture(path, size):
    """Write one minified JSON physical line with a sparse synthetic key."""
    if size < len(PREFIX) + len(MID) + len(TAIL) + len(SUFFIX) + len(SECRET) + 1:
        raise ValueError("fixture too small")
    fill_size = (
        size - len(PREFIX) - len(MID) - len(TAIL) - len(SUFFIX) - len(SECRET) - 1
    )
    with path.open("wb") as output:
        output.write(PREFIX)
        before = fill_size // 2
        after = fill_size - before
        amount = before
        while amount:
            block = FILL[: min(amount, len(FILL))]
            output.write(block)
            amount -= len(block)
        output.write(MID)
        output.write(SECRET)
        output.write(TAIL)
        while after:
            block = FILL[: min(after, len(FILL))]
            output.write(block)
            after -= len(block)
        output.write(SUFFIX + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        action="append",
        required=True,
        help="repeat as LABEL=/absolute/path/to/rayloc",
    )
    parser.add_argument("--sizes-mib", type=int, nargs="+", default=[1, 5, 10, 64, 256])
    parser.add_argument("--gigabyte", action="store_true", help="also measure 1024 MiB")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.samples < 3 or any(size < 1 for size in args.sizes_mib):
        parser.error("at least three samples and positive MiB sizes required")
    binaries = {}
    for value in args.binary:
        label, separator, filename = value.partition("=")
        binary = Path(filename).resolve()
        if not separator or not label or not binary.is_file():
            parser.error("--binary must be LABEL=existing-path")
        binaries[label] = binary
    sizes = list(args.sizes_mib) + ([1024] if args.gigabyte else [])
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        cpu = next(
            (
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            cpu,
        )
    result = {
        "hardware": platform.platform(),
        "cpu": cpu,
        "rust": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cache": "warm after fixture creation and one untimed scan; caches not flushed",
        "workload": "minified JSON single physical line; one synthetic AWS-shaped sparse candidate",
        "samples": args.samples,
        "measurements": {},
    }
    with tempfile.TemporaryDirectory(prefix="rayloc-longline-") as temporary:
        root = Path(temporary)
        for mib in sizes:
            size = mib * 1_000_000
            path = root / f"{mib}m.json"
            fixture(path, size)
            actual_size = path.stat().st_size
            for label, binary in binaries.items():
                line_limit = {"base": 1, "cap5": 5, "cap10": 10}.get(label)
                expected_exit = (
                    2
                    if line_limit is not None and actual_size > line_limit * 1024 * 1024
                    else 1
                )
                expected_findings = int(expected_exit == 1)
                warm = measure(
                    binary,
                    ["scan", str(path)],
                    root,
                    1,
                    expected_findings,
                    actual_size,
                    expected_exit,
                )
                measured = measure(
                    binary,
                    ["scan", str(path)],
                    root,
                    args.samples,
                    expected_findings,
                    actual_size,
                    expected_exit,
                )
                successful = expected_exit != 2
                result["measurements"][f"{label}/{mib}MiB"] = {
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "binary_bytes": binary.stat().st_size,
                    "input_bytes": actual_size,
                    "warm_exit_code": warm["exit_code"],
                    "samples": args.samples,
                    "successful_samples": args.samples if successful else 0,
                    "exit_codes": [expected_exit] * args.samples,
                    "median_ms": measured["median_ms"] if successful else None,
                    "max_ms": measured["p99_ms"] if successful else None,
                    "peak_rss_kib": measured["peak_rss_kib"],
                    "findings": expected_findings,
                    "complete_scan_MB_per_s": measured["MB_per_s"]
                    if successful
                    else None,
                    "classification": "complete"
                    if successful
                    else "unsupported_cap_error",
                }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
