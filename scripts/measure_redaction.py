#!/usr/bin/env python3
"""Measure file redaction using synthetic records and validate output bytes."""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def peak_bytes(max_rss, platform):
    return max_rss if platform == "darwin" else max_rss * 1024


def records(secret):
    if secret:
        token = b"ghp_" + b"SyntheticToken0123456789abcdef"
        return b"key=" + token + b"\n", b"key=[REDACTED]\n"
    return b"ordinary log line with harmless content\n", b"ordinary log line with harmless content\n"


def expected_digest(line, count):
    digest = hashlib.sha256()
    block = line * 4096
    for _ in range(count // 4096):
        digest.update(block)
    digest.update(line * (count % 4096))
    return digest.hexdigest()


def measure(binary, size, secret, directory, command=False):
    line, expected = records(secret)
    count = max(1, size // len(line))
    source = directory / "input"
    output = directory / "output"
    error_output = directory / "error-output"
    block = line * 4096
    with source.open("wb") as stream:
        for _ in range(count // 4096):
            stream.write(block)
        stream.write(line * (count % 4096))
    arguments = ([str(binary), "redact", "--", "sh", "-c", 'cat "$1" & cat "$1" >&2 & wait', "measure", str(source)]
                 if command else [str(binary), "redact", str(source)])
    with output.open("wb") as sink, error_output.open("wb") as error_sink:
        started = time.monotonic()
        child = subprocess.Popen(arguments, cwd=directory, stdout=sink, stderr=error_sink)
        _, status, usage = os.wait4(child.pid, 0)
        elapsed = time.monotonic() - started
        child.returncode = os.waitstatus_to_exitcode(status)
    if child.returncode != (1 if secret else 0):
        raise RuntimeError("redaction failed")
    for path, expected_value in [(output, expected_digest(expected, count)),
                                 (error_output, expected_digest(expected, count) if command else hashlib.sha256(b"").hexdigest())]:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(256 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_value:
            raise RuntimeError("output mismatch")
    return count * len(line) * (2 if command else 1), elapsed, peak_bytes(usage.ru_maxrss, sys.platform)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=lambda p: Path(p).resolve())
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--command", action="store_true", help="measure both child channels")
    args = parser.parse_args()
    if args.size_mib <= 0 or args.samples <= 0:
        parser.error("size and samples must be positive")
    with tempfile.TemporaryDirectory(prefix="rayloc-measure-") as temp:
        for secret in (False, True):
            for sample in range(args.samples):
                size, elapsed, peak = measure(args.binary, args.size_mib * 1024 * 1024, secret, Path(temp), args.command)
                print(f"kind={'secret' if secret else 'clean'} sample={sample + 1} bytes={size} seconds={elapsed:.6f} MB/s={size / elapsed / 1e6:.2f} peak_bytes={peak}")


if __name__ == "__main__":
    main()
