#!/usr/bin/env python3
"""Warm-cache startup-inclusive scanner measurements (Linux/macOS, stdlib only)."""
import argparse
import hashlib
from functools import cache
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
SECRET = (b'AKIA0123' + b'456789AB' + b'CDEF')
RECORD = b'ordinary code line\n'


def percentiles(samples):
    if not samples:
        raise ValueError('empty measurements')
    samples = sorted(samples)
    return {'median_ms': statistics.median(samples),
            'p95_ms': samples[math.ceil(len(samples) * 0.95) - 1],
            'p99_ms': samples[math.ceil(len(samples) * 0.99) - 1]}


def environment():
    result = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    result.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_ATTR_NOSYSTEM='1', LC_ALL='C')
    return result


def parse_read_bytes(report):
    raw = re.search(rb'; ([\d,]+) byte\(s\) read', report)
    if raw is not None:
        return int(raw.group(1).replace(b',', b'')), 0

    human = re.search(rb'; ([\d.]+) (B|KiB|MiB|GiB|TiB|PiB|EiB) read', report)
    if human is None:
        raise ValueError('benchmark omitted scope bytes')
    value = float(human.group(1))
    unit = human.group(2).decode('ascii')
    power = 0 if unit == 'B' else ('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB').index(unit) + 1
    multiplier = 1024 ** power
    tolerance = 0 if power == 0 else round(0.005 * multiplier) + 1
    return round(value * multiplier), tolerance


@cache
def rss_launcher():
    temporary = tempfile.TemporaryDirectory(prefix='rayloc-rss-launcher-')
    binary = Path(temporary.name) / 'launcher'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(ROOT / 'scripts/rss_launcher.c'), '-o', str(binary)], check=True)
    return temporary, binary


def measure(binary, arguments, directory, samples, findings, size, code=None):
    _, launcher = rss_launcher()
    times, rss = [], []
    if code is None:
        code = int(findings > 0)
    for _ in range(samples):
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as resources:
            # An exec-reset native launcher isolates scanner RSS from Python.
            # The ballast regression test verifies this boundary explicitly.
            previous = Path.cwd()
            try:
                os.chdir(directory)
                started = time.perf_counter_ns()
                pid = os.posix_spawn(str(launcher), [str(launcher), str(binary), *arguments], environment(),
                                     file_actions=[(os.POSIX_SPAWN_DUP2, output.fileno(), 1),
                                                   (os.POSIX_SPAWN_DUP2, errors.fileno(), 2),
                                                   (os.POSIX_SPAWN_DUP2, resources.fileno(), 3)])
            finally:
                os.chdir(previous)
            _, status = os.waitpid(pid, 0)
            returncode = os.waitstatus_to_exitcode(status)
            times.append((time.perf_counter_ns() - started) / 1e6)
            resources.seek(0)
            peak = int(resources.read())
            rss.append(peak / 1024 if sys.platform == 'darwin' else peak)
            output.seek(0)
            errors.seek(0)
            report, diagnostics = output.read(), errors.read()
            assert SECRET not in report + diagnostics, 'benchmark fixture leaked'
            assert returncode == code, 'unexpected benchmark scan exit'
            assert not diagnostics, 'unexpected scanner diagnostic'
            assert report.count(b'\nValue: ') == findings, 'benchmark omitted/added finding'
            if code != 2:
                parsed, tolerance = parse_read_bytes(report)
                assert abs(parsed - size) <= tolerance, 'benchmark omitted scope bytes'
    result = dict(percentiles(times), samples=samples, findings=findings, bytes=size,
                  exit_code=code, peak_rss_kib=max(rss))
    result['MB_per_s'] = size / (result['median_ms'] * 1000) if size else None
    return result


def version(*command):
    return subprocess.check_output(command, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rayloc')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/e2e-baseline.json')
    parser.add_argument('--samples', type=int, default=21)
    parser.add_argument('--large-mb', type=int, default=12, help='use 1024 for extended gigabyte run')
    parser.add_argument('--tiny-files', type=int, default=2000)
    parser.add_argument('--hardware', default=platform.node())
    args = parser.parse_args()
    if args.samples < 3 or args.large_mb < 11 or not 1 <= args.tiny_files <= 10000:
        parser.error('samples >=3, large-mb >=11, tiny-files 1..10000 required')
    binary = args.binary.resolve()
    cpu = platform.processor()
    if Path('/proc/cpuinfo').exists():
        cpu = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name'))
    result = dict(hardware=args.hardware, cpu=cpu, os=platform.platform(), rust=version('rustc', '--version'),
                  git=version('git', '--version'), binary_bytes=binary.stat().st_size,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  cache='warm: created fixtures and one untimed scan; OS caches not flushed',
                  rules='all 10 built-in rules; default entropy/inline policy; no custom rules',
                  threads='explicit file/staged: serial; directory: auto up to 8 workers',
                  rss='native wait4 peak KiB; scanner and waited child high water; Python heap excluded (96MiB ballast regression tested)',
                  throughput='decimal MB/s, aggregate wall time, includes native benchmark launcher/startup/policy/Git/rendering; staged bytes exclude patch framing and newlines', cases={})
    with tempfile.TemporaryDirectory(prefix='rayloc-e2e-') as temporary:
        base = Path(temporary)
        file_root = base / 'files'
        file_root.mkdir()
        large = file_root / 'large'
        count = math.ceil(args.large_mb * 1_000_000 / len(RECORD))
        with large.open('wb') as output:
            for _ in range(count // 8192):
                output.write(RECORD * 8192)
            output.write(RECORD * (count % 8192))
            output.write(SECRET + b'\n')
        giant = file_root / 'giant'
        giant.write_bytes(SECRET + b'\n' + b'x' * (1024 * 1024 + 1))
        throughput = file_root / 'throughput'
        throughput.mkdir()
        content = RECORD * (65536 // len(RECORD)) + SECRET + b'\n'
        for i in range(256):
            (throughput / f'{i:08}').write_bytes(content)
        tiny = file_root / 'tiny'
        tiny.mkdir()
        for i in range(args.tiny_files):
            (tiny / f'{i:08}').write_bytes(RECORD + (SECRET + b'\n' if i % 100 == 0 else b''))
        for label, scope, size, findings, code in [
                ('file_gt10MB', large, large.stat().st_size, 1, 1),
                ('directory_16MB', throughput, len(content) * 256, 256, 1),
                ('giant_line', giant, giant.stat().st_size, 1, 2),
                ('many_tiny', tiny, sum(p.stat().st_size for p in tiny.iterdir()), math.ceil(args.tiny_files / 100), 1)]:
            measure(binary, ['scan', str(scope)], file_root, 1, findings, size, code)
            result['cases'][label] = measure(binary, ['scan', str(scope)], file_root, args.samples, findings, size, code)
        for lines in (0, 10, 100, 1000):
            for files in ((1, 10) if lines == 0 else (1, min(10, lines), min(100, lines))):
                label = f'staged_lines{lines}_files{files}'
                if label in result['cases']:
                    continue
                repository = base / label
                repository.mkdir()
                def git(*arguments):
                    subprocess.run(['git', *arguments], cwd=repository, env=environment(), check=True, capture_output=True)
                git('init', '-q', '--template=')
                git('config', 'user.name', 'Fixture')
                git('config', 'user.email', 'fixture@example.invalid')
                for i in range(files):
                    (repository / f'{i:03}').write_bytes(RECORD)
                git('add', '.')
                git('commit', '-qm', 'base')
                for i in range(lines):
                    with (repository / f'{i % files:03}').open('ab') as output:
                        output.write((SECRET if i == 0 else RECORD.rstrip(b'\n')) + b'\n')
                git('add', '.')
                size = (lines - 1) * (len(RECORD) - 1) + len(SECRET) if lines else 0
                findings = int(lines > 0)
                measure(binary, ['scan', '--staged'], repository, 1, findings, size)
                result['cases'][label] = dict(measure(binary, ['scan', '--staged'], repository, args.samples, findings, size), added_lines=lines, files=files)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
