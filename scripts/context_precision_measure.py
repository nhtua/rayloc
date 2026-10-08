#!/usr/bin/env python3
"""Paired performance and scope checks for source-aware builtin detection."""
import argparse
from functools import cache
import hashlib
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
CORPORA = (ROOT / 'tests/corpus/detection/precision-calibration.jsonl',
           ROOT / 'tests/corpus/detection/precision-held-out.jsonl')
BASELINE_SOURCE_REVISION = 'b0ecc6ebebc81fbe42d7aeb495929ea04c2ca1ee'
SUMMARY = re.compile(rb'(\d[\d,]*) finding\(s\);[^\n]*; ([\d,.]+) (B|KiB|MiB|GiB|TiB|PiB|EiB) read')
PROGRESS = re.compile(rb'(?:rayloc: scanned \d+/\d+ files(?:\n|$))+')


def validate_samples(samples):
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 3:
        raise ValueError('sample count must be an integer of at least three')
    return samples


def validate_findings(actual, expected):
    if set(actual) != {'baseline', 'candidate'} or set(expected) != {'baseline', 'candidate'}:
        raise ValueError('baseline/candidate labels are required')
    for label in ('baseline', 'candidate'):
        if actual[label] != expected[label]:
            raise ValueError('scanner finding count differed from its labeled expectation')


def validate_sample(sample, expected):
    required = ('bytes', 'findings', 'exit_code')
    if any(key not in sample for key in required):
        raise ValueError('scanner sample omitted required scope metadata')
    if sample['exit_code'] == 2:
        raise ValueError('incomplete scans are not performance samples')
    for key in required:
        if sample[key] != expected[key]:
            raise ValueError(f'scanner sample {key} mismatch (expected {expected[key]}, observed {sample[key]})')


def gate_failures(baseline, candidate, large):
    for sample in (baseline, candidate):
        if any(key not in sample for key in ('median_ms', 'p95_ms', 'peak_rss_kib')):
            raise ValueError('performance result omitted a gate metric')
        if any(not isinstance(sample[key], (int, float)) or not math.isfinite(sample[key])
               for key in ('median_ms', 'p95_ms', 'peak_rss_kib')):
            raise ValueError('performance result contains an invalid gate metric')
    failures = []
    if large and candidate['median_ms'] > baseline['median_ms'] * 1.03:
        failures.append('median_time')
    if not large and candidate['p95_ms'] - baseline['p95_ms'] > max(0.5, baseline['p95_ms'] * 0.05):
        failures.append('p95_time')
    if candidate['peak_rss_kib'] - baseline['peak_rss_kib'] > max(256, baseline['peak_rss_kib'] * 0.01):
        failures.append('peak_rss')
    return failures


def percentiles(samples):
    ordered = sorted(samples)
    if not ordered:
        raise ValueError('empty timing samples')
    return dict(median_ms=statistics.median(ordered),
                p95_ms=ordered[math.ceil(len(ordered) * 0.95) - 1],
                p99_ms=ordered[math.ceil(len(ordered) * 0.99) - 1])


def binaries(specifications):
    found = {}
    for specification in specifications:
        label, separator, filename = specification.partition('=')
        if not separator or label not in ('baseline', 'candidate') or label in found or not filename:
            raise ValueError('binary arguments must define baseline and candidate exactly once')
        path = Path(filename).resolve()
        if not path.is_file():
            raise ValueError('scanner binary is missing')
        found[label] = path
    if set(found) != {'baseline', 'candidate'} or found['baseline'] == found['candidate']:
        raise ValueError('two distinct baseline and candidate binaries are required')
    return found


def environment():
    values = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    values.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                  GIT_ATTR_NOSYSTEM='1', LC_ALL='C')
    return values


def fixture_rows():
    rows = []
    for corpus in CORPORA:
        rows.extend(json.loads(line) for line in corpus.read_text().splitlines())
    return rows


def fixture_text(row):
    return ''.join(row['text_parts']).encode('utf-8')


def fixture_value(row):
    return ''.join(row['value_parts']).encode('utf-8')


def write_exact(path, prefix, size, filler=b'const value = 1;\n'):
    with path.open('wb') as output:
        if len(prefix) > size:
            raise ValueError('fixture prefix exceeds declared byte count')
        output.write(prefix)
        remaining = size - len(prefix)
        block = filler * max(1, min(8192, remaining // len(filler)))
        while remaining:
            part = block[:remaining]
            output.write(part)
            remaining -= len(part)


def read_summary(report):
    match = SUMMARY.search(report)
    if match is None:
        raise ValueError('scanner report omitted finding and byte counters')
    findings = int(match.group(1).replace(b',', b''))
    value = float(match.group(2).replace(b',', b''))
    unit = match.group(3).decode('ascii')
    power = 0 if unit == 'B' else ('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB').index(unit) + 1
    multiplier = 1024 ** power
    tolerance = 0 if power == 0 else round(0.005 * multiplier) + 1
    return findings, round(value * multiplier), tolerance


@cache
def launcher():
    directory = tempfile.TemporaryDirectory(prefix='rayloc-context-rss-')
    binary = Path(directory.name) / 'launcher'
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(ROOT / 'scripts/rss_launcher.c'), '-o', str(binary)], check=True)
    return directory, binary


def sample(binary, arguments, cwd, expected, sensitive):
    _, helper = launcher()
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as resources:
        previous = Path.cwd()
        try:
            os.chdir(cwd)
            started = time.perf_counter_ns()
            pid = os.posix_spawn(str(helper), [str(helper), str(binary), *arguments], environment(),
                                 file_actions=[(os.POSIX_SPAWN_DUP2, output.fileno(), 1),
                                               (os.POSIX_SPAWN_DUP2, errors.fileno(), 2),
                                               (os.POSIX_SPAWN_DUP2, resources.fileno(), 3)])
        finally:
            os.chdir(previous)
        _, status = os.waitpid(pid, 0)
        elapsed = (time.perf_counter_ns() - started) / 1e6
        code = os.waitstatus_to_exitcode(status)
        resources.seek(0)
        peak = int(resources.read())
        output.seek(0)
        errors.seek(0)
        report, diagnostics = output.read(), errors.read()
        if any(value and value in report + diagnostics for value in sensitive):
            raise ValueError('scanner output or diagnostics were unsafe')
        if diagnostics and PROGRESS.fullmatch(diagnostics) is None:
            raise ValueError('scanner emitted unexpected diagnostics')
        findings, byte_count, tolerance = read_summary(report)
        if abs(byte_count - expected['bytes']) > tolerance:
            raise ValueError('scanner byte counter differed from the exact fixture size')
        actual = dict(bytes=expected['bytes'], findings=findings, exit_code=code)
        validate_sample(actual, expected)
        times = dict(elapsed_ms=elapsed,
                     peak_rss_kib=peak if sys.platform != 'darwin' else peak / 1024)
        return times


def summarize(samples):
    return {**percentiles([sample['elapsed_ms'] for sample in samples]),
            'peak_rss_kib': max(sample['peak_rss_kib'] for sample in samples),
            'sample_count': len(samples)}


def run_paired(case, binaries_by_label, samples_count, sensitive):
    case_results = {}
    for label in ('baseline', 'candidate'):
        try:
            warmup = sample(binaries_by_label[label], case['arguments'], case['cwd'],
                             dict(bytes=case['bytes'], findings=case['expected_findings'][label],
                                  exit_code=case['expected_exit'][label]), sensitive)
        except ValueError as error:
            raise ValueError(f"{case['label']} ({label}): {error}") from None
        del warmup
    raw = {'baseline': [], 'candidate': []}
    for index in range(samples_count):
        order = ('baseline', 'candidate') if index % 2 == 0 else ('candidate', 'baseline')
        for label in order:
            try:
                raw[label].append(sample(
                    binaries_by_label[label], case['arguments'], case['cwd'],
                    dict(bytes=case['bytes'], findings=case['expected_findings'][label],
                         exit_code=case['expected_exit'][label]), sensitive))
            except ValueError as error:
                raise ValueError(f"{case['label']} ({label}): {error}") from None
    for label in ('baseline', 'candidate'):
        case_results[label] = summarize(raw[label])
        case_results[label].update(bytes=case['bytes'], findings=case['expected_findings'][label],
                                   exit_code=case['expected_exit'][label], binary_label=label)
    validate_findings({label: case_results[label]['findings'] for label in ('baseline', 'candidate')},
                      case['expected_findings'])
    large = case['gate_type'] == 'large'
    failures = gate_failures(case_results['baseline'], case_results['candidate'], large)
    baseline = case_results['baseline']
    candidate = case_results['candidate']
    return dict(expected_findings=case['expected_findings'], bytes=case['bytes'],
                gate_type=case['gate_type'], baseline=case_results['baseline'],
                candidate=case_results['candidate'], gate_failures=failures,
                ratios=dict(median=candidate['median_ms'] / baseline['median_ms'],
                            p95_delta_ms=candidate['p95_ms'] - baseline['p95_ms'],
                            peak_rss_delta_kib=candidate['peak_rss_kib'] - baseline['peak_rss_kib']),
                gates_passed=not failures)


def git(*arguments, cwd):
    subprocess.run(['git', *arguments], cwd=cwd, env=environment(), check=True, capture_output=True)


def workload_cases(root, worker_counts=(1, 8)):
    rows = fixture_rows()
    by_family = {}
    for row in rows:
        by_family.setdefault(row['family'], row)
    cases = []
    clean_size = 16 * 1024 * 1024
    reference = fixture_text(by_family['qualified-reference']) + b'\n'
    selector = fixture_text(by_family['key-expression']) + b'\n'
    for label, prefix in [('large_clean_code', b''),
                          ('large_reference_code', reference * 4096),
                          ('dense_references_and_selectors', reference * 4000 + selector * 2000)]:
        if label == 'large_reference_code':
            scope = root / label
            scope.mkdir()
            path = scope / 'references.ts'
            arguments = ['scan', '--silent', '--threads', '8', str(scope)]
        else:
            path = root / f'{label}.ts'
            arguments = ['scan', '--silent', str(path)]
        size = clean_size if label != 'dense_references_and_selectors' else len(prefix)
        write_exact(path, prefix, size)
        cases.append(dict(label=label, arguments=arguments, cwd=root,
                          bytes=size, expected_findings={'baseline': 0 if label == 'large_clean_code' else (4096 if label == 'large_reference_code' else 6000),
                                                         'candidate': 0},
                          expected_exit={'baseline': 0 if label == 'large_clean_code' else 1,
                                         'candidate': 0},
                          gate_type='large'))

    reference_count = 256
    lead = b'x' * (256 * 1024 - 1 - len(b' api_key')) + b' api_key'
    split_reference = lead + b'=' + fixture_value(by_family['qualified-reference'])
    long_prefix = split_reference + b'; ' + b'; '.join(
        [fixture_text(by_family['qualified-reference'])] * (reference_count - 1))
    long_prefix += b'; password=aaaaaaaa'
    long_path = root / 'long_line.ts'
    long_size = 600 * 1024
    write_exact(long_path, long_prefix, long_size, filler=b' ')
    cases.append(dict(label='long_line_512_associations', arguments=['scan', '--silent', str(long_path)],
                      cwd=root, bytes=long_size,
                      expected_findings={'baseline': reference_count + 1, 'candidate': 1},
                      expected_exit={'baseline': 1, 'candidate': 1}, gate_type='large'))

    accepted = fixture_text(by_family['opaque-positive']) + b'\n'
    accepted += b'api_key=aaaaaaaaaaaaaaaa\napi_key=ENV_API_KEY\n'
    accepted_path = root / 'generic_controls.ts'
    accepted_path.write_bytes(accepted)
    cases.append(dict(label='generic_accept_reject_and_alias', arguments=['scan', '--silent', str(accepted_path)],
                      cwd=root, bytes=len(accepted), expected_findings={'baseline': 1, 'candidate': 1},
                      expected_exit={'baseline': 1, 'candidate': 1}, gate_type='startup'))

    password_rows = [row for row in rows if row['family'] in ('weak-password', 'password-comparison')]
    baseline_password_findings = sum(row['family'] == 'weak-password' for row in password_rows)
    password_data = b'\n'.join(fixture_text(row) for row in password_rows) + b'\n'
    password_path = root / 'password_cases.ts'
    password_path.write_bytes(password_data)
    cases.append(dict(label='weak_passwords_and_comparisons', arguments=['scan', '--silent', str(password_path)],
                      cwd=root, bytes=len(password_data), expected_findings={'baseline': baseline_password_findings, 'candidate': len(password_rows)},
                      expected_exit={'baseline': 1, 'candidate': 1}, gate_type='startup'))

    marker = next(row for row in rows if row['family'] == 'private-key')
    github = next(row for row in rows if row['family'] == 'provider' and row['source_path'] == 'token.txt')
    historical = [json.loads(line) for line in (ROOT / 'tests/corpus/detection/calibration.jsonl').read_text().splitlines()]
    jws = next(row for row in historical if row['family'] == 'jws')
    provider_data = b'\n'.join((fixture_text(github), fixture_text(marker), fixture_text(jws))) + b'\n'
    provider_path = root / 'provider_cases.txt'
    provider_path.write_bytes(provider_data)
    cases.append(dict(label='provider_and_marker', arguments=['scan', '--silent', str(provider_path)],
                      cwd=root, bytes=len(provider_data), expected_findings={'baseline': 3, 'candidate': 3},
                      expected_exit={'baseline': 1, 'candidate': 1}, gate_type='startup'))

    custom_root = root / 'custom'
    custom_root.mkdir()
    custom_config = custom_root / 'rules.yaml'
    custom_config.write_text('version: "1"\nrules: [{id: precision-custom, regex: "corp_([a-z]+)", secret_group: 1, entropy: 0}]\n')
    custom_path = custom_root / 'custom.ts'
    custom_path.write_bytes(b'custom=corp_alphabeta\n')
    cases.append(dict(label='custom_rule', arguments=['scan', '--silent', '--config', str(custom_config), str(custom_path)],
                      cwd=custom_root, bytes=22, expected_findings={'baseline': 1, 'candidate': 1},
                      expected_exit={'baseline': 1, 'candidate': 1}, gate_type='startup'))

    directory = root / 'mixed_directory'
    directory.mkdir()
    directory_refs = 0
    directory_secrets = 0
    text_positive = next(row for row in rows if row['family'] == 'text-control')
    for index in range(2000):
        if index % 2 == 0:
            (directory / f'{index:04}.ts').write_bytes(reference)
            directory_refs += 1
        else:
            (directory / f'{index:04}.env').write_bytes(fixture_text(text_positive) + b'\n')
            directory_secrets += 1
    directory_size = sum(path.stat().st_size for path in directory.iterdir())
    for worker_count in worker_counts:
        expected = {'baseline': directory_refs + directory_secrets, 'candidate': directory_secrets}
        cases.append(dict(label=f'mixed_2000_files_threads_{worker_count}',
                          arguments=['scan', '--silent', '--threads', str(worker_count), str(directory)],
                          cwd=root, bytes=directory_size, expected_findings=expected,
                          expected_exit={'baseline': 1, 'candidate': 1}, gate_type='startup'))

    for additions in (0, 10, 100, 1000):
        repository = root / f'staged_{additions}'
        repository.mkdir()
        git('init', '-q', '--template=', cwd=repository)
        git('config', 'user.name', 'Fixture', cwd=repository)
        git('config', 'user.email', 'fixture@example.invalid', cwd=repository)
        (repository / 'source.ts').write_bytes(b'const existing = true;\n')
        git('add', 'source.ts', cwd=repository)
        git('commit', '-qm', 'base', cwd=repository)
        added = []
        if additions:
            added.append(fixture_text(by_family['weak-password']))
            added.extend(reference.rstrip(b'\n') for _ in range(additions - 1))
            with (repository / 'source.ts').open('ab') as output:
                output.write(b'\n'.join(added) + b'\n')
            git('add', 'source.ts', cwd=repository)
        expected = {'baseline': (additions if additions else 0), 'candidate': (1 if additions else 0)}
        cases.append(dict(label=f'staged_{additions}_added_lines', arguments=['scan', '--silent', '--staged'],
                          cwd=repository, bytes=sum(len(line) for line in added),
                          expected_findings=expected,
                          expected_exit={'baseline': int(additions > 0), 'candidate': int(additions > 0)},
                          gate_type='startup'))
    return cases


def version(*arguments):
    return subprocess.check_output(arguments, text=True).strip()


def source_archive_hash(revision):
    archive = subprocess.check_output(['git', 'archive', '--format=tar', revision,
                                       'src', 'Cargo.toml', 'Cargo.lock'], cwd=ROOT)
    return hashlib.sha256(archive).hexdigest()


def main():
    root = ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', action='append', default=[], metavar='LABEL=PATH', required=True)
    parser.add_argument('--samples', type=int, default=21)
    parser.add_argument('--threads', nargs='+', type=int, default=[1, 8], choices=[1, 8])
    parser.add_argument('--output', type=Path, default=root / 'target/context-precision-performance.json')
    args = parser.parse_args()
    try:
        count = validate_samples(args.samples)
        binary_paths = binaries(args.binary)
    except ValueError as error:
        parser.error(str(error))
    info = {}
    for label, binary in binary_paths.items():
        info[label] = dict(path=binary.name, bytes=binary.stat().st_size,
                           sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    rows = fixture_rows()
    sensitive = [fixture_value(row) for row in rows if row.get('secret')]
    with tempfile.TemporaryDirectory(prefix='rayloc-context-precision-') as temporary:
        case_results = {}
        for case in workload_cases(Path(temporary), args.threads):
            case_results[case['label']] = run_paired(case, binary_paths, count, sensitive)
    failed = [name for name, case in case_results.items() if not case['gates_passed']]
    revision = version('git', 'rev-parse', 'HEAD')
    cpu = platform.processor()
    if Path('/proc/cpuinfo').exists():
        cpu = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                    if line.startswith('model name')), cpu)
    result = dict(source_revisions={'baseline': BASELINE_SOURCE_REVISION, 'candidate': revision},
                  source_archive_sha256={'baseline': source_archive_hash(BASELINE_SOURCE_REVISION),
                                         'candidate': source_archive_hash(revision)},
                  corpora={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in CORPORA},
                  binaries=info, samples=count, threads=sorted(set(args.threads)),
                  hardware=dict(cpu=cpu, host=platform.node(), os=platform.platform(),
                                rust=version('rustc', '--version'), git=version('git', '--version')),
                  policy='all built-ins with default entropy/inline policy; custom rule only in its labeled workload',
                  cache='warm: fixtures created and each binary warmed once; caches not flushed',
                  rss='native wait4 peak KiB; scanner and waited children, Python heap excluded',
                  workloads=case_results, gates_passed=not failed, failed_gates=failed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
