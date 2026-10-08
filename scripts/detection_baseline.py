#!/usr/bin/env python3
"""Evaluate fixed synthetic calibration/held-out records using the real CLI.

Record-level labels describe fixture sensitivity/policy, never live validity.
Run after cargo build --release. Output contains only safe aggregate metadata.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

CODE_SUFFIXES = frozenset({
    '.py', '.pyi', '.rs', '.js', '.jsx', '.mjs', '.cjs',
    '.ts', '.tsx', '.mts', '.cts',
})
SAFE_SOURCE_PATH = re.compile(r'^[A-Za-z0-9_.-]+$')
FINDING = re.compile(rb'\nFile: [^\r\n]*:([0-9]+):([0-9]+)\nRule: [^\r\n]* \(([a-z0-9-]+)\)')


def source_path(row):
    value = row.get('source_path', 'source')
    if (not isinstance(value, str) or not value or value in ('.', '..')
            or not SAFE_SOURCE_PATH.fullmatch(value)):
        raise ValueError('invalid source path in detection corpus')
    return value


def expected_occurrences(row, inline):
    field = 'expected_findings_no_inline' if not inline and 'expected_findings_no_inline' in row else 'expected_findings'
    if field not in row:
        return None
    entries = row[field]
    if not isinstance(entries, list):
        raise ValueError('invalid occurrence annotations in detection corpus')
    expected = Counter()
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {'rule', 'line', 'column'}
                or not isinstance(entry['rule'], str)
                or not re.fullmatch(r'[a-z0-9-]+', entry['rule'])
                or not isinstance(entry['line'], int) or entry['line'] < 1
                or not isinstance(entry['column'], int) or entry['column'] < 1):
            raise ValueError('invalid occurrence annotations in detection corpus')
        expected[(entry['rule'], entry['line'], entry['column'])] += 1
    return expected


def evaluate(binary, corpus, inline=True):
    rows = [json.loads(line) for line in corpus.read_text().splitlines()]
    counts = Counter()
    families = defaultdict(Counter)
    lengths = defaultdict(Counter)
    contexts = defaultdict(Counter)
    suppressions = Counter()
    clean_bytes = 0
    supported_misses = 0
    occurrence_counts = Counter()
    occurrence_mismatches = 0
    supported_occurrence_misses = 0
    supported_occurrence_extras = 0
    annotated_records = 0
    source_paths = Counter()
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    with tempfile.TemporaryDirectory(prefix='rayloc-accuracy-') as directory:
        for row in rows:
            filename = source_path(row)
            is_code = Path(filename).suffix.lower() in CODE_SUFFIXES
            source_paths['code' if is_code else 'text'] += 1
            for field in ('text', 'value'):
                if field + '_parts' in row:
                    row[field] = ''.join(row[field + '_parts'])
            source = (row['text'] + '\n').encode()
            source_file = Path(directory) / filename
            source_file.write_bytes(source)
            arguments = [str(binary), 'scan', str(source_file)]
            if not inline:
                arguments.append('--no-inline-ignores')
            result = subprocess.run(arguments, cwd=directory, env=environment, capture_output=True)
            if result.returncode not in (0, 1) or result.stderr:
                raise RuntimeError('scanner execution failed during accuracy evaluation')
            if row['value'].encode() in result.stdout:
                raise RuntimeError('fixture value appeared in scanner output')
            predicted = result.returncode == 1
            metric = ('TP' if predicted else 'FN') if row['secret'] else ('FP' if predicted else 'TN')
            counts[metric] += 1
            families[row['family']][metric] += 1
            length = row['length']
            bucket = '<16' if length < 16 else '16-23' if length < 24 else '24-31' if length < 32 else '32+'
            lengths[bucket][metric] += 1
            contexts[row['context']][metric] += 1
            if row['secret'] and row['supported'] and not predicted:
                supported_misses += 1
            if not row['secret']:
                clean_bytes += len(source)
            match = re.search(rb'Suppressed: inline=(\d+); placeholder=(\d+); reference=(\d+); checksum=(\d+); generic-filter=(\d+)', result.stdout)
            if not match:
                raise RuntimeError('suppression counters missing from scanner output')
            suppressions.update(dict(zip(['inline', 'placeholder', 'reference', 'checksum', 'generic_filter'], map(int, match.groups()))))
            expected = expected_occurrences(row, inline)
            if expected is not None:
                annotated_records += 1
                actual = Counter(
                    (rule.decode('ascii'), int(line), int(column))
                    for line, column, rule in FINDING.findall(result.stdout)
                )
                true_positive = sum((actual & expected).values())
                false_positive = sum((actual - expected).values())
                false_negative = sum((expected - actual).values())
                occurrence_counts.update(TP=true_positive, FP=false_positive, FN=false_negative)
                if false_positive or false_negative:
                    occurrence_mismatches += 1
                if row['secret'] and row['supported']:
                    supported_occurrence_misses += false_negative
                if not row['secret'] and row['supported']:
                    supported_occurrence_extras += false_positive
    tp, fp, fn = (counts[name] for name in ('TP', 'FP', 'FN'))
    result = dict(records=len(rows), confusion=dict(counts), precision=tp / (tp + fp) if tp + fp else None,
                  recall=tp / (tp + fn) if tp + fn else None,
                  clean_bytes=clean_bytes, false_positives_per_clean_MB=fp / (clean_bytes / 1_000_000) if clean_bytes else None,
                  supported_positive_misses=supported_misses, by_family=dict(families), by_length=dict(lengths),
                  by_context=dict(contexts), suppressions=dict(suppressions), source_paths=dict(source_paths),
                  sha256=hashlib.sha256(corpus.read_bytes()).hexdigest())
    if annotated_records:
        result.update(occurrences={key: occurrence_counts[key] for key in ('TP', 'FP', 'FN')},
                      occurrence_mismatches=occurrence_mismatches,
                      occurrence_supported_positive_misses=supported_occurrence_misses,
                      occurrence_supported_negative_extras=supported_occurrence_extras,
                      annotated_records=annotated_records)
    return result


def check_regression(actual, expected):
    """Require existing measured confusion and suppression counts to stay stable."""
    for partition, reference in expected.items():
        if not isinstance(reference, dict) or 'confusion' not in reference:
            continue
        if partition not in actual:
            raise ValueError('expected detection partition is missing')
        candidate = actual[partition]
        for key in ('confusion', 'supported_positive_misses', 'suppressions', 'occurrences',
                    'occurrence_mismatches', 'occurrence_supported_positive_misses',
                    'occurrence_supported_negative_extras'):
            if key not in reference:
                continue
            if candidate[key] != reference[key]:
                raise ValueError('detection baseline drift; review labeled evidence before updating')
    for partition in actual.values():
        if (isinstance(partition, dict)
                and (partition.get('occurrence_supported_positive_misses', 0)
                     or partition.get('occurrence_supported_negative_extras', 0))):
            raise ValueError('supported occurrence expectation mismatch')
    if actual.get('held-out', {}).get('supported_positive_misses'):
        raise ValueError('held-out supported positive missed')


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=root / 'target/release/rayloc')
    parser.add_argument('--output', type=Path, default=root / 'target/detection-baseline.json')
    parser.add_argument('--check', action='store_true', help='require measured baseline counts and suppression stability')
    parser.add_argument('--expected', type=Path, help='comparison report used by --check')
    parser.add_argument('--corpus', action='append', default=[], metavar='LABEL=PATH',
                        help='evaluate an additional labeled JSONL partition')
    args = parser.parse_args()
    result = {'unit': 'record', 'data': 'synthetic; no credential activity assessed', 'thresholds': 'provisional, unchanged'}
    corpora = [(name, root / 'tests/corpus/detection' / (name + '.jsonl'))
               for name in ('calibration', 'held-out')]
    labels = {name for name, _ in corpora}
    for specification in args.corpus:
        label, separator, filename = specification.partition('=')
        if (not separator or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', label)
                or label in labels or not filename):
            parser.error('invalid or duplicate corpus label')
        labels.add(label)
        corpora.append((label, Path(filename)))
    for partition, corpus in corpora:
        result[partition] = evaluate(args.binary.resolve(), corpus)
        result[partition + '-no-inline'] = evaluate(args.binary.resolve(), corpus, inline=False)
    if args.check:
        expected_path = args.expected or root / 'docs/research/detection-baseline.json'
        check_regression(result, json.loads(expected_path.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
