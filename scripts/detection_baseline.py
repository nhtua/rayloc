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


def evaluate(binary, corpus, inline=True):
    rows = [json.loads(line) for line in corpus.read_text().splitlines()]
    counts = Counter()
    families = defaultdict(Counter)
    lengths = defaultdict(Counter)
    contexts = defaultdict(Counter)
    suppressions = Counter()
    clean_bytes = 0
    supported_misses = 0
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    with tempfile.TemporaryDirectory(prefix='rayloc-accuracy-') as directory:
        path = Path(directory) / 'source'
        for row in rows:
            for field in ('text', 'value'):
                if field + '_parts' in row:
                    row[field] = ''.join(row[field + '_parts'])
            source = (row['text'] + '\n').encode()
            path.write_bytes(source)
            arguments = [str(binary), 'scan', str(path)]
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
    tp, fp, fn = (counts[name] for name in ('TP', 'FP', 'FN'))
    return dict(records=len(rows), confusion=dict(counts), precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None,
                clean_bytes=clean_bytes, false_positives_per_clean_MB=fp / (clean_bytes / 1_000_000) if clean_bytes else None,
                supported_positive_misses=supported_misses, by_family=dict(families), by_length=dict(lengths),
                by_context=dict(contexts), suppressions=dict(suppressions), sha256=hashlib.sha256(corpus.read_bytes()).hexdigest())


def check_regression(actual, expected):
    """Require existing measured confusion and suppression counts to stay stable."""
    for partition, reference in expected.items():
        if not isinstance(reference, dict) or 'confusion' not in reference:
            continue
        candidate = actual[partition]
        for key in ('confusion', 'supported_positive_misses', 'suppressions'):
            if candidate[key] != reference[key]:
                raise ValueError('detection baseline drift; review labeled evidence before updating')
    if actual['held-out']['supported_positive_misses']:
        raise ValueError('held-out supported positive missed')


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=root / 'target/release/rayloc')
    parser.add_argument('--output', type=Path, default=root / 'target/detection-baseline.json')
    parser.add_argument('--check', action='store_true', help='require measured baseline counts and suppression stability')
    args = parser.parse_args()
    result = {'unit': 'record', 'data': 'synthetic; no credential activity assessed', 'thresholds': 'provisional, unchanged'}
    for partition in ['calibration', 'held-out']:
        corpus = root / 'tests/corpus/detection' / (partition + '.jsonl')
        result[partition] = evaluate(args.binary.resolve(), corpus)
        result[partition + '-no-inline'] = evaluate(args.binary.resolve(), corpus, inline=False)
    if args.check:
        check_regression(result, json.loads((root / 'docs/research/detection-baseline.json').read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
