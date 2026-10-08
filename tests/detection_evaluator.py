"""Exercise accuracy accounting using a real scanner and hand-labeled records."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('detection_baseline', ROOT / 'scripts/detection_baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class EvaluationTests(unittest.TestCase):
    def test_source_paths_preserve_unquoted_configuration_detection(self):
        rows = [
            dict(family='reference', context='assignment', length=17,
                 text_parts=['api_key=args.', 'vllm_api_key'],
                 value_parts=['args.vllm', '_api_key'], secret=False, supported=True,
                 source_path='member.ts', expected_findings=[]),
            dict(family='text', context='assignment', length=18,
                 text_parts=['password=', 'self.DUMMY', '_API_KEY'],
                 value_parts=['self.DUM', 'MY_API_K', 'EY'], secret=True, supported=True,
                 source_path='values.env',
                 expected_findings=[dict(rule='password-assignment', line=1, column=10)]),
            dict(family='legacy', context='assignment', length=8,
                 text_parts=['password', "='short'"], value_parts=['short'],
                 secret=True, supported=False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'sources.jsonl'
            corpus.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            result = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
        self.assertEqual(result['records'], 3)
        self.assertEqual(result['source_paths']['code'], 1)
        self.assertEqual(result['source_paths']['text'], 2)
        self.assertEqual(result['occurrences'], dict(TP=1, FP=0, FN=0))
        self.assertEqual(result['occurrence_mismatches'], 0)

    def test_source_path_rejects_absolute_and_parent_traversal_without_echoing_row(self):
        for source_path in ('/outside/secret.ts', '../secret.ts'):
            row = dict(family='safe', context='assignment', length=8,
                       text_parts=['password', "='short'"], value_parts=['short'],
                       secret=False, supported=True, source_path=source_path,
                       expected_findings=[])
            with tempfile.TemporaryDirectory() as directory:
                corpus = Path(directory) / 'unsafe.jsonl'
                corpus.write_text(json.dumps(row) + '\n')
                with self.assertRaises(ValueError) as caught:
                    baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
            self.assertNotIn(source_path, str(caught.exception))
            self.assertNotIn('short', str(caught.exception))

    def test_occurrence_scoring_detects_missing_and_extra_findings(self):
        row = dict(family='mixed', context='assignment', length=8,
                   text_parts=['password=aaaaaaaa; api_key=', 'Q7v2n9B4', 'x6M1z8K3'],
                   value_parts=['aaaaaaaa'], secret=True, supported=True,
                   expected_findings=[
                       dict(rule='password-assignment', line=1, column=10),
                       dict(rule='github-token', line=1, column=50),
                   ])
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'mixed.jsonl'
            corpus.write_text(json.dumps(row) + '\n')
            result = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
        self.assertEqual(result['confusion'], {'TP': 1})
        self.assertEqual(result['occurrences'], dict(TP=1, FP=1, FN=1))
        self.assertEqual(result['occurrence_mismatches'], 1)

    def test_occurrence_expectations_follow_inline_policy(self):
        row = dict(family='inline', context='assignment', length=8,
                   value_parts=['aaaaaaaa'],
                   text_parts=['password=', "'aaaa", 'aaaa', "' # ra", 'yloc:ign', 'ore'],
                   secret=False, supported=True, expected_findings=[],
                   expected_findings_no_inline=[dict(rule='password-assignment', line=1, column=11)])
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'inline.jsonl'
            corpus.write_text(json.dumps(row) + '\n')
            enabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
            disabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus, inline=False)
        self.assertEqual(enabled['occurrences'], dict(TP=0, FP=0, FN=0))
        self.assertEqual(disabled['occurrences'], dict(TP=1, FP=0, FN=0))
        self.assertEqual(enabled['confusion'], {'TN': 1})
        self.assertEqual(disabled['confusion'], {'FP': 1})

    def test_cli_accepts_extra_corpus_and_expected_candidate_report(self):
        row = dict(family='reference', context='assignment', length=8,
                   text_parts=['password=aaaaaaaa'], value_parts=['aaaaaaaa'],
                   secret=True, supported=True,
                   expected_findings=[dict(rule='password-assignment', line=1, column=10)])
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'extra.jsonl'
            report = Path(directory) / 'candidate.json'
            corpus.write_text(json.dumps(row) + '\n')
            script = ROOT / 'scripts/detection_baseline.py'
            command = [sys.executable, str(script), '--binary', str(ROOT / 'target/release/rayloc'),
                       '--corpus', f'extra={corpus}', '--output', str(report)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            check = subprocess.run(command + ['--check', '--expected', str(report)],
                                   capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertNotIn('aaaaaaaa', first.stdout + check.stdout)
            self.assertEqual(json.loads(report.read_text())['extra']['occurrences'],
                             dict(TP=1, FP=0, FN=0))

    def test_chunked_fixtures_preserve_detection_and_inline_policy(self):
        row = dict(family='inline', context='assignment', length=8,
                   value_parts=['aaaa', 'aaaa'],
                   text_parts=["password", "='aaaaaa", "aa' # ra", 'yloc:ign', 'ore'],
                   secret=False, supported=True)
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'labeled.jsonl'
            corpus.write_text(json.dumps(row) + '\n')
            enabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
            disabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus, inline=False)
        self.assertEqual(enabled['confusion'], {'TN': 1})
        self.assertEqual(enabled['suppressions']['inline'], 1)
        self.assertEqual(disabled['confusion'], {'FP': 1})
        self.assertEqual(disabled['suppressions']['inline'], 0)

    def test_repository_fixtures_store_only_short_chunks(self):
        for partition in ('calibration', 'held-out', 'precision-calibration', 'precision-held-out'):
            corpus = ROOT / 'tests/corpus/detection' / (partition + '.jsonl')
            for line in corpus.read_text().splitlines():
                row = json.loads(line)
                self.assertTrue('text' not in row and 'value' not in row,
                                'complete fixture strings must not be committed')
                for field in ('text_parts', 'value_parts'):
                    self.assertTrue(all(isinstance(part, str) and len(part) <= 8
                                        for part in row[field]),
                                    'fixture chunks must be short strings')

    def test_precision_partitions_remain_chunked_and_independent(self):
        partitions = [ROOT / 'tests/corpus/detection' / f'precision-{name}.jsonl'
                      for name in ('calibration', 'held-out')]
        self.assertTrue(all(path.exists() for path in partitions))
        value_sets = []
        observed_references = set()
        for corpus in partitions:
            values = set()
            for line in corpus.read_text().splitlines():
                row = json.loads(line)
                self.assertIn('expected_findings', row)
                self.assertTrue(all(len(part) <= 8 for part in row['text_parts']))
                self.assertTrue(all(len(part) <= 8 for part in row['value_parts']))
                if row.get('family') == 'qualified-reference':
                    observed_references.add(''.join(row['value_parts']))
                if row.get('family') == 'opaque-positive':
                    values.add(''.join(row['value_parts']))
            value_sets.append(values)
        self.assertTrue(value_sets[0].isdisjoint(value_sets[1]))
        self.assertGreaterEqual(len(observed_references), 13)

    def test_real_predictions_produce_all_four_confusion_cells(self):
        records = [
            dict(family='password', context='assignment', length=8, value='aaaaaaaa', text="password='aaaaaaaa'", secret=True, supported=True),
            dict(family='clean', context='assignment', length=8, value='bbbbbbbb', text="name='bbbbbbbb'", secret=False, supported=True),
            dict(family='short', context='assignment', length=5, value='short', text="password='short'", secret=True, supported=False),
            dict(family='public', context='assignment', length=16, value='Q7v2n9B4x6M1z8K3', text="api_key='Q7v2n9B4x6M1z8K3'", secret=False, supported=False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'labeled.jsonl'
            corpus.write_text(''.join(json.dumps(row) + '\n' for row in records))
            result = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
        self.assertEqual(result['confusion'], {'TP': 1, 'FP': 1, 'FN': 1, 'TN': 1})
        self.assertEqual(result['precision'], 0.5)
        self.assertEqual(result['recall'], 0.5)
        self.assertEqual(result['supported_positive_misses'], 0)
        self.assertEqual(result['by_family']['short'], {'FN': 1})
        self.assertEqual(result['by_length']['<16'], {'TP': 1, 'TN': 1, 'FN': 1})
        self.assertEqual(result['by_context']['assignment'], result['confusion'])
        self.assertEqual(result['suppressions']['inline'], 0)

    def test_inline_policy_effects_are_measured_separately(self):
        row = dict(family='inline', context='assignment', length=8, value='aaaaaaaa', text="password='aaaaaaaa' # rayloc:ignore", secret=False, supported=True)
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'labeled.jsonl'
            corpus.write_text(json.dumps(row) + '\n')
            enabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus)
            disabled = baseline.evaluate(ROOT / 'target/release/rayloc', corpus, inline=False)
        self.assertEqual(enabled['confusion'], {'TN': 1})
        self.assertEqual(enabled['suppressions']['inline'], 1)
        self.assertEqual(disabled['confusion'], {'FP': 1})
        self.assertEqual(disabled['suppressions']['inline'], 0)

class RegressionGateTests(unittest.TestCase):
    def test_gate_rejects_regressed_counts_supported_misses_and_suppression_drift(self):
        good = {'confusion': {'TP': 49, 'FP': 1, 'FN': 1, 'TN': 19},
                'supported_positive_misses': 0, 'suppressions': {'inline': 2}}
        expected = {'held-out': good}
        self.assertTrue(hasattr(baseline, 'check_regression'), 'accuracy regression gate missing')
        baseline.check_regression(expected, expected)
        for wrong in [dict(good, supported_positive_misses=1),
                      dict(good, confusion={'TP': 48, 'FP': 1, 'FN': 2, 'TN': 19}),
                      dict(good, suppressions={'inline': 0})]:
            with self.assertRaises(ValueError):
                baseline.check_regression({'held-out': wrong}, expected)

    def test_occurrence_gates_reject_supported_extra_or_missing_findings(self):
        good = {'confusion': {'TP': 1}, 'supported_positive_misses': 0,
                'suppressions': {'inline': 0}, 'occurrences': {'TP': 1, 'FP': 0, 'FN': 0},
                'occurrence_mismatches': 0, 'occurrence_supported_positive_misses': 0,
                'occurrence_supported_negative_extras': 0}
        baseline.check_regression({'precision-held-out': good}, {'precision-held-out': good})
        for field, value in [('occurrence_supported_positive_misses', 1),
                             ('occurrence_supported_negative_extras', 1)]:
            with self.assertRaises(ValueError):
                baseline.check_regression(
                    {'precision-held-out': dict(good, **{field: value})},
                    {'precision-held-out': good})


if __name__ == '__main__':
    unittest.main()
