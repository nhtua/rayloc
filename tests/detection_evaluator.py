"""Exercise accuracy accounting using a real scanner and hand-labeled records."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('detection_baseline', ROOT / 'scripts/detection_baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class EvaluationTests(unittest.TestCase):
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
        for partition in ('calibration', 'held-out'):
            corpus = ROOT / 'tests/corpus/detection' / (partition + '.jsonl')
            for line in corpus.read_text().splitlines():
                row = json.loads(line)
                self.assertTrue('text' not in row and 'value' not in row,
                                'complete fixture strings must not be committed')
                for field in ('text_parts', 'value_parts'):
                    self.assertTrue(all(isinstance(part, str) and len(part) <= 8
                                        for part in row[field]),
                                    'fixture chunks must be short strings')

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


if __name__ == '__main__':
    unittest.main()
