"""Measurement contract tests use actual scanner processes and literal expectations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class MeasurementTests(unittest.TestCase):
    def test_rank_percentiles_include_tail_and_reject_empty_samples(self):
        spec = importlib.util.spec_from_file_location('measure', ROOT / 'scripts/e2e_measure.py')
        measure = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(measure)
        except FileNotFoundError:
            self.fail('end-to-end measurement harness missing')
        self.assertEqual(measure.percentiles([5, 1, 4, 2, 3]), {'median_ms': 3, 'p95_ms': 5, 'p99_ms': 5})
        with self.assertRaises(ValueError):
            measure.percentiles([])
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_text(('AKIA0123' + '456789AB' + 'CDEF\n'))
            result = measure.measure(ROOT / 'target/release/rayloc', ['scan', str(source)], Path(directory), 3, 1, 21)
            self.assertEqual(result['findings'], 1)
            self.assertEqual(result['samples'], 3)
            self.assertGreater(result['p99_ms'], 0)
            self.assertGreater(result['peak_rss_kib'], 0)
            with self.assertRaises(AssertionError):
                measure.measure(ROOT / 'target/release/rayloc', ['scan', str(source)], Path(directory), 1, 0, 21)

    def test_rss_excludes_python_launcher_allocations(self):
        spec = importlib.util.spec_from_file_location('measure', ROOT / 'scripts/e2e_measure.py')
        measure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(measure)
        ballast = bytearray(96 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_text('ordinary\n')
            result = measure.measure(ROOT / 'target/release/rayloc', ['scan', str(source)], Path(directory), 1, 0, 9)
        self.assertLess(result['peak_rss_kib'], 64 * 1024, "Python launcher allocations counted as scanner RSS")
        self.assertEqual(len(ballast), 96 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
