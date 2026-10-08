"""Unit tests for source-aware performance measurement gates."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    'context_precision_measure', ROOT / 'scripts/context_precision_measure.py')
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class MeasurementGateTests(unittest.TestCase):
    def test_precision_measurement_checks_scope_and_gate_boundaries(self):
        baseline = dict(median_ms=100.0, p95_ms=10.0, peak_rss_kib=25600)
        candidate = dict(median_ms=103.0, p95_ms=10.5, peak_rss_kib=25856)
        self.assertEqual(measure.gate_failures(baseline, candidate, large=True), [])
        for changed, large in [
            (dict(candidate, median_ms=103.01), True),
            (dict(candidate, p95_ms=10.501), False),
            (dict(candidate, peak_rss_kib=25857), True),
        ]:
            self.assertTrue(measure.gate_failures(baseline, changed, large=large))

        expected = dict(bytes=16384, findings=1, exit_code=1)
        measure.validate_sample(dict(expected), expected)
        for sample in [dict(findings=1, exit_code=1),
                       dict(bytes=16384, findings=1, exit_code=2),
                       dict(bytes=16384, findings=0, exit_code=0)]:
            with self.assertRaises(ValueError):
                measure.validate_sample(sample, expected)

    def test_precision_measurement_rejects_swapped_roles_and_invalid_samples(self):
        expected = dict(baseline=2, candidate=1)
        with self.assertRaises(ValueError):
            measure.validate_findings({'baseline': 1, 'candidate': 2}, expected)
        with self.assertRaises(ValueError):
            measure.validate_samples(2)
        self.assertEqual(measure.validate_samples(3), 3)


if __name__ == '__main__':
    unittest.main()
