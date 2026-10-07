"""Measurement contract tests use actual scanner processes and literal expectations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class MeasurementTests(unittest.TestCase):
    def test_parallel_harness_builds_accounted_fixtures_without_returning_sources(self):
        spec = importlib.util.spec_from_file_location('parallel_measure', ROOT / 'scripts/parallel_measure.py')
        measure = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(measure)
        except FileNotFoundError:
            self.fail('parallel measurement harness missing')
        with tempfile.TemporaryDirectory() as directory:
            fixture = measure.create_fixture(Path(directory), '32_large', scale=1)
            self.assertEqual(fixture['expected_files'], 32)
            self.assertEqual(fixture['expected_bytes'], 32 * 4 * 1024 * 1024)
            self.assertEqual(sum(path.stat().st_size for path in fixture['root'].iterdir()), fixture['expected_bytes'])
            self.assertNotIn('contents', fixture)
            self.assertNotIn('secret', fixture)

    def test_parallel_harness_covers_boundaries_and_exclusion_accounting(self):
        spec = importlib.util.spec_from_file_location('parallel_measure', ROOT / 'scripts/parallel_measure.py')
        measure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(measure)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for count in (255, 256, 257):
                fixture = measure.create_fixture(parent, f'boundary_{count}')
                self.assertEqual(fixture['expected_files'], count)
                self.assertEqual(fixture['expected_bytes'], count * 64 * 1024)
            excluded = measure.create_fixture(parent, 'excluded_tree')
            self.assertEqual(excluded['expected_files'], 257)
            self.assertEqual(excluded['expected_bytes'], 256 * 1024 + len('cache/\n'))
            self.assertEqual(excluded['expected_excluded'], 8192)
            tracked = measure.create_fixture(parent, 'git_tracked_exceptions')
            self.assertEqual(tracked['expected_files'], 2)
            self.assertEqual(tracked['expected_excluded'], 2)
            dense = measure.create_fixture(parent, 'dense')
            self.assertEqual(dense['expected_files'], 8)
            self.assertEqual(dense['expected_findings'], 8 * 100)

    def test_parallel_harness_checks_a_real_redacted_dense_scan(self):
        spec = importlib.util.spec_from_file_location('parallel_measure', ROOT / 'scripts/parallel_measure.py')
        measure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(measure)
        with tempfile.TemporaryDirectory() as directory:
            fixture = measure.create_fixture(Path(directory), 'dense')
            result = measure.measure_once(ROOT / 'target/release/rayloc', fixture, 2, sink_delay_ms=1)
        self.assertEqual(result['findings'], 800)
        self.assertEqual(result['bytes_read'], fixture['expected_bytes'])
        self.assertNotIn('report', result)

    def test_parallel_harness_extracts_only_safe_process_metrics(self):
        spec = importlib.util.spec_from_file_location('parallel_measure', ROOT / 'scripts/parallel_measure.py')
        measure = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(measure)
        except FileNotFoundError:
            self.fail('parallel measurement harness missing')
        report = ('\nrayloc — FINDINGS\n1,234 finding(s); 2 retained; 3 of 3 file(s) completed; '
                  '9 line(s); 12.06 KiB read\n0 file(s) excluded\n').encode()
        self.assertEqual(measure.parse_summary(report), {
            'findings': 1234, 'files_completed': 3, 'files_attempted': 3,
            'files_excluded': 0, 'lines_scanned': 9, 'bytes_read': 12349,
            'bytes_read_tolerance': 6,
        })
        exact_report = report.replace(b'12.06 KiB read', b'12,345 byte(s) read')
        self.assertEqual(measure.parse_summary(exact_report)['bytes_read'], 12345)
        self.assertEqual(measure.parse_summary(exact_report)['bytes_read_tolerance'], 0)
        with self.assertRaises(ValueError):
            measure.parse_summary(b'not a rayloc report')

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
