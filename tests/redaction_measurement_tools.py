import hashlib
import importlib.util
import unittest
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("measure_redaction", Path(__file__).resolve().parents[1] / "scripts" / "measure_redaction.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class MeasurementTests(unittest.TestCase):
    def test_expected_digest_includes_partial_block(self):
        self.assertEqual(measure.expected_digest(b"abc", 4101), hashlib.sha256(b"abc" * 4101).hexdigest())

    def test_peak_memory_units_are_platform_specific(self):
        self.assertEqual(measure.peak_bytes(123, "linux"), 123 * 1024)
        self.assertEqual(measure.peak_bytes(123, "darwin"), 123)

    def test_synthetic_secret_fixture_has_expected_output(self):
        source, result = measure.records(True)
        self.assertIn(b"ghp_", source)
        self.assertEqual(result, b"key=[REDACTED]\n")

    def test_real_process_accounting_and_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / "fake-rayloc"
            binary.write_text('#!/bin/sh\ncat "$2"\n')
            binary.chmod(0o700)
            size, elapsed, peak = measure.measure(binary, 1024, False, directory)
            self.assertEqual(size, (1024 // len(measure.records(False)[0])) * len(measure.records(False)[0]))
            self.assertGreater(elapsed, 0)
            self.assertGreater(peak, 0)
            binary.write_text('#!/bin/sh\nexit 2\n')
            with self.assertRaisesRegex(RuntimeError, "redaction failed"):
                measure.measure(binary, 1024, False, directory)
            binary.write_text('#!/bin/sh\nprintf wrong\n')
            with self.assertRaisesRegex(RuntimeError, "output mismatch"):
                measure.measure(binary, 1024, False, directory)
            source, expected = measure.records(True)
            binary.write_text('#!/usr/bin/env python3\nimport pathlib,sys\nsys.stdout.buffer.write(pathlib.Path(sys.argv[2]).read_bytes().replace(' + repr(source) + ', ' + repr(expected) + '))\nsys.exit(1)\n')
            size, _, _ = measure.measure(binary, 1024, True, directory)
            self.assertEqual(size, (1024 // len(source)) * len(source))

    def test_stdin_mode_reads_the_fixture_from_stdin(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / "fake-rayloc"
            source, expected = measure.records(True)
            binary.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read().replace(' + repr(source) + ', ' + repr(expected) + '))\nsys.exit(1)\n')
            binary.chmod(0o700)
            size, elapsed, peak = measure.measure(binary, 1024, True, directory, stdin=True)
            self.assertEqual(size, (1024 // len(source)) * len(source))
            self.assertGreater(elapsed, 0)
            self.assertGreater(peak, 0)
            binary.write_text('#!/bin/sh\ncat > /dev/null\nprintf wrong\nexit 1\n')
            with self.assertRaisesRegex(RuntimeError, "output mismatch"):
                measure.measure(binary, 1024, True, directory, stdin=True)

    def test_latency_probe_returns_positive_seconds(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / "fake-rayloc"
            binary.write_text(
                '#!/usr/bin/env python3\n'
                'import sys\n'
                'if sys.argv[1:] != ["redact"]: sys.exit(23)\n'
                'line = sys.stdin.buffer.readline()\n'
                'sys.stdout.buffer.write(line)\n'
                'sys.stdout.flush()\n'
                'sys.stdin.buffer.read()\n'
            )
            binary.chmod(0o700)
            startup, record = measure.measure_latency(binary)
            self.assertGreater(startup, 0)
            self.assertGreater(record, 0)
            self.assertLess(record, 5)


if __name__ == "__main__":
    unittest.main()
