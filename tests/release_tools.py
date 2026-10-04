"""Release tooling contracts: shipped bytes, safe checksums and CLI fixtures."""
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ReleaseTests(unittest.TestCase):
    def run_tool(self, *arguments, code=0):
        result = subprocess.run(['python3', str(ROOT / 'scripts/release.py'), *map(str, arguments)], capture_output=True, text=True)
        self.assertEqual(result.returncode, code, result.stderr)
        return result

    def test_archive_contains_executable_license_readme_and_matching_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.run_tool('archive', '--binary', ROOT / 'target/release/rayloc', '--target', 'x86_64-unknown-linux-musl', '--output', output)
            archives = list(output.glob('*.tar.gz'))
            self.assertEqual(len(archives), 1)
            with tarfile.open(archives[0]) as archive:
                members = archive.getmembers()
                self.assertEqual({Path(m.name).name for m in members if m.isfile()}, {'rayloc', 'LICENSE', 'README.md', 'release.md'})
                self.assertTrue(next(m for m in members if m.name.endswith('/rayloc')).mode & 0o111)
            self.run_tool('checksums', '--output', output)
            self.run_tool('verify', '--output', output)
            archives[0].write_bytes(b'corrupted')
            self.run_tool('verify', '--output', output, code=2)

    def test_linkage_gate_rejects_dynamic_gnu_binary_as_static_musl(self):
        if not __import__('sys').platform.startswith('linux'):
            self.skipTest('ELF gate')
        self.run_tool('linkage', '--binary', ROOT / 'target/release/rayloc', '--target', 'x86_64-unknown-linux-musl', code=2)

    def test_unknown_target_cannot_produce_advertised_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_tool('archive', '--binary', ROOT / 'target/release/rayloc', '--target', 'unsupported', '--output', directory, code=2)

    def test_real_release_binary_passes_artifact_smoke(self):
        result = subprocess.run(['python3', str(ROOT / 'scripts/artifact_smoke.py'), str(ROOT / 'target/release/rayloc')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
