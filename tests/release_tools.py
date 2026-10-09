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

    def test_stamp_sets_manifest_and_lock_versions_and_rejects_invalid_versions(self):
        import shutil
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        from release import stamp
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)
            for name in ('Cargo.toml', 'Cargo.lock'):
                shutil.copyfile(ROOT / name, copy / name)
            stamp('2026.10.4', copy)
            self.assertIn('name = "rayloc"\nversion = "2026.10.4"', (copy / 'Cargo.toml').read_text())
            self.assertIn('name = "rayloc"\nversion = "2026.10.4"', (copy / 'Cargo.lock').read_text())
            for invalid in ('2026.10.04', 'v2026.10.4', '2026.10', '', None):
                with self.assertRaises(ValueError):
                    stamp(invalid, copy)
        self.run_tool('stamp', '--version', '2026.10.04', code=2)

    def test_sync_doc_moves_readme_pins_and_rejects_invalid_versions(self):
        import shutil
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        from release import sync_doc
        original = (ROOT / 'README.md').read_text().splitlines(keepends=True)
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)
            shutil.copyfile(ROOT / 'README.md', copy / 'README.md')
            sync_doc('2026.12.31', copy)
            updated = (copy / 'README.md').read_text()
            self.assertEqual(len(original), len(updated.splitlines(keepends=True)))
            changed = [i for i, (before, after) in enumerate(zip(original, updated.splitlines(keepends=True))) if before != after]
            self.assertEqual(len(changed), 3)
            self.assertTrue(all('RAYLOC_VERSION' in original[i] or 'rev:' in original[i] for i in changed))
            for pinned in ('Pin a release, e.g. `v2026.12.31`', 'RAYLOC_VERSION=v2026.12.31 sh', 'rev: v2026.12.31'):
                self.assertIn(pinned, updated)
            self.assertIn('pre-commit==4.6.2', updated)
            sync_doc('2026.12.31', copy)
            self.assertEqual((copy / 'README.md').read_text(), updated)
            (copy / 'README.md').write_text('# rayloc\n')
            with self.assertRaises(ValueError):
                sync_doc('2026.12.31', copy)
            for invalid in ('2026.12.04', 'v2026.12.31', '2026.12', '', None):
                with self.assertRaises(ValueError):
                    sync_doc(invalid, copy)
        self.run_tool('sync-doc', '--version', '2026.12.04', code=2)

    def test_install_script_verifies_checksum_and_installs_host_binary(self):
        import json
        import os
        import platform
        machine = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}[platform.machine().lower()]
        system = {'Linux': 'unknown-linux-musl', 'Darwin': 'apple-darwin'}[platform.system()]
        target = f'{machine}-{system}'
        metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
        version = next(package['version'] for package in metadata['packages'] if package['name'] == 'rayloc')
        with tempfile.TemporaryDirectory() as directory:
            releases = Path(directory) / 'releases'
            download = releases / 'download' / f'v{version}'
            self.run_tool('archive', '--binary', ROOT / 'target/release/rayloc', '--target', target, '--output', download)
            self.run_tool('checksums', '--output', download)
            destination = Path(directory) / 'bin'
            environment = dict(os.environ, RAYLOC_RELEASES_URL=releases.as_uri(), RAYLOC_VERSION=version,
                               RAYLOC_INSTALL_DIR=str(destination))

            def install():
                return subprocess.run(['sh', str(ROOT / 'install.sh')], env=environment, capture_output=True, text=True)

            result = install()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'rayloc {version}', result.stdout)
            self.assertTrue(os.access(destination / 'rayloc', os.X_OK))
            self.assertEqual(sorted(p.name for p in destination.iterdir()), ['rayloc'])
            (destination / 'rayloc').unlink()
            (download / 'SHA256SUMS').write_text('0' * 64 + f'  rayloc-{version}-{target}.tar.gz\n')
            result = install()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('checksum mismatch', result.stderr)
            self.assertFalse((destination / 'rayloc').exists())
            environment['RAYLOC_VERSION'] = '1.0.0;rm'
            self.assertIn('invalid release version', install().stderr)

    def test_real_release_binary_passes_artifact_smoke(self):
        result = subprocess.run(['python3', str(ROOT / 'scripts/artifact_smoke.py'), str(ROOT / 'target/release/rayloc')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
