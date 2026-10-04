#!/usr/bin/env python3
"""Prepare and inspect validation artifacts; never publish a release."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

TARGETS = ('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
           'x86_64-apple-darwin', 'aarch64-apple-darwin')
ROOT = Path(__file__).resolve().parent.parent


def linkage(binary, target):
    subprocess.run(['file', str(binary)], check=True)
    if target.endswith('linux-musl'):
        reports = {flag: subprocess.check_output(['readelf', flag, str(binary)], text=True)
                   for flag in ('-h', '-l', '-d')}
        for report in reports.values():
            print(report)
        architecture = 'Advanced Micro Devices X86-64' if target.startswith('x86_64') else 'AArch64'
        if architecture not in reports['-h'] or 'INTERP' in reports['-l'] or 'NEEDED' in reports['-d']:
            raise ValueError('ELF architecture/static linkage gate failed')
    else:
        architecture = subprocess.check_output(['lipo', '-archs', str(binary)], text=True).strip()
        if architecture != ('x86_64' if target.startswith('x86_64') else 'arm64'):
            raise ValueError('Mach-O architecture gate failed')
        libraries = subprocess.check_output(['otool', '-L', str(binary)], text=True)
        commands = subprocess.check_output(['otool', '-l', str(binary)], text=True)
        print(libraries, commands)
        if any(not line.strip().startswith(('/usr/lib/', '/System/Library/')) for line in libraries.splitlines()[1:]):
            raise ValueError('non-system Mach-O dependency')
        if 'LC_BUILD_VERSION' not in commands and 'LC_VERSION_MIN_MACOSX' not in commands:
            raise ValueError('missing minimum macOS load command')


def archive(binary, target, output):
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    version = next(package['version'] for package in metadata['packages'] if package['name'] == 'rayloc')
    stem = f'rayloc-{version}-{target}'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rayloc-archive-') as temporary:
        directory = Path(temporary) / stem
        directory.mkdir()
        shutil.copyfile(binary, directory / 'rayloc')
        (directory / 'rayloc').chmod(0o755)
        for source in ('LICENSE', 'README.md', 'docs/release.md'):
            shutil.copyfile(ROOT / source, directory / Path(source).name)
        with tarfile.open(output / f'{stem}.tar.gz', 'w:gz') as result:
            result.add(directory, arcname=stem)
    print(f'prepared {stem}.tar.gz')


def checksums(output, verify=False):
    archives = sorted(output.glob('rayloc-*.tar.gz'))
    if not archives:
        raise ValueError('no release archives')
    rows = []
    for path in archives:
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(256 * 1024), b''):
                digest.update(chunk)
        rows.append(f'{digest.hexdigest()}  {path.name}\n')
    contents = ''.join(rows)
    manifest = output / 'SHA256SUMS'
    if verify:
        if manifest.read_text() != contents:
            raise ValueError('archive checksum mismatch')
        print('PASS archive checksums')
    else:
        manifest.write_text(contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('archive', 'linkage', 'checksums', 'verify'))
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--target', choices=TARGETS)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    try:
        if args.action in ('archive', 'linkage'):
            if args.binary is None or args.target is None:
                parser.error('--binary and --target required')
            (archive(args.binary, args.target, args.output) if args.action == 'archive'
             else linkage(args.binary, args.target))
        else:
            checksums(args.output, args.action == 'verify')
    except (OSError, ValueError, subprocess.CalledProcessError):
        parser.exit(2, 'release artifact validation failed\n')


if __name__ == '__main__':
    main()
