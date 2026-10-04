#!/usr/bin/env python3
"""Exercise the shipped manifest via actual pre-commit 4.6.2 and real commits."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', required=True)
parser.add_argument('--rev', required=True)
parser.add_argument('--pre-commit', default='pre-commit')
parser.add_argument('--binary', required=True, help='installed rayloc executable the system hook runs')
args = parser.parse_args()
scanner = str(Path(args.binary).resolve())
secret = ('AKIA0123' + '456789AB' + 'CDEF')
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_ATTR_NOSYSTEM='1', LC_ALL='C')
# The manifest uses the system language: the hook runs whichever rayloc is on PATH.
env['PATH'] = str(Path(scanner).parent) + os.pathsep + env['PATH']

with tempfile.TemporaryDirectory(prefix='rayloc-framework-') as temporary:
    base = Path(temporary)
    root = base / 'consumer'
    root.mkdir()
    env['PRE_COMMIT_HOME'] = str(base / 'cache')

    def run(*command, code=0, cwd=root):
        result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert secret not in result.stdout, 'complete synthetic secret leaked'
        assert result.returncode == code, f'{command[0]} {command[1:]}: expected {code}, got {result.returncode}\n{result.stdout}'
        return result.stdout

    def git(*command, **kwargs):
        return run('git', *command, **kwargs)

    def stage(name, content):
        (root / name).write_text(content)
        git('add', '--', name)

    def commit(message, code=0):
        return git('commit', '--allow-empty', '-qm', message, code=code)

    assert run(args.pre_commit, '--version').strip() == 'pre-commit 4.6.2'
    git('init', '-q', '--template=')
    for key, value in [('user.name', 'Fixture'), ('user.email', 'fixture@example.invalid'), ('core.attributesFile', '/dev/null'), ('core.excludesFile', '/dev/null')]:
        git('config', key, value)
    config = f"repos:\n  - repo: {args.repo!r}\n    rev: {args.rev!r}\n    hooks:\n      - id: rayloc-staged\n"
    stage('.pre-commit-config.yaml', config)
    # The framework owns migration; prove a pre-existing hook still executes.
    hooks = root / '.git' / 'hooks'
    hooks.mkdir()
    hook = hooks / 'pre-commit'
    hook.write_text('#!/bin/sh\nprintf invoked >> .git/legacy-hook-runs\n')
    hook.chmod(0o755)
    run(args.pre_commit, 'validate-config')
    run(args.pre_commit, 'install', '--install-hooks')
    manifests = list((base / 'cache').glob('repo*/.pre-commit-hooks.yaml'))
    assert len(manifests) == 1
    run(args.pre_commit, 'validate-manifest', str(manifests[0]))
    # A system hook builds and downloads nothing.
    assert not list((base / 'cache').glob('repo*/*env-*')), 'hook environment was built'
    run(scanner, 'scan', '--staged')
    commit('clean setup')
    assert (root / '.git/legacy-hook-runs').read_text() == 'invoked'
    commit('empty scope')
    # --all-files retains staged-only semantics; an unstaged secret is not scanned.
    stage('arbitrary.unusual-extension', 'safe staged\n')
    (root / 'arbitrary.unusual-extension').write_text(secret + '\n')
    run(scanner, 'scan', '--staged')
    run(args.pre_commit, 'run', 'rayloc-staged', '--all-files')
    commit('clean partial staging')
    assert (root / 'arbitrary.unusual-extension').read_text() == secret + '\n'
    # Staged finding remains a finding despite clean unstaged replacement.
    git('add', 'arbitrary.unusual-extension')
    (root / 'arbitrary.unusual-extension').write_text('safe unstaged replacement\n')
    run(scanner, 'scan', '--staged', code=1)
    assert 'exit code: 1' in commit('blocked finding', code=1)
    # Index policy must prevail over a valid unstaged policy.
    stage('.rayloc.yaml', 'invalid configuration\n')
    (root / '.rayloc.yaml').write_text('version: "1"\n')
    run(scanner, 'scan', '--staged', code=2)
    assert 'exit code: 2' in commit('blocked configuration', code=1)
    stage('arbitrary.unusual-extension', 'safe again\n')
    git('add', '.rayloc.yaml')
    commit('recovered')
    # Direct installer preserves the framework-managed script and legacy hook.
    before = hook.read_bytes()
    assert 'manually integrate' in run(scanner, 'hook', 'install', code=2)
    assert hook.read_bytes() == before
    git('config', 'core.hooksPath', 'custom-hooks')
    assert 'core.hooksPath' in run(args.pre_commit, 'install', code=1)
    assert git('config', '--get', 'core.hooksPath').strip() == 'custom-hooks'
    run(scanner, 'hook', 'install')
    commit('custom hook clean')
    stage('arbitrary.unusual-extension', secret + '\n')
    commit('custom hook blocked', code=1)
    print(f'PASS pre-commit 4.6.2; language=system; clean/cache/empty/partial/findings/error/policy/coexistence/hooksPath')
