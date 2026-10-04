#!/usr/bin/env python3
"""Execute extracted/installed rayloc with real Git repositories and safe fixtures."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SECRET = ('AKIA0123' + '456789AB' + 'CDEF')


def smoke(binary):
    binary = str(Path(binary).resolve())
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_ATTR_NOSYSTEM='1', LC_ALL='C')
    with tempfile.TemporaryDirectory(prefix='rayloc-artifact-') as temporary:
        root = Path(temporary)
        env['PATH'] = str(root / 'bin') + os.pathsep + env['PATH']
        (root / 'bin').mkdir()
        os.symlink(binary, root / 'bin/rayloc')

        def run(*command, code=0, cwd=root, environment=env):
            result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True)
            assert SECRET.encode() not in result.stdout + result.stderr, 'complete fixture value leaked'
            assert result.returncode == code, f'artifact command {command[0]}: expected {code}, got {result.returncode}'
            return result

        def git(*arguments, **kwargs):
            return run('git', *arguments, **kwargs)

        def scan(*arguments, **kwargs):
            return run(binary, 'scan', *arguments, **kwargs)

        def write(name, content):
            (root / name).write_text(content)

        run(binary, '--help')
        run(binary, '--version')
        write('source', 'ordinary content\n')
        scan('source')
        write('source', SECRET + '\n')
        scan('source', code=1)
        scan('--glob', 'source', code=1)
        scan('.', code=1)
        write('.rayloc.yaml', 'malformed\n')
        scan('source', code=2)  # error takes precedence over a supported finding
        (root / '.rayloc.yaml').unlink()
        scan('--staged', code=2)  # outside Git
        scan('--diff', 'invalid-ref', code=2)
        git('init', '-q', '--template=')
        for key, value in [('user.name', 'Fixture'), ('user.email', 'fixture@example.invalid'),
                           ('core.attributesFile', '/dev/null'), ('core.excludesFile', '/dev/null')]:
            git('config', key, value)
        git('add', 'source')
        scan('--staged', code=1)  # unborn HEAD
        git('commit', '-qm', 'baseline')
        write('source', 'safe replacement\n')
        git('add', 'source')
        scan('--staged')  # deleted credential is outside scope
        write('source', SECRET + '\n')
        scan('--staged')  # partial staging: clean index, dirty workspace
        scan('--diff', 'HEAD', code=2)  # known fail-closed index-cache refresh edge
        write('source', 'safe replacement\n')
        git('commit', '-qm', 'clean baseline')
        write('source', 'safe replacement\n' + SECRET + '\n')
        git('add', 'source')
        write('source', 'safe workspace\n')
        scan('--staged', code=1)
        # Alternate index snapshot must ignore the ordinary index's finding.
        alternate = dict(env, GIT_INDEX_FILE=str(root / '.git/alternate'))
        git('read-tree', 'HEAD', environment=alternate)
        scan('--staged', environment=alternate)
        write('.rayloc.yaml', 'malformed\n')
        git('add', '.rayloc.yaml')
        scan('--staged', code=2)
        git('reset', '--quiet', 'HEAD', '--', '.rayloc.yaml', 'source')
        (root / '.rayloc.yaml').unlink()
        write('source', 'safe workspace\n')
        git('add', 'source')
        git('commit', '-qm', 'clean workspace')
        # Unchanged context credential cannot become a finding in either diff mode.
        write('source', SECRET + '\ncontext\n')
        git('add', 'source')
        git('commit', '-qm', 'synthetic context')
        write('source', SECRET + '\ncontext\nadded ordinary\n')
        git('add', 'source')
        scan('--staged')
        scan('--diff', 'HEAD')
        git('commit', '-qm', 'context untouched')
        linked = root / 'linked'
        git('worktree', 'add', '--quiet', '-b', 'fixture-linked', str(linked))
        scan('--staged', cwd=linked)
        # Direct managed hook, custom path, idempotence and real commit enforcement.
        git('config', 'core.hooksPath', 'custom-hooks')
        run(binary, 'hook', 'install')
        run(binary, 'hook', 'install')
        write('source', 'safe hook\n')
        git('add', 'source')
        git('commit', '-qm', 'hook clean')
        write('source', SECRET + '\n')
        git('add', 'source')
        git('commit', '-qm', 'hook blocked', code=1)
        # Missing Git must fail with a safe error. Explicit file works outside Git.
        standalone = root / 'standalone'
        standalone.mkdir()
        (standalone / 'clean').write_text('ordinary\n')
        no_git = dict(env, PATH=str(root / 'empty-path'))
        scan('--staged', cwd=standalone, environment=no_git, code=2)
        scan('clean', cwd=standalone, environment=no_git, code=2)
    print('PASS artifact CLI, redaction, 0/1/2, scope, snapshots, refs, hooks and Git failures')


if __name__ == '__main__':
    smoke(sys.argv[1])
