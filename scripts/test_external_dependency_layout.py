"""Execute the workflow's real layout shell, including failure paths."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/validate-rulespec.yml'
STEPS = next(v['steps'] for v in yaml.safe_load(WORKFLOW.read_text())['jobs'].values()
             if any(s.get('name') == 'Reserve isolated dependency directories' for s in v.get('steps', [])))


def step(name):
    return next(s for s in STEPS if s.get('name') == name)


def run(name, env):
    return subprocess.run(['bash', '-e', '-c', step(name)['run']], env={**os.environ, **env}, capture_output=True, text=True)


class LayoutTests(unittest.TestCase):
    def layout(self, parent):
        workspace = parent / 'rulespec-us'
        workspace.mkdir()
        temp = parent / 'runner temp'
        temp.mkdir()
        envfile = parent / 'env'
        envfile.touch()
        env = {'GITHUB_WORKSPACE': str(workspace), 'RUNNER_TEMP': str(temp), 'GITHUB_ENV': str(envfile)}
        result = run('Reserve isolated dependency directories', env)
        self.assertEqual(result.returncode, 0, result.stderr)
        env.update(dict(line.split('=', 1) for line in envfile.read_text().splitlines()))
        return workspace, env

    def test_relocation_preserves_source_and_checkout_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, env = self.layout(Path(directory))
            source = workspace / 'policy.yaml'
            source.write_bytes(b'caller-owned policy\n')
            caller = workspace / '_axiom'
            caller.mkdir()
            (caller / 'keep.yaml').write_bytes(b'caller owned too\n')
            staged = workspace / env['AXIOM_DEPENDENCY_STAGE'] / 'axiom-encode'
            staged.mkdir()
            (staged / 'malformed.yaml').write_text('broken: [\n')
            subprocess.run(['git', 'init', '-q', str(staged)], check=True)
            subprocess.run(['git', '-C', str(staged), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(staged), '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'fixture'], check=True)
            before = subprocess.check_output(['git', '-C', str(staged), 'rev-parse', 'HEAD'])
            result = run('Relocate dependency axiom-encode', env)
            self.assertEqual(result.returncode, 0, result.stderr)
            relocated = Path(env['AXIOM_DEPENDENCY_ROOT']) / 'axiom-encode'
            self.assertEqual(subprocess.check_output(['git', '-C', str(relocated), 'rev-parse', 'HEAD']), before)
            self.assertFalse(staged.exists())
            self.assertEqual(sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob('*.yaml')), ['_axiom/keep.yaml', 'policy.yaml'])
            self.assertEqual(source.read_bytes(), b'caller-owned policy\n')
            self.assertEqual((caller / 'keep.yaml').read_bytes(), b'caller owned too\n')

    def test_destination_collision_and_staged_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, env = self.layout(Path(directory))
            staged = workspace / env['AXIOM_DEPENDENCY_STAGE'] / 'axiom-encode'
            staged.mkdir()
            destination = Path(env['AXIOM_DEPENDENCY_ROOT']) / 'axiom-encode'
            destination.mkdir()
            self.assertNotEqual(run('Relocate dependency axiom-encode', env).returncode, 0)
            self.assertTrue(staged.is_dir())
            destination.rmdir()
            staged.rmdir()
            staged.symlink_to(workspace, target_is_directory=True)
            self.assertNotEqual(run('Relocate dependency axiom-encode', env).returncode, 0)
            self.assertFalse(destination.exists())

    def test_nested_runner_temp_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envfile = root / 'env'
            envfile.touch()
            result = run('Reserve isolated dependency directories', {'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(root), 'GITHUB_ENV': str(envfile)})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(envfile.read_text(), '')

    def test_foreign_dependency_is_explicit_and_us_is_not_duplicated(self):
        for tail in WORKFLOW.read_text().split('          dependency_args=()')[1:]:
            block = textwrap.dedent('          dependency_args=()' + tail.split('          fi', 1)[0] + '          fi\n')
            for country, composer, expected in [('ca', 'a' * 40, ['--rulespec-dependency-root', '/external path/rulespec-us']), ('us', 'a' * 40, []), ('ca', '', [])]:
                result = subprocess.run(['bash', '-eu', '-c', block + '\nif [ "${#dependency_args[@]}" -gt 0 ]; then printf "%s\\n" "${dependency_args[@]}"; fi'], env={**os.environ, 'GITHUB_WORKSPACE': '/source/rulespec-' + country, 'AXIOM_COMPOSE_REF': composer, 'AXIOM_DEPENDENCY_ROOT': '/external path'}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), expected)
        self.assertEqual(WORKFLOW.read_text().count('"${composer_args[@]}" "${dependency_args[@]}"'), 3)

    def test_every_dependency_checkout_is_relocated_before_next_step(self):
        count = 0
        for index, checkout in enumerate(STEPS):
            path = checkout.get('with', {}).get('path', '')
            if not path.startswith('${{ env.AXIOM_DEPENDENCY_STAGE }}/'):
                continue
            count += 1
            relocation = STEPS[index + 1]
            self.assertEqual(relocation['name'], 'Relocate dependency ' + path.split('/')[-1])
            self.assertEqual(relocation.get('if'), checkout.get('if'))
        self.assertEqual(count, 6)
        self.assertNotIn('_axiom/', WORKFLOW.read_text())


if __name__ == '__main__':
    unittest.main()
