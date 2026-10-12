"""Execute composer pin admission and check protected consumer wiring."""
import os
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/validate-rulespec.yml'


class ComposerWorkflowTests(unittest.TestCase):
    def test_pin_admission(self):
        text = WORKFLOW.read_text()
        source = text.split("python - <<'PYCOMPOSE'\n", 1)[1].split('          PYCOMPOSE', 1)[0]
        source = textwrap.dedent(source)
        spec = importlib.util.spec_from_file_location(
            'validator_tests', WORKFLOW.parents[2] / 'scripts/test_validate_rulespec_workflow.py',
        )
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        ref = 'a' * 40
        table = helper.workflow_toolchain({**helper.WORKFLOW_INPUT_PINS, 'axiom_compose_ref': ref})
        caller = (
            'name: Repository checks\non: pull_request\njobs:\n  validate:\n'
            '    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
            '    with:\n      axiom-compose-ref: ' + ref + '\n'
        )
        with helper.WorkflowInputFixture(table=table, caller=caller) as fixture:
            root = fixture.root
            config = root / '.axiom/workflow-toolchain.toml'
            def run(value):
                helper.git(root, 'add', '-A')
                helper.git(root, 'commit', '--allow-empty', '-qm', 'fixture composer pin')
                base = helper.git(root, 'rev-parse', 'HEAD')
                return helper.run_workflow_inputs(
                    root, base, pins={'axiom_compose_ref': value},
                ).returncode
            self.assertEqual(run(ref), 0)
            for value in ['', 'main', 'b' * 40, 'A' * 40, 'a' * 39, 'a' * 40 + '\n']:
                self.assertNotEqual(run(value), 0, value)
            saved = root / 'saved.toml'
            config.rename(saved)
            config.symlink_to(saved)
            self.assertNotEqual(run(ref), 0)
            config.unlink()
            config.write_text(saved.read_text())
            config.parent.rename(root / 'actual')
            (root / '.axiom').symlink_to(root / 'actual', target_is_directory=True)
            self.assertNotEqual(run(ref), 0)
            # The later composer step keeps its syntax check, after trusted
            # configuration consistency has already passed in the shards job.
            for value in ['', 'main', 'A' * 40, 'a' * 39, 'a' * 40 + '\n']:
                result = subprocess.run(['python3', '-c', source], cwd=root,
                                        env={**os.environ, 'AXIOM_COMPOSE_REF': value},
                                        capture_output=True)
                self.assertNotEqual(result.returncode, 0, value)
        # Equality and Git-blob checks run together before dependency checkout;
        # the executable protected-input regressions exercise their rejection.
        protected = text.index('- name: Validate immutable dependency inputs')
        checkout = text.index('- name: Checkout axiom-encode')
        compose = text.index('- name: Checkout axiom-compose')
        self.assertLess(protected, checkout)
        self.assertLess(protected, compose)
        self.assertIn('effective axiom_compose_ref must match the protected configuration', text)

    def test_consumer_flags_fail_closed_and_old_input_is_compatible(self):
        text = WORKFLOW.read_text()
        setup = text.split('          composer_args=()', 1)[1].split('          fi', 1)[0]
        setup = textwrap.dedent('          composer_args=()' + setup + '          fi\n')
        # With no composer input the legacy command receives no additional args.
        result = subprocess.run(['bash', '-c', 'set -eu\n' + setup + '\nprintf "%s" "${#composer_args[@]}"'],
                                env={**os.environ, 'AXIOM_COMPOSE_REF': ''}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '0')
        # Missing executable must fail before a command can proceed.
        with tempfile.TemporaryDirectory() as directory:
            setup = setup.replace('/opt/axiom-compose-verification/axiom-compose', directory + '/missing')
            result = subprocess.run(['bash', '-c', 'set -eu\n' + setup],
                                    env={**os.environ, 'AXIOM_COMPOSE_REF': 'a' * 40}, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        # Execute all three forwarding blocks with an available pinned binary.
        for tail in text.split('          composer_args=()')[1:]:
            block = textwrap.dedent('          composer_args=()' + tail.split('          fi', 1)[0] + '          fi\n')
            with tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / 'composer'
                binary.write_text('#!/bin/sh\nexit 0\n')
                binary.chmod(0o755)
                block = block.replace('/opt/axiom-compose-verification/axiom-compose', str(binary))
                result = subprocess.run(['bash', '-c', 'set -eu\n' + block + '\nprintf "%s\\n" "${composer_args[@]}"'],
                                        env={**os.environ, 'AXIOM_COMPOSE_REF': 'a' * 40}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ['--axiom-compose-path', str(binary)])
        self.assertEqual(text.count('composer_args=()'), 3)
        self.assertEqual(text.count('test -x /opt/axiom-compose-verification/axiom-compose'), 3)
        for command in ['validation-waivers audit "${composer_args[@]}"',
                        '--skip-reviewers "${composer_args[@]}"',
                        'axiom-encode test "${composer_args[@]}"']:
            self.assertIn(command, text)
        self.assertLess(text.index('- name: Build protected axiom-compose runtime'), text.index('# waiver-ratchet-python-end'))
        self.assertIn('sudo chmod -R go-w /opt/axiom-compose-verification', text)
        self.assertIn('--locked', text)


if __name__ == '__main__':
    unittest.main()
