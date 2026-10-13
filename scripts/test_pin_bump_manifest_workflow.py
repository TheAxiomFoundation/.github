"""Exercise pin-bump guard arguments with a strict trusted CLI stand-in."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import yaml


TEMP_PARENT = "/private/tmp" if Path("/private/tmp").is_dir() else None

WORKFLOW = Path(os.environ.get(
    "AXIOM_PIN_BUMP_TEST_WORKFLOW",
    str(Path(__file__).resolve().parents[1] / ".github/workflows/validate-rulespec.yml"),
))
BASE = "a" * 40
HEAD = "b" * 40
PROPOSED = "e" * 40
MODULE = "uk/statutes/unchanged.yaml"
MANIFEST = ".axiom/encoding-manifests/uk/statutes/unchanged.json"


def run_guard(*, mode="full-toolchain-bump", valid=True, encoder="fixture"):
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    shell = next(step["run"] for step in steps if step.get("name") == "Reject manual RuleSpec changes")
    with tempfile.TemporaryDirectory(prefix="hub-.github-125-pin-manifest-", dir=TEMP_PARENT) as directory:
        root = Path(directory)
        workspace = root / "rulespec-uk"
        workspace.mkdir()
        module = workspace / MODULE
        module.parent.mkdir(parents=True)
        module.write_text("fixture: unchanged\n")
        manifest = workspace / MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"valid": valid, "sha256": hashlib.sha256(module.read_bytes()).hexdigest()}))
        dependencies = root / "dependencies with spaces"
        checkout = dependencies / "axiom-encode"
        checkout.mkdir(parents=True)
        (checkout / "pin").write_text(PROPOSED)
        protected = root / "protected"
        protected.mkdir()
        tools = root / "tools"
        tools.mkdir()
        (tools / "python").symlink_to(sys.executable)
        integrity = root / "integrity"
        integrity.mkdir()
        (integrity / "check.py").write_text("import sys\nassert sys.argv[1:] == ['verify']\n")
        calls = root / "calls.jsonl"
        calls.touch()
        supervisor = protected / "axiom-encode-signing-supervisor"
        supervisor.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import json
            import os
            import sys

            args = sys.argv[1:]
            with open(os.environ['GUARD_CALLS'], 'a') as log:
                log.write(json.dumps({'supervisor': args}) + '\\n')
            boundary = args.index('--')
            protected = os.environ['PROTECTED_RUNTIME']
            assert args[:boundary] == [
                '--trusted-signing-roots', protected + '/signing-trust-roots.json',
                '--trusted-python-runtime-root', protected + '/python',
                '--trusted-python-import-root', protected + '/python/lib/python3.13/site-packages',
                '--trusted-python-package-root', protected + '/python/lib/python3.13/site-packages/axiom_encode',
            ]
            command = args[boundary + 1:]
            assert command[0] == protected + '/axiom-encode'
            os.execv(command[0], command)
            """))
        cli = protected / "axiom-encode"
        cli.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import argparse
            import hashlib
            import json
            import os
            from pathlib import Path
            import sys

            argv = sys.argv[1:]
            assert argv[0] == 'guard-generated'
            parser = argparse.ArgumentParser()
            for name in ('repo', 'base-ref', 'head-ref', 'corpus-path', 'expected-encoder-checkout'):
                parser.add_argument('--' + name, required=True)
            parser.add_argument('--all', action='store_true')
            args = parser.parse_args(argv[1:])
            assert args.base_ref == os.environ['EXPECTED_BASE']
            assert args.head_ref == os.environ['GITHUB_SHA']
            pin = (Path(args.expected_encoder_checkout) / 'pin').read_text()
            assert pin == os.environ['PROPOSED_ENCODER']
            assert args.corpus_path == os.environ['AXIOM_DEPENDENCY_ROOT'] + '/axiom-corpus'
            with open(os.environ['GUARD_CALLS'], 'a') as log:
                log.write(json.dumps({'cli': argv, 'encoder_ref': pin,
                                      'encoder_fixture': os.environ['ENCODER_FIXTURE']}) + '\\n')
            # Model the observed --all/default selection distinction. This is
            # a strict fixture gate, not external signature authentication.
            if args.all:
                root = Path(args.repo)
                payload = json.loads((root / os.environ['MANIFEST']).read_text())
                digest = hashlib.sha256((root / os.environ['MODULE']).read_bytes()).hexdigest()
                if not payload['valid'] or payload['sha256'] != digest:
                    print('unchanged manifest rejected at proposed encoder', file=sys.stderr)
                    sys.exit(1)
            print('guard fixture accepted')
            """))
        supervisor.chmod(0o755)
        cli.chmod(0o755)
        shell = shell.replace("/opt/axiom-verification", str(protected)).replace(
            "/opt/axiom-dependency-integrity", str(integrity))
        for expression, value in (
            ("${{ github.event_name }}", "pull_request"),
            ("${{ github.event.pull_request.base.sha }}", BASE),
            ("${{ github.event.before }}", ""),
            ("${{ inputs.python-version }}", "3.13"),
        ):
            shell = shell.replace(expression, value)
        assert "${{" not in shell
        result = subprocess.run(["bash", "-c", shell], cwd=workspace, env={
            **os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(root),
            "AXIOM_DEPENDENCY_ROOT": str(dependencies), "GITHUB_SHA": HEAD,
            "RULESPEC_VALIDATION_MODE": mode, "EXPECTED_BASE": BASE,
            "PROPOSED_ENCODER": PROPOSED, "GUARD_CALLS": str(calls),
            "PROTECTED_RUNTIME": str(protected), "ENCODER_FIXTURE": encoder,
            "MODULE": MODULE, "MANIFEST": MANIFEST,
        }, capture_output=True, text=True, timeout=30)
        return result, [json.loads(line) for line in calls.read_text().splitlines()]


class PinBumpManifestTests(unittest.TestCase):
    def test_pin_only_audits_unchanged_manifests_at_proposed_pin(self):
        # Exact a9987a4b and c326d1ac CLI source both admit guard-generated
        # --all, enumerate all manifests, and preserve base-ref processing.
        for encoder in ("rulespec-nz/a9987a4b", "rulespec-uk/c326d1ac"):
            for valid in (True, False):
                with self.subTest(encoder=encoder, valid=valid):
                    result, calls = run_guard(valid=valid, encoder=encoder)
                    self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
                    self.assertEqual(len(calls), 2)
                    self.assertIn("--all", calls[-1]["cli"])
                    self.assertEqual(calls[-1]["encoder_ref"], PROPOSED)
                    if not valid:
                        self.assertIn("unchanged manifest rejected", result.stderr)

    def test_other_validation_modes_preserve_changed_manifest_behavior(self):
        for mode in ("changed", "changed-corpus-toolchain-bump", "full-push"):
            with self.subTest(mode=mode):
                result, calls = run_guard(mode=mode, valid=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("--all", calls[-1]["cli"])
                args = calls[-1]["cli"]
                self.assertEqual(args[args.index("--base-ref") + 1], BASE)
                self.assertEqual(args[args.index("--head-ref") + 1], HEAD)

    def test_selection_precedes_manifest_guard_and_module_validation(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        names = [step.get("name") for step in steps]
        selection = names.index("Select RuleSpec validation targets")
        guard = names.index("Reject manual RuleSpec changes")
        validation = names.index("Validate RuleSpec YAML")
        self.assertLess(selection, guard)
        self.assertLess(guard, validation)


if __name__ == "__main__":
    unittest.main()
