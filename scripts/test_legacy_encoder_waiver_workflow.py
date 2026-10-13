"""Execute the trusted audit shell against strict legacy and partitioned CLIs."""
from __future__ import annotations

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
    "AXIOM_LEGACY_ENCODER_TEST_WORKFLOW",
    str(Path(__file__).resolve().parents[1] / ".github/workflows/validate-rulespec.yml"),
))
MODULES = ["uk/statutes/active.yaml", "uk-region/policies/pending.yaml", "uk/statutes/removed.yaml"]


def run_audit(*, capability="old", shard="uk", first="uk", probe_status=0,
              audit_status=0, workers="1", encoder="fixture", matrix=None):
    matrix = ["uk", "uk-region"] if matrix is None else matrix
    step = next(item for item in yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
                if item.get("name") == "Enforce validation waiver ratchet")
    shell = step["run"].split("# waiver-ratchet-python-end\n", 1)[1]
    with tempfile.TemporaryDirectory(prefix="hub-.github-125-legacy-waiver-", dir=TEMP_PARENT) as directory:
        root = Path(directory)
        protected = root / "protected"
        protected.mkdir()
        workspace = root / "rulespec-uk"
        workspace.mkdir()
        for module in MODULES:
            path = workspace / module
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture: unchanged\n")
        calls = root / "calls.jsonl"
        calls.touch()
        base = root / "protected-ledger.txt"
        base.write_text("protected base ledger\n")
        changed = root / "audit-changed-paths.txt"
        changed.write_text("known-validation-gaps.yaml\n")
        supervisor = protected / "axiom-encode-signing-supervisor"
        supervisor.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import json
            import os
            import sys

            args = sys.argv[1:]
            with open(os.environ["AUDIT_CALLS"], "a") as log:
                log.write(json.dumps({"supervisor": args}) + "\\n")
            boundary = args.index("--")
            protected = os.environ["PROTECTED_RUNTIME"]
            assert args[:boundary] == [
                "--trusted-signing-roots", protected + "/signing-trust-roots.json",
                "--trusted-python-runtime-root", protected + "/python",
                "--trusted-python-import-root", protected + "/python/lib/python3.13/site-packages",
                "--trusted-python-package-root", protected + "/python/lib/python3.13/site-packages/axiom_encode",
            ], args
            command = args[boundary + 1:]
            assert command[0] == protected + "/axiom-encode", command
            os.execv(command[0], command)
            """))
        cli = protected / "axiom-encode"
        cli.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent("""\
            import argparse
            import json
            import os
            from pathlib import Path
            import sys

            argv = sys.argv[1:]
            with open(os.environ["AUDIT_CALLS"], "a") as log:
                log.write(json.dumps({"cli": argv}) + "\\n")
            assert argv[:2] == ["validation-waivers", "audit"], argv
            if argv[2:] == ["--help"]:
                status = int(os.environ["PROBE_STATUS"])
                if status:
                    print("protected CLI probe failed", file=sys.stderr)
                    sys.exit(status)
                if os.environ["AUDIT_CAPABILITY"] == "empty":
                    sys.exit(0)
            parser = argparse.ArgumentParser(prog="axiom-encode validation-waivers audit")
            parser.add_argument("--json", action="store_true")
            for option in ("--root", "--corpus-path", "--protected-base", "--changed-paths",
                           "--axiom-rules-engine-path"):
                parser.add_argument(option, required=True)
            capability = os.environ["AUDIT_CAPABILITY"]
            if capability in {"new", "key-only"}:
                parser.add_argument("--partition-key")
            if capability in {"new", "keys-only"}:
                parser.add_argument("--partition-keys-json")
            args = parser.parse_args(argv[2:])
            assert args.json
            assert args.root == os.environ["GITHUB_WORKSPACE"]
            assert args.corpus_path == os.environ["AXIOM_DEPENDENCY_ROOT"] + "/axiom-corpus"
            assert args.axiom_rules_engine_path == os.environ["AXIOM_DEPENDENCY_ROOT"] + "/axiom-rules-engine"
            assert Path(args.protected_base).read_text() == "protected base ledger\\n"
            assert Path(args.changed_paths).read_text() == "known-validation-gaps.yaml\\n"
            modules = sorted(path.relative_to(args.root).as_posix()
                             for path in Path(args.root).rglob("*.yaml"))
            key = getattr(args, "partition_key", None)
            keys = getattr(args, "partition_keys_json", None)
            if key is not None:
                assert json.loads(keys) == json.loads(os.environ["AUDIT_MATRIX"])
                modules = [module for module in modules if module.split("/")[0] == key]
            else:
                assert keys is None
            workers = int(os.environ.get("AXIOM_ENCODE_WAIVER_AUDIT_WORKERS", "1"))
            assert 1 <= workers <= 4
            print(json.dumps({"checked_modules": modules, "workers": workers,
                              "encoder_fixture": os.environ["ENCODER_FIXTURE"]}))
            sys.exit(int(os.environ["AUDIT_STATUS"]))
            """))
        supervisor.chmod(0o755)
        cli.chmod(0o755)
        shell = shell.replace("/opt/axiom-verification", str(protected))
        for expression, value in (
            ("${{ inputs.python-version }}", "3.13"),
            ("${{ matrix.shard }}", shard),
            ("${{ needs.shards.outputs.first }}", first),
            ("${{ needs.shards.outputs.matrix }}", json.dumps(matrix)),
        ):
            shell = shell.replace(expression, value)
        assert "${{" not in shell
        result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + shell], cwd=workspace, env={
            **os.environ, "RUNNER_TEMP": str(root), "GITHUB_WORKSPACE": str(workspace),
            "AXIOM_DEPENDENCY_ROOT": str(root / "dependencies with spaces"),
            "AXIOM_COMPOSE_REF": "", "AXIOM_ENCODE_WAIVER_AUDIT_WORKERS": workers,
            "PROTECTED_RUNTIME": str(protected), "AUDIT_CALLS": str(calls),
            "AUDIT_CAPABILITY": capability, "PROBE_STATUS": str(probe_status),
            "AUDIT_MATRIX": json.dumps(matrix),
            "AUDIT_STATUS": str(audit_status), "ENCODER_FIXTURE": encoder,
            "protected_base": str(base), "audit_changed_paths": str(changed),
        }, capture_output=True, text=True, timeout=30)
        return result, [json.loads(line) for line in calls.read_text().splitlines()]


class LegacyEncoderWaiverTests(unittest.TestCase):
    def test_prepartition_nz_and_uk_encoders_audit_all_roots_on_first_shard(self):
        for encoder in ("rulespec-nz/a9987a4b", "rulespec-uk/c326d1ac"):
            with self.subTest(encoder=encoder):
                result, calls = run_audit(encoder=encoder, workers="2")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)
                report = json.loads(result.stdout.splitlines()[-1])
                self.assertEqual(report["checked_modules"], sorted(MODULES))
                self.assertEqual(report["workers"], 1)
                self.assertFalse(any(arg.startswith("--partition-") for arg in calls[-1]["cli"]))
                result, calls = run_audit(encoder=encoder, shard="uk-region")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 2)
                self.assertIn("complete audit runs on the first shard", result.stdout)
                result, calls = run_audit(encoder=encoder, shard="uk-region", first="uk-region", matrix=["uk-region"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)
                self.assertEqual(json.loads(result.stdout.splitlines()[-1])["checked_modules"], sorted(MODULES))

    def test_partial_partition_support_falls_back_to_complete_audit(self):
        for capability in ("key-only", "keys-only"):
            with self.subTest(capability=capability):
                result, calls = run_audit(capability=capability)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout.splitlines()[-1])["checked_modules"], sorted(MODULES))
                self.assertFalse(any(arg.startswith("--partition-") for arg in calls[-1]["cli"]))

    def test_partitioned_encoder_preserves_arguments_workers_and_complete_coverage(self):
        checked = []
        for shard in ("uk", "uk-region"):
            result, calls = run_audit(capability="new", shard=shard, workers="2")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 4)
            args = calls[-1]["cli"]
            self.assertEqual(args[args.index("--partition-key") + 1], shard)
            self.assertEqual(json.loads(args[args.index("--partition-keys-json") + 1]), ["uk", "uk-region"])
            report = json.loads(result.stdout)
            self.assertEqual(report["workers"], 2)
            checked.extend(report["checked_modules"])
        self.assertEqual(sorted(checked), sorted(MODULES))

    def test_failed_empty_probes_and_audit_failures_stay_red(self):
        for capability in ("old", "new"):
            result, calls = run_audit(capability=capability, probe_status=37)
            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertEqual(len(calls), 2)
            self.assertIn("capability probe failed", result.stderr)
            result, calls = run_audit(capability=capability, audit_status=41)
            self.assertEqual(result.returncode, 41, result.stderr)
            self.assertEqual(len(calls), 4)
        result, calls = run_audit(capability="empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("capability probe returned no help", result.stderr)

    def test_worker_count_fails_closed(self):
        for workers in ("0", "5", "-1", "many"):
            with self.subTest(workers=workers):
                result, calls = run_audit(capability="new", workers=workers)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertIn("between 1 and 4", result.stderr)


if __name__ == "__main__":
    unittest.main()
