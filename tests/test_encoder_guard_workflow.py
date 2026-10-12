#!/usr/bin/env python3
"""Run the actual base-anchored encoder guard against isolated Git fixtures."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/encoder-guard.yml"
CALLER = ROOT / "workflow-templates/encoder-guard-caller.yml"
GUARD_STEP = "Reject RuleSpec modules without encoder manifests"
REVISION_STEP = "Resolve immutable event revisions"
GUARD_EVALUATIONS = 0


def document(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def events(workflow: dict) -> dict:
    # PyYAML's YAML 1.1 reader treats the Actions key `on` as a boolean.
    return workflow.get("on", workflow.get(True))


def step(workflow: dict, name: str) -> dict:
    return next(item for item in workflow["jobs"]["guard"]["steps"] if item.get("name") == name)


def source(workflow: dict, name: str = GUARD_STEP) -> str:
    lines = step(workflow, name)["run"].splitlines()
    begin = lines.index("python3 -I - <<'PY'") + 1
    end = lines.index("PY", begin)
    return "\n".join(lines[begin:end]) + "\n"


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


class Fixture:
    """Only fixture commits change; the shared workspace's Git history stays intact."""

    def __init__(self, initial: dict[str, str] | None = None):
        self.temporary = tempfile.TemporaryDirectory(prefix=".encoder-guard-fixture-", dir=ROOT / "tests")
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Encoder guard fixture")
        git(self.root, "config", "user.email", "fixture@example.invalid")
        git(self.root, "config", "commit.gpgsign", "false")
        self.write("README.md", "Fixture only.\n")
        self.write(".github/workflows/trusted-guard.yml", WORKFLOW.read_text())
        self.write(".github/workflows/encoder-guard.yml", CALLER.read_text())
        for path, content in (initial or {}).items():
            self.write(path, content)
        self.base = self.commit("Base fixture")
        git(self.root, "checkout", "-qb", "fixture-head")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.temporary.cleanup()

    def write(self, path: str, content: str = "fixture: data\n") -> Path:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
        return destination

    def manifest(self, path: str) -> Path:
        # This guard checks a regular Git blob's presence, not its JSON content.
        return self.write(path, '{"fixture": "encoder manifest"}\n')

    def commit(self, message: str) -> str:
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", message)
        return git(self.root, "rev-parse", "HEAD")

    def head(self) -> str:
        head = self.commit("Head fixture")
        git(self.root, "checkout", "--detach", "-q", self.base)
        return head

    def run(self, head: str, *, base: str | None = None) -> subprocess.CompletedProcess[str]:
        global GUARD_EVALUATIONS
        GUARD_EVALUATIONS += 1
        # Extract executable code from BASE, never from the candidate tree.
        trusted = yaml.safe_load(git(self.root, "show", f"{self.base}:.github/workflows/trusted-guard.yml"))
        return subprocess.run(
            [sys.executable, "-I", "-c", source(trusted)], cwd=self.root,
            env={**os.environ, "BASE_SHA": self.base if base is None else base, "HEAD_SHA": head},
            capture_output=True, text=True,
        )


class GuardDecisionTests(unittest.TestCase):
    def assert_pass(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_fail(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_module_root_requires_a_manifest_with_and_without_jurisdiction(self):
        for root in ("statutes", "regulations", "policies", "legislation", "programs"):
            for prefix in ("", "us/"):
                with self.subTest(root=root, prefix=prefix), Fixture() as fixture:
                    fixture.write(f"{prefix}{root}/bare.yaml")
                    result = fixture.run(fixture.head())
                    self.assert_fail(result)
                    self.assertIn("Missing encoder apply manifests: 1", result.stderr)

    def test_new_manifest_in_each_supported_layout_passes(self):
        for manifest in (
            ".axiom/encoding-manifests/us/statutes/title/item.json",
            ".axiom/encoding-manifests/statutes/title/item.json",
            "us/.axiom/encoding-manifests/statutes/title/item.json",
        ):
            with self.subTest(manifest=manifest), Fixture() as fixture:
                fixture.write("us/statutes/title/item.yaml")
                fixture.manifest(manifest)
                self.assert_pass(fixture.run(fixture.head()))

    def test_existing_manifest_in_each_supported_layout_passes(self):
        for manifest in (
            ".axiom/encoding-manifests/us/statutes/title/item.json",
            ".axiom/encoding-manifests/statutes/title/item.json",
            "us/.axiom/encoding-manifests/statutes/title/item.json",
        ):
            initial = {"us/statutes/title/item.yaml": "fixture: base\n", manifest: "{}\n"}
            with self.subTest(manifest=manifest), Fixture(initial) as fixture:
                fixture.write("us/statutes/title/item.yaml", "fixture: head\n")
                self.assert_pass(fixture.run(fixture.head()))

    def test_companion_tests_only_are_exempt(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/title/item.test.yaml")
            fixture.write("us/programs/item.test.yml")
            self.assert_pass(fixture.run(fixture.head()))

    def test_composed_paths_are_exempt(self):
        with Fixture() as fixture:
            fixture.write("us/policies/composed/assembled.yaml")
            fixture.write("programs/composed/assembled.yml")
            self.assert_pass(fixture.run(fixture.head()))

    def test_axiom_metadata_at_root_and_jurisdiction_root_is_outside_module_roots(self):
        with Fixture() as fixture:
            fixture.write(".axiom/config.yaml")
            fixture.write("us/.axiom/config.yml")
            self.assert_pass(fixture.run(fixture.head()))

    def test_axiom_inside_module_root_is_still_guarded(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/.axiom/bare.yaml")
            self.assert_fail(fixture.run(fixture.head()))

    def test_caller_edit_alone_passes(self):
        with Fixture() as fixture:
            fixture.write(".github/workflows/encoder-guard.yml", "name: candidate edit\n")
            self.assert_pass(fixture.run(fixture.head()))

    def test_caller_and_shared_guard_edits_cannot_disable_base_code(self):
        with Fixture() as fixture:
            fixture.write(".github/workflows/encoder-guard.yml", "name: Disabled\non: pull_request\njobs: {}\n")
            fixture.write(".github/workflows/trusted-guard.yml", "name: Disabled\non: workflow_call\njobs: {}\n")
            fixture.write("us/statutes/bare.yaml")
            head = fixture.head()
            self.assertIn("Disabled", git(fixture.root, "show", f"{head}:.github/workflows/encoder-guard.yml"))
            self.assertEqual((fixture.root / ".github/workflows/encoder-guard.yml").read_text(), CALLER.read_text())
            result = fixture.run(head)
            self.assert_fail(result)
            self.assertIn("Missing encoder apply manifests: 1", result.stderr)

    def test_head_scripts_and_configs_are_never_executed(self):
        with Fixture() as fixture:
            malicious = "raise RuntimeError('candidate code must never execute')\n"
            fixture.write("sitecustomize.py", malicious)
            fixture.write("os.py", malicious)
            fixture.write(".gitattributes", "*.yaml diff=candidate filter=candidate\n")
            fixture.write("Makefile", "all:\n\ttouch executed-candidate\n")
            fixture.write("us/statutes/item.yaml", malicious)
            fixture.manifest(".axiom/encoding-manifests/us/statutes/item.json")
            head = fixture.head()
            self.assert_pass(fixture.run(head))
            self.assertFalse((fixture.root / "executed-candidate").exists())
            self.assertEqual(git(fixture.root, "rev-parse", "HEAD"), fixture.base)
            self.assertEqual(git(fixture.root, "status", "--porcelain"), "")

    def test_three_dot_diff_ignores_base_only_module_changes(self):
        with Fixture({"us/statutes/legacy.yaml": "fixture: ancestor\n"}) as fixture:
            fixture.write("README.md", "fixture: candidate docs\n")
            head = fixture.head()
            fixture.write("us/statutes/legacy.yaml", "fixture: base advancement\n")
            advanced_base = fixture.commit("Advance base only")
            self.assertIn("us/statutes/legacy.yaml", git(fixture.root, "diff", "--name-only", advanced_base, head))
            self.assert_pass(fixture.run(head, base=advanced_base))

    def test_rename_destination_needs_its_own_manifest(self):
        initial = {"us/statutes/old.yaml": "fixture: base\n", ".axiom/encoding-manifests/us/statutes/old.json": "{}\n"}
        for add_manifest in (False, True):
            with self.subTest(add_manifest=add_manifest), Fixture(initial) as fixture:
                git(fixture.root, "mv", "us/statutes/old.yaml", "us/statutes/new.yaml")
                if add_manifest:
                    fixture.manifest(".axiom/encoding-manifests/us/statutes/new.json")
                result = fixture.run(fixture.head())
                (self.assert_pass if add_manifest else self.assert_fail)(result)

    def test_deleted_module_is_not_a_changed_module_to_encode(self):
        with Fixture({"us/statutes/removed.yaml": "fixture: base\n"}) as fixture:
            (fixture.root / "us/statutes/removed.yaml").unlink()
            self.assert_pass(fixture.run(fixture.head()))

    def test_top_level_yml_module_has_extension_stripped_for_manifest(self):
        with Fixture() as fixture:
            fixture.write("regulations/item.yml")
            fixture.manifest(".axiom/encoding-manifests/regulations/item.json")
            self.assert_pass(fixture.run(fixture.head()))

    def test_top_level_nested_module_root_does_not_gain_jurisdiction_mirror_layouts(self):
        for manifest, passes in (
            (".axiom/encoding-manifests/programs/item.json", False),
            (".axiom/encoding-manifests/statutes/programs/item.json", True),
        ):
            with self.subTest(manifest=manifest), Fixture() as fixture:
                fixture.write("statutes/programs/item.yaml")
                fixture.manifest(manifest)
                result = fixture.run(fixture.head())
                (self.assert_pass if passes else self.assert_fail)(result)

    def test_hyphenated_jurisdiction_is_guarded(self):
        with Fixture() as fixture:
            fixture.write("us-ca/policies/bare.yaml")
            self.assert_fail(fixture.run(fixture.head()))

    def test_symlink_manifest_does_not_count(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/item.yaml")
            destination = fixture.root / ".axiom/encoding-manifests/us/statutes/item.json"
            destination.parent.mkdir(parents=True)
            destination.symlink_to("../../../../README.md")
            self.assert_fail(fixture.run(fixture.head()))

    def test_manifest_directory_does_not_count(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/item.yaml")
            fixture.write(".axiom/encoding-manifests/us/statutes/item.json/nested.json", "{}\n")
            self.assert_fail(fixture.run(fixture.head()))

    def test_executable_regular_manifest_blob_counts(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/item.yaml")
            fixture.manifest(".axiom/encoding-manifests/us/statutes/item.json").chmod(0o755)
            self.assert_pass(fixture.run(fixture.head()))

    def test_unrelated_manifest_does_not_cover_module(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/item.yaml")
            fixture.manifest(".axiom/encoding-manifests/us/statutes/other.json")
            self.assert_fail(fixture.run(fixture.head()))

    def test_manifest_deleted_in_head_does_not_count(self):
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({manifest: "{}\n"}) as fixture:
            fixture.write("us/statutes/item.yaml")
            (fixture.root / manifest).unlink()
            self.assert_fail(fixture.run(fixture.head()))

    def test_untracked_manifest_in_base_worktree_does_not_count(self):
        with Fixture() as fixture:
            fixture.write("us/statutes/item.yaml")
            head = fixture.head()
            fixture.manifest(".axiom/encoding-manifests/us/statutes/item.json")
            self.assert_fail(fixture.run(head))

    def test_tab_newline_unicode_and_shell_characters_in_paths_remain_data(self):
        path = 'us/statutes/odd\tquote"\n$(touch executed-candidate)-é.yaml'
        for add_manifest in (False, True):
            with self.subTest(add_manifest=add_manifest), Fixture() as fixture:
                fixture.write(path)
                if add_manifest:
                    fixture.manifest(".axiom/encoding-manifests/" + path[:-5] + ".json")
                result = fixture.run(fixture.head())
                (self.assert_pass if add_manifest else self.assert_fail)(result)
                self.assertFalse((fixture.root / "executed-candidate").exists())

    def test_malformed_and_nonexistent_commit_shas_fail_closed(self):
        with Fixture() as fixture:
            fixture.write("README.md", "fixture: candidate docs\n")
            head = fixture.head()
            for invalid in ("", "main", "a" * 39, "A" * 40, "a" * 40 + "\n", "a" * 40 + ";touch executed-candidate", "0" * 40):
                for side in ("base", "head"):
                    with self.subTest(invalid=invalid, side=side):
                        result = fixture.run(head, base=invalid) if side == "base" else fixture.run(invalid)
                        self.assert_fail(result)
            self.assertFalse((fixture.root / "executed-candidate").exists())

    def test_empty_diff_passes(self):
        with Fixture() as fixture:
            self.assert_pass(fixture.run(fixture.base))


class WorkflowSecurityTests(unittest.TestCase):
    def test_reusable_workflow_has_read_only_permissions_no_secrets_or_opt_out(self):
        workflow = document(WORKFLOW)
        self.assertEqual(events(workflow), {"workflow_call": None})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), {"guard"})
        job = workflow["jobs"]["guard"]
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("if", job)
        self.assertNotIn("secrets.", json.dumps(workflow))
        self.assertNotIn("secrets: inherit", WORKFLOW.read_text())
        for item in job["steps"]:
            self.assertNotIn("if", item)
            if "uses" in item:
                self.assertRegex(item["uses"], r"^[^@]+@[0-9a-f]{40}$")

    def test_checkout_uses_validated_base_only_without_credentials_submodules_or_lfs(self):
        workflow = document(WORKFLOW)
        steps = workflow["jobs"]["guard"]["steps"]
        checkout = [item for item in steps if item.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(len(checkout), 1)
        settings = checkout[0]["with"]
        self.assertEqual(settings["ref"], "${{ steps.revisions.outputs.base-sha }}")
        self.assertEqual(settings["fetch-depth"], 0)
        self.assertIs(settings["persist-credentials"], False)
        self.assertIs(settings["submodules"], False)
        self.assertIs(settings["lfs"], False)
        self.assertEqual(steps[0]["name"], REVISION_STEP)

    def test_head_is_only_fetched_and_guard_uses_isolated_standard_library_python(self):
        workflow = document(WORKFLOW)
        fetch = step(workflow, "Fetch the head commit as Git objects only")
        self.assertIn('fetch --no-tags --no-recurse-submodules origin "$HEAD_SHA"', fetch["run"])
        self.assertEqual(fetch["env"]["HEAD_SHA"], "${{ steps.revisions.outputs.head-sha }}")
        guard = step(workflow, GUARD_STEP)
        self.assertEqual(guard["env"], {
            "BASE_SHA": "${{ steps.revisions.outputs.base-sha }}",
            "HEAD_SHA": "${{ steps.revisions.outputs.head-sha }}",
        })
        imports = re.findall(r"^import (\w+)$", source(workflow), re.MULTILINE)
        self.assertEqual(set(imports), {"os", "re", "subprocess", "sys"})
        for item in workflow["jobs"]["guard"]["steps"]:
            shell = item.get("run", "")
            self.assertNotRegex(shell, r"\bgit\s+(?:checkout|switch|worktree)\b")
            self.assertNotRegex(shell, r"\b(?:pip|npm|make|uv|eval|exec)\s")
            self.assertNotIn("shell=True", shell)
        self.assertIn('"--no-ext-diff"', source(workflow))
        self.assertIn('"--no-textconv"', source(workflow))

    def test_revision_resolution_reads_event_base_and_head_and_rejects_other_events(self):
        workflow = document(WORKFLOW)
        resolver = source(workflow, REVISION_STEP)
        with tempfile.TemporaryDirectory(prefix=".encoder-guard-fixture-", dir=ROOT / "tests") as directory:
            root = Path(directory)
            payload = root / "event.json"
            output = root / "outputs"
            revisions = {"base": "a" * 40, "head": "b" * 40}
            payload.write_text(json.dumps({"pull_request": {side: {"sha": sha} for side, sha in revisions.items()}}))
            env = {**os.environ, "EVENT_NAME": "pull_request_target", "GITHUB_EVENT_PATH": str(payload), "GITHUB_OUTPUT": str(output)}
            result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), "base-sha=" + revisions["base"] + "\nhead-sha=" + revisions["head"] + "\n")
            for event in ("pull_request", "workflow_dispatch", "push"):
                with self.subTest(event=event):
                    output.unlink(missing_ok=True)
                    result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env={**env, "EVENT_NAME": event}, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
            for side in ("base", "head"):
                with self.subTest(side=side):
                    output.unlink(missing_ok=True)
                    invalid = {other: {"sha": "main" if other == side else sha} for other, sha in revisions.items()}
                    payload.write_text(json.dumps({"pull_request": invalid}))
                    result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_caller_is_unfiltered_base_anchored_and_declares_exact_context(self):
        caller = document(CALLER)
        self.assertEqual(events(caller), {"pull_request_target": {"types": ["opened", "synchronize", "reopened", "ready_for_review"]}})
        self.assertEqual(caller["permissions"], {"contents": "read"})
        self.assertEqual(set(caller["jobs"]), {"encoder-guard"})
        job = caller["jobs"]["encoder-guard"]
        self.assertEqual(set(job), {"uses"})
        self.assertRegex(job["uses"], r"^TheAxiomFoundation/\.github/\.github/workflows/encoder-guard\.yml@[0-9a-f]{40}$")
        # The unreleased template deliberately fails closed until a real SHA exists.
        self.assertEqual(job["uses"].split("@", 1)[1], "0" * 40)
        self.assertEqual(document(WORKFLOW)["jobs"]["guard"]["name"], "guard")


if __name__ == "__main__":
    run = unittest.main(exit=False)
    print(f"Git fixture guard evaluations: {GUARD_EVALUATIONS}")
    raise SystemExit(not run.result.wasSuccessful())
