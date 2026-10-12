#!/usr/bin/env python3
"""Run the actual base-anchored encoder guard against isolated Git fixtures."""

from __future__ import annotations

import fnmatch
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
RULESET = ROOT / "rulesets/rulespec-encoder-guard.json"
GUARD_STEP = "Reject RuleSpec modules without encoder manifests"
REVISION_STEP = "Resolve immutable event revisions"
GUARD_EVALUATIONS = 0
PR_EVENT_TYPES = ["opened", "synchronize", "reopened", "ready_for_review", "edited"]


def temporary_fixture_directory():
    # Keep Git fixtures outside the checkout; /private/tmp is the local fleet's
    # scratch directory, while hosted Linux runners use their system temp dir.
    parent = "/private/tmp" if Path("/private/tmp").is_dir() else None
    return tempfile.TemporaryDirectory(prefix="hub-.github-125-fixture-", dir=parent)


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
        self.temporary = temporary_fixture_directory()
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
    def test_required_workflow_has_supported_events_read_only_permissions_and_no_opt_out(self):
        workflow = document(WORKFLOW)
        self.assertEqual(events(workflow), {
            "pull_request": {"types": PR_EVENT_TYPES},
            "pull_request_target": {"types": PR_EVENT_TYPES},
            "merge_group": {"types": ["checks_requested"]},
            "workflow_call": None,
        })
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
        self.assertEqual(settings.get("repository"), "${{ github.repository }}")
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
        with temporary_fixture_directory() as directory:
            root = Path(directory)
            payload = root / "event.json"
            output = root / "outputs"
            revisions = {"base": "a" * 40, "head": "b" * 40}
            payload.write_text(json.dumps({"pull_request": {side: {"sha": sha} for side, sha in revisions.items()}}))
            env = {**os.environ, "EVENT_NAME": "pull_request_target", "GITHUB_EVENT_PATH": str(payload), "GITHUB_OUTPUT": str(output)}
            for event in ("pull_request", "pull_request_target"):
                with self.subTest(event=event):
                    output.unlink(missing_ok=True)
                    result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env={**env, "EVENT_NAME": event}, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(), "base-sha=" + revisions["base"] + "\nhead-sha=" + revisions["head"] + "\n")
            for event in ("workflow_dispatch", "push", "workflow_call"):
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

    def test_merge_group_resolution_uses_payload_shas_not_checkout_or_environment_refs(self):
        resolver = source(document(WORKFLOW), REVISION_STEP)
        with temporary_fixture_directory() as directory:
            root = Path(directory)
            payload = root / "event.json"
            output = root / "outputs"
            base, head = "c" * 40, "d" * 40
            event = {
                "action": "checks_requested",
                "merge_group": {"base_sha": base, "head_sha": head, "base_ref": "refs/heads/main", "head_ref": "refs/heads/gh-readonly-queue/main/group"},
                "pull_request": {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}},
            }
            env = {
                **os.environ, "EVENT_NAME": "merge_group", "GITHUB_EVENT_PATH": str(payload),
                "GITHUB_OUTPUT": str(output), "GITHUB_SHA": "e" * 40,
                "GITHUB_BASE_REF": "untrusted-ref", "GITHUB_HEAD_REF": "untrusted-ref",
            }
            payload.write_text(json.dumps(event))
            result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), f"base-sha={base}\nhead-sha={head}\n")
            for side in ("base", "head"):
                with self.subTest(side=side):
                    output.unlink(missing_ok=True)
                    invalid = {**event, "merge_group": {**event["merge_group"], f"{side}_sha": "main"}}
                    payload.write_text(json.dumps(invalid))
                    result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=root, env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_retargeting_is_configured_and_uses_current_base_with_unchanged_head(self):
        for workflow_path, event_name in ((WORKFLOW, "pull_request"), (WORKFLOW, "pull_request_target"), (CALLER, "pull_request_target")):
            with self.subTest(workflow=workflow_path.name, event=event_name):
                self.assertIn("edited", events(document(workflow_path)).get(event_name, {}).get("types", []))
        resolver = source(document(WORKFLOW), REVISION_STEP)
        with Fixture() as fixture:
            fixture.write("us/statutes/retargeted.yaml")
            alternate_base = fixture.commit("Alternate base already has module")
            fixture.write("README.md", "Candidate docs only on alternate base.\n")
            head = fixture.head()
            payload, output = fixture.root / "event.json", fixture.root / "outputs"
            env = {**os.environ, "EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(payload), "GITHUB_OUTPUT": str(output)}
            payload.write_text(json.dumps({
                "action": "edited",
                "changes": {"base": {"ref": {"from": "alternate"}, "sha": {"from": alternate_base}}},
                "pull_request": {"base": {"sha": fixture.base}, "head": {"sha": head}},
            }))
            result = subprocess.run([sys.executable, "-I", "-c", resolver], cwd=fixture.root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), f"base-sha={fixture.base}\nhead-sha={head}\n")
            alternate_result = fixture.run(head, base=alternate_base)
            self.assertEqual(alternate_result.returncode, 0, alternate_result.stdout + alternate_result.stderr)
            self.assertIn("passed for 0 changed module(s)", alternate_result.stdout)
            default_result = fixture.run(head)
            self.assertNotEqual(default_result.returncode, 0)
            self.assertIn("Missing encoder apply manifests: 1 of 1", default_result.stderr)

    def test_optional_visibility_caller_is_unfiltered_base_anchored_and_pinned(self):
        caller = document(CALLER)
        self.assertEqual(events(caller), {"pull_request_target": {"types": PR_EVENT_TYPES}})
        self.assertEqual(caller["permissions"], {"contents": "read"})
        self.assertEqual(set(caller["jobs"]), {"encoder-guard"})
        job = caller["jobs"]["encoder-guard"]
        self.assertEqual(set(job), {"uses"})
        self.assertRegex(job["uses"], r"^TheAxiomFoundation/\.github/\.github/workflows/encoder-guard\.yml@[0-9a-f]{40}$")
        # The unreleased template deliberately fails closed until a real SHA exists.
        self.assertEqual(job["uses"].split("@", 1)[1], "0" * 40)
        self.assertEqual(document(WORKFLOW)["jobs"]["guard"]["name"], "guard")


class RulesetPolicyTests(unittest.TestCase):
    def test_ruleset_is_active_identity_required_and_has_exact_repository_and_branch_scope(self):
        self.assertTrue(RULESET.is_file(), "Required-workflow ruleset must be tracked")
        ruleset = json.loads(RULESET.read_text())
        self.assertEqual(ruleset["target"], "branch")
        self.assertEqual(ruleset["enforcement"], "active")
        self.assertEqual(ruleset["bypass_actors"], [])
        self.assertEqual(ruleset["conditions"], {
            "repository_name": {"include": ["rulespec-*"], "exclude": ["rulespec-graph-viewer"], "protected": False},
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
        })
        names = ruleset["conditions"]["repository_name"]
        for name, included in (
            ("rulespec-us", True), ("rulespec-us-ca", True), ("rulespec-future", True),
            ("rulespec-graph-viewer", False), ("rulespec", False), (".github", False),
            ("prefix-rulespec-us", False),
        ):
            with self.subTest(repository=name):
                selected = any(fnmatch.fnmatchcase(name, pattern) for pattern in names["include"]) and not any(
                    fnmatch.fnmatchcase(name, pattern) for pattern in names["exclude"]
                )
                self.assertEqual(selected, included)
        self.assertEqual(len(ruleset["rules"]), 1)
        rule = ruleset["rules"][0]
        self.assertEqual(rule["type"], "workflows")
        self.assertIs(rule["parameters"]["do_not_enforce_on_create"], False)
        workflows = rule["parameters"]["workflows"]
        self.assertEqual(len(workflows), 1)
        required = workflows[0]
        self.assertEqual(required["repository_id"], 1146671719)
        self.assertEqual(required["path"], ".github/workflows/encoder-guard.yml")
        self.assertRegex(required["sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(required["sha"], "0" * 40)
        self.assertNotIn("ref", required)

    def test_caller_removal_and_counterfeit_job_do_not_replace_required_workflow_identity(self):
        self.assertTrue(RULESET.is_file(), "Caller-independent required workflow policy must exist")
        rule = json.loads(RULESET.read_text())["rules"][0]
        self.assertEqual(rule["type"], "workflows")
        self.assertEqual(rule["parameters"]["workflows"], [{
            "repository_id": 1146671719,
            "path": ".github/workflows/encoder-guard.yml",
            "sha": "0" * 40,
        }])
        with Fixture() as fixture:
            (fixture.root / ".github/workflows/encoder-guard.yml").unlink()
            caller_deleted = fixture.head()
            deletion_result = fixture.run(caller_deleted)
            self.assertEqual(deletion_result.returncode, 0, deletion_result.stdout + deletion_result.stderr)
            self.assertIn("passed for 0 changed module(s)", deletion_result.stdout)
            # Model caller deletion reaching the base before a later candidate.
            git(fixture.root, "checkout", "--detach", "-q", caller_deleted)
            fixture.base = caller_deleted
            git(fixture.root, "checkout", "-qb", "counterfeit-candidate")
            fixture.write("us/statutes/unmanifested.yaml")
            fixture.write(".github/workflows/counterfeit.yml", """name: encoder-guard
on: pull_request
jobs:
  guard:
    name: encoder-guard / guard
    runs-on: ubuntu-latest
    steps:
      - run: exit 0
""")
            head = fixture.head()
            self.assertFalse((fixture.root / ".github/workflows/encoder-guard.yml").exists())
            counterfeit = yaml.safe_load(git(fixture.root, "show", f"{head}:.github/workflows/counterfeit.yml"))
            self.assertEqual(counterfeit["jobs"]["guard"]["name"], "encoder-guard / guard")
            trusted_result = fixture.run(head)
            self.assertNotEqual(trusted_result.returncode, 0)
            self.assertIn("Missing encoder apply manifests: 1 of 1", trusted_result.stderr)

    def test_readme_uses_ruleset_workflow_identity_as_enforcement_point(self):
        section = (ROOT / "README.md").read_text().split("### Base-anchored encoder guard", 1)[1].split("### Run bounds", 1)[0]
        self.assertIn("rulesets/rulespec-encoder-guard.json", section)
        self.assertIn("Require workflows to pass before merging", section)
        self.assertRegex(section.lower(), r"(?:optional|only).{0,100}(?:visibility|local)")
        self.assertNotIn("exact status-check context **`encoder-guard / guard`** in branch protection", section)

    def test_readme_qualifies_program_signatures_and_companion_exemptions(self):
        section = (ROOT / "README.md").read_text().split("### Base-anchored encoder guard", 1)[1].split("### Run bounds", 1)[0]
        text = " ".join(section.split())
        self.assertRegex(text, r"ProgramSpecs? (?:are|is) excluded from (?:its|the) supervised generated guard")
        self.assertRegex(text, r"(?i)ProgramSpec.{0,200}companion.{0,200}(?:checks|covers|includes|applies)")
        self.assertNotIn("the existing supervised validator remains responsible for manifest contents, signatures and module hashes", text)

    def test_readme_drops_unsupported_repository_audit_assertion(self):
        section = (ROOT / "README.md").read_text().split("### Base-anchored encoder guard", 1)[1].split("### Run bounds", 1)[0]
        self.assertNotIn("27 active", section)


if __name__ == "__main__":
    run = unittest.main(exit=False)
    print(f"Git fixture guard evaluations: {GUARD_EVALUATIONS}")
    raise SystemExit(not run.result.wasSuccessful())
