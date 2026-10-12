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

    def run(self, head: str, *, base: str | None = None, merge: str = "", event: str = "pull_request") -> subprocess.CompletedProcess[str]:
        global GUARD_EVALUATIONS
        GUARD_EVALUATIONS += 1
        # Extract executable code from BASE, never from the candidate tree.
        trusted = yaml.safe_load(git(self.root, "show", f"{self.base}:.github/workflows/trusted-guard.yml"))
        return subprocess.run(
            [sys.executable, "-I", "-c", source(trusted)], cwd=self.root,
            env={**os.environ, "BASE_SHA": self.base if base is None else base, "HEAD_SHA": head, "MERGE_SHA": merge, "EVENT_NAME": event},
            capture_output=True, text=True,
        )


class GuardDecisionTests(unittest.TestCase):
    def assert_pass(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_fail(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_module_root_requires_a_manifest_with_and_without_jurisdiction(self):
        for root in ("statutes", "regulations", "policies", "legislation"):
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

    def test_shape_checked_programspecs_keep_default_validator_contract(self):
        validator = document(ROOT / ".github/workflows/validate-rulespec.yml")
        precheck = next(
            item for job in validator["jobs"].values() for item in job.get("steps", [])
            if item.get("name") == "Reject unmanifested RuleSpec content"
        )["run"]
        initial = {
            "statutes/7/2014/a.yaml": "format: rulespec/v1\nrules: []\n",
            "us-xx/policies/manual/page-1.yaml": "format: rulespec/v1\nrules: []\n",
        }
        program = (
            "program: us-xx/tanf\nperiod: 2026-01\noutputs:\n  - eligible\n"
            "scope:\n  federal:\n    - us:statutes/7/2014/a\n"
            "  state:\n    - us-xx:policies/manual/page-1\n"
            "transformations:\n  - pattern: derived_formula\n    name: eligible\n"
            "    effective_from: '2026-01-01'\n    formula: imported_eligible\n"
        )
        for path in ("programs/us-xx/tanf/fy-2026.yaml", "us-xx/programs/tanf/fy-2026.yaml"):
            with self.subTest(path=path), Fixture(initial) as fixture:
                fixture.write(path, program)
                head = fixture.head()
                git(fixture.root, "checkout", "--detach", "-q", head)
                result = subprocess.run(
                    ["bash", "-c", precheck], cwd=fixture.root,
                    env={**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
                         "BASE_SHA": fixture.base, "GITHUB_SHA": head,
                         "GITHUB_REPOSITORY": "TheAxiomFoundation/rulespec-us", "EVENT_NAME": "pull_request",
                         "RUN_GENERATED_GUARD": "true", "GUARD_PROGRAMS_ROOT": "false"},
                    capture_output=True, text=True,
                )
                self.assert_pass(result)
                self.assertIn("1 changed ProgramSpec file(s) have the ProgramSpec shape", result.stdout)
                self.assertIn("No guarded RuleSpec content in scope", result.stdout)
                git(fixture.root, "checkout", "--detach", "-q", fixture.base)
                self.assert_pass(fixture.run(head))

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

    def test_base_advance_cannot_remove_candidate_manifest_from_merge_result(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        for removal in ("delete", "rename", "symlink"):
            with self.subTest(removal=removal), Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
                fixture.write(module, "fixture: candidate\n")
                head = fixture.head()
                self.assert_pass(fixture.run(head))
                if removal == "rename":
                    git(fixture.root, "mv", manifest, ".axiom/encoding-manifests/archive.json")
                else:
                    (fixture.root / manifest).unlink()
                    if removal == "symlink":
                        (fixture.root / manifest).symlink_to("../../../../README.md")
                advanced = fixture.commit("Base removes manifest")
                tree = git(fixture.root, "merge-tree", "--write-tree", advanced, head)
                self.assertIn(module, git(fixture.root, "ls-tree", "-r", "--name-only", tree))
                entry = git(fixture.root, "ls-tree", tree, "--", manifest)
                self.assertFalse(entry.startswith("100644 blob"))
                result = fixture.run(head, base=advanced)
                self.assert_fail(result)
                self.assertIn("Missing encoder apply manifests: 1", result.stderr)

    def test_manifest_removal_alone_is_rejected_for_every_mirror_layout(self):
        module = "us/statutes/item.yaml"
        for manifest in (
            ".axiom/encoding-manifests/us/statutes/item.json",
            ".axiom/encoding-manifests/statutes/item.json",
            "us/.axiom/encoding-manifests/statutes/item.json",
        ):
            for removal in ("delete", "rename", "symlink"):
                with self.subTest(manifest=manifest, removal=removal), Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
                    if removal == "rename":
                        git(fixture.root, "mv", manifest, "archived-manifest.json")
                    else:
                        (fixture.root / manifest).unlink()
                        if removal == "symlink":
                            (fixture.root / manifest).symlink_to("../../../../README.md")
                    self.assert_fail(fixture.run(fixture.head()))

    def test_removing_one_of_multiple_mirrors_still_requires_retirement(self):
        module = "us/statutes/item.yaml"
        short = ".axiom/encoding-manifests/statutes/item.json"
        full = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "fixture: base\n", short: "{}\n", full: "{}\n"}) as fixture:
            (fixture.root / full).unlink()
            self.assert_fail(fixture.run(fixture.head()))

    def test_base_side_rename_does_not_hide_modified_merge_destination(self):
        module = "us/statutes/item.yaml"
        destination = "statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            fixture.write(module, "fixture: candidate\n")
            head = fixture.head()
            (fixture.root / destination).parent.mkdir(parents=True, exist_ok=True)
            git(fixture.root, "mv", module, destination)
            (fixture.root / manifest).unlink()
            advanced = fixture.commit("Base relocates module and removes manifest")
            tree = git(fixture.root, "merge-tree", "--write-tree", advanced, head)
            self.assertEqual(git(fixture.root, "show", f"{tree}:{destination}"), "fixture: candidate")
            self.assert_fail(fixture.run(head, base=advanced))

    def test_base_rename_does_not_allow_retiring_only_the_old_filename(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            fixture.write(module, "fixture: candidate\n")
            (fixture.root / manifest).unlink()
            fixture.write(".axiom/encoding-manifests/apply-receipt.json", json.dumps({"applied_files": [{"path": module, "sha256": "deleted"}]}))
            head = fixture.head()
            (fixture.root / "statutes").mkdir(exist_ok=True)
            git(fixture.root, "mv", module, "statutes/item.yaml")
            advanced = fixture.commit("Base relocates module with shared mirror")
            # The base rename itself preserves a valid mirror.
            self.assert_pass(fixture.run(advanced))
            self.assert_fail(fixture.run(head, base=advanced))

    def test_removed_manifest_needs_same_change_retirement_receipt_when_module_deleted(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        receipt = ".axiom/encoding-manifests/apply-receipt.json"
        deletion = json.dumps({"applied_files": [{"path": module, "sha256": "deleted"}]})
        for kind in ("absent", "unchanged", "wrong-module", "malformed", "symlink", "valid"):
            initial = {module: "fixture: base\n", manifest: "{}\n"}
            if kind == "unchanged":
                initial[receipt] = deletion
            with self.subTest(receipt=kind), Fixture(initial) as fixture:
                (fixture.root / module).unlink()
                (fixture.root / manifest).unlink()
                if kind in ("valid", "symlink"):
                    fixture.write(receipt, deletion)
                    if kind == "symlink":
                        fixture.write("receipt-data.json", deletion)
                        (fixture.root / receipt).unlink()
                        (fixture.root / receipt).symlink_to("../../receipt-data.json")
                elif kind == "wrong-module":
                    fixture.write(receipt, json.dumps({"applied_files": [{"path": "us/statutes/other.yaml", "sha256": "deleted"}]}))
                elif kind == "malformed":
                    fixture.write(receipt, "{invalid")
                result = fixture.run(fixture.head())
                (self.assert_pass if kind == "valid" else self.assert_fail)(result)

    def test_retirement_receipt_cannot_excuse_a_surviving_module(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            (fixture.root / manifest).unlink()
            fixture.write(".axiom/encoding-manifests/apply-receipt.json", json.dumps({"applied_files": [{"path": module, "sha256": "deleted"}]}))
            self.assert_fail(fixture.run(fixture.head()))

    def test_event_merge_commit_is_evaluated_and_bound_to_exact_base_and_head(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            fixture.write(module, "fixture: head\n")
            head = fixture.head()
            (fixture.root / manifest).unlink()
            advanced = fixture.commit("Remove manifest on base")
            tree = git(fixture.root, "merge-tree", "--write-tree", advanced, head)
            merge = git(fixture.root, "commit-tree", tree, "-p", advanced, "-p", head, "-m", "Event test merge")
            self.assert_fail(fixture.run(head, base=advanced, merge=merge))
            # A stale event merge still has a regular manifest but wrong base.
            stale = git(fixture.root, "commit-tree", f"{head}^{{tree}}", "-p", fixture.base, "-p", head, "-m", "Stale test merge")
            self.assert_pass(fixture.run(head, merge=stale))
            self.assert_fail(fixture.run(head, base=advanced, merge=stale))
            self.assert_fail(fixture.run(head, merge="not-a-sha"))

    def test_jurisdiction_retirement_receipt_uses_relative_module_path(self):
        module = "us/statutes/item.yaml"
        manifest = "us/.axiom/encoding-manifests/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            (fixture.root / module).unlink()
            (fixture.root / manifest).unlink()
            fixture.write("us/.axiom/encoding-manifests/apply-receipt.json", json.dumps({"applied_files": [{"path": "statutes/item.yaml", "sha256": "deleted"}]}))
            self.assert_pass(fixture.run(fixture.head()))

    def test_conflicting_merge_fails_closed_even_when_head_has_manifest(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n", ".gitattributes": "*.yaml merge=candidate\n"}) as fixture:
            git(fixture.root, "config", "merge.candidate.driver", "touch executed-candidate")
            fixture.write(module, "fixture: head\n")
            head = fixture.head()
            fixture.write(module, "fixture: advanced-base\n")
            advanced = fixture.commit("Conflicting base change")
            self.assert_fail(fixture.run(head, base=advanced))
            self.assertFalse((fixture.root / "executed-candidate").exists())

    def test_object_merge_combines_clean_edits_without_running_merge_drivers(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "first: base\n\n\nlast: base\n", manifest: "{}\n", ".gitattributes": "*.yaml merge=candidate\n"}) as fixture:
            git(fixture.root, "config", "merge.candidate.driver", "touch executed-candidate")
            fixture.write(module, "first: head\n\n\nlast: base\n")
            head = fixture.head()
            fixture.write(module, "first: base\n\n\nlast: advanced\n")
            advanced = fixture.commit("Clean base edit")
            before = git(fixture.root, "status", "--porcelain")
            self.assert_pass(fixture.run(head, base=advanced))
            self.assertFalse((fixture.root / "executed-candidate").exists())
            self.assertEqual(git(fixture.root, "status", "--porcelain"), before)
            self.assertEqual(git(fixture.root, "rev-parse", "HEAD"), advanced)

    def test_merge_group_evaluates_its_actual_head_and_rejects_an_older_base(self):
        module = "us/statutes/item.yaml"
        manifest = ".axiom/encoding-manifests/us/statutes/item.json"
        with Fixture({module: "fixture: base\n", manifest: "{}\n"}) as fixture:
            fixture.write(module, "fixture: group\n")
            head = fixture.head()
            self.assert_pass(fixture.run(head, event="merge_group"))
            (fixture.root / manifest).unlink()
            advanced = fixture.commit("Base advances outside group")
            self.assert_fail(fixture.run(head, base=advanced, event="merge_group"))


class ValidationPinTests(unittest.TestCase):
    """A candidate cannot choose validation pins for content in the same change."""

    assert_pass = GuardDecisionTests.assert_pass
    assert_fail = GuardDecisionTests.assert_fail
    TOOLCHAIN = ".axiom/workflow-toolchain.toml"
    VALIDATION_CALLER = ".github/workflows/repository-checks.yml"
    BASE_PIN = "8" * 40
    LOWER_PIN = "1" * 40
    HIGHER_PIN = "e" * 40

    @staticmethod
    def toolchain(encoder: str, **changes: str) -> str:
        pins = {
            "axiom_encode_version": "0.1.0",
            "axiom_encode_ref": encoder,
            "axiom_compose_ref": "2" * 40,
            "axiom_rules_engine_ref": "3" * 40,
            "axiom_artifact_rules_engine_ref": "4" * 40,
            "source_staleness_axiom_encode_ref": "5" * 40,
            "axiom_corpus_ref": "6" * 40,
            "rulespec_us_ref": "7" * 40,
        }
        pins.update(changes)
        return "[workflow_toolchain]\n" + "".join(f'{key} = "{value}"\n' for key, value in pins.items())

    @staticmethod
    def caller(encoder: str, validator: str = "a" * 40) -> str:
        return (
            "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
            f"    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@{validator}\n"
            f"    with:\n      axiom-encode-ref: {encoder}\n"
        )

    def initial(self, *, literal: bool = False) -> dict[str, str]:
        return {
            self.TOOLCHAIN: self.toolchain(self.BASE_PIN),
            self.VALIDATION_CALLER: self.caller(
                self.BASE_PIN if literal else "${{ needs.toolchain.outputs.axiom_encode_ref }}"
            ),
        }

    def module(self, fixture: Fixture, path: str = "us/statutes/item.yaml") -> None:
        fixture.write(path, "fixture: candidate module\n")
        fixture.manifest(".axiom/encoding-manifests/" + path.rsplit(".", 1)[0] + ".json")

    def assert_isolated(self, result) -> None:
        self.assert_fail(result)
        self.assertIn("pin changes must be their own pull request", result.stderr.lower())

    def test_lowered_pin_with_every_atomic_root_is_rejected_for_supported_events(self):
        cases = (
            ("statutes", "pull_request"),
            ("regulations", "pull_request_target"),
            ("policies", "merge_group"),
            ("legislation", "pull_request"),
            ("programs", "pull_request"),
        )
        for root, event in cases:
            with self.subTest(root=root, event=event), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, self.toolchain(self.LOWER_PIN))
                self.module(fixture, f"us/{root}/item.yaml")
                self.assert_isolated(fixture.run(fixture.head(), event=event))

    def test_raised_pin_with_manifest_change_is_rejected_in_both_root_layouts(self):
        for path in (
            ".axiom/encoding-manifests/statutes/item.json",
            "us/.axiom/encoding-manifests/statutes/item.json",
        ):
            with self.subTest(path=path), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, self.toolchain(self.HIGHER_PIN))
                fixture.manifest(path)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_pin_only_changes_pass_with_toolchain_and_literal_fallback(self):
        for source_path in (self.TOOLCHAIN, self.VALIDATION_CALLER):
            initial = self.initial() if source_path == self.TOOLCHAIN else {
                self.VALIDATION_CALLER: self.caller(self.BASE_PIN)
            }
            with self.subTest(source_path=source_path), Fixture(initial) as fixture:
                content = self.toolchain(self.HIGHER_PIN) if source_path == self.TOOLCHAIN else self.caller(self.HIGHER_PIN)
                fixture.write(source_path, content)
                self.assert_pass(fixture.run(fixture.head()))

    def test_unchanged_pin_with_module_or_programspec_passes(self):
        for path in ("us/statutes/item.yaml", "us/programs/item.yaml"):
            with self.subTest(path=path), Fixture(self.initial()) as fixture:
                self.module(fixture, path)
                self.assert_pass(fixture.run(fixture.head()))

    def test_workflow_literal_pin_change_with_module_is_rejected_for_both_extensions(self):
        for path in (self.VALIDATION_CALLER, self.VALIDATION_CALLER.removesuffix(".yml") + ".yaml"):
            with self.subTest(path=path), Fixture({path: self.caller(self.BASE_PIN)}) as fixture:
                fixture.write(path, self.caller(self.LOWER_PIN))
                self.module(fixture)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_base_without_toolchain_uses_unchanged_workflow_literal(self):
        with Fixture({self.VALIDATION_CALLER: self.caller(self.BASE_PIN)}) as fixture:
            self.module(fixture)
            self.assert_pass(fixture.run(fixture.head()))

    def test_other_validation_pin_and_version_changes_with_module_are_rejected(self):
        for key, value in (("source_staleness_axiom_encode_ref", "f" * 40), ("axiom_encode_version", "0.2.0")):
            with self.subTest(key=key), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, self.toolchain(self.BASE_PIN, **{key: value}))
                self.module(fixture)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_validation_workflow_call_change_or_removal_with_module_is_rejected(self):
        for change in ("replace", "remove"):
            with self.subTest(change=change), Fixture(self.initial(literal=True)) as fixture:
                if change == "remove":
                    (fixture.root / self.VALIDATION_CALLER).unlink()
                else:
                    fixture.write(self.VALIDATION_CALLER, self.caller(self.BASE_PIN, validator="b" * 40))
                self.module(fixture)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_malformed_toml_in_base_or_merge_fails_closed(self):
        malformed = "[workflow_toolchain\naxiom_encode_ref = invalid\n"
        for side in ("base", "merge"):
            initial = self.initial()
            if side == "base":
                initial[self.TOOLCHAIN] = malformed
            with self.subTest(side=side), Fixture(initial) as fixture:
                fixture.write("README.md", "Fixture documentation change.\n")
                if side == "merge":
                    fixture.write(self.TOOLCHAIN, malformed)
                self.assert_fail(fixture.run(fixture.head()))

    def test_invalid_candidate_toolchain_pin_schema_fails_closed(self):
        invalid = (
            "[workflow_toolchain]\n",
            "[workflow_toolchain]\naxiom_encode_ref = 8\n",
            '[workflow_toolchain]\naxiom_encode_ref = "' + "8" * 39 + '"\n',
        )
        for content in invalid:
            with self.subTest(content=content), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, content)
                self.assert_fail(fixture.run(fixture.head()))

    def test_candidate_symlink_toolchain_fails_closed(self):
        with Fixture(self.initial()) as fixture:
            fixture.write("pin-data.toml", self.toolchain(self.BASE_PIN))
            (fixture.root / self.TOOLCHAIN).unlink()
            (fixture.root / self.TOOLCHAIN).symlink_to("../pin-data.toml")
            self.assert_fail(fixture.run(fixture.head()))

    def test_advanced_base_pin_is_compared_with_merged_tree_instead_of_candidate_head(self):
        initial = self.initial()
        initial.update({
            "us/statutes/item.yaml": "fixture: base module\n",
            ".axiom/encoding-manifests/us/statutes/item.json": "{}\n",
        })
        with Fixture(initial) as fixture:
            fixture.write("us/statutes/item.yaml", "fixture: candidate module\n")
            head = fixture.head()
            fixture.write(self.TOOLCHAIN, self.toolchain(self.HIGHER_PIN))
            advanced = fixture.commit("Advance protected base validation pin")
            tree = git(fixture.root, "merge-tree", "--write-tree", advanced, head)
            self.assertEqual(git(fixture.root, "show", f"{head}:{self.TOOLCHAIN}"), self.toolchain(self.BASE_PIN).strip())
            self.assertEqual(git(fixture.root, "show", f"{tree}:{self.TOOLCHAIN}"), self.toolchain(self.HIGHER_PIN).strip())
            self.assert_pass(fixture.run(head, base=advanced))
            merge = git(fixture.root, "commit-tree", tree, "-p", advanced, "-p", head, "-m", "Event test merge")
            self.assert_pass(fixture.run(head, base=advanced, merge=merge))

    def test_toolchain_addition_or_removal_with_module_cannot_bypass_isolation(self):
        for change in ("add", "remove"):
            initial = self.initial(literal=True)
            if change == "add":
                del initial[self.TOOLCHAIN]
            with self.subTest(change=change), Fixture(initial) as fixture:
                if change == "remove":
                    (fixture.root / self.TOOLCHAIN).unlink()
                else:
                    fixture.write(self.TOOLCHAIN, self.toolchain(self.BASE_PIN))
                self.module(fixture)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_pin_changes_with_other_provenance_receipts_are_rejected(self):
        for path in (
            ".axiom/receipts/apply.json",
            "us/.axiom/provenance/receipt.json",
            "known-validation-gaps.yaml",
        ):
            with self.subTest(path=path), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, self.toolchain(self.HIGHER_PIN))
                fixture.write(path, "{}\n")
                self.assert_isolated(fixture.run(fixture.head()))

    def test_pin_change_with_atomic_module_deletion_is_rejected(self):
        initial = self.initial()
        initial.update({
            "us/statutes/item.yaml": "fixture: base module\n",
            ".axiom/encoding-manifests/us/statutes/item.json": "{}\n",
        })
        with Fixture(initial) as fixture:
            fixture.write(self.TOOLCHAIN, self.toolchain(self.LOWER_PIN))
            (fixture.root / "us/statutes/item.yaml").unlink()
            self.assert_isolated(fixture.run(fixture.head()))

    def test_pin_isolation_includes_companions_and_composed_paths(self):
        for path in ("us/statutes/item.test.yaml", "us/policies/composed/item.yaml"):
            with self.subTest(path=path), Fixture(self.initial()) as fixture:
                fixture.write(self.TOOLCHAIN, self.toolchain(self.LOWER_PIN))
                fixture.write(path)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_canonical_caller_cannot_be_renamed_out_of_protection_even_without_content(self):
        with Fixture({self.VALIDATION_CALLER: self.caller(self.BASE_PIN)}) as fixture:
            git(fixture.root, "mv", self.VALIDATION_CALLER, ".github/workflows/validate.yml")
            self.assert_fail(fixture.run(fixture.head()))

    def test_two_pr_rename_cannot_restore_initialization_compatibility(self):
        # Simulate the first rename having landed under an earlier guard. The
        # second PR must fail even though both canonical snapshots are empty.
        module = "us/statutes/item.yaml"
        initial = {
            self.VALIDATION_CALLER: self.caller(self.BASE_PIN),
            module: "fixture: protected module\n",
            ".axiom/encoding-manifests/us/statutes/item.json": "{}\n",
        }
        with Fixture(initial) as fixture:
            renamed = ".github/workflows/validate.yml"
            git(fixture.root, "mv", self.VALIDATION_CALLER, renamed)
            first = fixture.commit("Move validation caller")
            fixture.base = first
            fixture.write(renamed, self.caller(self.LOWER_PIN))
            fixture.write(module, "fixture: changed module\n")
            head = fixture.head()
            for revision in (first, head):
                for path in (self.VALIDATION_CALLER, self.TOOLCHAIN):
                    self.assertEqual(git(fixture.root, "ls-tree", revision, "--", path), "")
            self.assert_fail(fixture.run(head))

    def test_missing_historical_caller_fails_even_when_workflows_are_unchanged(self):
        with Fixture({self.VALIDATION_CALLER: self.caller(self.BASE_PIN)}) as fixture:
            (fixture.root / self.VALIDATION_CALLER).unlink()
            fixture.base = fixture.commit("Remove validation caller")
            fixture.write("README.md", "fixture: documentation\n")
            self.assert_fail(fixture.run(fixture.head()))

    def test_established_toml_cannot_be_removed_in_a_configuration_only_pr(self):
        with Fixture(self.initial(literal=True)) as fixture:
            (fixture.root / self.TOOLCHAIN).unlink()
            self.assert_fail(fixture.run(fixture.head()))

    def test_missing_historical_toml_cannot_fall_back_to_literal_caller(self):
        with Fixture(self.initial(literal=True)) as fixture:
            (fixture.root / self.TOOLCHAIN).unlink()
            fixture.base = fixture.commit("Remove validation toolchain")
            self.module(fixture)
            self.assert_fail(fixture.run(fixture.head()))

    def test_additional_validator_caller_is_configuration_even_outside_canonical_paths(self):
        with Fixture(self.initial()) as fixture:
            fixture.write(".github/workflows/additional.yml", self.caller(self.LOWER_PIN))
            self.module(fixture)
            self.assert_isolated(fixture.run(fixture.head()))

    def test_noncanonical_validator_caller_pin_change_cannot_share_content(self):
        caller = ".github/workflows/validate.yaml"
        with Fixture({caller: self.caller(self.BASE_PIN)}) as fixture:
            fixture.write(caller, self.caller(self.LOWER_PIN))
            self.module(fixture)
            self.assert_isolated(fixture.run(fixture.head()))

    def test_helper_workflow_input_defaults_and_env_are_configuration(self):
        helpers = (
            'on:\n  workflow_call:\n    inputs:\n      encoder-ref:\n        type: string\n        default: "PIN"\njobs: {}\n',
            'on: workflow_call\njobs:\n  pins:\n    runs-on: ubuntu-latest\n    env:\n      AXIOM_ENCODE_REF: "PIN"\n    steps: []\n',
        )
        for helper in helpers:
            initial = self.initial()
            initial[".github/workflows/read-pins.yml"] = helper.replace("PIN", self.BASE_PIN)
            with self.subTest(helper=helper), Fixture(initial) as fixture:
                fixture.write(".github/workflows/read-pins.yml", helper.replace("PIN", self.LOWER_PIN))
                self.module(fixture)
                self.assert_isolated(fixture.run(fixture.head()))

    def test_workflow_mode_change_cannot_share_content(self):
        with Fixture(self.initial(literal=True)) as fixture:
            (fixture.root / self.VALIDATION_CALLER).chmod(0o755)
            self.module(fixture)
            self.assert_isolated(fixture.run(fixture.head()))

    def test_protection_includes_source_established_on_merged_base_ancestry(self):
        with Fixture() as fixture:
            fixture.write(self.TOOLCHAIN, self.toolchain(self.BASE_PIN))
            established = fixture.commit("Establish toolchain on merged ancestry")
            original_tree = git(fixture.root, "rev-parse", f"{fixture.base}^{{tree}}")
            base = git(fixture.root, "commit-tree", original_tree, "-p", fixture.base,
                       "-p", established, "-m", "Merge without retaining established toolchain")
            git(fixture.root, "checkout", "--detach", "-q", base)
            fixture.base = base
            self.module(fixture)
            self.assert_fail(fixture.run(fixture.head()))

    def test_shallow_base_history_cannot_claim_initialization(self):
        with Fixture() as fixture:
            self.module(fixture)
            head = fixture.head()
            (fixture.root / ".git/shallow").write_text(fixture.base + "\n")
            self.assert_fail(fixture.run(head))

    def test_canonical_extension_move_and_toml_migration_remain_configuration_only(self):
        for change in ("extension", "toml"):
            with self.subTest(change=change), Fixture({self.VALIDATION_CALLER: self.caller(self.BASE_PIN)}) as fixture:
                if change == "extension":
                    git(fixture.root, "mv", self.VALIDATION_CALLER,
                        self.VALIDATION_CALLER.removesuffix(".yml") + ".yaml")
                else:
                    fixture.write(self.TOOLCHAIN, self.toolchain(self.BASE_PIN))
                    (fixture.root / self.VALIDATION_CALLER).unlink()
                self.assert_pass(fixture.run(fixture.head()))

    def test_never_established_source_preserves_initialization(self):
        with Fixture() as fixture:
            self.module(fixture)
            self.assert_pass(fixture.run(fixture.head()))


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
        fetch = step(workflow, "Fetch candidate and event merge commits as Git objects only")
        self.assertIn('for revision in "$HEAD_SHA" "$MERGE_SHA"', fetch["run"])
        self.assertIn('fetch --no-tags --no-recurse-submodules origin "$revision"', fetch["run"])
        self.assertEqual(fetch["env"]["HEAD_SHA"], "${{ steps.revisions.outputs.head-sha }}")
        self.assertEqual(fetch["env"]["MERGE_SHA"], "${{ steps.revisions.outputs.merge-sha }}")
        guard = step(workflow, GUARD_STEP)
        self.assertEqual(guard["env"], {
            "BASE_SHA": "${{ steps.revisions.outputs.base-sha }}",
            "HEAD_SHA": "${{ steps.revisions.outputs.head-sha }}",
            "MERGE_SHA": "${{ steps.revisions.outputs.merge-sha }}",
            "EVENT_NAME": "${{ github.event_name }}",
        })
        imports = re.findall(r"^import (\w+)$", source(workflow), re.MULTILINE)
        self.assertEqual(set(imports), {"json", "os", "re", "subprocess", "sys", "tempfile", "tomllib"})
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
                    self.assertEqual(output.read_text(), "base-sha=" + revisions["base"] + "\nhead-sha=" + revisions["head"] + "\nmerge-sha=\n")
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

    def test_revision_resolution_uses_optional_event_merge_sha_and_validates_it(self):
        resolver = source(document(WORKFLOW), REVISION_STEP)
        with temporary_fixture_directory() as directory:
            root = Path(directory)
            payload, output = root / "event.json", root / "outputs"
            for event in ("pull_request", "pull_request_target"):
                for merge in ("c" * 40, None, "main", "c" * 39, "C" * 40, "c" * 40 + "\n"):
                    with self.subTest(event=event, merge=merge):
                        output.unlink(missing_ok=True)
                        payload.write_text(json.dumps({"pull_request": {
                            "base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}, "merge_commit_sha": merge,
                        }}))
                        result = subprocess.run(
                            [sys.executable, "-I", "-c", resolver], cwd=root,
                            env={**os.environ, "EVENT_NAME": event, "GITHUB_EVENT_PATH": str(payload), "GITHUB_OUTPUT": str(output)},
                            capture_output=True, text=True,
                        )
                        if merge in ("c" * 40, None):
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(output.read_text(), "base-sha=" + "a" * 40 + "\nhead-sha=" + "b" * 40 + "\nmerge-sha=" + (merge or "") + "\n")
                        else:
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
            self.assertEqual(output.read_text(), f"base-sha={base}\nhead-sha={head}\nmerge-sha=\n")
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
            self.assertEqual(output.read_text(), f"base-sha={fixture.base}\nhead-sha={head}\nmerge-sha=\n")
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
        self.assertIs(rule["parameters"]["do_not_enforce_on_create"], True)
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

    def test_adoption_explicitly_requires_effective_pin_and_full_revalidation_evidence(self):
        text = " ".join((ROOT / "README.md").read_text().split())
        for requirement in ("input default", "environment pin", "pin-only", "unchanged modules",
                            "exact validator SHA", "protected base", "after merge"):
            with self.subTest(requirement=requirement):
                self.assertTrue(requirement.lower() in text.lower(), f"Missing adoption evidence: {requirement}")
        self.assertNotIn("436cf3044", text)
        self.assertNotIn("fabe0b3b", text)
        self.assertNotIn("#1844 admission rule", text)
        self.assertNotIn("supplied by [.github#126]", text)

    def test_adoption_requires_freshness_and_hosted_acceptance_before_enforcement(self):
        text = " ".join((ROOT / "README.md").read_text().split())
        section = text.split("### Base-anchored encoder guard", 1)[1].split("### Run bounds", 1)[0]
        for requirement in (
            "Require branches to be up to date before merging", "every targeted repository",
            "older base", "group head", "ADOPTION CHECKLIST", "caller-free", "sandbox",
            "retarget", "base-advance", "create and update", "GITHUB_TOKEN",
            "do not launch ruleset workflows", "GitHub App installation token",
            "Accessible from repositories", "if: true", "source repository",
            "merge result", "scratch index", "deletes or renames away", "retirement receipt",
            "shape-checked ProgramSpecs", "no manifest is required", "audited revision",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, section)
        self.assertNotIn("no current encoder tool can produce a ProgramSpec manifest", text)
        self.assertNotIn("statutes|regulations|policies|legislation|programs", section)


if __name__ == "__main__":
    run = unittest.main(exit=False)
    print(f"Git fixture guard evaluations: {GUARD_EVALUATIONS}")
    raise SystemExit(not run.result.wasSuccessful())
