#!/usr/bin/env python3
"""Test curated preservation, offline checks, and the real publication shell."""

from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

import generate_lanes as generator


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/lanes-registry.yml"
CURATED = "<!-- curated:start -->\n## Ownership\n\n- **us** — keep | punctuation and trailing spaces  \n<!-- curated:end -->"


def row(lane: str = "us", date: str = "2026-10-01T12:00:00Z") -> dict:
    return {
        "lane": lane, "repo": f"rulespec-{lane}", "date": date,
        "commit": "2026-10-01 — fix <rule> | table\ncontinued", "prs": "2",
        "release": "us-release", "encoder": "a" * 40, "checks": "success",
    }


def run_bounded(command: list[str], *, cwd: Path, env: dict, timeout: int) -> subprocess.CompletedProcess:
    # Kill fixture descendants too, so a child holding a pipe cannot defeat the bound.
    with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


class GeneratorTests(unittest.TestCase):
    def test_extract_preserves_curated_text_and_discards_generated_surroundings(self):
        self.assertEqual(generator.extract_curated("old board\n" + CURATED + "\nfooter"), CURATED)
        self.assertEqual(generator.extract_curated(CURATED.replace("\n", "\r\n")), CURATED.replace("\n", "\r\n"))

    def test_extract_rejects_missing_duplicate_and_reversed_markers(self):
        for document in (
            "no markers", CURATED.replace(generator.CURATED_START, ""),
            CURATED.replace(generator.CURATED_END, ""), CURATED + CURATED,
            generator.CURATED_END + "\n" + generator.CURATED_START,
        ):
            with self.subTest(document=document), self.assertRaises(ValueError):
                generator.extract_curated(document)

    def test_render_full_board_escapes_cells_and_preserves_curated_section(self):
        rendered = generator.render([row()], CURATED)
        self.assertIn("| Lane | Last main commit | Open PRs | Corpus release | Encoder ref | Repository Checks |", rendered)
        self.assertIn("[us](https://github.com/TheAxiomFoundation/rulespec-us)", rendered)
        self.assertIn("fix &lt;rule&gt; &#124; table continued | 2 | us-release |", rendered)
        self.assertEqual(generator.extract_curated(rendered), CURATED)
        self.assertTrue(rendered.endswith(CURATED + "\n"))

    def invoke(self, source: Path, *args: str) -> int:
        with patch.object(generator, "SOURCE", source), patch.object(sys, "argv", ["generate_lanes.py", *args]):
            return generator.main()

    def test_check_is_offline_and_does_not_compare_live_board_or_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source = Path(directory) / "LANES.md"
            original = generator.render_source(CURATED)
            source.write_text(original)
            with patch.object(generator, "lane_data", side_effect=AssertionError("no network during --check")):
                self.assertEqual(self.invoke(source, "--check"), 0)
            self.assertEqual(source.read_text(), original)
            source.write_text(generator.render_source(CURATED.replace("Ownership", "Updated ownership")))
            self.assertEqual(self.invoke(source, "--check"), 0)

    def test_repository_source_is_curated_only(self):
        with patch.object(generator, "lane_data", side_effect=AssertionError("no network during --check")):
            self.assertEqual(self.invoke(ROOT / "LANES.md", "--check"), 0)

    def test_check_rejects_generated_content_and_invalid_curated_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source = Path(directory) / "LANES.md"
            with contextlib.redirect_stderr(io.StringIO()):
                source.write_text(generator.render([row()], CURATED))
                self.assertEqual(self.invoke(source, "--check"), 1)
                source.write_text("no curated section\n")
                self.assertEqual(self.invoke(source, "--check"), 2)

    def test_output_uses_main_curated_content_and_sorts_live_rows(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, output = Path(directory) / "LANES.md", Path(directory) / "board.md"
            original = generator.render_source(CURATED)
            source.write_text(original)
            with patch.object(generator, "LANES", ("us", "uk")), patch.object(
                generator, "lane_data", side_effect=[row(), row("uk", "2026-10-02T12:00:00Z")]
            ):
                self.assertEqual(self.invoke(source, "--output", str(output)), 0)
            rendered = output.read_text()
            self.assertLess(rendered.index("[uk]"), rendered.index("[us]"))
            self.assertEqual(generator.extract_curated(rendered), CURATED)
            self.assertEqual(source.read_text(), original)

    def test_pending_output_is_offline_and_source_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, output = Path(directory) / "LANES.md", Path(directory) / "board.md"
            source.write_text(generator.render_source(CURATED))
            with patch.object(generator, "lane_data", side_effect=AssertionError("pending is offline")):
                self.assertEqual(self.invoke(source, "--pending", "--output", str(output)), 0)
            self.assertEqual(output.read_text().count("pending first scheduled run"), len(generator.LANES))
            for args in ((), ("--output", str(source)), ("--check", "--output", str(output))):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    self.invoke(source, *args)
                self.assertEqual(error.exception.code, 2)

    def test_hard_linked_output_cannot_overwrite_the_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            source, alias = Path(directory) / "LANES.md", Path(directory) / "alias.md"
            source.write_text(generator.render_source(CURATED))
            original = source.read_bytes()
            os.link(source, alias)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                self.invoke(source, "--pending", "--output", str(alias))
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(source.read_bytes(), original)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        # Fixtures use only local repositories; no real remote is contacted.
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.remote, self.runner = self.root / "checkout", self.root / "origin.git", self.root / "runner temp"
        self.repo.mkdir()
        self.runner.mkdir()
        template = self.root / "empty-template"
        template.mkdir()
        self.git_env = {
            **os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_TEMPLATE_DIR": str(template),
        }
        self.git("init", "-q", "-b", "main")
        self.git("config", "core.hooksPath", "/dev/null")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.com")
        (self.repo / "LANES.md").write_text(generator.render_source(CURATED))
        (self.repo / "README.md").write_text("main's source stays on main\n")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture main")
        self.main_sha = self.git("rev-parse", "HEAD")
        self.git("clone", "--bare", "-q", str(self.repo), str(self.remote))
        self.git("remote", "add", "origin", str(self.remote))
        self.workflow = yaml.safe_load(WORKFLOW.read_text())
        self.job = self.workflow["jobs"]["update"]
        self.publish = next(step for step in self.job["steps"] if step.get("name", "").startswith("Publish registry"))
        self.log = self.root / "pushes.jsonl"
        bin_path = self.root / "bin"
        bin_path.mkdir()
        wrapper = bin_path / "git"
        wrapper.write_text(
            '#!/bin/bash\n'
            'if [[ "$1" == "push" ]]; then printf "%s\\n" "$*" >> "$PUSH_LOG"; fi\n'
            'if [[ "$1" == "ls-remote" && "$FAIL_LOOKUP" == "1" ]]; then exit 128; fi\n'
            'export PATH="$ORIGINAL_PATH"\n'
            'exec "$REAL_GIT" "$@"\n'
        )
        wrapper.chmod(0o755)
        self.env = {
            **self.git_env, **self.job["env"], "RUNNER_TEMP": str(self.runner),
            "PATH": str(bin_path) + os.pathsep + os.environ["PATH"],
            "ORIGINAL_PATH": os.environ["PATH"],
            "REAL_GIT": shutil.which("git"), "PUSH_LOG": str(self.log), "FAIL_LOOKUP": "0",
        }
        (self.runner / "LANES.md").write_text(generator.render([row()], CURATED))

    def git(self, *args: str) -> str:
        result = run_bounded(["git", *args], cwd=self.repo, env=self.git_env, timeout=20)
        result.check_returncode()
        return result.stdout.strip()

    def run_publish(self, **overrides: str) -> subprocess.CompletedProcess:
        return run_bounded(
            ["bash", "-c", self.publish["run"]], cwd=self.repo,
            env={**self.env, **overrides}, timeout=120,
        )

    def test_workflow_reads_main_and_limits_write_permission_to_publication_job(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.job["permissions"], {"contents": "write"})
        self.assertEqual(self.workflow["concurrency"], {"group": "lanes-registry", "cancel-in-progress": False})
        checkout = next(step for step in self.job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "main")

    def test_first_publish_update_and_noop_leave_remote_main_untouched(self):
        first = self.run_publish()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        board_sha = self.git("--git-dir", str(self.remote), "rev-parse", "lanes-registry")
        self.assertEqual(self.git("--git-dir", str(self.remote), "ls-tree", "--name-only", "lanes-registry"), "LANES.md")
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-list", "--count", "lanes-registry"), "1")
        self.git("checkout", "main")
        noop = self.run_publish()
        self.assertEqual(noop.returncode, 0, noop.stdout + noop.stderr)
        self.assertIn("unchanged", noop.stdout)
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "lanes-registry"), board_sha)
        self.git("checkout", "main")
        updated_curated = CURATED.replace("Ownership", "Ownership updated by PR")
        (self.repo / "LANES.md").write_text(generator.render_source(updated_curated))
        self.git("add", "LANES.md")
        self.git("commit", "-qm", "fixture curated PR")
        (self.runner / "LANES.md").write_text(generator.render([row("uk")], updated_curated))
        updated = self.run_publish()
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "lanes-registry^"), board_sha)
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "main"), self.main_sha)
        board = self.git("--git-dir", str(self.remote), "show", "lanes-registry:LANES.md")
        self.assertEqual(generator.extract_curated(board), updated_curated)
        self.assertEqual(self.log.read_text().splitlines(), [
            "push origin HEAD:refs/heads/lanes-registry",
            "push origin HEAD:refs/heads/lanes-registry",
        ])

    def test_guard_rejects_every_other_target_before_any_push(self):
        for target in ("refs/heads/main", "refs/heads/master", "refs/heads/other", "lanes-registry", ""):
            result = self.run_publish(PUBLISH_REF=target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to push", result.stdout)
            self.assertEqual(self.git("rev-parse", "HEAD"), self.main_sha)
        self.assertFalse(self.log.exists())

    def test_remote_lookup_failure_does_not_bootstrap_or_push(self):
        result = self.run_publish(FAIL_LOOKUP="1")
        self.assertEqual(result.returncode, 128)
        self.assertFalse(self.log.exists())
        self.assertEqual(self.git("rev-parse", "HEAD"), self.main_sha)
        self.assertEqual(self.git("branch", "--list", "lanes-registry"), "")


if __name__ == "__main__":
    unittest.main()
