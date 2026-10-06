#!/usr/bin/env python3
"""Exercise the reusable workflow's durable generated-guard anchor."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
REPOSITORY = "TheAxiomFoundation/rulespec-us"
CALLER_PATH = ".github/workflows/repository-checks.yml"
SHARED_PATH = (
    "TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml"
)
CURRENT_SHARED = "a" * 40
OLD_SHARED = "b" * 40
WORKFLOW_ID = 77
CURRENT_RUN_ID = 900


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


def anchor_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# durable-generated-guard-anchor-start")
    end = workflow.index("# durable-generated-guard-anchor-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = "python - <<'PY' >> \"$GITHUB_OUTPUT\"\n"
    assert block.startswith(marker)
    source = block[len(marker) :].rsplit("\nPY", 1)[0]
    return textwrap.dedent(source)


class Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.email", "workflow-test@example.com")
        git(self.root, "config", "user.name", "Workflow Test")
        caller = self.root / CALLER_PATH
        caller.parent.mkdir(parents=True)
        caller.write_text("name: Repository Checks\n")
        (self.root / "README.md").write_text("reviewed base\n")
        self.seed = commit(self.root, "reviewed known-good seed")
        anchor = self.root / ".axiom/generated-guard-anchor.toml"
        anchor.parent.mkdir(parents=True)
        anchor.write_text(
            "[generated_guard_anchor]\n"
            'contract = "axiom/generated-guard-anchor/v1"\n'
            f'reviewed_known_good_sha = "{self.seed}"\n'
        )
        self.introduction = commit(self.root, "introduce durable guard anchor")
        (self.root / "README.md").write_text("reviewed base\nvalidated\n")
        self.good = commit(self.root, "successful validation")
        protected = self.root / "statutes/unauthorized.yaml"
        protected.parent.mkdir(parents=True)
        protected.write_text("forged: receipt\n")
        self.bad = commit(self.root, "unauthorized protected change")
        (self.root / "README.md").write_text(
            "reviewed base\nvalidated\nunrelated follow-up\n"
        )
        self.head = commit(self.root, "unrelated second push")

    def close(self) -> None:
        self.temp.cleanup()

    def tree(self, commit_sha: str) -> str:
        return git(self.root, "rev-parse", f"{commit_sha}^{{tree}}")


def run_detail(
    fixture: Fixture,
    *,
    run_id: int,
    head: str,
    shared: str = CURRENT_SHARED,
    active: bool = False,
    references: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "id": run_id,
        "workflow_id": WORKFLOW_ID,
        "path": CALLER_PATH,
        "event": "pull_request" if active else "push",
        "head_branch": "feature" if active else "main",
        "head_sha": head,
        "head_commit": {"id": head, "tree_id": fixture.tree(head)},
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "status": "in_progress" if active else "completed",
        "conclusion": None if active else "success",
        "referenced_workflows": references
        if references is not None
        else [{"path": f"{SHARED_PATH}@{shared}", "sha": shared}],
    }


def successful_guard_jobs() -> dict[str, object]:
    return {
        "total_count": 1,
        "jobs": [
            {
                "name": "validate / validate (__all__)",
                "steps": [
                    {
                        "name": "Reject manual RuleSpec changes",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }
        ],
    }


def successful_multishard_guard_jobs() -> dict[str, object]:
    steps = []
    for conclusion in ("success", "skipped", "skipped"):
        steps.append(
            {
                "name": "validate / validate (shard)",
                "steps": [
                    {
                        "name": "Reject manual RuleSpec changes",
                        "status": "completed",
                        "conclusion": conclusion,
                    }
                ],
            }
        )
    return {"total_count": len(steps), "jobs": steps}


class ApiState:
    def __init__(self, fixture: Fixture) -> None:
        self.current = run_detail(
            fixture,
            run_id=CURRENT_RUN_ID,
            head=fixture.head,
            active=True,
        )
        self.runs: dict[int, dict[str, object]] = {}
        self.jobs: dict[int, dict[str, object]] = {}
        self.failure_prefix: str | None = None
        self.listing_pages: dict[int, dict[str, object]] | None = None

    def add_success(
        self,
        fixture: Fixture,
        *,
        run_id: int,
        head: str,
        shared: str = CURRENT_SHARED,
    ) -> None:
        self.runs[run_id] = run_detail(
            fixture, run_id=run_id, head=head, shared=shared
        )
        self.jobs[run_id] = successful_guard_jobs()

    def response(self, path: str, query: dict[str, list[str]]) -> object:
        if self.failure_prefix is not None and path.startswith(self.failure_prefix):
            raise RuntimeError("forced API failure")
        prefix = f"/repos/{REPOSITORY}"
        if path == prefix:
            return {"full_name": REPOSITORY, "default_branch": "main"}
        if path == f"{prefix}/actions/runs/{CURRENT_RUN_ID}":
            return self.current
        if path.startswith(f"{prefix}/actions/runs/") and path.endswith("/jobs"):
            run_id = int(path.removesuffix("/jobs").rsplit("/", 1)[1])
            return self.jobs[run_id]
        if path.startswith(f"{prefix}/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            return self.runs[run_id]
        if path == f"{prefix}/actions/workflows/{WORKFLOW_ID}/runs":
            page = int(query.get("page", ["1"])[0])
            if self.listing_pages is not None:
                return self.listing_pages[page]
            ordered = list(self.runs.values())
            start = (page - 1) * 100
            page_runs = ordered[start : start + 100]
            return {"total_count": len(ordered), "workflow_runs": page_runs}
        raise KeyError(path)


@contextmanager
def api_server(state: ApiState) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            try:
                payload = state.response(
                    parsed.path, urllib.parse.parse_qs(parsed.query)
                )
            except (KeyError, RuntimeError):
                self.send_response(500)
                self.end_headers()
                return
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run_anchor(
    fixture: Fixture,
    state: ApiState,
    *,
    checkout: str | None = None,
    reviewed_seed: str | None = None,
) -> subprocess.CompletedProcess[str]:
    checkout_sha = checkout or fixture.head
    state.current["head_sha"] = checkout_sha
    state.current["head_commit"] = {
        "id": checkout_sha,
        "tree_id": fixture.tree(checkout_sha),
    }
    with api_server(state) as url:
        env = {
            **os.environ,
            "ANCHOR_API_URL": url,
            "ANCHOR_CHECKOUT_SHA": checkout_sha,
            "ANCHOR_REPOSITORY": REPOSITORY,
            "ANCHOR_RUN_HEAD_SHA": checkout_sha,
            "ANCHOR_RUN_ID": str(CURRENT_RUN_ID),
            "ANCHOR_TEST_ALLOW_HTTP": "true",
            "ANCHOR_TEST_REVIEWED_SEED": reviewed_seed or fixture.seed,
            "ANCHOR_TOKEN": "test-token",
        }
        return subprocess.run(
            [sys.executable, "-c", anchor_source()],
            cwd=fixture.root,
            env=env,
            capture_output=True,
            text=True,
        )


def output(result: subprocess.CompletedProcess[str]) -> dict[str, str]:
    assert result.returncode == 0, result.stderr
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def test_two_push_laundering_uses_last_trusted_success(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    result = output(run_anchor(fixture, state))
    assert result == {
        "mode": "durable",
        "base_ref": fixture.good,
        "contract_sha": CURRENT_SHARED,
    }
    assert fixture.bad != result["base_ref"]


def test_unconfigured_repository_retains_legacy_mode(fixture: Fixture) -> None:
    result = output(run_anchor(fixture, ApiState(fixture), checkout=fixture.seed))
    assert result == {"mode": "legacy", "base_ref": ""}


def test_no_matching_contract_falls_back_to_reviewed_seed(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.add_success(
        fixture, run_id=100, head=fixture.good, shared=OLD_SHARED
    )
    result = output(run_anchor(fixture, state))
    assert result["base_ref"] == fixture.seed


def test_anchor_bootstrap_uses_centrally_reviewed_seed(fixture: Fixture) -> None:
    result = output(
        run_anchor(fixture, ApiState(fixture), checkout=fixture.introduction)
    )
    assert result["base_ref"] == fixture.seed


def test_caller_cannot_self_attest_a_different_seed(fixture: Fixture) -> None:
    result = run_anchor(fixture, ApiState(fixture), reviewed_seed=fixture.good)
    assert result.returncode != 0
    assert "centrally reviewed bootstrap seed" in result.stderr


def test_caller_workflow_drift_resets_to_seed() -> None:
    fixture = Fixture()
    try:
        state = ApiState(fixture)
        state.add_success(fixture, run_id=100, head=fixture.good)
        (fixture.root / CALLER_PATH).write_text(
            "name: Repository Checks\n# reviewed caller update\n"
        )
        fixture.head = commit(fixture.root, "update caller workflow")
        result = output(run_anchor(fixture, state))
        assert result["base_ref"] == fixture.seed
    finally:
        fixture.close()


def test_skipped_guard_does_not_advance_anchor(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    state.jobs[100] = {
        "total_count": 1,
        "jobs": [
            {
                "name": "validate / validate (__all__)",
                "steps": [
                    {
                        "name": "Reject manual RuleSpec changes",
                        "status": "completed",
                        "conclusion": "skipped",
                    }
                ],
            }
        ],
    }
    result = output(run_anchor(fixture, state))
    assert result["base_ref"] == fixture.seed


def test_one_success_and_skipped_matrix_steps_advance_anchor(
    fixture: Fixture,
) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    state.jobs[100] = successful_multishard_guard_jobs()
    result = output(run_anchor(fixture, state))
    assert result["base_ref"] == fixture.good


def test_duplicate_successful_guard_steps_are_ambiguous(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    jobs = successful_multishard_guard_jobs()
    jobs["jobs"][1]["steps"][0]["conclusion"] = "success"
    state.jobs[100] = jobs
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "ambiguous generated-guard steps" in result.stderr


def test_run_tree_metadata_drift_fails_closed(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    state.runs[100]["head_commit"] = {
        "id": fixture.good,
        "tree_id": "f" * 40,
    }
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "resolved Git tree" in result.stderr


def test_replayed_run_from_another_repository_fails_closed(
    fixture: Fixture,
) -> None:
    state = ApiState(fixture)
    state.add_success(fixture, run_id=100, head=fixture.good)
    state.runs[100]["repository"] = {"full_name": "attacker/replay"}
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "not bound to the caller repository" in result.stderr


def test_unavailable_actions_evidence_fails_closed(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.failure_prefix = f"/repos/{REPOSITORY}/actions/runs/{CURRENT_RUN_ID}"
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "current Actions run is unavailable" in result.stderr


def test_ambiguous_current_reusable_identity_fails_closed(
    fixture: Fixture,
) -> None:
    state = ApiState(fixture)
    reference = {"path": f"{SHARED_PATH}@{CURRENT_SHARED}", "sha": CURRENT_SHARED}
    state.current["referenced_workflows"] = [reference, reference]
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "ambiguous reusable-workflow evidence" in result.stderr


def test_incomplete_pagination_fails_closed(fixture: Fixture) -> None:
    state = ApiState(fixture)
    state.listing_pages = {1: {"total_count": 1, "workflow_runs": []}}
    result = run_anchor(fixture, state)
    assert result.returncode != 0
    assert "pagination ended before its declared total" in result.stderr


def test_incomparable_successes_fail_closed() -> None:
    fixture = Fixture()
    try:
        root = fixture.root
        git(root, "switch", "-qc", "side-a", fixture.introduction)
        (root / "a.txt").write_text("a\n")
        side_a = commit(root, "side a")
        git(root, "switch", "-qc", "side-b", fixture.introduction)
        (root / "b.txt").write_text("b\n")
        side_b = commit(root, "side b")
        git(root, "switch", "-q", "main")
        git(root, "merge", "--no-ff", "-qm", "merge side a", side_a)
        git(root, "merge", "--no-ff", "-qm", "merge side b", side_b)
        fixture.head = git(root, "rev-parse", "HEAD")
        state = ApiState(fixture)
        state.add_success(fixture, run_id=100, head=side_a)
        state.add_success(fixture, run_id=101, head=side_b)
        result = run_anchor(fixture, state)
        assert result.returncode != 0
        assert "no unique maximal ancestor" in result.stderr
    finally:
        fixture.close()


def test_anchor_mutation_and_reintroduction_fail_closed() -> None:
    fixture = Fixture()
    try:
        anchor = fixture.root / ".axiom/generated-guard-anchor.toml"
        anchor.write_text(
            "[generated_guard_anchor]\n"
            'contract = "axiom/generated-guard-anchor/v1"\n'
            f'reviewed_known_good_sha = "{fixture.good}"\n'
        )
        fixture.head = commit(fixture.root, "mutate anchor")
        result = run_anchor(fixture, ApiState(fixture))
        assert result.returncode != 0
        assert "changed after its introduction" in result.stderr

        anchor.unlink()
        commit(fixture.root, "delete anchor")
        anchor.write_text(
            "[generated_guard_anchor]\n"
            'contract = "axiom/generated-guard-anchor/v1"\n'
            f'reviewed_known_good_sha = "{fixture.seed}"\n'
        )
        fixture.head = commit(fixture.root, "reintroduce anchor")
        result = run_anchor(fixture, ApiState(fixture))
        assert result.returncode != 0
        assert "exactly one introducing commit" in result.stderr
    finally:
        fixture.close()


def test_missing_and_malformed_anchor_fail_closed() -> None:
    missing = Fixture()
    try:
        (missing.root / ".axiom/generated-guard-anchor.toml").unlink()
        missing.head = commit(missing.root, "delete anchor")
        result = run_anchor(missing, ApiState(missing))
        assert result.returncode != 0
        assert "does not contain .axiom/generated-guard-anchor.toml" in result.stderr
    finally:
        missing.close()

    malformed = Fixture()
    try:
        git(malformed.root, "reset", "--hard", malformed.introduction)
        anchor = malformed.root / ".axiom/generated-guard-anchor.toml"
        anchor.write_text("[generated_guard_anchor\n")
        git(malformed.root, "add", anchor.as_posix())
        git(malformed.root, "commit", "--amend", "-qm", "malformed anchor")
        malformed.introduction = git(malformed.root, "rev-parse", "HEAD")
        malformed.head = malformed.introduction
        result = run_anchor(malformed, ApiState(malformed))
        assert result.returncode != 0
        assert "is not strict UTF-8 TOML" in result.stderr
    finally:
        malformed.close()


def test_static_workflow_contract() -> None:
    workflow = WORKFLOW.read_text()
    source = anchor_source()
    assert "permissions:\n  actions: read\n  contents: read" in workflow
    assert workflow.index("Resolve durable generated-guard anchor") < workflow.index(
        "Reject manual RuleSpec changes"
    )
    assert 'DURABLE_BASE_REF: ${{ steps.generated_guard_anchor.outputs.base_ref }}' in workflow
    assert "github.event.before" not in source
    assert "origin/main" not in source
    assert "reviewed_known_good_sha" in source
    assert "referenced_workflows" in source
    assert 'step.get("name") == "Reject manual RuleSpec changes"' in source


def main() -> None:
    fixture = Fixture()
    try:
        test_two_push_laundering_uses_last_trusted_success(fixture)
        test_unconfigured_repository_retains_legacy_mode(fixture)
        test_no_matching_contract_falls_back_to_reviewed_seed(fixture)
        test_anchor_bootstrap_uses_centrally_reviewed_seed(fixture)
        test_caller_cannot_self_attest_a_different_seed(fixture)
        test_skipped_guard_does_not_advance_anchor(fixture)
        test_one_success_and_skipped_matrix_steps_advance_anchor(fixture)
        test_duplicate_successful_guard_steps_are_ambiguous(fixture)
        test_run_tree_metadata_drift_fails_closed(fixture)
        test_replayed_run_from_another_repository_fails_closed(fixture)
        test_unavailable_actions_evidence_fails_closed(fixture)
        test_ambiguous_current_reusable_identity_fails_closed(fixture)
        test_incomplete_pagination_fails_closed(fixture)
    finally:
        fixture.close()
    test_caller_workflow_drift_resets_to_seed()
    test_incomparable_successes_fail_closed()
    test_anchor_mutation_and_reintroduction_fail_closed()
    test_missing_and_malformed_anchor_fail_closed()
    test_static_workflow_contract()
    print("durable generated-guard anchor: ok")


if __name__ == "__main__":
    main()
