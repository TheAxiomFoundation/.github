"""Regression checks for the encoder-main verifier (axiom-encode#2093, #2095).

Each check runs a real step script of validate-rulespec.yml against a
synthetic Git history, like scripts/test_validate_rulespec_workflow.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import test_validate_rulespec_workflow as base  # noqa: E402

WORKFLOW = base.WORKFLOW
MAIN_SHA = "9" * 40
LEDGER = "known-validation-gaps.yaml"


@contextmanager
def environment(**values: str):
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def shards_step(step_id: str) -> dict:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["shards"]["steps"]
    return next(step for step in steps if step.get("id") == step_id)


def ledger(records: dict[str, str]) -> str:
    if not records:
        return "validate_failures: {}\n"
    text = "validate_failures:\n"
    for path, marker in sorted(records.items()):
        text += (
            f"  {path}:\n    active:\n"
            f'      fingerprint: "sha256:{marker * 64}"\n'
            '      owner: "@owner"\n'
            '      issue: "https://github.com/example/rules/issues/1"\n'
            '      expires: "2026-12-21"\n'
        )
    return text


def toolchain(waiver_digest: str, corpus: str = "before") -> str:
    return (
        "[toolchain]\n"
        f'axiom_corpus_release = "{corpus}"\n'
        f'axiom_corpus_release_content_sha256 = "{"a" * 64}"\n'
        f'validation_waiver_set_sha256 = "{waiver_digest * 64}"\n'
    )


def history(changes: dict[str, str]) -> tuple[tempfile.TemporaryDirectory, Path, str, str]:
    temporary = tempfile.TemporaryDirectory(prefix="encoder-main-verifier-")
    root = Path(temporary.name)
    base.git(root, "init", "-q", "-b", "main")
    base.git(root, "config", "user.email", "workflow-test@example.com")
    base.git(root, "config", "user.name", "Workflow Test")

    def write(path: str, content: str) -> None:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    files = {
        ".axiom/toolchain.toml": toolchain("b"),
        ".axiom/workflow-toolchain.toml": base.SELECTOR_WORKFLOW_TOOLCHAIN,
        LEDGER: ledger({"us/statutes/one.yaml": "1", "us-ma/statutes/three.yaml": "3"}),
        "README.md": "before\n",
        **{path: "fixture\n" for path in base.SELECTOR_MODULES + base.SELECTOR_COMPANIONS},
        "us-ma/statutes/three.yaml": "fixture\n",
        "us-ma/statutes/three.test.yaml": "fixture\n",
    }
    for path, content in files.items():
        write(path, content)
    first = base.commit(root, "base")
    for path, content in changes.items():
        write(path, content)
    second = base.commit(root, "head")
    return temporary, root, first, second


def run_verifier_scope(
    changes: dict[str, str], *, verifier: str = "main", floor_only: str = "false",
    event: str = "pull_request",
) -> dict[str, str]:
    temporary, root, first, second = history(changes)
    with temporary:
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        real_git = subprocess.run(["which", "git"], capture_output=True, text=True).stdout.strip()
        # Only `git ls-remote` is faked; every other call reaches real Git.
        (fake_bin / "git").write_text(
            "#!/bin/sh\n"
            'if [ "$1" = ls-remote ]; then\n'
            f'  printf "%s\\trefs/heads/main\\n" "{MAIN_SHA}"\n'
            "  exit 0\n"
            "fi\n"
            f'exec "{real_git}" "$@"\n'
        )
        (fake_bin / "git").chmod(0o755)
        output = root / "output"
        step = shards_step("verifier_scope")
        result = subprocess.run(
            ["bash", "-c", base.selector_shell_source(step["run"])],
            cwd=root,
            env={
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
                "ENCODER_VERIFIER": verifier,
                "EVENT_NAME": event,
                "PR_BASE_SHA": first,
                "HEAD_SHA": second,
                "FLOOR_REF": "a" * 40,
                "ENCODER_FLOOR_ONLY": floor_only,
                "GITHUB_OUTPUT": str(output),
            },
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return dict(line.split("=", 1) for line in output.read_text().splitlines())


def test_pinned_verifier_keeps_the_pin_and_no_scope() -> None:
    outputs = run_verifier_scope({"README.md": "after\n"}, verifier="pinned")
    assert outputs == {"verifier_encode_ref": "a" * 40, "scope_drop": "[]", "scope_add": "[]"}


def test_main_verifier_resolves_main_once() -> None:
    outputs = run_verifier_scope({"README.md": "after\n"})
    assert outputs["verifier_encode_ref"] == MAIN_SHA
    assert json.loads(outputs["scope_drop"]) == [] and json.loads(outputs["scope_add"]) == []


def test_floor_only_pin_change_is_dropped_from_selection() -> None:
    changed = base.SELECTOR_WORKFLOW_TOOLCHAIN.replace("a" * 40, "f" * 40)
    outputs = run_verifier_scope({".axiom/workflow-toolchain.toml": changed}, floor_only="true")
    assert json.loads(outputs["scope_drop"]) == [".axiom/workflow-toolchain.toml"]
    # Without the floor-only flag (engine or other pins), nothing is dropped.
    outputs = run_verifier_scope({".axiom/workflow-toolchain.toml": changed})
    assert json.loads(outputs["scope_drop"]) == []


def test_ledger_only_change_selects_the_files_whose_records_changed() -> None:
    outputs = run_verifier_scope({
        ".axiom/toolchain.toml": toolchain("c"),
        LEDGER: ledger({"us/statutes/one.yaml": "1", "us-ma/statutes/three.yaml": "4",
                        "us/regulations/two.yml": "2"}),
    })
    assert json.loads(outputs["scope_drop"]) == [".axiom/toolchain.toml", LEDGER]
    assert json.loads(outputs["scope_add"]) == [
        "us-ma/statutes/three.yaml", "us/regulations/two.yml",
    ]


def test_removed_waiver_selects_its_file() -> None:
    outputs = run_verifier_scope({
        ".axiom/toolchain.toml": toolchain("c"),
        LEDGER: ledger({"us/statutes/one.yaml": "1"}),
    })
    assert json.loads(outputs["scope_add"]) == ["us-ma/statutes/three.yaml"]


def test_ledger_with_another_toolchain_change_keeps_default_selection() -> None:
    outputs = run_verifier_scope({
        ".axiom/toolchain.toml": toolchain("c", corpus="after"),
        LEDGER: ledger({"us/statutes/one.yaml": "9"}),
    })
    assert json.loads(outputs["scope_drop"]) == [] and json.loads(outputs["scope_add"]) == []


def test_malformed_ledger_keeps_default_selection() -> None:
    outputs = run_verifier_scope({
        ".axiom/toolchain.toml": toolchain("c"),
        LEDGER: "validate_failures: [not, a, mapping]\n",
    })
    assert json.loads(outputs["scope_drop"]) == [] and json.loads(outputs["scope_add"]) == []


def test_unsafe_waiver_path_keeps_default_selection() -> None:
    outputs = run_verifier_scope({
        ".axiom/toolchain.toml": toolchain("c"),
        LEDGER: ledger({"../outside.yaml": "1"}),
    })
    assert json.loads(outputs["scope_drop"]) == [] and json.loads(outputs["scope_add"]) == []


def run_dependency_step(
    *, base_mode: str | None, head_mode: str | None, requested: str,
    pin_changes: dict[str, str], guard: str = "true",
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    def table(mode, pins):
        extra = {"encoder_verifier": mode} if mode else {}
        return base.workflow_toolchain({**pins, **extra})

    with base.WorkflowInputFixture(
        table=table(base_mode, base.WORKFLOW_INPUT_PINS),
        caller=base.literal_pin_caller(base.WORKFLOW_INPUT_PINS),
    ) as fixture:
        proposed = {**base.WORKFLOW_INPUT_PINS, **pin_changes}
        fixture.write(base.WORKFLOW_TOOLCHAIN, table(head_mode, proposed))
        if not pin_changes and base_mode == head_mode:
            fixture.write("fixture.txt", "head\n")  # a commit with no pin change
        head = base.commit(fixture.root, "configuration change")
        output = fixture.root / "output"
        with environment(ENCODER_VERIFIER=requested, RUN_GENERATED_GUARD=guard):
            result = base.run_workflow_inputs(
                fixture.root, fixture.base, pins=proposed, head=head, output=output,
            )
        bound = (
            dict(line.split("=", 1) for line in output.read_text().splitlines())
            if result.returncode == 0 else {}
        )
        return result, bound


def test_dependency_step_reports_a_floor_only_encoder_pin_change() -> None:
    encoder_pin = {"axiom_encode_ref": "9" * 40}
    result, bound = run_dependency_step(
        base_mode="main", head_mode="main", requested="main", pin_changes=encoder_pin,
    )
    assert result.returncode == 0, result.stderr
    assert bound["encoder_verifier"] == "main"
    assert (bound["encoder_floor_only"], bound["dependency_pins_changed"]) == ("true", "false")
    result, bound = run_dependency_step(
        base_mode=None, head_mode=None, requested="pinned", pin_changes=encoder_pin,
    )
    assert result.returncode == 0, result.stderr
    assert (bound["encoder_floor_only"], bound["dependency_pins_changed"]) == ("false", "true")
    # Without the generated guard nothing enforces the floor: full bump.
    result, bound = run_dependency_step(
        base_mode="main", head_mode="main", requested="main", pin_changes=encoder_pin,
        guard="false",
    )
    assert (bound["encoder_floor_only"], bound["dependency_pins_changed"]) == ("false", "true")


def test_engine_pin_change_stays_a_full_dependency_bump_with_main_verifier() -> None:
    result, bound = run_dependency_step(
        base_mode="main", head_mode="main", requested="main",
        pin_changes={"axiom_encode_ref": "9" * 40, "axiom_rules_engine_ref": "4" * 40},
    )
    assert result.returncode == 0, result.stderr
    assert (bound["encoder_floor_only"], bound["dependency_pins_changed"]) == ("false", "true")


def test_the_caller_cannot_choose_its_verifier_mode() -> None:
    for protected, requested in (("main", "pinned"), (None, "main")):
        result, _ = run_dependency_step(
            base_mode=protected, head_mode=protected, requested=requested, pin_changes={},
        )
        assert result.returncode != 0, (protected, requested)
        assert "must match the protected" in result.stdout + result.stderr


def test_switching_the_mode_is_a_full_dependency_change() -> None:
    result, bound = run_dependency_step(
        base_mode=None, head_mode="main", requested="main",
        pin_changes={"axiom_encode_ref": "9" * 40},
    )
    assert result.returncode == 0, result.stderr
    assert (bound["encoder_floor_only"], bound["dependency_pins_changed"]) == ("false", "true")


def test_invalid_verifier_value_fails_closed() -> None:
    result, _ = run_dependency_step(
        base_mode="latest", head_mode="latest", requested="pinned", pin_changes={},
    )
    assert result.returncode != 0
    assert "encoder_verifier must be pinned or main" in result.stdout + result.stderr
    result, _ = run_dependency_step(
        base_mode=None, head_mode=None, requested="latest", pin_changes={},
    )
    assert result.returncode != 0


def test_validation_targets_apply_the_verifier_scope() -> None:
    added = json.dumps(["us/regulations/two.yml"])
    dropped = json.dumps([".axiom/toolchain.toml", LEDGER])
    with environment(VERIFIER_SCOPE_DROP=dropped, VERIFIER_SCOPE_ADD=added):
        result = base.run_validation_targets({
            ".axiom/toolchain.toml": base.SELECTOR_TOOLCHAIN.replace("b" * 64, "c" * 64),
        })
    assert result == (
        "changed-waiver-ledger", ["us/regulations/two.yml"], ["us/regulations/two.test.yml"],
    )
    # Without the scope, the same waiver-digest change is still a full bump.
    assert base.run_validation_targets({
        ".axiom/toolchain.toml": base.SELECTOR_TOOLCHAIN.replace("b" * 64, "c" * 64),
    })[0] == "full-toolchain-bump"


def test_guard_passes_the_floor_only_to_the_head_runtime() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# encoder-main-verifier-guard-start")
    end = workflow.index("# encoder-main-verifier-guard-end")
    block = workflow[start:end]
    assert 'head_floor_args=(--encoder-producer-floor "$PRODUCER_FLOOR")' in block
    # A floor-only change checks every manifest against the new floor.
    assert "head_floor_args+=(--all)" in block
    # The floor may only move forward on first-parent main.
    assert 'merge-base --is-ancestor "$BASE_ENCODER_REF" "$PRODUCER_FLOOR"' in block
    assert "rev-list --first-parent refs/remotes/origin/main" in block
    steps = yaml.safe_load(workflow)["jobs"]["validate"]["steps"]
    names = [step.get("name") for step in steps]
    record = steps[names.index("Record the encoder-main verifier")]
    assert names.index("Record the encoder-main verifier") < names.index("Reject manual RuleSpec changes")
    assert "run-generated-guard" not in record["if"]
    assert "verifier-identity" in record["run"] and "GITHUB_STEP_SUMMARY" in record["run"]
    assert "inputs.encoder-verifier" not in workflow.split("jobs:", 1)[1].replace(
        "ENCODER_VERIFIER: ${{ inputs.encoder-verifier }}\n          RUN_GENERATED_GUARD", ""
    )
    assert 'if [ "$runtime" = /opt/axiom-verification ]; then' in workflow
    # Every head encoder checkout follows the verifier, never the bare pin.
    assert "needs.shards.outputs.axiom_encode_ref }}\n          path:" not in workflow
    assert workflow.count("needs.shards.outputs.verifier_encode_ref") == 5


def test_shard_selection_applies_the_verifier_scope() -> None:
    toolchain_change = {
        ".axiom/toolchain.toml": base.SELECTOR_TOOLCHAIN.replace("b" * 64, "c" * 64),
    }
    for enabled in (False, True):
        # A waiver-digest change normally runs every shard.
        assert base.run_import_aware_selection(toolchain_change, enabled=enabled)[
            "matrix"
        ] == base.SELECTION_JURISDICTIONS
        with environment(
            VERIFIER_SCOPE_DROP=json.dumps([".axiom/toolchain.toml"]),
            VERIFIER_SCOPE_ADD=json.dumps(["us-ma/statutes/local.yaml"]),
        ):
            result = base.run_import_aware_selection(toolchain_change, enabled=enabled)
        assert result["matrix"] == ["us-ma"], (enabled, result["matrix"])
        mode, modules, companions = result["targets"]["us-ma"]
        assert mode == "changed-waiver-ledger", (enabled, mode)
        assert "us-ma/statutes/local.yaml" in modules
        assert "us-ma/statutes/local.test.yaml" in companions
        # A floor-only change leaves only the first shard for the guard.
        with environment(
            VERIFIER_SCOPE_DROP=json.dumps([".axiom/toolchain.toml"]),
            VERIFIER_SCOPE_ADD="[]",
        ):
            result = base.run_import_aware_selection(toolchain_change, enabled=enabled)
        # The first discovered shard, which carries the guard.
        assert result["matrix"] == [base.SELECTION_JURISDICTIONS[0]], (
            enabled, result["matrix"],
        )
        assert result["targets"][result["matrix"][0]][1:] == ([], [])


def test_drift_targets_scope_a_dispatched_run() -> None:
    targets = ["us-ma/statutes/local.yaml", "us/regulations/independent.yml"]
    with environment(DRIFT_TARGETS=json.dumps(targets), EVENT_NAME="workflow_dispatch",
                     DRIFT_TARGETS_VALID="true"):
        result = base.run_import_aware_selection({}, enabled=False, event="workflow_dispatch")
    assert result["drift-targets-valid"] == "true"
    assert result["matrix"] == ["us-ma", "us"], result["matrix"]
    assert result["targets"]["us-ma"][:2] == ("drift-targets", ["us-ma/statutes/local.yaml"])
    assert result["targets"]["us"][1] == ["us/regulations/independent.yml"]
    assert result["targets"]["us"][2] == ["us/regulations/independent.test.yml"]


def test_invalid_drift_targets_run_everything() -> None:
    for targets in ('["../etc/passwd.yaml"]', '"us/statutes/local.yaml"', "not json", "[]",
                    '["xx/statutes/a.yaml"]', '["us/statutes/a\\nus/b.yaml"]'):
        # The target step sees the selector's verdict through this output.
        with environment(DRIFT_TARGETS=targets, EVENT_NAME="workflow_dispatch",
                         DRIFT_TARGETS_VALID="false"):
            result = base.run_import_aware_selection({}, enabled=False, event="workflow_dispatch")
        assert result.get("drift-targets-valid", "false") == "false", targets
        assert result["matrix"] == base.SELECTION_JURISDICTIONS, (targets, result["matrix"])
        for mode, modules, _companions in result["targets"].values():
            assert mode in {"full-drift-fallback", "full-push"}, (targets, mode)
            assert modules, targets


def test_missing_drift_target_runs_everything() -> None:
    targets = ["us-ma/statutes/local.yaml", "us-ma/statutes/missing.yaml"]
    with environment(DRIFT_TARGETS=json.dumps(targets), EVENT_NAME="workflow_dispatch",
                     DRIFT_TARGETS_VALID="true"):
        result = base.run_import_aware_selection({}, enabled=False, event="workflow_dispatch")
    mode, modules, _companions = result["targets"]["us-ma"]
    assert mode == "full-drift-fallback", mode
    assert len(modules) > 1


def test_pull_requests_ignore_drift_targets() -> None:
    change = {"us-ma/statutes/local.yaml": base.selection_module() + "# edited\n"}
    with environment(DRIFT_TARGETS=json.dumps(["us/statutes/local.yaml"]),
                     EVENT_NAME="pull_request"):
        result = base.run_import_aware_selection(change, enabled=False)
    assert result["matrix"] == ["us-ma"], result["matrix"]
    assert result["targets"]["us-ma"][0] == "changed"


def run_floor_direction_check(commits: int, base_index: int, floor_index: int) -> int:
    """Run the guard's forward-floor check on a synthetic first-parent history."""

    workflow = WORKFLOW.read_text()
    block = workflow[
        workflow.index("            if [ \"${ENCODER_FLOOR_ONLY:-false}\" = \"true\" ]; then"):
        workflow.index("              head_floor_args+=(--all)")
    ]
    with tempfile.TemporaryDirectory(prefix="floor-direction-") as directory:
        root = Path(directory)
        history = root / "deps" / "axiom-encode"
        history.mkdir(parents=True)
        base.git(history, "init", "-q", "-b", "main")
        # fast-import builds a long first-parent chain quickly.
        stream = "".join(
            f"commit refs/heads/main\nmark :{n + 1}\n"
            "committer Fixture <f@example.com> 1767225600 +0000\n"
            f"data {len(str(n))}\n{n}\n"
            + (f"from :{n}\n" if n else "")
            + "\n"
            for n in range(commits)
        )
        subprocess.run(["git", "fast-import", "--quiet"], cwd=history, input=stream,
                       text=True, check=True)
        base.git(history, "update-ref", "refs/remotes/origin/main", "refs/heads/main")
        chain = base.git(history, "rev-list", "--reverse", "refs/heads/main").split()
        script = (
            "set -euo pipefail\n" + block + "\n              echo forward\n            fi\n"
        )
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=root,
            env={
                **os.environ,
                "ENCODER_FLOOR_ONLY": "true",
                "AXIOM_DEPENDENCY_ROOT": str(root / "deps"),
                "BASE_ENCODER_REF": chain[base_index],
                "PRODUCER_FLOOR": chain[floor_index],
            },
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode


def test_forward_floor_check_survives_a_long_history() -> None:
    # The old `rev-list | grep -q` failed under pipefail for short and long
    # histories alike; 2,000 commits also exceed a 64 KB pipe buffer.
    for commits in (50, 2000):
        assert run_floor_direction_check(commits, commits // 2, commits - 2) == 0
        assert run_floor_direction_check(commits, commits - 2, commits // 2) == 1


def test_validate_step_prints_one_result_line_per_chunk() -> None:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    run = next(step for step in steps if step.get("name") == "Validate RuleSpec YAML")["run"]
    assert "RULESPEC_VALIDATION_CHUNK files=%s status=%s single=%s" in run
    assert run.count('chunk_result "') == 2
    assert run.count("RULESPEC_VALIDATION_CHUNKS total=") == 2


def main() -> None:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print(f"{name}: ok")


if __name__ == "__main__":
    main()
