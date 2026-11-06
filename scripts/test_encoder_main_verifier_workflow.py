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


def test_dependency_step_reports_a_floor_only_encoder_pin_change() -> None:
    for verifier, floor_only, pins_changed in (
        ("main", "true", "false"), ("pinned", "false", "true"),
    ):
        with base.WorkflowInputFixture(
            table=base.workflow_toolchain(base.WORKFLOW_INPUT_PINS),
            caller=base.literal_pin_caller(base.WORKFLOW_INPUT_PINS),
        ) as fixture:
            proposed = {**base.WORKFLOW_INPUT_PINS, "axiom_encode_ref": "9" * 40}
            fixture.write(base.WORKFLOW_TOOLCHAIN, base.workflow_toolchain(proposed))
            head = base.commit(fixture.root, "encoder pin")
            output = fixture.root / "output"
            with environment(ENCODER_VERIFIER=verifier):
                result = base.run_workflow_inputs(
                    fixture.root, fixture.base, pins=proposed, head=head, output=output,
                )
            assert result.returncode == 0, result.stderr
            bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
            assert bound["encoder_floor_only"] == floor_only, verifier
            assert bound["dependency_pins_changed"] == pins_changed, verifier


def test_engine_pin_change_stays_a_full_dependency_bump_with_main_verifier() -> None:
    with base.WorkflowInputFixture(
        table=base.workflow_toolchain(base.WORKFLOW_INPUT_PINS),
        caller=base.literal_pin_caller(base.WORKFLOW_INPUT_PINS),
    ) as fixture:
        proposed = {**base.WORKFLOW_INPUT_PINS, "axiom_encode_ref": "9" * 40,
                    "axiom_rules_engine_ref": "4" * 40}
        fixture.write(base.WORKFLOW_TOOLCHAIN, base.workflow_toolchain(proposed))
        head = base.commit(fixture.root, "encoder and engine pins")
        output = fixture.root / "output"
        with environment(ENCODER_VERIFIER="main"):
            result = base.run_workflow_inputs(
                fixture.root, fixture.base, pins=proposed, head=head, output=output,
            )
        assert result.returncode == 0, result.stderr
        bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert bound["encoder_floor_only"] == "false"
        assert bound["dependency_pins_changed"] == "true"


def test_invalid_verifier_value_fails_closed() -> None:
    with base.WorkflowInputFixture(
        table=base.workflow_toolchain(base.WORKFLOW_INPUT_PINS),
        caller=base.literal_pin_caller(base.WORKFLOW_INPUT_PINS),
    ) as fixture:
        with environment(ENCODER_VERIFIER="latest"):
            result = base.run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode != 0
        assert "encoder-verifier must be pinned or main" in result.stdout + result.stderr


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
    assert "verifier-identity" in block and "GITHUB_STEP_SUMMARY" in block
    assert 'head_floor_args=(--encoder-producer-floor "$PRODUCER_FLOOR")' in block
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


def main() -> None:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print(f"{name}: ok")


if __name__ == "__main__":
    main()
