#!/usr/bin/env python3
"""Exercise embedded RuleSpec workflow guards and corpus placement shell."""

from __future__ import annotations

import json
import hashlib
from functools import lru_cache
import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
RETIRED = "1" * 64
WAIVER = "2" * 64
CORPUS_PLACEMENT_STEP = "Place the pinned corpus release's provisions"
BASE_CORPUS_PREPARATION_STEP = "Prepare protected-base manifest audit"


def corpus_placement_step() -> dict:
    import yaml

    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    return next(step for step in steps if step.get("name") == CORPUS_PLACEMENT_STEP)


def test_corpus_placement_runs_before_supervised_gates_with_step_only_credentials() -> None:
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["validate"]["steps"]
    names = [step.get("name") for step in steps]
    index = names.index(CORPUS_PLACEMENT_STEP)
    assert names[index - 1] == "Authenticate signed corpus provenance commit"
    assert names[index + 1] == "Provision protected verification supervisor"
    install = steps[names.index("Install Python dependencies")]
    assert names.index("Install Python dependencies") < index
    assert 'python -I -m pip --isolated install "$RUNNER_TEMP/axiom-encode-install"' in install["run"]

    step = steps[index]
    assert step["shell"] == "bash"
    assert step["run"].startswith("set -euo pipefail\n")
    assert "${{" not in step["run"]
    assert "/opt/axiom-verification" not in step["run"]
    assert "axiom-encode-signing-supervisor" not in step["run"]
    assert step["working-directory"] == "${{ runner.temp }}"
    assert step["env"]["CORPUS_PATH"] == "${{ env.AXIOM_DEPENDENCY_ROOT }}/axiom-corpus"
    assert step["env"]["RELEASE_NAME"] == "${{ steps.toolchain.outputs.axiom_corpus_release }}"
    assert step["env"]["RELEASE_CONTENT_SHA256"] == "${{ steps.toolchain.outputs.axiom_corpus_release_content_sha256 }}"
    assert step["env"]["R2_ACCESS_KEY_ID"] == "${{ secrets.R2_CORPUS_READ_ACCESS_KEY_ID }}"
    assert step["env"]["R2_SECRET_ACCESS_KEY"] == "${{ secrets.R2_CORPUS_READ_SECRET_ACCESS_KEY }}"

    credential_names = ("R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY")
    secret_names = ("R2_CORPUS_READ_ACCESS_KEY_ID", "R2_CORPUS_READ_SECRET_ACCESS_KEY")
    assert not any(key in workflow.get("env", {}) for key in credential_names)
    for job in workflow["jobs"].values():
        assert not any(key in job.get("env", {}) for key in credential_names)
        for other_step in job.get("steps", []):
            if other_step == step or other_step.get("name") == BASE_CORPUS_PREPARATION_STEP:
                assert other_step["env"]["R2_ACCESS_KEY_ID"] == "${{ secrets.R2_CORPUS_READ_ACCESS_KEY_ID }}"
                assert other_step["env"]["R2_SECRET_ACCESS_KEY"] == "${{ secrets.R2_CORPUS_READ_SECRET_ACCESS_KEY }}"
                continue
            assert not any(key in other_step.get("env", {}) for key in credential_names)
            assert not any(secret in json.dumps(other_step) for secret in secret_names)
    for earlier in steps[:index]:
        assert "axiom-encode-signing-supervisor" not in earlier.get("run", "")


def run_corpus_placement(
    *,
    locks: bool = True,
    supported: bool = True,
    credentials: bool = False,
    r2_only: bool = False,
) -> tuple[subprocess.CompletedProcess[str], list[dict], bool]:
    """Run the actual shell using a pinned-encoder stand-in, without network access."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        workspace = root / "rulespec with spaces"
        corpus = root / "corpus checkout with spaces"
        bin_path = root / "bin"
        workspace.mkdir()
        corpus.mkdir()
        bin_path.mkdir()
        if locks:
            (corpus / ".axiom/corpus-locks").mkdir(parents=True)
        release_name, release_sha = "pinned-release", "b" * 64
        release = corpus / "releases" / release_name / f"{release_sha}.json"
        release.parent.mkdir(parents=True)
        release.write_text(json.dumps({"release": release_name, "content_sha256": release_sha}))
        calls = root / "encoder-calls.jsonl"
        local = root / "local-provisions.json"
        local.write_text('{"provisions": ["local git artifact"]}\n')
        fake = bin_path / "axiom-encode"
        fake.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent("""\
                import argparse
                import json
                import os
                from pathlib import Path
                import sys

                with open(os.environ["ENCODER_CALLS"], "a") as log:
                    log.write(json.dumps({
                        "args": sys.argv[1:],
                        "access_key_id": os.environ.get("R2_ACCESS_KEY_ID", ""),
                        "secret_access_key": os.environ.get("R2_SECRET_ACCESS_KEY", ""),
                    }) + "\\n")
                assert sys.argv[1] == "corpus-fetch", sys.argv[1:]
                if sys.argv[2:] == ["--help"]:
                    if os.environ["ENCODER_SUPPORTED"] == "false":
                        print("unknown command corpus-fetch", file=sys.stderr)
                        sys.exit(2)
                    print("usage: axiom-encode corpus-fetch")
                    sys.exit(0)
                parser = argparse.ArgumentParser()
                parser.add_argument("--corpus-path", type=Path, required=True)
                parser.add_argument("--release", required=True)
                parser.add_argument("--content-sha256", required=True)
                parser.add_argument("--artifact-class", action="append", choices=["provisions"])
                args = parser.parse_args(sys.argv[2:])
                assert args.corpus_path == Path(os.environ["CORPUS_PATH"])
                assert args.release == os.environ["RELEASE_NAME"]
                assert args.content_sha256 == os.environ["RELEASE_CONTENT_SHA256"]
                release = args.corpus_path / "releases" / args.release / (args.content_sha256 + ".json")
                assert release.is_file(), "must reuse the previously fetched release object"
                if os.environ["R2_ONLY"] == "true" and not (
                    os.environ.get("R2_ACCESS_KEY_ID") and os.environ.get("R2_SECRET_ACCESS_KEY")
                ):
                    print("data/corpus/provisions/us/statutes/v1.json: git: absent; R2 read credentials absent", file=sys.stderr)
                    sys.exit(1)
                destination = args.corpus_path / "data/corpus/provisions/us/statutes/v1.json"
                destination.parent.mkdir(parents=True)
                destination.write_bytes(Path(os.environ["LOCAL_PROVISIONS"]).read_bytes())
                print("pinned-release: 1 artifact(s) placed")
                """)
        )
        fake.chmod(0o755)
        # Keep ambient credentials out of these fixtures, including developer
        # overrides that could accidentally make the missing-secret case pass.
        env = {key: value for key, value in os.environ.items() if not key.startswith("R2_")}
        env.update({
            "PATH": str(bin_path) + os.pathsep + env.get("PATH", ""),
            "GITHUB_WORKSPACE": str(workspace),
            "AXIOM_DEPENDENCY_ROOT": str(root),
            "CORPUS_PATH": str(corpus),
            "RELEASE_NAME": release_name,
            "RELEASE_CONTENT_SHA256": release_sha,
            "ENCODER_CALLS": str(calls),
            "ENCODER_SUPPORTED": str(supported).lower(),
            "R2_ONLY": str(r2_only).lower(),
            "LOCAL_PROVISIONS": str(local),
            "R2_ACCESS_KEY_ID": "fixture-read-access-key" if credentials else "",
            "R2_SECRET_ACCESS_KEY": "fixture-read-secret-key" if credentials else "",
        })
        # Source integrity has its own real-Git regression suite. This fixture
        # exercises corpus placement after that precondition using a fake CLI.
        integrity = root / "integrity.py"
        integrity.write_text("import sys\nassert sys.argv[1] in {'verify', 'refresh-corpus'}\n")
        shell = corpus_placement_step()["run"].replace(
            "/opt/axiom-dependency-integrity/check.py", str(integrity),
        ).replace('sudo "$(command -v python)" -I', '"$(command -v python)" -I')
        result = subprocess.run(
            ["bash", "-c", shell],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
        )
        invocations = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        destination = corpus / "data/corpus/provisions/us/statutes/v1.json"
        placed = destination.exists() and destination.read_bytes() == local.read_bytes()
        # Credential values may reach the encoder's environment, never shell logs.
        assert "fixture-read-access-key" not in result.stdout + result.stderr
        assert "fixture-read-secret-key" not in result.stdout + result.stderr
        return result, invocations, placed


def test_pre_switch_corpus_skips_placement_without_invoking_old_encoder() -> None:
    result, invocations, placed = run_corpus_placement(locks=False, supported=False)
    assert result.returncode == 0, result.stderr
    assert not invocations
    assert not placed
    assert "No .axiom/corpus-locks directory" in result.stdout
    assert "skipping provisions placement for this pre-switch corpus pin" in result.stdout
    assert "::error::" not in result.stdout + result.stderr


def test_post_switch_corpus_rejects_encoder_without_corpus_fetch() -> None:
    result, invocations, placed = run_corpus_placement(supported=False)
    assert result.returncode != 0
    assert [call["args"] for call in invocations] == [["corpus-fetch", "--help"]]
    assert not placed
    assert "::error::" in result.stdout + result.stderr
    assert "pin an axiom-encode that includes #1742" in result.stdout + result.stderr


def test_post_switch_corpus_places_pinned_release_with_read_credentials() -> None:
    result, invocations, placed = run_corpus_placement(credentials=True, r2_only=True)
    assert result.returncode == 0, result.stderr
    assert placed
    assert len(invocations) == 2
    assert invocations[0]["args"] == ["corpus-fetch", "--help"]
    assert invocations[1]["access_key_id"] == "fixture-read-access-key"
    assert invocations[1]["secret_access_key"] == "fixture-read-secret-key"
    assert "::error::" not in result.stdout + result.stderr


def test_post_switch_corpus_accepts_local_artifacts_without_credentials() -> None:
    result, invocations, placed = run_corpus_placement()
    assert result.returncode == 0, result.stderr
    assert placed
    assert len(invocations) == 2, "credentials cannot be required before trying local sources"
    assert invocations[1]["access_key_id"] == ""
    assert invocations[1]["secret_access_key"] == ""


def test_post_switch_corpus_fetch_failure_preserves_missing_artifact_diagnostic() -> None:
    result, invocations, placed = run_corpus_placement(r2_only=True)
    assert result.returncode != 0
    assert len(invocations) == 2, "the encoder must determine whether R2 is needed"
    assert not placed
    output = result.stdout + result.stderr
    assert "::error::" in output
    assert "data/corpus/provisions/us/statutes/v1.json" in output
    assert "R2 read credentials absent" in output


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


WORKFLOW_TOOLCHAIN = ".axiom/workflow-toolchain.toml"
VALIDATION_CALLER = ".github/workflows/repository-checks.yml"
WORKFLOW_INPUT_PINS = {
    "axiom_encode_ref": "8" * 40,
    "axiom_rules_engine_ref": "3" * 40,
    "axiom_corpus_ref": "6" * 40,
    "rulespec_us_ref": "7" * 40,
}
WORKFLOW_INPUT_ENV = {
    "axiom_encode_ref": "AXIOM_ENCODE_SHA",
    "axiom_rules_engine_ref": "AXIOM_RULES_ENGINE_SHA",
    "axiom_corpus_ref": "AXIOM_CORPUS_SHA",
    "rulespec_us_ref": "RULESPEC_US_SHA",
    "axiom_compose_ref": "AXIOM_COMPOSE_REF",
}


def workflow_toolchain(pins: dict[str, str]) -> str:
    return "[workflow_toolchain]\n" + "".join(
        f'{key} = "{value}"\n' for key, value in pins.items()
    )


def workflow_input_step() -> dict:
    import yaml

    steps = [
        step
        for job in yaml.safe_load(WORKFLOW.read_text())["jobs"].values()
        for step in job.get("steps", [])
    ]
    return next(step for step in steps if step.get("name") == "Validate immutable dependency inputs")


def run_workflow_inputs(
    root: Path, base: str, *, pins: dict[str, str] | None = None,
    event: str = "pull_request", head: str | None = None,
    caller_path: str = VALIDATION_CALLER,
    current_ref: str = "refs/heads/main",
    output: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    actual = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "", **(pins or {})}
    environment = {
        **os.environ,
        **{WORKFLOW_INPUT_ENV[key]: value for key, value in actual.items()},
        "EVENT_NAME": event,
        "PR_BASE_SHA": base if event in ("pull_request", "pull_request_target") else "",
        "MERGE_GROUP_BASE_SHA": base if event == "merge_group" else "",
        "CURRENT_SHA": head or git(root, "rev-parse", "HEAD"),
        "CURRENT_REF": current_ref,
        "DEFAULT_BRANCH": "main",
        "REPOSITORY": "example/rules",
        "CALLER_WORKFLOW_REF": f"example/rules/{caller_path}@{current_ref}",
        "GITHUB_SHA": head or git(root, "rev-parse", "HEAD"),
        "RELEASE_BASE_URL": "https://example.invalid",
        "RELEASE_REGISTRY_URL": "",
        "RELEASE_REGISTRY_ANON_KEY": "",
        "PYTHON_VERSION": "3.13",
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
        "PYTHONPATH": str(root),
        "GITHUB_OUTPUT": str(output) if output else os.devnull,
    }
    return subprocess.run(
        ["bash", "-c", workflow_input_step()["run"]],
        cwd=root, env=environment, capture_output=True, text=True,
    )


class WorkflowInputFixture:
    def __init__(self, *, table: str | None = None, caller: str | None = None) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="encoder-guard-inputs-",
            # Respect an owned external parent so bounded runs can also clean
            # incomplete fixtures after their subprocess group is terminated.
            dir=os.environ.get("TMPDIR") or ("/private/tmp" if Path("/private/tmp").is_dir() else None),
        )
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.name", "Workflow test")
        git(self.root, "config", "user.email", "workflow-test@example.com")
        self.write("fixture.txt", "base\n")
        if table is not None:
            self.write(WORKFLOW_TOOLCHAIN, table)
        if caller is not None:
            self.write(VALIDATION_CALLER, caller)
        self.base = commit(self.root, "fixture base")

    def __enter__(self) -> "WorkflowInputFixture":
        return self

    def __exit__(self, *_: object) -> None:
        self.temporary.cleanup()

    def write(self, path: str, text: str) -> None:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)

    def module(self) -> None:
        self.write("us/statutes/item.yaml", "fixture: changed module\n")
        self.write(".axiom/encoding-manifests/us/statutes/item.json", "{}\n")


def indirect_workflow_input_probe(route: str) -> None:
    """Replay candidate-controlled script/default/env pin sources as effective inputs."""
    import yaml

    caller = """name: Repository checks
on: pull_request
jobs:
  toolchain:
    USE_HELPER
  validate:
    needs: toolchain
    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    with:
      axiom-encode-ref: ${{ needs.toolchain.outputs.axiom_encode_ref }}
      axiom-rules-engine-ref: 3333333333333333333333333333333333333333
      axiom-corpus-ref: 6666666666666666666666666666666666666666
      rulespec-us-ref: 7777777777777777777777777777777777777777
      corpus-release-base-url: https://example.invalid
"""
    reader = """runs-on: ubuntu-latest
    outputs:
      axiom_encode_ref: ${{ steps.pins.outputs.axiom_encode_ref }}
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - id: pins
        run: python scripts/read_pins.py >> "$GITHUB_OUTPUT"
""".rstrip()
    caller = caller.replace(
        "USE_HELPER", reader if route == "script" else "uses: ./.github/workflows/read-pins.yml",
    )
    lowered = "1" * 40
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS), caller=caller) as fixture:
        if route == "script":
            helper = "scripts/read_pins.py"
            original = f'print("axiom_encode_ref={WORKFLOW_INPUT_PINS["axiom_encode_ref"]}")\n'
            proposed = f'print("axiom_encode_ref={lowered}")\n'
        elif route == "input-default":
            helper = ".github/workflows/read-pins.yml"
            original = (
                "name: Read pins\non:\n  workflow_call:\n    inputs:\n"
                "      encoder-ref:\n        type: string\n        required: false\n"
                f'        default: "{WORKFLOW_INPUT_PINS["axiom_encode_ref"]}"\n'
                "    outputs:\n      axiom_encode_ref:\n"
                "        value: ${{ jobs.pins.outputs.axiom_encode_ref }}\n"
                "jobs:\n  pins:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      axiom_encode_ref: ${{ steps.output.outputs.axiom_encode_ref }}\n"
                "    env:\n      AXIOM_ENCODE_REF: ${{ inputs.encoder-ref }}\n"
                "    steps:\n      - id: output\n"
                '        run: echo "axiom_encode_ref=$AXIOM_ENCODE_REF" >> "$GITHUB_OUTPUT"\n'
            )
            proposed = original.replace(WORKFLOW_INPUT_PINS["axiom_encode_ref"], lowered)
        else:
            assert route == "env"
            helper = ".github/workflows/read-pins.yml"
            original = (
                "name: Read pins\non:\n  workflow_call:\n    outputs:\n"
                "      axiom_encode_ref:\n        value: ${{ jobs.pins.outputs.axiom_encode_ref }}\n"
                "jobs:\n  pins:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      axiom_encode_ref: ${{ steps.output.outputs.axiom_encode_ref }}\n"
                f'    env:\n      AXIOM_ENCODE_REF: "{WORKFLOW_INPUT_PINS["axiom_encode_ref"]}"\n'
                "    steps:\n      - id: output\n"
                '        run: echo "axiom_encode_ref=$AXIOM_ENCODE_REF" >> "$GITHUB_OUTPUT"\n'
            )
            proposed = original.replace(WORKFLOW_INPUT_PINS["axiom_encode_ref"], lowered)
        fixture.write(helper, original)
        fixture.base = commit(fixture.root, "fixture helper")
        fixture.write(helper, proposed)
        fixture.module()
        head = commit(fixture.root, "fixture candidate")
        if route == "script":
            output = subprocess.run(
                [sys.executable, "-I", str(fixture.root / helper)],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            effective = output.split("=", 1)[1]
        elif route == "input-default":
            payload = yaml.safe_load(proposed)
            effective = payload.get("on", payload.get(True))["workflow_call"]["inputs"]["encoder-ref"]["default"]
        else:
            effective = yaml.safe_load(proposed)["jobs"]["pins"]["env"]["AXIOM_ENCODE_REF"]
        for path in (WORKFLOW_TOOLCHAIN, VALIDATION_CALLER):
            assert git(fixture.root, "rev-parse", f"{fixture.base}:{path}") == git(fixture.root, "rev-parse", f"{head}:{path}")
        control = run_workflow_inputs(fixture.root, fixture.base)
        assert control.returncode == 0, control.stderr
        result = run_workflow_inputs(fixture.root, fixture.base, pins={"axiom_encode_ref": effective})
        assert result.returncode != 0, f"{route} pin rollback passed: {result.stdout}"
        assert "axiom_encode_ref" in result.stderr


def test_indirect_script_encoder_pin_cannot_validate_changed_module() -> None:
    indirect_workflow_input_probe("script")


def test_reusable_workflow_input_default_cannot_validate_changed_module() -> None:
    indirect_workflow_input_probe("input-default")


def test_reusable_workflow_env_pin_cannot_validate_changed_module() -> None:
    indirect_workflow_input_probe("env")


def test_every_effective_dependency_matches_protected_workflow_toolchain() -> None:
    pins = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "2" * 40}
    direct = (
        "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "    with:\n      axiom-encode-ref: ${{ needs.toolchain.outputs.axiom_encode_ref }}\n"
    )
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=direct) as fixture:
        for key in pins:
            actual = {"axiom_compose_ref": pins["axiom_compose_ref"], key: "1" * 40}
            result = run_workflow_inputs(fixture.root, fixture.base, pins=actual)
            assert result.returncode != 0, f"unprotected input: {key}"
            assert key in result.stderr
        for actual in ({}, {"axiom_compose_ref": pins["axiom_compose_ref"]}):
            result = run_workflow_inputs(fixture.root, fixture.base, pins=actual)
            assert result.returncode == 0, result.stderr
        noncanonical = run_workflow_inputs(fixture.root, fixture.base, caller_path=".github/workflows/wrapper.yml")
        assert noncanonical.returncode != 0
    # A staged composer pin is compatible with an older encoder only while the
    # trusted caller has not enabled the composer input. Once enabled, a helper
    # cannot disable it by supplying an empty effective value.
    caller = (
        "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "    with:\n      axiom-compose-ref: ${{ needs.toolchain.outputs.axiom_compose_ref }}\n"
    )
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
        disabled = run_workflow_inputs(fixture.root, fixture.base)
        assert disabled.returncode != 0
        assert "axiom_compose_ref" in disabled.stderr
        enabled = run_workflow_inputs(fixture.root, fixture.base, pins={"axiom_compose_ref": pins["axiom_compose_ref"]})
        assert enabled.returncode == 0, enabled.stderr
    wrapper = "name: Repository checks\non: pull_request\njobs:\n  validate:\n    uses: ./.github/workflows/wrapper.yml\n"
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=wrapper) as fixture:
        fixture.write(".github/workflows/wrapper.yml", caller)
        fixture.base = commit(fixture.root, "fixture composer wrapper")
        assert run_workflow_inputs(fixture.root, fixture.base).returncode != 0
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=direct) as fixture:
        fixture.write(".github/workflows/wrapper.yml", caller)
        fixture.base = commit(fixture.root, "fixture additional composer caller")
        assert run_workflow_inputs(fixture.root, fixture.base, caller_path=".github/workflows/wrapper.yml").returncode != 0


def test_protected_workflow_toolchain_fails_closed() -> None:
    variants = (
        "not TOML [\n",
        "[other_table]\n",
        workflow_toolchain({"axiom_encode_ref": WORKFLOW_INPUT_PINS["axiom_encode_ref"]}),
        workflow_toolchain({**WORKFLOW_INPUT_PINS, "axiom_corpus_ref": "main"}),
        workflow_toolchain(WORKFLOW_INPUT_PINS) + 'axiom_encode_ref = "' + "1" * 40 + '"\n',
    )
    for table in variants:
        with WorkflowInputFixture(table=table) as fixture:
            result = run_workflow_inputs(fixture.root, fixture.base)
            assert result.returncode != 0, table
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        fixture.write("pins.toml", workflow_toolchain(WORKFLOW_INPUT_PINS))
        path = fixture.root / WORKFLOW_TOOLCHAIN
        path.unlink()
        path.symlink_to("../pins.toml")
        symlink_base = commit(fixture.root, "fixture symlink")
        assert run_workflow_inputs(fixture.root, symlink_base).returncode != 0
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        (fixture.root / WORKFLOW_TOOLCHAIN).unlink()
        deleted_base = commit(fixture.root, "fixture removal")
        assert run_workflow_inputs(fixture.root, deleted_base).returncode != 0
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        assert run_workflow_inputs(fixture.root, "a" * 40).returncode != 0


def test_pin_only_candidate_uses_protected_base_and_landed_pin_uses_new_base() -> None:
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        changed = {**WORKFLOW_INPUT_PINS, "axiom_encode_ref": "e" * 40}
        fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain(changed))
        head = commit(fixture.root, "fixture pin change")
        for event in ("pull_request", "pull_request_target", "merge_group"):
            protected = run_workflow_inputs(fixture.root, fixture.base, event=event)
            assert protected.returncode == 0, protected.stderr
            proposed = run_workflow_inputs(fixture.root, fixture.base, pins=changed, event=event)
            assert proposed.returncode == 0, proposed.stderr
        landed = run_workflow_inputs(fixture.root, head, pins=changed, event="push", head=head)
        assert landed.returncode == 0, landed.stderr


def test_legacy_literal_workflow_inputs_preserve_old_encoder_compatibility() -> None:
    caller = (
        "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "    with:\n" + "".join(
            f"      {key.replace('_', '-')}: {value}\n" for key, value in WORKFLOW_INPUT_PINS.items()
        )
    )
    with WorkflowInputFixture(caller=caller) as fixture:
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode == 0, result.stderr
        fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain({**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "2" * 40}))
        initialized = run_workflow_inputs(fixture.root, fixture.base)
        assert initialized.returncode == 0, initialized.stderr
        rollback = run_workflow_inputs(fixture.root, fixture.base, pins={"axiom_encode_ref": "1" * 40})
        assert rollback.returncode != 0
        (fixture.root / VALIDATION_CALLER).rename(fixture.root / ".github/workflows/validate.yml")
        (fixture.root / WORKFLOW_TOOLCHAIN).unlink()
        removed = commit(fixture.root, "fixture moved caller")
        assert run_workflow_inputs(fixture.root, removed).returncode != 0
    # Existing tables can predate the canonical-target pin key; the trusted
    # literal caller still binds that effective input without an encoder bump.
    legacy_table = {key: value for key, value in WORKFLOW_INPUT_PINS.items() if key != "rulespec_us_ref"}
    with WorkflowInputFixture(table=workflow_toolchain(legacy_table), caller=caller) as fixture:
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode == 0, result.stderr
        rollback = run_workflow_inputs(fixture.root, fixture.base, pins={"rulespec_us_ref": "1" * 40})
        assert rollback.returncode != 0


def test_workflow_input_protection_precedes_dependency_checkout() -> None:
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"]["shards"]["steps"]
    step = workflow_input_step()
    assert step["env"]["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha || '' }}"
    assert step["env"]["MERGE_GROUP_BASE_SHA"] == "${{ github.event.merge_group.base_sha || '' }}"
    assert step["env"]["CURRENT_SHA"] == "${{ github.sha }}"
    assert step["env"]["EVENT_NAME"] == "${{ github.event_name }}"
    assert "python -I - <<'PYPINS'" in step["run"]
    assert steps.index(step) == 3
    assert steps[2]["name"] == "Install the ProgramSpec shape-check parser"
    assert "python -I -m pip --isolated install" in steps[2]["run"]
    assert steps[2]["working-directory"] == "${{ runner.temp }}"
    assert workflow["jobs"]["validate"]["needs"] == "shards"
    assert WORKFLOW.read_text().index("      - name: Validate immutable dependency inputs") < WORKFLOW.read_text().index("      - name: Checkout axiom-encode")


def test_protected_workflow_yaml_cannot_disguise_active_composer() -> None:
    pins = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "2" * 40}
    direct = (
        "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "    with:\n"
    )
    encoded = direct + r'      "axiom\u002dcompose\u002dref": ${{ needs.toolchain.outputs.compose }}' + "\n"
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=encoded) as fixture:
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode != 0, "escaped input key disabled protected composer"
        assert "axiom_compose_ref" in result.stderr
    disguised = (
        "name: Repository checks\non: pull_request\nenv:\n  CALLER_DESCRIPTION: |\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "jobs:\n  validate:\n    uses: ./.github/workflows/wrapper.yml\n"
    )
    with WorkflowInputFixture(table=workflow_toolchain(pins), caller=disguised) as fixture:
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode != 0, "block scalar spoofed direct validator caller"
    duplicates = (
        direct + "      axiom-compose-ref: " + "2" * 40 + "\n      axiom-compose-ref: ''\n",
        direct + "      <<: {axiom-compose-ref: " + "2" * 40 + "}\n",
    )
    for caller in duplicates:
        with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
            assert run_workflow_inputs(fixture.root, fixture.base).returncode != 0


def test_caller_scalar_loader_matches_ruleset_guard() -> None:
    """Both isolated consumers embed exactly the same strict caller loader."""
    import yaml

    guard = yaml.safe_load((ROOT / ".github/workflows/encoder-guard.yml").read_text())
    guard_run = next(step["run"] for step in guard["jobs"]["guard"]["steps"]
                     if step.get("name") == "Reject RuleSpec modules without encoder manifests")
    binding_run = workflow_input_step()["run"]
    begin, end = "# strict-caller-loader-start", "# strict-caller-loader-end"
    assert begin in guard_run and begin in binding_run, "caller loaders do not share a strict grammar"
    assert guard_run.split(begin, 1)[1].split(end, 1)[0] == binding_run.split(begin, 1)[1].split(end, 1)[0]


def test_literal_numeric_looking_pins_keep_exact_string_identity() -> None:
    pins = {key: "0" * 39 + str(index) for index, key in enumerate(WORKFLOW_INPUT_PINS, 1)}
    caller = literal_pin_caller(pins).replace("'", "")
    with WorkflowInputFixture(caller=caller) as fixture:
        result = run_workflow_inputs(fixture.root, fixture.base, pins=pins)
        assert result.returncode == 0, result.stderr


def test_binding_rejects_caller_pin_lines_outside_printable_ascii_lf() -> None:
    caller = literal_pin_caller(WORKFLOW_INPUT_PINS)
    line = next(line for line in caller.split("\n") if "axiom-encode-ref:" in line)
    variants = (
        caller.replace(line + "\n", line + "\x0c\n"),
        caller.replace(line + "\n", line + "\x85\n"),
        caller.replace(line + "\n", line + "\u2028\n"),
        caller.replace(line + "\n", line + "\x7f\n"),
        caller.replace(line + "\n", line + "\u00e9\n"),
        caller.replace(line + "\n", line + "\r\n"),
        caller.replace("axiom-encode-ref: ", "axiom-encode-ref:\t"),
    )
    for proposed in variants:
        with WorkflowInputFixture(caller=proposed) as fixture:
            result = run_workflow_inputs(fixture.root, fixture.base)
            assert result.returncode != 0, repr(proposed)
            assert "printable ASCII" in result.stderr, result.stderr
            assert "Traceback" not in result.stderr


def test_protected_workflow_inputs_reject_untrusted_event_sources() -> None:
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        for event in ("workflow_run", "repository_dispatch", "pull_request_review"):
            result = run_workflow_inputs(fixture.root, fixture.base, event=event)
            assert result.returncode != 0, event
        for event in ("push", "schedule", "workflow_dispatch"):
            output = fixture.root / f"{event}-output"
            control = run_workflow_inputs(fixture.root, fixture.base, event=event, output=output)
            assert control.returncode == 0, (event, control.stdout, control.stderr)
            assert output.exists(), event
            assert "Traceback" not in control.stderr, control.stderr
            result = run_workflow_inputs(
                fixture.root, fixture.base, event=event,
                current_ref="refs/heads/candidate", output=output,
            )
            assert result.returncode == 1, (event, result.stdout, result.stderr)
            assert result.stderr == (
                "ProtectedWorkflowInputError: non-PR validation must run on the protected default branch\n"
            ), (event, result.stderr)
            assert "Traceback" not in result.stderr, result.stderr


def test_protected_workflow_input_imports_ignore_candidate_python() -> None:
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        source = 'from pathlib import Path\nPath("candidate-executed").write_text("executed")\n'
        for path in ("sitecustomize.py", "tomllib.py", "yaml.py"):
            fixture.write(path, source)
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode == 0, result.stderr
        assert not (fixture.root / "candidate-executed").exists()
SELECTOR_TOOLCHAIN = (
    '[toolchain]\n'
    'axiom_corpus_release = "before"\n'
    f'axiom_corpus_release_content_sha256 = "{"a" * 64}"\n'
    f'validation_waiver_set_sha256 = "{"b" * 64}"\n'
)
SELECTOR_WORKFLOW_TOOLCHAIN = (
    '[workflow_toolchain]\n'
    f'axiom_encode_ref = "{"a" * 40}"\n'
    f'axiom_rules_engine_ref = "{"b" * 40}"\n'
    f'axiom_compose_ref = "{"c" * 40}"\n'
    f'axiom_corpus_ref = "{"d" * 40}"\n'
    f'rulespec_us_ref = "{"e" * 40}"\n'
)
SELECTOR_MODULES = ["us/regulations/two.yml", "us/statutes/one.yaml"]
SELECTOR_COMPANIONS = ["us/regulations/two.test.yml", "us/statutes/one.test.yaml"]


def selector_shell_source(source: str) -> str:
    """Supply Bash 3 compatibility while preserving the workflow Python body."""
    bash_major = subprocess.run(
        ["bash", "-c", 'printf "%s" "${BASH_VERSINFO[0]}"'],
        check=True, capture_output=True, text=True,
    ).stdout
    if int(bash_major) < 4:
        # Bash 3 misparses the compute heredoc inside process substitution.
        # Pass its exact Python body to isolated -c; keep the actual outer
        # discovery, selection and output assembly shell under test.
        source = re.sub(
            r"python3 -I <<'PY'\n(.*?)^PY$",
            lambda match: "python3 -I -c " + shlex.quote(match.group(1)),
            source, flags=re.MULTILINE | re.DOTALL,
        )
    return textwrap.dedent("""\
        if ! type mapfile >/dev/null 2>&1; then
          # Bash 3 expands braces in Python heredocs inside process substitution.
          # The workflow runs Bash 5; disable that legacy parsing bug locally.
          set +B
          mapfile() {
            local delimiter=$'\\n' destination line
            while [ "$#" -gt 1 ]; do
              case "$1" in
                -t) shift ;;
                -d) delimiter="$2"; shift 2 ;;
                *) return 2 ;;
              esac
            done
            destination="$1"
            eval "$destination=()"
            while IFS= read -r -d "$delimiter" line || [ -n "$line" ]; do
              eval "$destination+=(\\"\\$line\\")"
            done
          }
        fi
        """) + source


def run_validation_targets(
    changes: dict[str, str], *, event: str = "pull_request"
) -> tuple[str, list[str], list[str]]:
    """Execute the workflow's real selector against a synthetic Git diff."""
    import yaml

    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    step = next(s for s in steps if s.get("id") == "validation_targets")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")

        def write(path: str, content: str) -> None:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)

        files = {
            ".axiom/toolchain.toml": SELECTOR_TOOLCHAIN,
            ".axiom/workflow-toolchain.toml": SELECTOR_WORKFLOW_TOOLCHAIN,
            VALIDATION_CALLER: literal_pin_caller(WORKFLOW_INPUT_PINS),
            "README.md": "before\n",
            **{path: "fixture\n" for path in SELECTOR_MODULES + SELECTOR_COMPANIONS},
        }
        for path, content in files.items():
            write(path, content)
        base = commit(root, "selector base")
        for path, content in changes.items():
            write(path, content)
        head = commit(root, "selector head")
        assert git(root, "diff", "--name-only", base, head).splitlines() == sorted(changes)

        runner_temp = root / "runner-temp"
        runner_temp.mkdir()
        bound_output = runner_temp / "bound-output"
        import tomllib
        original_pins = tomllib.loads(SELECTOR_WORKFLOW_TOOLCHAIN)["workflow_toolchain"]
        binding = run_workflow_inputs(root, base, pins={**original_pins, "axiom_compose_ref": ""},
                                      event=event, head=head, output=bound_output)
        assert binding.returncode == 0, binding.stderr
        bound = dict(line.split("=", 1) for line in bound_output.read_text().splitlines())
        output = runner_temp / "output"
        source = (
            step["run"]
            .replace("${{ github.event_name }}", event)
            .replace("${{ github.event.pull_request.base.sha }}", base)
        )
        assert "${{" not in source
        result = subprocess.run(
            ["bash", "-c", selector_shell_source(source)],
            cwd=root,
            env={
                **os.environ,
                "GITHUB_SHA": head,
                "RUNNER_TEMP": str(runner_temp),
                "GITHUB_ENV": str(runner_temp / "env"),
                "GITHUB_OUTPUT": str(output),
                "VALIDATE_ROOTS": "us",
                "VALIDATE_ROOTS_INPUT": "auto",
                "DEPENDENCY_PINS_CHANGED": bound.get("dependency_pins_changed", "false"),
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        mode = dict(line.split("=", 1) for line in output.read_text().splitlines())["mode"]
        return (
            mode,
            (runner_temp / "rulespec-files.txt").read_text().splitlines(),
            (runner_temp / "rulespec-test-files.txt").read_text().splitlines(),
        )


def test_validation_targets_workflow_toolchain_pin_only_requires_full_validation() -> None:
    for pin in ("a", "b", "c", "d", "e"):
        changed = SELECTOR_WORKFLOW_TOOLCHAIN.replace(pin * 40, "f" * 40)
        assert run_validation_targets({".axiom/workflow-toolchain.toml": changed}) == (
            "full-toolchain-bump", SELECTOR_MODULES, SELECTOR_COMPANIONS
        ), pin

    # A corpus-only shortcut must not suppress a workflow dependency re-pin.
    assert run_validation_targets({
        ".axiom/toolchain.toml": SELECTOR_TOOLCHAIN.replace('"before"', '"after"'),
        ".axiom/workflow-toolchain.toml": changed,
    }) == ("full-toolchain-bump", SELECTOR_MODULES, SELECTOR_COMPANIONS)


def test_workflow_edits_without_dependency_pin_changes_use_changed_guard() -> None:
    for path in (".github/workflows/validate.yml", ".github/workflows/validate.yaml"):
        assert run_validation_targets({path: "changed\n"}) == ("changed", [], [])
    commented = SELECTOR_WORKFLOW_TOOLCHAIN + "# unchanged refs\n"
    assert run_validation_targets({".axiom/workflow-toolchain.toml": commented}) == ("changed", [], [])


def test_manifest_audit_flag_tracks_actual_dependency_and_validator_refs() -> None:
    pins = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "7" * 40,
            "shared_workflow_ref": "842c69d6aa62a0d75a4da850fabc3d0df20701d7"}
    caller = literal_pin_caller({key: value for key, value in pins.items() if key != "shared_workflow_ref"})
    caller = caller.replace("@" + "a" * 40, "@" + pins["shared_workflow_ref"])
    for key in (*pins, "workflow-comment"):
        with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
            changed = {**pins, key: "9" * 40} if key in pins else pins
            table = workflow_toolchain(changed)
            if key == "workflow-comment":
                table += "# retained dependency pins\n"
            fixture.write(WORKFLOW_TOOLCHAIN, table)
            if key == "shared_workflow_ref":
                fixture.write(VALIDATION_CALLER, caller.replace(pins[key], changed[key]))
            head = commit(fixture.root, "fixture configuration update")
            output = fixture.root / "binding-output"
            result = run_workflow_inputs(fixture.root, fixture.base,
                                         pins={key: value for key, value in pins.items() if key in WORKFLOW_INPUT_ENV},
                                         head=head, output=output)
            assert result.returncode == 0, result.stderr
            bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
            assert bound["dependency_pins_changed"] == ("false" if key == "workflow-comment" else "true"), key
            assert bound["base_axiom_encode_ref"] == pins["axiom_encode_ref"]
            assert bound["base_axiom_corpus_ref"] == pins["axiom_corpus_ref"]


def test_corpus_release_metadata_companion_preserves_proposed_pin_binding() -> None:
    pins = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "7" * 40, "shared_workflow_ref": "8" * 40}
    caller = literal_pin_caller(WORKFLOW_INPUT_PINS).replace("@" + "a" * 40, "@" + pins["shared_workflow_ref"])
    for key in (*pins, "metadata-only"):
        with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
            fixture.write(".axiom/toolchain.toml", SELECTOR_TOOLCHAIN)
            fixture.base = commit(fixture.root, "base with corpus release metadata")
            proposed = {**pins, key: "9" * 40} if key in pins else pins
            fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain(proposed))
            fixture.write(".axiom/toolchain.toml", SELECTOR_TOOLCHAIN.replace('"before"', '"after"'))
            if key == "shared_workflow_ref":
                fixture.write(VALIDATION_CALLER, caller.replace(pins[key], proposed[key]))
            head = commit(fixture.root, "configuration with corpus release metadata")
            output = fixture.root / "binding-output"
            result = run_workflow_inputs(fixture.root, fixture.base,
                                         pins={name: value for name, value in proposed.items() if name in WORKFLOW_INPUT_PINS},
                                         head=head, output=output)
            assert result.returncode == 0, (key, result.stderr)
            bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
            assert all(bound[name] == proposed[name] for name in WORKFLOW_INPUT_PINS), (key, bound)
            assert bound["axiom_compose_ref"] == "", "staged composer must remain inactive"
            assert bound["dependency_pins_changed"] == ("false" if key == "metadata-only" else "true"), key
            assert bound["base_axiom_encode_ref"] == pins["axiom_encode_ref"]
            assert bound["base_axiom_corpus_ref"] == pins["axiom_corpus_ref"]


def test_legacy_binding_validator_adoption_keeps_encoder_pin_and_enables_ratchet() -> None:
    for encoder, corpus in (
        ("a9987a4bc6a58e3f0407972f2e5726b7092b9c4b", "581d60b4af079be27c1758832814b5623fa8ac19"),
        ("c326d1ac0acdb557f047a3054160b19dd72602fa", "440162d04375a5071f2ac02de94f85def3e74053"),
    ):
        pins = {"axiom_encode_ref": encoder, "axiom_rules_engine_ref": "05eac9d2f89dabe5c6673176260762cef3a58f47",
                "axiom_corpus_ref": corpus, "rulespec_us_ref": "0f291b367bf7e15555f9973112278c5cbf221653",
                "shared_workflow_ref": "842c69d6aa62a0d75a4da850fabc3d0df20701d7"}
        caller = literal_pin_caller({key: value for key, value in pins.items() if key != "shared_workflow_ref"})
        caller = caller.replace("@" + "a" * 40, "@" + pins["shared_workflow_ref"])
        with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
            fixture.write("statutes/legacy.yaml", "fixture: unchanged\n")
            fixture.base = commit(fixture.root, "unmanifested legacy base")
            fixture.write(VALIDATION_CALLER, caller.replace(pins["shared_workflow_ref"], "f" * 40))
            fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain({**pins, "shared_workflow_ref": "f" * 40}))
            head = commit(fixture.root, "validator adoption at unchanged encoder")
            output = fixture.root / "binding-output"
            result = run_workflow_inputs(fixture.root, fixture.base,
                                         pins={key: value for key, value in pins.items() if key in WORKFLOW_INPUT_ENV},
                                         head=head, output=output)
            assert result.returncode == 0, result.stderr
            bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
            assert bound["base_axiom_encode_ref"] == bound["axiom_encode_ref"] == encoder
            assert bound["dependency_pins_changed"] == "true"


def test_validation_targets_preserve_other_path_classifications() -> None:
    full = ("full-toolchain-bump", SELECTOR_MODULES, SELECTOR_COMPANIONS)
    corpus_only = SELECTOR_TOOLCHAIN.replace('"before"', '"after"')
    cases = [
        ({".github/workflows/validate.yml": "changed\n"}, ("changed", [], [])),
        ({".github/workflows/validate.yaml": "changed\n"}, ("changed", [], [])),
        ({".axiom/toolchain.toml": SELECTOR_TOOLCHAIN.replace("b" * 64, "c" * 64)}, full),
        ({".axiom/toolchain.toml": corpus_only}, ("changed-corpus-toolchain-bump", [], [])),
        ({"README.md": "changed\n"}, ("changed", [], [])),
        ({".axiom/other.toml": "changed\n"}, ("changed", [], [])),
        ({"us/statutes/one.yaml": "changed\n"},
         ("changed", ["us/statutes/one.yaml"], ["us/statutes/one.test.yaml"])),
        ({"us/statutes/one.test.yaml": "changed\n"},
         ("changed", ["us/statutes/one.yaml"], ["us/statutes/one.test.yaml"])),
        ({".axiom/toolchain.toml": corpus_only, "us/statutes/one.yaml": "changed\n"},
         ("changed-corpus-toolchain-bump", ["us/statutes/one.yaml"], ["us/statutes/one.test.yaml"])),
    ]
    for changes, expected in cases:
        assert run_validation_targets(changes) == expected, changes
    assert run_validation_targets({"README.md": "changed\n"}, event="push") == (
        "full-push", SELECTOR_MODULES, SELECTOR_COMPANIONS
    )


# The workflow discovers `*/` in C-locale glob order: '-' sorts before '/'.
SELECTION_JURISDICTIONS = ["us-ca", "us-fl", "us-ma", "us-sc", "us"]


def selection_module(*imports: str, null_imports: bool = False, proof: str = "") -> str:
    import yaml

    document: dict = {
        "format": "rulespec/v1",
        "imports": None if null_imports else list(imports),
        "rules": [],
    }
    if proof:
        document["rules"] = [{
            "name": "fixture",
            "metadata": {"proof": {"atoms": [{
                "kind": "import",
                "import": {"target": proof, "output": "fixture", "hash": "a" * 64},
            }]}},
        }]
    return yaml.safe_dump(document, sort_keys=False)


def selection_import_evidence(target: str, *, kind: str = "parameter") -> dict:
    # The Colorado parameter proof uses local import evidence independently
    # of its proof kind. These are selector fixtures, not corpus modules.
    return {
        "path": "versions[0].formula",
        "kind": kind,
        "import": {"target": target, "output": "fixture", "hash": "sha256:local"},
    }


def selection_evidence_module(atom: dict) -> str:
    import yaml

    return yaml.safe_dump({
        "format": "rulespec/v1",
        "imports": [],
        "rules": [{"name": "fixture", "metadata": {"proof": {"atoms": [atom]}}}],
    }, sort_keys=False)


def selection_program(owner: str, scope: dict) -> str:
    import yaml

    return yaml.safe_dump({
        "program": f"{owner}/fixture",
        "period": "2026",
        "outputs": ["fixture"],
        "scope": scope,
    }, sort_keys=False)


def selection_manifest(*paths: str, revision: int = 0) -> str:
    return json.dumps({
        "schema_version": "axiom-encode/applied-rulespec/v5",
        "revision": revision,
        "applied_files": [{"path": path, "sha256": "a" * 64} for path in paths],
    }) + "\n"


def selection_files(jurisdictions: list[str] = SELECTION_JURISDICTIONS) -> dict[str, str]:
    files = {
        ".axiom/toolchain.toml": SELECTOR_TOOLCHAIN,
        ".axiom/workflow-toolchain.toml": SELECTOR_WORKFLOW_TOOLCHAIN,
        "README.md": "before\n",
    }
    for jurisdiction in jurisdictions:
        files[f"{jurisdiction}/statutes/local.yaml"] = selection_module()
        files[f"{jurisdiction}/statutes/local.test.yaml"] = "tests: []\n"
        files[f"{jurisdiction}/regulations/independent.yml"] = selection_module(null_imports=True)
        files[f"{jurisdiction}/regulations/independent.test.yml"] = "tests: []\n"
        # Neither noncanonical source trees nor composition specs are atomic targets.
        files[f"{jurisdiction}/manual/context.yaml"] = "source: context\n"
    return files


@lru_cache(maxsize=2)
def selection_workflow(source: str) -> dict:
    import yaml

    # Fixture runs only read this workflow. Key by its exact content so
    # differential runs still execute the appropriate base/current scripts.
    return yaml.safe_load(source)


def run_import_aware_selection(
    changes: dict[str, str | None],
    *,
    files: dict[str, str] | None = None,
    enabled: bool | None = True,
    event: str = "pull_request",
    base_override: str | None = None,
    head_override: str | None = None,
    guard_programs: bool = False,
    roots_input: str = "auto",
    fail_git: str = "",
    shape_programs: tuple[str, ...] = (),
    dependency_pins_changed: bool = False,
) -> dict:
    """Run real compute, root-resolution and target shell against protected Git trees."""
    workflow = selection_workflow(WORKFLOW.read_text())
    compute = next(s for s in workflow["jobs"]["shards"]["steps"] if s.get("id") == "compute")
    steps = workflow["jobs"]["validate"]["steps"]
    resolve = next(s for s in steps if s.get("id") == "resolve_roots")
    targets = next(s for s in steps if s.get("id") == "validation_targets")
    with tempfile.TemporaryDirectory(prefix="rulespec-selector-") as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")

        def write(path: str, content: str) -> None:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)

        baseline = selection_files() if files is None else files
        for path, content in baseline.items():
            if path not in shape_programs:
                write(path, content)
        if shape_programs:
            shape_base = commit(root, "before program specs")
            for path in shape_programs:
                write(path, baseline[path])
        base = commit(root, "selection base")
        if shape_programs:
            precheck = next(s for s in workflow["jobs"]["shards"]["steps"]
                            if s.get("name") == "Reject unmanifested RuleSpec content")
            shape = subprocess.run(
                ["bash", "-c", precheck["run"]], cwd=root,
                env={**os.environ, "BASE_SHA": shape_base, "GITHUB_SHA": base,
                     "GITHUB_REPOSITORY": "TheAxiomFoundation/rulespec-us",
                     "EVENT_NAME": "pull_request", "RUN_GENERATED_GUARD": "true",
                     "GUARD_PROGRAMS_ROOT": "false"},
                capture_output=True, text=True, timeout=60,
            )
            assert shape.returncode == 0, shape.stdout + shape.stderr
            assert f"{len(shape_programs)} changed ProgramSpec file(s) have the ProgramSpec shape (scan=diff)" in shape.stdout
        for path, content in changes.items():
            if content is None:
                (root / path).unlink()
            else:
                write(path, content)
        git(root, "add", "-A")
        git(root, "commit", "--allow-empty", "-qm", "selection head")
        head = git(root, "rev-parse", "HEAD")
        base = base if base_override is None else base_override
        head = head if head_override is None else head_override
        runner_temp = root / "runner-temp"
        runner_temp.mkdir()
        env = {
            **os.environ,
            "LC_ALL": "C",
            "GITHUB_SHA": head,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_ENV": str(runner_temp / "env"),
            "VALIDATE_ROOTS_INPUT": roots_input,
            "GUARD_PROGRAMS_ROOT": str(guard_programs).lower(),
            "EVENT_NAME": event,
            "PR_BASE_SHA": base,
            "HEAD_SHA": head,
            "DEPENDENCY_PINS_CHANGED": str(dependency_pins_changed).lower(),
        }
        # Absence models a caller that does not supply the new workflow input.
        env.pop("IMPORT_AWARE_SELECTION", None)
        if enabled is not None:
            env["IMPORT_AWARE_SELECTION"] = str(enabled).lower()
        if fail_git:
            bin_path = runner_temp / "bin"
            bin_path.mkdir()
            real_git = subprocess.run(["which", "git"], check=True, capture_output=True, text=True).stdout.strip()
            wrapper = bin_path / "git"
            wrapper.write_text(
                "#!/bin/sh\n"
                f'if [ "$1" = "{fail_git}" ]; then exit 1; fi\n'
                f'exec "{real_git}" "$@"\n'
            )
            wrapper.chmod(0o755)
            env["PATH"] = str(bin_path) + os.pathsep + env["PATH"]

        raw_outputs = {}
        diagnostics = {}

        def run(source: str, name: str, extra_env: dict[str, str] | None = None) -> dict[str, str]:
            output = runner_temp / f"{name}-output"
            result = subprocess.run(
                ["bash", "-c", selector_shell_source(source)],
                cwd=root,
                env={**env, **(extra_env or {}), "GITHUB_OUTPUT": str(output)},
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert result.returncode == 0, f"{name}: {result.stdout}{result.stderr}"
            assert output.exists(), f"{name}: no outputs; {result.stdout}{result.stderr}"
            raw_outputs[name] = output.read_bytes()
            diagnostics[name] = result.stderr
            return dict(line.split("=", 1) for line in output.read_text().splitlines())

        outputs = run(compute["run"], "compute")
        matrix = json.loads(outputs["matrix"])
        assert matrix, "required validation cannot pass with an empty matrix"
        assert outputs["first"] == matrix[0]
        revalidate = json.loads(outputs.get("revalidate-shards", "[]"))
        selected_targets = {}
        source = (
            targets["run"]
            .replace("${{ github.event_name }}", event)
            .replace("${{ github.event.pull_request.base.sha }}", base)
        )
        assert "${{" not in source
        for shard in matrix:
            roots = run(resolve["run"], f"resolve-{shard}", {"SHARD": shard})["roots"]
            target_outputs = run(source, f"targets-{shard}", {
                "VALIDATE_ROOTS": roots,
                "VALIDATION_SHARD": shard,
                "REVALIDATE_SHARDS": json.dumps(revalidate),
                "FULL_TARGETS": outputs.get("full-targets", "false"),
            })
            selected_targets[shard] = (
                target_outputs["mode"],
                (runner_temp / "rulespec-files.txt").read_text().splitlines(),
                (runner_temp / "rulespec-test-files.txt").read_text().splitlines(),
            )
            for filename in ("rulespec-files.txt", "rulespec-test-files.txt"):
                raw_outputs[f"targets-{shard}/{filename}"] = (runner_temp / filename).read_bytes()
        return {**outputs, "matrix": matrix, "revalidate": revalidate, "targets": selected_targets,
                "scope-diagnostics": diagnostics["compute"], "raw-outputs": raw_outputs}


def assert_selection(
    result: dict,
    expected: list[str],
    *,
    jurisdictions: list[str] = SELECTION_JURISDICTIONS,
    revalidate: list[str] | None = None,
    guard_programs: bool = False,
    full_targets: bool = False,
) -> None:
    assert result["matrix"] == expected, result
    assert result["first"] == expected[0], result
    assert result["roots"] == " ".join(jurisdictions) + (" programs" if guard_programs else ""), result
    assert result["allowed-extra"] == ("sources" if guard_programs else "sources programs"), result
    assert result.get("full-targets", "false") == str(full_targets).lower(), result
    if revalidate is not None:
        assert result["revalidate"] == revalidate, result


def assert_full_leg(result: dict, shard: str, files: dict[str, str], mode: str = "full-dependencies") -> None:
    modules = sorted(
        path for path in files if path.startswith(f"{shard}/")
        and path.split("/")[1] in {"statutes", "regulations", "policies", "legislation"}
        and path.endswith((".yaml", ".yml"))
        and not path.endswith((".test.yaml", ".test.yml"))
    )
    companions = sorted(
        path for path in files if path.startswith(f"{shard}/")
        and path.split("/")[1] in {"statutes", "regulations", "policies", "legislation"}
        and path.endswith((".test.yaml", ".test.yml"))
    )
    assert result["targets"][shard] == (mode, modules, companions), result


def test_import_selection_local_modules_and_companions() -> None:
    for path in ("us-fl/statutes/local.yaml", "us-fl/statutes/local.test.yaml"):
        result = run_import_aware_selection({path: selection_module() + "# changed\n"})
        assert_selection(result, ["us-fl"], revalidate=[])
        assert result["targets"]["us-fl"] == (
            "changed", ["us-fl/statutes/local.yaml"], ["us-fl/statutes/local.test.yaml"],
        )
    for extension in ("yaml", "yml"):
        module = f"us-fl/policies/new.{extension}"
        companion = f"us-fl/policies/new.test.{extension}"
        result = run_import_aware_selection({module: selection_module(), companion: "tests: []\n"})
        assert_selection(result, ["us-fl"], revalidate=[])
        assert result["targets"]["us-fl"] == ("changed", [module], [companion])
    # Independent jurisdictions no longer force a full matrix.
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": selection_module() + "# changed\n",
        "us-fl/regulations/independent.yml": selection_module() + "# changed\n",
    })
    assert_selection(result, ["us-fl", "us-ma"], revalidate=[])
    assert result["targets"]["us-fl"] == (
        "changed", ["us-fl/regulations/independent.yml"], ["us-fl/regulations/independent.test.yml"],
    )
    # Deleting a companion preserves its extant module; deleting both skips absent files.
    result = run_import_aware_selection({"us-fl/statutes/local.test.yaml": None})
    assert result["targets"]["us-fl"] == ("changed", ["us-fl/statutes/local.yaml"], [])
    result = run_import_aware_selection({
        "us-fl/statutes/local.yaml": None, "us-fl/statutes/local.test.yaml": None,
    })
    assert_selection(result, ["us-fl"], revalidate=[])
    assert result["targets"]["us-fl"] == ("changed", [], [])
    # Rename records are deliberately expanded as delete/add by the real diff.
    result = run_import_aware_selection({
        "us-fl/statutes/local.yaml": None, "us-fl/statutes/local.test.yaml": None,
        "us-ma/legislation/renamed.yml": selection_module(),
        "us-ma/legislation/renamed.test.yml": "tests: []\n",
    })
    assert_selection(result, ["us-fl", "us-ma"], revalidate=[])
    assert result["targets"]["us-ma"] == (
        "changed", ["us-ma/legislation/renamed.yml"], ["us-ma/legislation/renamed.test.yml"],
    )


def test_import_selection_transitive_graph_and_cycles() -> None:
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module("us-ma:statutes/local#first", "us-ma:regulations/independent#second")
    files["us-fl/statutes/local.yaml"] = selection_module("us-sc:statutes/local#fixture")
    files["us-ma/regulations/independent.yml"] = selection_module("us-ma:statutes/local#fixture")
    for provider in ("us-ma/statutes/local.yaml", "us-ma/regulations/independent.yml"):
        result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
        assert_selection(result, ["us-fl", "us-ma", "us-sc"])
        assert_full_leg(result, "us-sc", files)
        assert_full_leg(result, "us-fl", files)
        if provider.endswith("local.yaml"):
            assert_full_leg(result, "us-ma", files)
    # Companion-only edits pair their module without seeding importer closure.
    result = run_import_aware_selection({"us-ma/statutes/local.test.yaml": "tests: []\n# changed\n"}, files=files)
    assert_selection(result, ["us-ma"], revalidate=[])
    files["us-ma/statutes/local.yaml"] = selection_module("us-fl:statutes/local#fixture")
    result = run_import_aware_selection({"us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n"}, files=files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"])
    for shard in result["revalidate"]:
        assert_full_leg(result, shard, files)


def test_import_selection_dependencies_at_any_depth_and_in_companions() -> None:
    import yaml

    provider = "us/statutes/local.yaml"
    target = "us:statutes/local#fixture"
    atom = {"kind": "import", "import": {
        "target": target, "output": "fixture", "hash": "a" * 64,
    }}
    probes = [
        # These three forms were the independent review's missed-edge probes.
        ("us-fl/statutes/local.test.yaml", {"imports": [target], "tests": []}),
        ("us-fl/statutes/local.yaml", {"rules": [{"imports": [target]}]}),
        ("us-fl/statutes/local.yaml", {"rules": [{"metadata": {"proofs": [atom]}}]}),
        # Companion files also have a real root-array schema. Neither that
        # shape nor nesting an atom within it may hide a dependency.
        ("us-fl/statutes/local.test.yaml", [{"metadata": {"provenance": [atom]}}]),
        ("us-fl/statutes/local.test.yaml", [{"metadata": {"imports": [target]}}]),
        ("us-fl/statutes/local.yaml", {"imports": [target], "rules": [{
            "versions": [{"values": {2026: "fixture"}}],
        }]}),
    ]
    for importer, document in probes:
        files = {**selection_files(), importer: yaml.safe_dump(document, sort_keys=False)}
        result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
        assert_selection(result, ["us-fl", "us"], revalidate=["us-fl"])
        assert_full_leg(result, "us-fl", files)


def test_import_selection_parameter_evidence_self_edge() -> None:
    jurisdictions = ["us-ca", "us-co", "us-fl", "us-ma", "us-sc", "us"]
    colorado = "us-co/statutes/39/39-22-509.yaml"
    atom = selection_import_evidence(
        "us-co:statutes/39/39-22-509#minimum_in_state_employee_count",
    )
    atom["import"]["output"] = "minimum_in_state_employee_count"
    files = {**selection_files(jurisdictions), colorado: selection_evidence_module(atom)}
    # The unchanged self-edge previously forced every unrelated change full.
    result = run_import_aware_selection({
        "us-fl/statutes/local.yaml": files["us-fl/statutes/local.yaml"] + "# changed\n",
    }, files=files)
    assert_selection(result, ["us-fl"], jurisdictions=jurisdictions, revalidate=[])
    result = run_import_aware_selection({colorado: files[colorado] + "# changed\n"}, files=files)
    assert_selection(result, ["us-co"], jurisdictions=jurisdictions, revalidate=[])
    assert result["targets"]["us-co"] == ("changed", [colorado], [])


def test_import_selection_every_proof_kind_can_carry_import_evidence() -> None:
    # Encoder PROOF_ATOM_KINDS: proof kind and evidence are independent.
    # Start with parameter so the pre-fix selector fails on the reported bug.
    kinds = (
        "parameter", "amount", "condition", "definition", "default", "effective_period",
        "exception", "formula", "import", "ordering", "parameter_table", "predicate",
        "table_cell", "unit",
    )
    provider = "us-ma/statutes/local.yaml"
    for kind in kinds:
        files = selection_files()
        files["us-sc/statutes/local.yaml"] = selection_evidence_module(
            selection_import_evidence("us-ma:statutes/local#fixture", kind=kind),
        )
        files["us-fl/statutes/local.yaml"] = selection_evidence_module(
            selection_import_evidence("us-sc:statutes/local#fixture", kind=kind),
        )
        result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
        assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl", "us-sc"])
        for shard in ("us-fl", "us-sc"):
            assert_full_leg(result, shard, files)


def test_import_selection_parameter_evidence_in_companions_and_side_channels() -> None:
    import yaml

    provider = "us-ma/statutes/local.yaml"
    atom = selection_import_evidence("us-ma:statutes/local#fixture")
    probes = [
        ("us-sc/statutes/local.test.yaml", {"tests": [{"metadata": {"proof": {"atoms": [atom]}}}]}),
        ("us-sc/statutes/local.test.yaml", [{"metadata": {"provenance": [atom]}}]),
        ("us-sc/statutes/local.yaml", {"metadata": {"audit": [{"nested": {"evidence": [atom]}}]}}),
        ("us-sc/statutes/local.yaml", {"metadata": {"source": {"nested": [atom]}}}),
        # A proof atom's source remains a recursive dependency side channel,
        # even when the same atom already carries its own import evidence.
        ("us-sc/statutes/local.yaml", {"metadata": {
            **selection_import_evidence("us-sc:statutes/local#fixture"),
            "source": {"nested": [atom]},
        }}),
    ]
    for importer, document in probes:
        files = {**selection_files(), importer: yaml.safe_dump(document, sort_keys=False)}
        files["us-fl/statutes/local.yaml"] = selection_module("us-sc:statutes/local#fixture")
        result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
        assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl", "us-sc"])
        for shard in ("us-fl", "us-sc"):
            assert_full_leg(result, shard, files)
    # The strict YAML loader rejects a recursive alias. That remains an
    # explicit full fallback rather than concealing nested evidence.
    cycle: dict = {"evidence": [atom]}
    cycle["recursive"] = cycle
    files = {**selection_files(), "us-sc/statutes/local.yaml": yaml.safe_dump({"metadata": cycle})}
    result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    assert "scope=full (import analysis failed:" in result["scope-diagnostics"], result


def test_import_selection_parameter_evidence_base_only_and_deleted_provider() -> None:
    provider = "us-ma/statutes/local.yaml"
    importer = "us-sc/statutes/local.yaml"
    companion = "us-sc/statutes/local.test.yaml"
    files = selection_files()
    evidence = selection_evidence_module(selection_import_evidence("us-ma:statutes/local#fixture"))
    files[importer] = evidence
    files["us-fl/statutes/local.yaml"] = selection_module("us-sc:statutes/local#fixture")
    result = run_import_aware_selection({
        provider: files[provider] + "# changed\n", importer: selection_module(),
    }, files=files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl"])
    assert_full_leg(result, "us-fl", files)
    # Removing or deleting a companion retains its base-only edge. It is not
    # a module seed, so losing that edge would also lose the transitive leg.
    companion_files = {**files, importer: selection_module(), companion: evidence}
    for replacement in ("tests: []\n", None):
        result = run_import_aware_selection({
            provider: files[provider] + "# changed\n", companion: replacement,
        }, files=companion_files)
        assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl", "us-sc"])
        assert_full_leg(result, "us-fl", companion_files)
    # A deleted target still seeds reverse closure through the base tree.
    result = run_import_aware_selection({
        provider: None, "us-ma/statutes/local.test.yaml": None, importer: selection_module(),
    }, files=files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl"])
    assert_full_leg(result, "us-fl", files)
    # Leaving dangling evidence at head remains a full fallback.
    result = run_import_aware_selection({
        provider: None, "us-ma/statutes/local.test.yaml": None,
    }, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)


def assert_parameter_evidence_control() -> None:
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_evidence_module(
        selection_import_evidence("us-ma:statutes/local#fixture"),
    )
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n",
    }, files=files)
    assert_selection(result, ["us-ma", "us-sc"], revalidate=["us-sc"])


def test_import_selection_parameter_evidence_duplicate_and_ambiguous_fails_closed() -> None:
    import yaml

    assert_parameter_evidence_control()
    atom = selection_import_evidence("us-ma:statutes/local#fixture")
    probes = [
        # Duplicate singular evidence and duplicate target keys stay strict,
        # even when their repeated values happen to agree.
        ("metadata:\n  kind: parameter\n  import: {target: 'us-ma:statutes/local#fixture'}\n"
         "  import: {target: 'us-ma:statutes/local#fixture'}\n", {}),
        ("metadata:\n  kind: parameter\n  import:\n"
         "    target: 'us-ma:statutes/local#fixture'\n"
         "    target: 'us-ma:statutes/local#fixture'\n"
         "    output: fixture\n    hash: sha256:local\n", {}),
        # Both extensions resolve to the same logical provider identity.
        (selection_evidence_module(atom), {"us-ma/statutes/local.yml": selection_module()}),
        (selection_evidence_module({**atom, "fallback": "us-fl:statutes/local#fixture"}), {}),
        (selection_evidence_module({**atom, "import": {
            **atom["import"], "fallback": "us-fl:statutes/local#fixture",
        }}), {}),
        # A modeled import cannot hide an unmodeled evidence side channel.
        (yaml.safe_dump({"metadata": {**atom, "source": {"imports": "us-fl:statutes/local#fixture"}}}), {}),
    ]
    for source, extras in probes:
        files = {**selection_files(), **extras, "us-sc/statutes/local.yaml": source}
        result = run_import_aware_selection({
            "us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n",
        }, files=files)
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        assert "scope=full (import analysis failed:" in result["scope-diagnostics"], result
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_parameter_evidence_malformed_fails_closed() -> None:
    assert_parameter_evidence_control()
    atom = selection_import_evidence("us-ma:statutes/local#fixture")
    probes = [
        {**atom, "kind": "unknown-proof-kind"},
        {key: value for key, value in atom.items() if key != "kind"},
        {**atom, "kind": ["parameter"]},
        {**atom, "path": ["versions[0].formula"]},
        {**atom, "import": None},
        {**atom, "import": "us-ma:statutes/local#fixture"},
        {**atom, "import": {"output": "fixture", "hash": "sha256:local"}},
        {**atom, "import": {**atom["import"], "target": ["us-ma:statutes/local#fixture"]}},
        {**atom, "import": {**atom["import"], "target": "us-ma:statutes/missing#fixture"}},
        {**atom, "import": {**atom["import"], "target": "../us-ma/statutes/local#fixture"}},
        {**atom, "import": {**atom["import"], "target": ""}},
        {**atom, "import": {**atom["import"], "output": ["fixture"]}},
        {**atom, "import": {**atom["import"], "hash": {"value": "sha256:local"}}},
    ]
    for malformed in probes:
        files = {**selection_files(), "us-sc/statutes/local.yaml": selection_evidence_module(malformed)}
        result = run_import_aware_selection({
            "us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n",
        }, files=files)
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        assert "scope=full (import analysis failed:" in result["scope-diagnostics"], result
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_parameter_evidence_full_selection_reasons() -> None:
    assert_parameter_evidence_control()
    cases = [
        ({"README.md": "changed\n"}, "shared/root path: README.md"),
        ({".axiom/audit-manifests/audit.json": "{}\n"},
         "shared/root path: .axiom/audit-manifests/audit.json"),
        ({"known-validation-gaps.yaml": "changed\n"}, "ledger change: known-validation-gaps.yaml"),
        ({"known-missing-money-atoms.yaml": "changed\n"}, "ledger change: known-missing-money-atoms.yaml"),
        ({".axiom/toolchain.toml": SELECTOR_TOOLCHAIN.replace('"before"', '"after"')},
         "toolchain change: .axiom/toolchain.toml"),
        ({".axiom/workflow-toolchain.toml": SELECTOR_WORKFLOW_TOOLCHAIN + "# changed\n"},
         "toolchain change: .axiom/workflow-toolchain.toml"),
        ({".axiom/index/provisions_to_rules.json": "{}\n"},
         "no affected jurisdiction (index-only diff)"),
    ]
    for changes, reason in cases:
        result = run_import_aware_selection(changes)
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        assert f"scope=full ({reason})" in result["scope-diagnostics"], result
    combined = run_import_aware_selection({
        "README.md": "changed\n", "known-validation-gaps.yaml": "changed\n",
    })
    assert "ledger change: known-validation-gaps.yaml" in combined["scope-diagnostics"], combined
    assert "shared/root path: README.md" in combined["scope-diagnostics"], combined
    # A modeled dependency fanout may legitimately cover the complete matrix;
    # its diagnostic must remain distinguishable from unsupported input.
    files = selection_files()
    for shard in SELECTION_JURISDICTIONS:
        if shard != "us":
            files[f"{shard}/statutes/local.yaml"] = selection_evidence_module(
                selection_import_evidence("us:statutes/local#fixture"),
            )
    result = run_import_aware_selection({
        "us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n",
    }, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, revalidate=SELECTION_JURISDICTIONS[:-1])
    assert "scope=full (modeled import closure covers all jurisdictions)" in result["scope-diagnostics"], result


def test_import_selection_unmodelled_dependency_shapes_fail_closed() -> None:
    import yaml

    target = "us:statutes/local#fixture"
    atom_import = {"target": target, "output": "fixture", "hash": "a" * 64}
    probes = [
        {"metadata": {"imports": target}},
        {"metadata": {"imports": {"provider": target}}},
        {"metadata": {"imports": [{"target": target}]}},
        {"metadata": {"kind": "import", "import": target}},
        {"metadata": {"kind": "import", "import": {"output": "fixture"}}},
        {"metadata": {"kind": "import", "import": {**atom_import, "fallback": target}}},
        {"metadata": {"kind": "import", "import": atom_import, "fallback": target}},
        {"metadata": {"kind": "import", "import": {**atom_import, "target": [target]}}},
        {"metadata": {"kind": "import", "import": {**atom_import, "output": ["fixture"]}}},
        {"metadata": {"kind": "import", "import": {**atom_import, "hash": {"value": "a" * 64}}}},
        {"metadata": {"kind": "import", "path": ["fixture"], "import": atom_import}},
        {"metadata": {"import": atom_import}},
        {"metadata": {None: {"imports": [target]}}},
        {"metadata": {True: {"imports": [target]}}},
        {"metadata": {1.5: {"imports": [target]}}},
    ]
    sources = [yaml.safe_dump(document) for document in probes] + [
        "metadata: !!omap\n  - imports: ['us:statutes/local#fixture']\n",
        "metadata: !!pairs\n  - imports: ['us:statutes/local#fixture']\n",
        "metadata: !!set\n  ? imports\n",
        "- scalar-companion-item\n",
        "- - imports: ['us:statutes/local#fixture']\n",
    ]
    for source in sources:
        files = {**selection_files(), "us-fl/statutes/local.test.yaml": source}
        result = run_import_aware_selection(
            {"us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n"}, files=files,
        )
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_federal_fanout() -> None:
    states = [f"us-{number:02d}" for number in range(51)]
    jurisdictions = states + ["us"]
    files = selection_files(jurisdictions)
    for shard in states:
        files[f"{shard}/statutes/local.yaml"] = selection_module("us:statutes/local#federal_output")
    result = run_import_aware_selection({"us/statutes/local.yaml": selection_module() + "# changed\n"}, files=files)
    assert_selection(result, jurisdictions, jurisdictions=jurisdictions, revalidate=states)
    for shard in states:
        assert_full_leg(result, shard, files)
    assert result["targets"]["us"] == (
        "changed", ["us/statutes/local.yaml"], ["us/statutes/local.test.yaml"],
    )


def test_import_selection_base_head_union_and_deleted_provider() -> None:
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module("us-ma:statutes/local#fixture")
    files["us-fl/statutes/local.yaml"] = selection_module("us-sc:statutes/local#fixture")
    # Removing a dependency at head must not erase its base-tree edge.
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": selection_module() + "# changed\n",
        "us-sc/statutes/local.yaml": selection_module(),
    }, files=files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl"])
    assert_full_leg(result, "us-fl", files)
    assert result["targets"]["us-sc"] == (
        "changed", ["us-sc/statutes/local.yaml"], ["us-sc/statutes/local.test.yaml"],
    )
    # A changed companion is not itself a module seed. Its removed import must
    # therefore survive through the base graph to reach the unchanged module
    # and its transitive importer; using only the head graph loses us-fl.
    companion_files = {**files, "us-sc/statutes/local.yaml": selection_module(),
                       "us-sc/statutes/local.test.yaml": selection_module("us-ma:statutes/local#fixture")}
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": selection_module() + "# changed\n",
        "us-sc/statutes/local.test.yaml": "tests: []\n",
    }, files=companion_files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl", "us-sc"])
    assert_full_leg(result, "us-fl", companion_files)
    assert_full_leg(result, "us-sc", companion_files)
    # An unmodelled base dependency must also fail closed after it is repaired
    # at head. This directly kills the head-tree-only mutation for modules.
    invalid_base = {**selection_files(), "us-sc/statutes/local.yaml": "imports: [{target: unmodelled}]\n"}
    result = run_import_aware_selection({"us-sc/statutes/local.yaml": selection_module()}, files=invalid_base)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, invalid_base, "full-selection-fallback")
    # Renaming a provider and updating its direct importer still revalidates
    # the unchanged transitive importer using the union of both module graphs.
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": None,
        "us-ma/statutes/local.test.yaml": None,
        "us-ma/statutes/renamed.yaml": selection_module(),
        "us-ma/statutes/renamed.test.yaml": "tests: []\n",
        "us-sc/statutes/local.yaml": selection_module("us-ma:statutes/renamed#fixture"),
    }, files=files)
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl"])
    assert_full_leg(result, "us-fl", files)
    files["us-fl/statutes/local.yaml"] = selection_module()
    # A dangling import at head is an analysis failure, so all legs use full targets.
    result = run_import_aware_selection({"us-ma/statutes/local.yaml": None}, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    remaining = {path: text for path, text in files.items() if path != "us-ma/statutes/local.yaml"}
    for shard in result["matrix"]:
        assert_full_leg(result, shard, remaining, "full-selection-fallback")
    # A clean deletion still includes the base importer jurisdiction.
    result = run_import_aware_selection({
        "us-ma/statutes/local.yaml": None,
        "us-ma/statutes/local.test.yaml": None,
        "us-sc/statutes/local.yaml": None,
        "us-sc/statutes/local.test.yaml": None,
    }, files=files)
    assert_selection(result, ["us-ma", "us-sc"], revalidate=[])


def test_import_selection_manifest_ownership_and_failures() -> None:
    layouts = [
        (".axiom/encoding-manifests/us-ma/wrong-name.json", "us-fl/statutes/local.yaml"),
        ("us-fl/.axiom/encoding-manifests/wrong-name.json", "statutes/local.yaml"),
    ]
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module("us-fl:statutes/local#fixture")
    for manifest, applied in layouts:
        baseline = {**files, manifest: selection_manifest(applied)}
        result = run_import_aware_selection({manifest: selection_manifest(applied, revision=1)}, files=baseline)
        assert_selection(result, ["us-fl", "us-sc"], revalidate=["us-fl", "us-sc"])
        for shard in ("us-fl", "us-sc"):
            assert_full_leg(result, shard, files)
        result = run_import_aware_selection({manifest: None}, files=baseline)
        assert_selection(result, ["us-fl", "us-sc"], revalidate=["us-fl", "us-sc"])
    # A changed manifest uses both versions of applied_files, never its filename.
    manifest = ".axiom/encoding-manifests/us/wrong-name.json"
    result = run_import_aware_selection(
        {manifest: selection_manifest("us-ma/regulations/independent.yml", revision=1)},
        files={**files, manifest: selection_manifest("us-fl/statutes/local.yaml")},
    )
    assert_selection(result, ["us-fl", "us-ma", "us-sc"], revalidate=["us-fl", "us-ma", "us-sc"])
    result = run_import_aware_selection({manifest: selection_manifest("us-fl/statutes/local.test.yaml")})
    assert_selection(result, ["us-fl"], revalidate=["us-fl"])
    assert_full_leg(result, "us-fl", selection_files())
    # A manifest changed alongside its applied module needs no extra full leg.
    result = run_import_aware_selection({
        manifest: selection_manifest("us-fl/statutes/local.yaml"),
        "us-fl/statutes/local.yaml": selection_module() + "# changed\n",
    })
    assert_selection(result, ["us-fl"], revalidate=[])
    malformed = [
        "{broken", "[]", "{}", '{"applied_files": null}',
        '{"applied_files": ["us-fl/statutes/local.yaml"]}',
        '{"applied_files": [{"path": 1}]}', selection_manifest(),
        selection_manifest("../us-fl/statutes/local.yaml"),
        selection_manifest("us-zz/statutes/local.yaml"),
        selection_manifest("tests/shared.py"),
        selection_manifest("us-fl/statutes/local.yaml", ".axiom/toolchain.toml"),
    ]
    for content in malformed:
        result = run_import_aware_selection({manifest: content})
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, selection_files(), "full-selection-fallback")
    # Unqualified root manifests cannot assign ownership from a federal filename.
    result = run_import_aware_selection({
        ".axiom/encoding-manifests/statutes/local.json": selection_manifest("statutes/local.yaml"),
    })
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)


def test_import_selection_manifest_deletions_and_ambiguity() -> None:
    for manifest, prefix in (
        (".axiom/encoding-manifests/us-fl/local.json", "us-fl/"),
        ("us-fl/.axiom/encoding-manifests/local.json", ""),
    ):
        module = "us-fl/statutes/local.yaml"
        companion = "us-fl/statutes/local.test.yaml"
        applied = prefix + "statutes/local.yaml"
        applied_companion = prefix + "statutes/local.test.yaml"
        files = {**selection_files(), manifest: selection_manifest(applied, applied_companion)}
        deletion = json.loads(selection_manifest(applied, applied_companion, revision=1))
        for item in deletion["applied_files"]:
            del item["sha256"]
            item["deleted"] = True
        result = run_import_aware_selection({
            module: None, companion: None, manifest: json.dumps(deletion),
        }, files=files)
        assert_selection(result, ["us-fl"], revalidate=[])
        assert result["targets"]["us-fl"] == ("changed", [], [])
        # Companion deletion can still be paired with its unchanged module.
        deletion["applied_files"] = [deletion["applied_files"][1]]
        result = run_import_aware_selection({
            companion: None, manifest: json.dumps(deletion),
        }, files=files)
        assert_selection(result, ["us-fl"], revalidate=["us-fl"])
        assert_full_leg(result, "us-fl", {p: c for p, c in files.items() if p != companion})
        # Keep the deletion sentinel recognized by the existing pre-check.
        deletion["applied_files"][0] = {"path": applied_companion, "sha256": "deleted"}
        result = run_import_aware_selection({
            companion: None, manifest: json.dumps(deletion),
        }, files=files)
        assert_selection(result, ["us-fl"], revalidate=["us-fl"])
        # An ordinary hash cannot claim a path absent from that version's tree.
        result = run_import_aware_selection({
            module: None, companion: None,
            manifest: selection_manifest(applied, applied_companion, revision=1),
        }, files=files)
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)

    manifest = ".axiom/encoding-manifests/us-fl/local.json"
    schema = '"schema_version": "axiom-encode/applied-rulespec/v5"'
    for payload in (
        '{' + schema + ', "applied_files": [], "applied_files": [{"path": "us-fl/statutes/local.yaml"}]}',
        '{' + schema + ', "applied_files": [{"path": "us-ma/statutes/local.yaml", "path": "us-fl/statutes/local.yaml"}]}',
        selection_manifest("us-fl/statutes/missing.yaml"),
        selection_manifest("us-fl/statutes/local.yaml", "us-fl/statutes/local.yaml"),
        selection_manifest("us-fl/statutes/local.yaml").replace('"sha256": "' + "a" * 64 + '"', '"sha256": 1'),
        selection_manifest("us-fl/statutes/local.yaml").replace('"schema_version"', '"unknown_schema"'),
        '{' + schema + ', "applied_files": [{"path": "us-fl/statutes/local.yaml", "deleted": "true"}]}',
        '{' + schema + ', "applied_files": [{"path": "us-fl/statutes/local.yaml", "deleted": true}]}',
        '{' + schema + ', "applied_files": [{"path": "us-fl/statutes/local.yaml"}]}',
    ):
        result = run_import_aware_selection({manifest: payload})
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    # Reject a malformed base manifest even when its replacement is valid.
    result = run_import_aware_selection(
        {manifest: selection_manifest("us-fl/statutes/local.yaml")},
        files={**selection_files(), manifest: "{broken"},
    )
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)


def test_import_selection_program_scopes_and_proof_provenance() -> None:
    for program in ("programs/us-fl/fixture.yaml", "us-fl/programs/fixture.yaml"):
        files = selection_files()
        # ProgramSpec resolution appends .yaml; ordinary module/proof imports
        # still exercise the .yml providers in the other jurisdictions below.
        for ending in ("", ".test"):
            files[f"us-fl/regulations/independent{ending}.yaml"] = files.pop(
                f"us-fl/regulations/independent{ending}.yml"
            )
        files[program] = selection_program("us-fl", {
            "federal": ["statutes/local"],
            "state": ["regulations/independent"],
            "us-ma": ["statutes/local"],
            "jurisdictions": ["us-fl"], "include": ["fixture"], "exclude": [],
        })
        result = run_import_aware_selection(
            {program: files[program] + "# changed\n"}, files=files, shape_programs=(program,),
        )
        assert_selection(result, ["us-fl"], revalidate=[])
        assert result["targets"]["us-fl"] == ("changed", [], [])
        manifest = ".axiom/encoding-manifests/programs/wrong-name.json"
        result = run_import_aware_selection({manifest: selection_manifest(program)}, files=files)
        assert_selection(result, ["us-fl"], revalidate=[])
        assert result["targets"]["us-fl"] == ("changed", [], [])
        for provider, owner in (("us/statutes/local.yaml", "us"), ("us-fl/regulations/independent.yaml", "us-fl"), ("us-ma/statutes/local.yaml", "us-ma")):
            result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
            expected = [s for s in SELECTION_JURISDICTIONS if s in {owner, "us-fl"}]
            assert_selection(result, expected, revalidate=["us-fl"])
            assert_full_leg(result, "us-fl", files)
        # Explicit prefix takes precedence over the federal alias.
        files[program] = selection_program("us-fl", {"federal": ["us-ma:statutes/local"]})
        result = run_import_aware_selection({"us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n"}, files=files)
        assert_selection(result, ["us-fl", "us-ma"], revalidate=["us-fl"])
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module(proof="us-ma:regulations/independent#fixture")
    result = run_import_aware_selection({"us-ma/regulations/independent.yml": files["us-ma/regulations/independent.yml"] + "# changed\n"}, files=files)
    assert_selection(result, ["us-ma", "us-sc"], revalidate=["us-sc"])
    assert_full_leg(result, "us-sc", files)
    bad_programs = ["broken: [", "[]", selection_program("us-fl", {"federal": ["statutes/missing"]}), selection_program("us-fl", {"federal": {"unexpected": "mapping"}})]
    for program in bad_programs:
        result = run_import_aware_selection({"programs/us-fl/fixture.yaml": program})
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)


def test_import_selection_program_paths_provider_only(program_paths: tuple[str, ...] = (
    "programs/federal/fixture.yaml", "programs/fixture.yml",
    "programs/helpers/deep/fixture.test.yaml", "programs/us-ca/fixture.yaml",
    "us-ca/programs/fixture.yml", "us-ab_cd/programs/fixture.yaml",
)) -> None:
    # Every shape-accepted ProgramSpec participates, regardless of its directory.
    for program in program_paths:
        files = selection_files()
        files[program] = selection_program("us-fl", {"federal": ["statutes/local"]})
        result = run_import_aware_selection(
            {"us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n"},
            files=files, shape_programs=(program,),
        )
        assert_selection(result, ["us-fl", "us"], revalidate=["us-fl"])
        assert_full_leg(result, "us-fl", files)


def assert_program_suffix_provider_selection(suffix: str, *, ambiguous: bool) -> None:
    files = selection_files()
    program = "programs/fixture.yaml"
    provider = f"us/statutes/local.{suffix}.yaml"
    files[provider] = selection_module()
    files[program] = selection_program("us-fl", {"federal": [f"statutes/local.{suffix}"]})
    if not ambiguous:
        del files["us/statutes/local.yaml"]
        files[provider[:-5] + ".test.yaml"] = files.pop("us/statutes/local.test.yaml")
    # The actual ProgramSpec precheck appends .yaml to the entire scope entry.
    # Its successful execution proves that the unchanged spec consumes provider.
    result = run_import_aware_selection(
        {provider: files[provider] + "# changed provider\n"},
        files=files, shape_programs=(program,),
    )
    if ambiguous:
        # Stripping the suffix names a different existing provider. Neither the
        # matrix nor target selection may rely on choosing one interpretation.
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")
    else:
        assert_selection(result, ["us-fl", "us"], revalidate=["us-fl"])
        assert_full_leg(result, "us-fl", files)


def test_import_selection_program_yaml_suffix_provider_ambiguity() -> None:
    assert_program_suffix_provider_selection("yaml", ambiguous=True)


def test_import_selection_program_yml_suffix_provider_ambiguity() -> None:
    assert_program_suffix_provider_selection("yml", ambiguous=True)


def test_import_selection_program_suffix_unique_provider() -> None:
    for suffix in ("yaml", "yml"):
        assert_program_suffix_provider_selection(suffix, ambiguous=False)


def test_import_selection_program_candidate_location_ambiguity() -> None:
    for alternate in ("statutes/local.yaml", "rulespec-us/statutes/local.yaml"):
        files = selection_files()
        program = "programs/location-ambiguity.yaml"
        provider = "us/statutes/local.yaml"
        files[alternate] = selection_module()
        files[program] = selection_program("us-fl", {"federal": ["statutes/local"]})
        result = run_import_aware_selection(
            {provider: files[provider] + "# changed prefixed provider\n"},
            files=files, shape_programs=(program,),
        )
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_program_requires_canonical_yaml_provider() -> None:
    # The module resolver accepts a unique .yml provider, but ProgramSpec's
    # precheck appends .yaml. Its graph must reject that disagreement rather
    # than infer a scoped result from the more permissive module resolver.
    files = selection_files()
    files["programs/fixture.yaml"] = selection_program("us-fl", {"federal": ["regulations/independent"]})
    provider = "us/regulations/independent.yml"
    result = run_import_aware_selection({provider: files[provider] + "# changed\n"}, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_program_paths_base_head_and_manifests(program_paths: tuple[str, ...] = (
    "programs/fixture.yaml", "programs/federal/fixture.yml",
)) -> None:
    for program in program_paths:
        files = selection_files()
        for ending in ("", ".test"):
            files[f"us-fl/regulations/independent{ending}.yaml"] = files.pop(
                f"us-fl/regulations/independent{ending}.yml"
            )
        files[program] = selection_program("us-fl", {"federal": ["statutes/local"]})
        provider_change = {"us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n"}
        # The base edge survives removal at head, including deletion of the spec.
        for replacement in (selection_program("us-fl", {"state": ["regulations/independent"]}), None):
            result = run_import_aware_selection({**provider_change, program: replacement}, files=files)
            assert_selection(result, ["us-fl", "us"], revalidate=["us-fl"])
            assert_full_leg(result, "us-fl", files)
        # Head-only specs and state aliases use the declared owner.
        result = run_import_aware_selection({**provider_change, program: files[program]}, files=selection_files())
        assert_selection(result, ["us-fl", "us"], revalidate=["us-fl"])
        state_files = {**files, program: selection_program("us-fl", {"state": ["statutes/local"]})}
        result = run_import_aware_selection(
            {"us-fl/statutes/local.yaml": state_files["us-fl/statutes/local.yaml"] + "# changed\n"}, files=state_files,
        )
        assert_selection(result, ["us-fl"], revalidate=["us-fl"])
        assert_full_leg(result, "us-fl", state_files)
        # A manifest-only program edit must use the same declared ownership.
        manifest = ".axiom/encoding-manifests/programs/fixture.json"
        result = run_import_aware_selection({manifest: selection_manifest(program)}, files=files)
        assert_selection(result, ["us-fl"], revalidate=[])
        deletion = json.loads(selection_manifest(program))
        deletion["applied_files"][0] = {"path": program, "deleted": True}
        result = run_import_aware_selection({program: None, manifest: json.dumps(deletion)}, files=files)
        assert_selection(result, ["us-fl"], revalidate=[])


def test_import_selection_unresolved_program_ownership_falls_back() -> None:
    for owner in ("us-zz", "us-fl_extra"):
        program = "programs/federal/fixture.yaml"
        files = {**selection_files(), program: selection_program(owner, {"federal": ["statutes/local"]})}
        result = run_import_aware_selection(
            {"us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n"},
            files=files, shape_programs=(program,),
        )
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")
    # A path-keyed graph must not overwrite the base declaration's owner.
    program = "programs/us-fl/fixture.yaml"
    files = {**selection_files(), program: selection_program("us-fl", {"federal": ["statutes/local"]})}
    result = run_import_aware_selection({
        "us/statutes/local.yaml": files["us/statutes/local.yaml"] + "# changed\n",
        program: selection_program("us-ca", {"federal": ["statutes/local"]}),
    }, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_contradictory_manifest_deletion() -> None:
    manifest = ".axiom/encoding-manifests/us-fl/local.json"
    module = "us-fl/statutes/local.yaml"
    payload = json.loads(selection_manifest(module))
    payload["applied_files"][0].update(sha256="deleted", deleted=False)
    result = run_import_aware_selection({module: None, manifest: json.dumps(payload)})
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)


def test_import_selection_graph_parse_and_read_failures() -> None:
    for content in ("broken: [", "[]", "imports: not-a-list\n", "imports:\n  - 7\n", "imports:\n  - 'us-xx:statutes/missing#fixture'\n", "imports: []\nimports: []\n"):
        result = run_import_aware_selection({"us-fl/statutes/local.yaml": content})
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, selection_files(), "full-selection-fallback")
    # Fail both the tree and blob readers; no partial graph may escape.
    for command in ("ls-tree", "cat-file", "diff"):
        result = run_import_aware_selection({"us-fl/statutes/local.yaml": selection_module() + "# changed\n"}, fail_git=command)
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, selection_files(), "full-selection-fallback")
    result = run_import_aware_selection({"us-fl/statutes/local.yml": selection_module()})
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    # Unchanged malformed modules in either tree must prevent partial analysis.
    files = {**selection_files(), "us-ma/statutes/local.yaml": "broken: ["}
    result = run_import_aware_selection({"us-fl/statutes/local.yaml": selection_module() + "# changed\n"}, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    # A companion without its module has no modeled importer identity, even
    # when its own YAML is valid and the changed provider is well formed.
    files = {**selection_files(), "us-fl/statutes/orphan.test.yaml": "tests: []\n"}
    result = run_import_aware_selection({"us/statutes/local.yaml": selection_module() + "# changed\n"}, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, files, "full-selection-fallback")


def selector_document_helpers(loader_base: type | None = None, *, c_available: bool = True) -> dict:
    """Execute the real embedded loader/cache helpers without invoking Git."""
    import ast
    import types
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text())
    compute = next(step for step in workflow["jobs"]["shards"]["steps"] if step.get("id") == "compute")
    source = compute["run"].split("python3 -I <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    nodes = list(ast.walk(ast.parse(source)))
    loader = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == "UniqueLoader")
    mapping = next(node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == "unique_mapping")
    constructor = next(node for node in nodes if isinstance(node, ast.Expr)
                       and isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Attribute)
                       and isinstance(node.value.func.value, ast.Name)
                       and node.value.func.value.id == "UniqueLoader"
                       and node.value.func.attr == "add_constructor")
    cache = next(node for node in nodes if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "documents" for target in node.targets))
    document = next(node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == "document")
    if loader_base is None:
        yaml_module = yaml
    else:
        # Both names resolve to the requested implementation, exercising the
        # exact constructor with the C and Python SafeLoader code paths.
        yaml_module = types.SimpleNamespace(SafeLoader=loader_base, CSafeLoader=loader_base,
                                            resolver=yaml.resolver, load=yaml.load)
        if not c_available:
            del yaml_module.CSafeLoader
    namespace = {"yaml": yaml_module, "is_companion": lambda path: path.endswith((".test.yaml", ".test.yml"))}
    exec(compile(ast.Module(body=[loader, mapping, constructor, cache, document], type_ignores=[]),
                 str(WORKFLOW), "exec"), namespace)
    return namespace


def test_import_selection_c_and_python_loader_safety_parity() -> None:
    import yaml

    expected_base = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    assert selector_document_helpers()["UniqueLoader"].__bases__ == (expected_base,)
    assert selector_document_helpers(yaml.SafeLoader, c_available=False)["UniqueLoader"].__bases__ == (yaml.SafeLoader,)
    accepted = [
        "imports: []\nrules: []\n",
        "first: &shared {value: fixture}\nsecond: *shared\n",
        "defaults: &defaults {field: fixture}\nmodule:\n  <<: *defaults\n  extra: value\n",
        "metadata: !!omap\n  - imports: ['us:statutes/local#fixture']\n",
        "metadata: !!pairs\n  - imports: ['us:statutes/local#fixture']\n",
        "metadata: !!set\n  ? imports\n",
    ]
    rejected = [
        "imports: []\nimports: []\n",
        "metadata: {name: first, name: second}\n",
        "defaults: &defaults {field: first}\nmodule:\n  <<: *defaults\n  field: second\n",
        "defaults: &defaults {field: first}\nmodule:\n  <<: [*defaults, *defaults]\n",
        "module: !!python/object/apply:os.system ['printf should-not-run']\n",
        "module: !unknown fixture\n",
        "? [unhashable, key]\n: fixture\n",
        "imports: []\n---\nimports: []\n",
    ]
    implementations = []
    bases = [yaml.SafeLoader]
    if hasattr(yaml, "CSafeLoader"):
        bases.append(yaml.CSafeLoader)
    for base in bases:
        loader = selector_document_helpers(base)["UniqueLoader"]
        implementations.append([yaml.load(source, Loader=loader) for source in accepted])
        for source in rejected:
            try:
                yaml.load(source, Loader=loader)
            except (ValueError, TypeError, yaml.YAMLError):
                pass
            else:
                raise AssertionError(f"{base.__name__} accepted unsafe/ambiguous YAML: {source!r}")
    assert all(implementation == implementations[0] for implementation in implementations)


def test_import_selection_documents_cached_by_blob_across_trees() -> None:
    namespace = selector_document_helpers()
    original_load = namespace["yaml"].load
    calls = []

    def count_load(payload, **kwargs):
        calls.append(payload)
        return original_load(payload, **kwargs)

    import types
    namespace["yaml"] = types.SimpleNamespace(load=count_load)
    namespace["blobs"] = {"same": b"imports: []\nrules: []\n", "changed": b"imports: null\nrules: []\n"}
    base = {"us/statutes/base.yaml": ("100644", "blob", "same")}
    head = {"us/statutes/base.yaml": ("100644", "blob", "same"),
            "us-ma/statutes/copy.yaml": ("100644", "blob", "same"),
            "us-fl/statutes/changed.yaml": ("100644", "blob", "changed")}
    document = namespace["document"]
    first = document(base, "us/statutes/base.yaml")
    assert document(head, "us/statutes/base.yaml") is first
    assert document(head, "us-ma/statutes/copy.yaml") is first
    assert document(head, "us-fl/statutes/changed.yaml")["imports"] is None
    assert calls == [namespace["blobs"]["same"], namespace["blobs"]["changed"]], calls
    # Cache hits must still apply each path's shape rule: a root array is a
    # valid companion but cannot become a valid atomic module through reuse.
    namespace["blobs"]["array"] = b"[]\n"
    shared = {"us/statutes/base.test.yaml": ("100644", "blob", "array"),
              "us-ma/statutes/invalid.yaml": ("100644", "blob", "array")}
    assert document(shared, "us/statutes/base.test.yaml") == []
    try:
        document(shared, "us-ma/statutes/invalid.yaml")
    except ValueError:
        pass
    else:
        raise AssertionError("cached companion array accepted as an atomic module")
    assert calls.count(namespace["blobs"]["array"]) == 1, calls


def test_import_selection_shared_paths_and_toolchains() -> None:
    paths = [
        "tests/test_shared.py", "tools/shared.py", "bulk/shared.py",
        ".axiom/structure.toml", ".axiom/oracle-registry.yaml", ".axiom/other.json",
        "known-validation-gaps.yaml", "known-missing-money-atoms.yaml",
        "sources/provision.yaml", ".axiom/replacement-receipts/receipt.json",
        "us-fl/sources/provision.yaml", "us-fl/manual/context.yaml", "unknown/file.txt",
    ]
    for path in paths:
        result = run_import_aware_selection({path: "changed\n"})
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        assert all(target == ("changed", [], []) for target in result["targets"].values()), (path, result)
    # A shared change keeps the matrix full while a changed provider still
    # expands targets in its unchanged importer's leg.
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module("us-ma:statutes/local#fixture")
    result = run_import_aware_selection({
        "tests/test_shared.py": "changed\n",
        "us-ma/statutes/local.yaml": selection_module() + "# changed\n",
    }, files=files)
    assert_selection(result, SELECTION_JURISDICTIONS, revalidate=["us-sc"])
    assert_full_leg(result, "us-sc", files)
    for path, content, mode in (
        (".github/workflows/shared.yml", "changed\n", "changed"),
        (".github/workflows/shared.yaml", "changed\n", "changed"),
        (".axiom/workflow-toolchain.toml", SELECTOR_WORKFLOW_TOOLCHAIN.replace("a" * 40, "d" * 40), "full-toolchain-bump"),
        (".axiom/toolchain.toml", SELECTOR_TOOLCHAIN.replace("b" * 64, "c" * 64), "full-toolchain-bump"),
        (".axiom/toolchain.toml", SELECTOR_TOOLCHAIN.replace('"before"', '"after"'), "changed-corpus-toolchain-bump"),
    ):
        result = run_import_aware_selection(
            {path: content}, dependency_pins_changed=path == ".axiom/workflow-toolchain.toml",
        )
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        for shard in result["matrix"]:
            if mode == "full-toolchain-bump":
                assert_full_leg(result, shard, selection_files(), mode)
            else:
                assert result["targets"][shard] == (mode, [], [])
    result = run_import_aware_selection({
        ".axiom/toolchain.toml": SELECTOR_TOOLCHAIN.replace('"before"', '"after"'),
        ".axiom/workflow-toolchain.toml": SELECTOR_WORKFLOW_TOOLCHAIN.replace("a" * 40, "d" * 40),
    }, dependency_pins_changed=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, selection_files(), "full-toolchain-bump")
    # Full-toolchain priority also wins over graph-failure full-target mode.
    result = run_import_aware_selection({
        ".axiom/workflow-toolchain.toml": SELECTOR_WORKFLOW_TOOLCHAIN.replace("a" * 40, "d" * 40),
        "us-fl/statutes/local.yaml": "imports: broken\n",
    }, dependency_pins_changed=True)
    assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
    for shard in result["matrix"]:
        assert_full_leg(result, shard, selection_files(), "full-toolchain-bump")


def test_import_selection_events_refs_index_and_opt_in_default() -> None:
    result = run_import_aware_selection({".axiom/index/provisions_to_rules.json": "{}\n"})
    assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
    result = run_import_aware_selection({
        ".axiom/index/provisions_to_rules.json": "{}\n",
        "us-fl/statutes/local.yaml": selection_module() + "# changed\n",
    }, guard_programs=True)
    assert_selection(result, ["us-fl"], revalidate=[], guard_programs=True)
    result = run_import_aware_selection({})
    assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
    for event in ("push", "schedule", "workflow_dispatch"):
        result = run_import_aware_selection({"us-fl/statutes/local.yaml": selection_module() + "# changed\n"}, event=event)
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        for shard in result["matrix"]:
            assert_full_leg(result, shard, selection_files(), "full-push")
    for override in ({"base_override": ""}, {"head_override": ""}, {"base_override": "f" * 40}, {"head_override": "e" * 40}):
        result = run_import_aware_selection({"us-fl/statutes/local.yaml": selection_module() + "# changed\n"}, **override)
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, selection_files(), "full-selection-fallback")
    files = selection_files()
    files["us-sc/statutes/local.yaml"] = selection_module("us-ma:statutes/local#fixture")
    for enabled in (False, None):
        # Legacy callers scope solely by first path component and do not expand imports.
        result = run_import_aware_selection({"us-ma/statutes/local.yaml": files["us-ma/statutes/local.yaml"] + "# changed\n"}, files=files, enabled=enabled)
        assert_selection(result, ["us-ma"], revalidate=[])
        assert result["targets"]["us-ma"] == ("changed", ["us-ma/statutes/local.yaml"], ["us-ma/statutes/local.test.yaml"])
        result = run_import_aware_selection({".axiom/encoding-manifests/us-fl/local.json": selection_manifest("us-fl/statutes/local.yaml")}, enabled=enabled)
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        result = run_import_aware_selection({
            "us-fl/statutes/local.yaml": selection_module() + "# changed\n",
            "us-ma/statutes/local.yaml": selection_module() + "# changed\n",
        }, enabled=enabled)
        assert_selection(result, SELECTION_JURISDICTIONS, revalidate=[])
        # A malformed graph was never parsed for callers who have not opted in.
        result = run_import_aware_selection({"us-fl/statutes/local.yaml": "broken: ["}, enabled=enabled)
        assert_selection(result, ["us-fl"], revalidate=[])
    result = run_import_aware_selection({"us-fl/statutes/local.yaml": selection_module() + "# changed\n"}, roots_input="us-fl", enabled=True)
    assert result["matrix"] == ["__all__"]
    assert result["roots"] == "us-fl"
    assert result["targets"]["__all__"] == ("changed", ["us-fl/statutes/local.yaml"], ["us-fl/statutes/local.test.yaml"])


def test_import_selection_generated_graph_property(cases: range = range(20)) -> None:
    for case in cases:
        rng = random.Random(20261012 + case)
        files = selection_files()
        modules = [f"{shard}/statutes/{name}.yaml" for shard in SELECTION_JURISDICTIONS for name in ("local", "generated")]
        program_owners = {
            "programs/federal/fixture.yaml": "us-fl",
            "programs/fixture.yml": "us-ma",
            "programs/helpers/deep/fixture.test.yaml": "us-sc",
            "us-fl/programs/fixture.yml": "us-fl",
            "programs/us-ma/fixture.yaml": "us-ma",
        }
        if case:
            for program in list(program_owners)[:3]:
                program_owners[program] = rng.choice(SELECTION_JURISDICTIONS)
        owners = {node: node.split("/", 1)[0] for node in modules} | program_owners
        nodes = modules + list(program_owners)
        dependencies = {node: {other for other in modules if rng.random() < 0.17} for node in modules}
        for program in program_owners:
            dependencies[program] = {other for other in modules if rng.random() < 0.17} or {rng.choice(modules)}
        if case == 0:
            # A sparse provider-only graph guarantees that the declaration-owned
            # importer cannot be selected accidentally through another module.
            dependencies = {node: set() for node in modules}
            dependencies.update({
                program: {f"{owner}/statutes/generated.yaml"}
                for program, owner in program_owners.items()
            })
            dependencies["programs/federal/fixture.yaml"] = {"us/statutes/local.yaml"}
            changed_modules = {"us/statutes/local.yaml"}
        else:
            changed_modules = set(rng.sample(modules, rng.randint(1, 3)))

        def target(node: str) -> str:
            return f"{owners[node]}:{node.split('/', 1)[1].removesuffix('.yaml')}#fixture"

        for node in modules:
            files[node] = selection_module(*[
                target(provider) for provider in sorted(dependencies[node])
            ])
        for program, owner in program_owners.items():
            files[program] = selection_program(owner, {
                "federal": [target(provider).removesuffix("#fixture") for provider in sorted(dependencies[program])],
            })
        changed_programs = {rng.choice(list(program_owners))} if case % 3 == 1 else set()
        changed = changed_modules | changed_programs
        head_dependencies = {
            node: ({other for other in modules if rng.random() < 0.17} if node in changed else imports)
            for node, imports in dependencies.items()
        }
        for program in changed_programs:
            head_dependencies[program] = head_dependencies[program] or {rng.choice(modules)}
        # Compute the reverse closure independently over both complete trees.
        # Changed programs are owned directly; only changed atomic providers
        # seed imports, and programs are sink nodes rather than atomic targets.
        affected = set(changed_modules)
        while True:
            expanded = affected | {
                node for node in nodes
                if (dependencies[node] | head_dependencies[node]) & affected
            }
            if expanded == affected:
                break
            affected = expanded
        required = {owners[node] for node in affected | changed_programs}
        changes = {
            node: selection_module(*[
                target(provider) for provider in sorted(head_dependencies[node])
            ]) + f"# change {case}\n"
            for node in changed_modules
        }
        changes.update({
            program: selection_program(program_owners[program], {
                "federal": [target(provider).removesuffix("#fixture") for provider in sorted(head_dependencies[program])],
            }) + f"# change {case}\n"
            for program in changed_programs
        })
        result = run_import_aware_selection(changes, files=files)
        full_fallback = (
            result["matrix"] == SELECTION_JURISDICTIONS
            and result.get("full-targets") == "true"
        )
        for node in affected | changed_programs:
            assert owners[node] in result["matrix"] or full_fallback, (case, node, dependencies, changed, result)
        assert required <= set(result["matrix"]), (case, dependencies, changed, result)
        expected = [shard for shard in SELECTION_JURISDICTIONS if shard in required]
        revalidate = [shard for shard in SELECTION_JURISDICTIONS if any(owners[node] == shard for node in affected - changed_modules)]
        assert_selection(result, expected, revalidate=revalidate)
        for shard in revalidate:
            assert_full_leg(result, shard, files)
        for shard in set(expected) - set(revalidate):
            targets = sorted(node for node in changed_modules if owners[node] == shard)
            companions = sorted(node.removesuffix(".yaml") + ".test.yaml" for node in targets if node.removesuffix(".yaml") + ".test.yaml" in files)
            assert result["targets"][shard] == ("changed", targets, companions), (case, result)


def test_import_selection_generated_suffix_ambiguity_property(cases: range = range(8)) -> None:
    for case in cases:
        rng = random.Random(20261015 + case)
        provider_owner, program_owner, bridge_owner = rng.sample(SELECTION_JURISDICTIONS, 3)
        suffix = ("yaml", "yml")[case % 2]
        alternate_suffix = ("yaml", "yml")[(case // 2) % 2]
        relative = f"statutes/generated-{rng.randrange(1000000)}.{suffix}"
        provider = f"{provider_owner}/{relative}.yaml"
        alternate = f"{provider_owner}/{relative.rsplit('.', 1)[0]}.{alternate_suffix}"
        bridge = f"{bridge_owner}/statutes/suffix-bridge.yaml"
        program = "programs/suffix-property.yaml"
        files = selection_files()
        files[provider] = selection_module()
        files[alternate] = selection_module()
        # A second importer supplies a module graph edge to the actual
        # provider, independently of the ambiguous ProgramSpec scope spelling.
        files[bridge] = selection_module(f"{provider_owner}:{relative}.yaml#fixture")
        label = "federal" if provider_owner == "us" else provider_owner
        entry = f"{provider_owner}:{relative}" if case % 2 else relative
        files[program] = selection_program(program_owner, {label: [entry]})
        result = run_import_aware_selection(
            {provider: files[provider] + f"# generated change {case}\n"},
            files=files, shape_programs=(program,),
        )
        # The independent candidate set has two different existing files. A
        # selector must fall back even if one resolver could choose a winner.
        assert provider != alternate and {provider, alternate} <= files.keys()
        assert_selection(result, SELECTION_JURISDICTIONS, full_targets=True)
        for owner in (program_owner, bridge_owner):
            assert owner in result["matrix"], (case, owner, result)
        for shard in result["matrix"]:
            assert_full_leg(result, shard, files, "full-selection-fallback")


def test_import_selection_preserves_enforcement_wiring() -> None:
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text())
    # PyYAML's YAML 1.1 resolver reads the GitHub key `on` as boolean True.
    inputs = workflow.get("on", workflow.get(True))["workflow_call"]["inputs"]
    assert inputs["import-aware-selection"]["type"] == "boolean"
    assert inputs["import-aware-selection"]["default"] is False
    jobs = workflow["jobs"]
    compute = next(s for s in jobs["shards"]["steps"] if s.get("id") == "compute")
    assert compute["env"]["IMPORT_AWARE_SELECTION"] == "${{ inputs.import-aware-selection }}"
    assert jobs["shards"]["outputs"]["revalidate-shards"] == "${{ steps.compute.outputs.revalidate-shards }}"
    assert jobs["shards"]["outputs"]["full-targets"] == "${{ steps.compute.outputs.full-targets }}"
    assert jobs["validate"]["strategy"]["matrix"]["shard"] == "${{ fromJSON(needs.shards.outputs.matrix) }}"
    steps = {s.get("name"): s for s in jobs["validate"]["steps"]}
    target_env = steps["Select RuleSpec validation targets"]["env"]
    assert target_env["REVALIDATE_SHARDS"] == "${{ needs.shards.outputs.revalidate-shards }}"
    assert target_env["FULL_TARGETS"] == "${{ needs.shards.outputs.full-targets }}"
    assert target_env["VALIDATION_SHARD"] == "${{ matrix.shard }}"
    assert target_env["DEPENDENCY_PINS_CHANGED"] == "${{ needs.shards.outputs.dependency_pins_changed }}"
    first = "matrix.shard == needs.shards.outputs.first"
    for name in ("Reject obsolete generated files", "Reject disallowed repository layout", "Reject manual RuleSpec changes", "Require money proof atoms", "Run repository tests"):
        assert first in steps[name]["if"], name
    for name in ("Reject disallowed repository layout", "Require money proof atoms"):
        assert steps[name]["env"]["VALIDATE_ROOTS"] == "${{ needs.shards.outputs.roots }}", name
    audit = steps["Enforce validation waiver ratchet"]
    assert first not in audit.get("if", "")
    assert audit["timeout-minutes"] == 150
    assert jobs["validate"]["timeout-minutes"] == 180
    assert '--partition-key "${{ matrix.shard }}"' in audit["run"]
    assert "--partition-keys-json '${{ needs.shards.outputs.matrix }}'" in audit["run"]
    complete = jobs["validate-complete"]
    assert complete["name"] == "validate"
    assert complete["needs"] == "validate"
    assert complete["if"] == "${{ always() }}"
    assert complete["steps"][0]["env"]["VALIDATE_RESULT"] == "${{ needs.validate.result }}"
    assert 'if [ "$VALIDATE_RESULT" != "success" ]; then' in complete["steps"][0]["run"]


def run_selector_tests() -> None:
    tests = [
        test_validation_targets_workflow_toolchain_pin_only_requires_full_validation,
        test_validation_targets_preserve_other_path_classifications,
        test_import_selection_local_modules_and_companions,
        test_import_selection_transitive_graph_and_cycles,
        test_import_selection_dependencies_at_any_depth_and_in_companions,
        test_import_selection_parameter_evidence_self_edge,
        test_import_selection_every_proof_kind_can_carry_import_evidence,
        test_import_selection_parameter_evidence_in_companions_and_side_channels,
        test_import_selection_parameter_evidence_base_only_and_deleted_provider,
        test_import_selection_parameter_evidence_duplicate_and_ambiguous_fails_closed,
        test_import_selection_parameter_evidence_malformed_fails_closed,
        test_import_selection_parameter_evidence_full_selection_reasons,
        test_import_selection_unmodelled_dependency_shapes_fail_closed,
        test_import_selection_federal_fanout,
        test_import_selection_base_head_union_and_deleted_provider,
        test_import_selection_manifest_ownership_and_failures,
        test_import_selection_manifest_deletions_and_ambiguity,
        test_import_selection_contradictory_manifest_deletion,
        test_import_selection_program_scopes_and_proof_provenance,
        test_import_selection_program_paths_provider_only,
        test_import_selection_program_yaml_suffix_provider_ambiguity,
        test_import_selection_program_yml_suffix_provider_ambiguity,
        test_import_selection_program_suffix_unique_provider,
        test_import_selection_program_candidate_location_ambiguity,
        test_import_selection_program_requires_canonical_yaml_provider,
        test_import_selection_program_paths_base_head_and_manifests,
        test_import_selection_unresolved_program_ownership_falls_back,
        test_import_selection_graph_parse_and_read_failures,
        test_import_selection_c_and_python_loader_safety_parity,
        test_import_selection_documents_cached_by_blob_across_trees,
        test_import_selection_shared_paths_and_toolchains,
        test_import_selection_events_refs_index_and_opt_in_default,
        test_import_selection_generated_graph_property,
        test_import_selection_generated_suffix_ambiguity_property,
        test_import_selection_preserves_enforcement_wiring,
    ]
    for test in tests:
        test()
        print(f"{test.__name__}: passed", flush=True)
    print("actual workflow selectors: passed (20 generated module/program graph property cases; 8 generated suffix ambiguity cases; Bash 3 mapfile compatibility when needed)", flush=True)


def literal_pin_caller(pins: dict[str, str]) -> str:
    return (
        "name: Repository checks\non: pull_request\njobs:\n  validate:\n"
        "    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@"
        + "a" * 40 + "\n    with:\n"
        + "".join(f"      {key.replace('_', '-')}: '{value}'\n" for key, value in pins.items())
    )


def pin_only_binding_and_selection(*, literal: bool) -> None:
    """Replay the review's caller/input/selection probes in one Git fixture."""
    import yaml

    with WorkflowInputFixture(
        table=workflow_toolchain(WORKFLOW_INPUT_PINS),
        caller=literal_pin_caller(WORKFLOW_INPUT_PINS),
    ) as fixture, tempfile.TemporaryDirectory(
        prefix="encoder-guard-pin-only-",
        dir="/private/tmp" if Path("/private/tmp").is_dir() else None,
    ) as directory:
        runner_temp = Path(directory)
        for path in SELECTOR_MODULES + SELECTOR_COMPANIONS:
            fixture.write(path, "fixture: unchanged\n")
        for path in SELECTOR_MODULES:
            fixture.write(".axiom/encoding-manifests/" + path.rsplit(".", 1)[0] + ".json", "{}\n")
        fixture.base = commit(fixture.root, "base with unchanged modules and companions")
        proposed = {**WORKFLOW_INPUT_PINS, "axiom_encode_ref": "e" * 40}
        fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain(proposed))
        if literal:
            fixture.write(VALIDATION_CALLER, literal_pin_caller(proposed))
        head = commit(fixture.root, "content-free pin candidate")
        output = runner_temp / "binding-output"
        result = run_workflow_inputs(fixture.root, fixture.base, pins=proposed if literal else None,
                                     head=head, output=output)
        assert result.returncode == 0, result.stderr
        assert output.exists(), "proposed dependency refs were not carried to the validator"
        bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert all(bound[key] == value for key, value in proposed.items()), bound
        workflow = yaml.safe_load(WORKFLOW.read_text())
        select = next(step for step in workflow["jobs"]["validate"]["steps"]
                      if step.get("id") == "validation_targets")
        source = select["run"].replace("${{ github.event_name }}", "pull_request").replace(
            "${{ github.event.pull_request.base.sha }}", fixture.base)
        selected_output = runner_temp / "selection-output"
        selected = subprocess.run(["bash", "-c", source], cwd=fixture.root, env={
            **os.environ, "GITHUB_SHA": head, "RUNNER_TEMP": directory,
            "GITHUB_ENV": str(runner_temp / "env"), "GITHUB_OUTPUT": str(selected_output),
            "VALIDATE_ROOTS": "us", "VALIDATE_ROOTS_INPUT": "auto",
            "DEPENDENCY_PINS_CHANGED": bound["dependency_pins_changed"],
        }, capture_output=True, text=True, timeout=30)
        assert selected.returncode == 0, selected.stdout + selected.stderr
        assert "mode=full-toolchain-bump" in selected_output.read_text()
        assert (runner_temp / "rulespec-files.txt").read_text().splitlines() == SELECTOR_MODULES
        assert (runner_temp / "rulespec-test-files.txt").read_text().splitlines() == SELECTOR_COMPANIONS
        # Assert that the verified proposed pins actually reach all dependency
        # checkout and authentication steps, including optional consumers.
        for key in (*WORKFLOW_INPUT_PINS, "axiom_compose_ref"):
            assert workflow["jobs"]["shards"]["outputs"][key] == "${{ steps.dependency_inputs.outputs." + key + " }}"
        for step in workflow["jobs"]["validate"]["steps"]:
            if step.get("name", "").startswith("Checkout ") and "TheAxiomFoundation/" in step.get("with", {}).get("repository", ""):
                assert step["with"]["ref"].startswith("${{ needs.shards.outputs."), step


def test_literal_pin_only_binds_proposed_pin_and_selects_every_target() -> None:
    pin_only_binding_and_selection(literal=True)


def test_table_pin_only_binds_proposed_pin_and_selects_every_target() -> None:
    pin_only_binding_and_selection(literal=False)


def test_proposed_pin_exception_rejects_content_and_helper_changes() -> None:
    for path in ("us/statutes/item.yaml", "us/statutes/item.test.yaml", ".axiom/encoding-manifests/us/statutes/item.json",
                 "programs/us/item.yaml", "scripts/read_pin.py", "README.md"):
        with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
            proposed = {**WORKFLOW_INPUT_PINS, "axiom_encode_ref": "e" * 40}
            fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain(proposed))
            fixture.write(".axiom/toolchain.toml", SELECTOR_TOOLCHAIN.replace('"before"', '"after"'))
            fixture.write(path, "candidate\n")
            head = commit(fixture.root, "pin and non-configuration candidate")
            result = run_workflow_inputs(fixture.root, fixture.base, pins=proposed, head=head)
            assert result.returncode != 0, path
            assert "axiom_encode_ref" in result.stderr, result.stderr


def test_pin_changes_with_other_files_cannot_skip_proposed_pin_audit() -> None:
    pins = {**WORKFLOW_INPUT_PINS, "shared_workflow_ref": "8" * 40}
    caller = literal_pin_caller(WORKFLOW_INPUT_PINS).replace("@" + "a" * 40, "@" + pins["shared_workflow_ref"])
    for pin_source in ("table", "caller"):
        for path in ("README.md", "scripts/read_pin.py", ".github/workflows/unrelated.yml"):
            with WorkflowInputFixture(table=workflow_toolchain(pins), caller=caller) as fixture:
                if pin_source == "table":
                    fixture.write(WORKFLOW_TOOLCHAIN, workflow_toolchain({**pins, "axiom_encode_ref": "9" * 40}))
                else:
                    fixture.write(VALIDATION_CALLER, caller.replace(pins["shared_workflow_ref"], "9" * 40))
                fixture.write(path, "candidate\n")
                head = commit(fixture.root, "pin update with unrelated file")
                # Supplying the old inputs must not make a real pin change look
                # like a docs/helper update and evade proposed-pin revalidation.
                result = run_workflow_inputs(fixture.root, fixture.base, pins=WORKFLOW_INPUT_PINS, head=head)
                assert result.returncode != 0, (pin_source, path)
                assert "dependency pin changes require a configuration-only change" in result.stderr, result.stderr


def authorization_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# reviewed-migration-authorization-start")
    end = workflow.index("# reviewed-migration-authorization-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = next(marker for marker in (
        "python -I - <<'PY' >> \"$GITHUB_OUTPUT\"\n",
        "python - <<'PY' >> \"$GITHUB_OUTPUT\"\n",
    ) if block.startswith(marker))
    assert block.startswith(marker)
    assert block.endswith("          PY\n") or block.endswith("PY\n")
    source = block[len(marker) :]
    source = source.rsplit("\nPY", 1)[0]
    return textwrap.dedent(source)


def waiver_ratchet_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# waiver-ratchet-python-start")
    end = workflow.index("# waiver-ratchet-python-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = "<<'PY'\n"
    assert marker in block
    source = block.split(marker, 1)[1]
    source = source.rsplit("\nPY", 1)[0]
    return textwrap.dedent(source)


def test_pending_waiver_requires_exact_digest_only_toolchain_companion() -> None:
    metadata = (
        'fingerprint: "sha256:' + "a" * 64 + '"\n'
        '      owner: "@owner"\n'
        '      issue: "https://github.com/TheAxiomFoundation/repo/issues/1"\n'
        '      expires: "2026-10-01"\n'
    )
    base_waiver = (
        "validate_failures:\n"
        "  us/statutes/1.yaml:\n"
        "    active:\n      "
        + metadata
    ).encode()
    pending_metadata = metadata.replace("a" * 64, "b" * 64)
    head_waiver = base_waiver + b"    pending:\n      " + pending_metadata.encode()
    base_digest = hashlib.sha256(base_waiver).hexdigest()
    head_digest = hashlib.sha256(head_waiver).hexdigest()
    base_toolchain = (
        "[toolchain]\n"
        'axiom_corpus_release = "unchanged"\n'
        f'axiom_corpus_release_content_sha256 = "{"c" * 64}"\n'
        f'validation_waiver_set_sha256 = "{base_digest}"\n'
    ).encode()
    head_toolchain = base_toolchain.replace(base_digest.encode(), head_digest.encode())

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = {
            "base_waiver": root / "base.yaml",
            "head_waiver": root / "head.yaml",
            "base_toolchain": root / "base.toml",
            "head_toolchain": root / "head.toml",
            "changed": root / "changed.txt",
            "audit_changed": root / "audit-changed.txt",
        }
        paths["base_waiver"].write_bytes(base_waiver)
        paths["head_waiver"].write_bytes(head_waiver)
        paths["base_toolchain"].write_bytes(base_toolchain)
        paths["head_toolchain"].write_bytes(head_toolchain)
        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"
        )

        def run() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    waiver_ratchet_source(),
                    *(str(path) for path in paths.values()),
                ],
                capture_output=True,
                text=True,
            )

        result = run()
        assert result.returncode == 0, result.stderr
        assert paths["audit_changed"].read_text() == "known-validation-gaps.yaml\n"

        # Staging requires an exact byte-for-byte digest-only companion,
        # including unrelated TOML that would leave the parsed pins unchanged.
        for unrelated_edit in (
            head_toolchain.replace(b'"unchanged"', b'"changed"'),
            head_toolchain + b'axiom_encode_ref = "unrelated"\n',
            head_toolchain + b"[other]\nsetting = true\n",
            head_toolchain + b"# unrelated comment\n",
            head_toolchain.replace(b"[toolchain]\n", b"[toolchain]\n\n"),
        ):
            paths["head_toolchain"].write_bytes(unrelated_edit)
            result = run()
            assert result.returncode != 0, result.stdout
            assert "ValidationWaiverPinCompanionScope" in result.stderr

        paths["head_toolchain"].write_bytes(
            head_toolchain.replace(head_digest.encode(), b"0" * 64)
        )
        result = run()
        assert result.returncode != 0, result.stdout
        assert "ValidationWaiverPinCompanionMismatch" in result.stderr
        paths["head_toolchain"].write_bytes(head_toolchain)

        paths["changed"].write_text("known-validation-gaps.yaml\n")
        assert run().returncode != 0

        for extra_path in ("us/statutes/1.yaml", ".github/workflows/repository-checks.yml"):
            paths["changed"].write_text(
                "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"
                + extra_path
                + "\n"
            )
            result = run()
            assert result.returncode != 0, result.stdout
            assert "ValidationWaiverRatchetGrowth" in result.stderr

        # A newly introduced module can be preapproved, but still only through
        # the same exact two-file transition.
        new_base_waiver = b"validate_failures: {}\n"
        new_head_waiver = (
            b"validate_failures:\n  us/statutes/1.yaml:\n    pending:\n      "
            + pending_metadata.encode()
        )
        new_base_digest = hashlib.sha256(new_base_waiver).hexdigest()
        new_head_digest = hashlib.sha256(new_head_waiver).hexdigest()
        new_base_toolchain = base_toolchain.replace(
            base_digest.encode(), new_base_digest.encode()
        )
        new_head_toolchain = new_base_toolchain.replace(
            new_base_digest.encode(), new_head_digest.encode()
        )
        paths["base_waiver"].write_bytes(new_base_waiver)
        paths["head_waiver"].write_bytes(new_head_waiver)
        paths["base_toolchain"].write_bytes(new_base_toolchain)
        paths["head_toolchain"].write_bytes(new_head_toolchain)
        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"
        )
        assert run().returncode == 0

        # Bootstrap mode authenticates the exact head candidate as its own
        # protected comparison baseline; the ratchet must accept that identity.
        paths["base_waiver"].write_bytes(new_head_waiver)
        paths["base_toolchain"].write_bytes(new_head_toolchain)
        assert run().returncode == 0


def test_release_pin_companion_requires_strict_retirement() -> None:
    import yaml

    entry = {"active": {"fingerprint": "sha256:" + "a" * 64}}
    base_entries = {"us/one.yaml": entry, "us/two.yaml": entry}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = [root / name for name in (
            "base.yaml", "head.yaml", "base.toml", "head.toml", "changed", "audit"
        )]
        changed = "known-validation-gaps.yaml\n.axiom/toolchain.toml\nus/one.yaml\n"
        paths[4].write_text(changed)

        def run(entries=None, *, release="new-release", digest="b" * 64,
                extra="", corrupt_pin=False):
            if entries is None:
                entries = {"us/two.yaml": entry}
            for path, records in zip(paths[:2], (base_entries, entries)):
                path.write_text(yaml.safe_dump({"validate_failures": records}))
            for index, name, sha in ((0, "old-release", "a" * 64), (1, release, digest)):
                pin = hashlib.sha256(paths[index].read_bytes()).hexdigest()
                if index == 1 and corrupt_pin:
                    pin = "0" * 64
                paths[index + 2].write_text(
                    '[toolchain]\n'
                    f'axiom_corpus_release = "{name}"\n'
                    f'axiom_corpus_release_content_sha256 = "{sha}"\n'
                    f'validation_waiver_set_sha256 = "{pin}"\n'
                    + (extra if index == 1 else "")
                )
            return subprocess.run(
                [sys.executable, "-c", waiver_ratchet_source(), *map(str, paths)],
                capture_output=True, text=True,
            )

        result = run()
        assert result.returncode == 0, result.stderr
        assert paths[5].read_text() == changed
        # Even a two-file retirement must retain the release pin in the audit.
        paths[4].write_text("known-validation-gaps.yaml\n.axiom/toolchain.toml\n")
        assert run().returncode == 0
        assert paths[5].read_text() == paths[4].read_text()
        assert run({}).returncode == 0
        assert run(base_entries).returncode != 0  # No retirement.
        assert run({"us/new.yaml": entry}).returncode != 0
        assert run({"us/two.yaml": {"pending": entry["active"]}}).returncode != 0
        assert run({"us/two.yaml": {**entry, "pending": entry["active"]}}).returncode != 0
        assert run({"us/two.yaml": {"active": {"fingerprint": "changed"}}}).returncode != 0
        assert run(extra='axiom_encode_ref = "changed"\n').returncode != 0
        assert run(extra='[other]\nsetting = true\n').returncode != 0
        assert run(corrupt_pin=True).returncode != 0
        assert run(release="../unsigned").returncode != 0
        assert run(digest="invalid").returncode != 0


def waiver_record(fingerprint: str, *, expires: str = "2026-11-01") -> dict:
    return {
        "fingerprint": "sha256:" + fingerprint * 64,
        "owner": "@owner",
        "issue": "https://github.com/TheAxiomFoundation/rulespec-us/issues/1",
        "expires": expires,
    }


def run_release_repin(
    base_entries: dict,
    head_entries: dict,
    *,
    changed: str = "known-validation-gaps.yaml\n.axiom/toolchain.toml\n",
    release: str = "new-release",
    release_sha: str = "b" * 64,
    extra: str = "",
    head_ledger_suffix: str = "",
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run the extracted ratchet over a corpus re-pin; return (result, audit)."""
    import yaml

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        base_ledger, head_ledger, base_toml, head_toml, changed_path, audit = (
            root / name
            for name in (
                "base.yaml", "head.yaml", "base.toml", "head.toml", "changed", "audit"
            )
        )
        base_ledger.write_text(yaml.safe_dump({"validate_failures": base_entries}))
        head_ledger.write_text(
            yaml.safe_dump({"validate_failures": head_entries}) + head_ledger_suffix
        )
        for ledger, toml, name, sha, suffix in (
            (base_ledger, base_toml, "old-release", "a" * 64, ""),
            (head_ledger, head_toml, release, release_sha, extra),
        ):
            toml.write_text(
                "[toolchain]\n"
                f'axiom_corpus_release = "{name}"\n'
                f'axiom_corpus_release_content_sha256 = "{sha}"\n'
                'validation_waiver_set_sha256 = '
                f'"{hashlib.sha256(ledger.read_bytes()).hexdigest()}"\n'
                + suffix
            )
        changed_path.write_text(changed)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                waiver_ratchet_source(),
                *map(
                    str,
                    (base_ledger, head_ledger, base_toml, head_toml, changed_path, audit),
                ),
            ],
            capture_output=True,
            text=True,
        )
        return result, audit.read_text() if audit.exists() else ""


def test_release_pin_companion_accepts_exact_staged_consumption() -> None:
    old, new, other = waiver_record("a"), waiver_record("b"), waiver_record("c")
    kept = {"active": other}
    staged = {"active": old, "pending": new}
    pending_only = {"pending": new}
    base = {"us/kept.yaml": kept, "us/staged.yaml": staged, "us/fixed.yaml": kept}
    changed = "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"

    def accepted(head: dict, base_entries: dict = base, **kwargs) -> None:
        result, audit = run_release_repin(base_entries, head, **kwargs)
        assert result.returncode == 0, result.stderr
        # The re-pin never narrows the audit to the ledger alone.
        assert audit == kwargs.get("changed", changed)

    def rejected(head: dict, base_entries: dict = base, **kwargs) -> str:
        result, _ = run_release_repin(base_entries, head, **kwargs)
        assert result.returncode != 0, result.stdout
        return result.stderr

    consumed = {"us/kept.yaml": kept, "us/staged.yaml": {"active": new}}

    # Positive: {active, pending} -> {active: base.pending} with the re-pin.
    accepted({**consumed, "us/fixed.yaml": kept})
    # Positive: consumption and strict retirement travel together.
    accepted(consumed)
    # Positive: strict retirement alone (the #111 path) still passes.
    accepted({"us/kept.yaml": kept, "us/staged.yaml": staged})
    # Positive: pending-only {pending} -> {active: base.pending}.
    accepted(
        {"us/new-failure.yaml": {"active": new}, "us/kept.yaml": kept},
        {"us/new-failure.yaml": pending_only, "us/kept.yaml": kept},
    )
    # Positive: several staged approvals may be consumed by one re-pin.
    accepted(
        {"us/one.yaml": {"active": new}, "us/two.yaml": {"active": other}},
        {
            "us/one.yaml": {"active": old, "pending": new},
            "us/two.yaml": {"active": old, "pending": other},
        },
    )
    # Positive: the audit keeps every changed path of a wider re-pin PR.
    accepted(consumed, changed=changed + "us/kept.yaml\n")

    # Negative: an active fingerprint change with no staged base pending.
    assert "us/kept.yaml" in rejected(
        {**consumed, "us/kept.yaml": {"active": new}}
    )
    # Negative: a new pending record, on its own or next to a consumption.
    rejected({**consumed, "us/kept.yaml": {"active": other, "pending": new}})
    rejected(
        {**base, "us/kept.yaml": {"active": other, "pending": new}},
    )
    # Negative: any other toolchain key changes with the re-pin.
    assert "toolchain key" in rejected(consumed, extra='axiom_encode_ref = "x"\n')
    rejected(consumed, extra="[other]\nsetting = true\n")
    # Negative: a new ledger entry, even a pending-only one.
    assert "new entry" in rejected({**consumed, "us/new.yaml": {"active": new}})
    rejected({**consumed, "us/new.yaml": pending_only})
    # Negative: consumption that does not match the base pending exactly.
    rejected({**consumed, "us/staged.yaml": {"active": other}})
    rejected(
        {**consumed, "us/staged.yaml": {"active": {**new, "expires": "2026-12-01"}}}
    )
    rejected({**consumed, "us/staged.yaml": {"active": {**new, "owner": "@other"}}})
    rejected(
        {
            **consumed,
            "us/staged.yaml": {
                "active": {
                    **new,
                    "issue": "https://github.com/TheAxiomFoundation/rulespec-us/issues/2",
                }
            },
        }
    )
    rejected(
        {
            **consumed,
            "us/staged.yaml": {
                "active": {key: value for key, value in new.items() if key != "owner"}
            },
        }
    )
    rejected(
        {**consumed, "us/staged.yaml": {"active": {**new, "extra": "field"}}}
    )
    # Type-strict: an int may not stand in for a float in a staged record.
    rejected(
        {"us/staged.yaml": {"active": {**new, "rank": 1}}},
        {"us/staged.yaml": {"active": old, "pending": {**new, "rank": 1.0}}},
    )
    # Negative: consumption must drop pending, not keep it beside active.
    rejected({**consumed, "us/staged.yaml": {"active": new, "pending": new}})
    # Negative: dropping pending while keeping the old active is not consumption.
    rejected({**consumed, "us/staged.yaml": {"active": old}})
    # Negative: a pending record from one module cannot activate another.
    rejected(
        {"us/one.yaml": {"active": new}, "us/two.yaml": {"active": old, "pending": new}},
        {"us/one.yaml": {"active": old}, "us/two.yaml": {"active": old, "pending": new}},
    )
    # Negative: a re-pin whose rewritten ledger records no transition at all.
    assert "at least one" in rejected(base, head_ledger_suffix="# comment\n")
    # Negative: a non-digest toolchain rewrite must actually move the release,
    # and the new release must stay well-formed.
    rejected(consumed, release="old-release", release_sha="a" * 64, extra="# x\n")
    rejected(consumed, release="../unsigned")
    rejected(consumed, release_sha="invalid")


def guard_base_ref_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Reject manual RuleSpec changes")
    end = workflow.index("      - name: Validate RuleSpec YAML", start)
    step = workflow[start:end]
    block_start = step.index("# generated-guard-base-ref-start")
    block_end = step.index("# generated-guard-base-ref-end")
    return textwrap.dedent(step[block_start:block_end].split("\n", 1)[1])


# Mirrors safe_ref in axiom-encode scripts/provision_verification_supervisor.py,
# the trusted git wrapper the supervised generated guard runs under.
TRUSTED_GIT_SAFE_REF = r"(?:HEAD|main|origin/main|[0-9a-f]{40})(?:\^\{commit\})?"


def test_generated_guard_resolves_scheduled_base_to_exact_commit() -> None:
    import re

    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Reject manual RuleSpec changes")
    end = workflow.index("      - name: Validate RuleSpec YAML", start)
    step = workflow[start:end]
    assert 'base_ref="HEAD~1"' not in step
    assert '--base-ref "$base_ref"' in step
    # HEAD~1 must exist in the validate job's clone for rev-parse to resolve it.
    validate_job = workflow.index("    name: validate\n")
    checkout = workflow.index("      - name: Checkout rules repository", validate_job)
    checkout_step = workflow[checkout : workflow.index("      - name:", checkout + 1)]
    assert "fetch-depth: 0" in checkout_step
    assert checkout < start

    def resolve(root: Path, *, event: str, pr_base: str = "", group_base: str = "", before: str = ""):
        source = (
            guard_base_ref_source()
            .replace("${{ github.event_name }}", event)
            .replace("${{ github.event.pull_request.base.sha }}", pr_base)
            .replace("${{ github.event.merge_group.base_sha }}", group_base)
            .replace("${{ github.event.before }}", before)
        )
        assert "${{" not in source
        return subprocess.run(
            ["bash", "-c", "set -euo pipefail\n" + source + 'printf %s "$base_ref"\n'],
            cwd=root,
            capture_output=True,
            text=True,
        )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")
        (root / "file.txt").write_text("one\n")
        first = commit(root, "first")

        # A root commit has no parent: fail closed instead of passing HEAD~1.
        assert resolve(root, event="schedule").returncode != 0

        (root / "file.txt").write_text("two\n")
        second = commit(root, "second")
        for event in ("schedule", "workflow_dispatch"):
            result = resolve(root, event=event)
            assert result.returncode == 0, result.stderr
            assert result.stdout == first
            assert re.fullmatch(TRUSTED_GIT_SAFE_REF, result.stdout)
            assert not re.fullmatch(TRUSTED_GIT_SAFE_REF, "HEAD~1")
        # A push that created the branch reports an all-zero before SHA.
        result = resolve(root, event="push", before="0" * 40)
        assert result.returncode == 0, result.stderr
        assert result.stdout == first
        result = resolve(root, event="push", before=first)
        assert result.returncode == 0 and result.stdout == first
        result = resolve(root, event="pull_request", pr_base=second)
        assert result.returncode == 0 and result.stdout == second
        result = resolve(root, event="merge_group", group_base=second)
        assert result.returncode == 0 and result.stdout == second
        # Anything that is not an exact commit identity is refused up front.
        assert resolve(root, event="pull_request", pr_base="main").returncode != 0
        assert resolve(root, event="merge_group", group_base="main").returncode != 0
        assert resolve(root, event="push", before="HEAD~1").returncode != 0


def test_unmanifested_precheck_guards_programs_only_on_opt_in() -> None:
    import yaml

    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = [
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    ]
    step = next(s for s in steps if s.get("name") == "Reject unmanifested RuleSpec content")
    # The opt-in must reach the step from the same input that adds
    # `programs` to the validate roots, and the shape check's parser must be
    # installed before the step runs.
    assert step["env"]["GUARD_PROGRAMS_ROOT"] == "${{ inputs.guard-programs-root }}"
    assert "${{" not in step["run"]
    install = steps.index(next(s for s in steps if s.get("name") == "Install the ProgramSpec shape-check parser"))
    assert "pyyaml==6.0.3" in steps[install]["run"]
    assert install < steps.index(step)

    def manifest(path: str, content: str) -> str:
        digest = hashlib.sha256(content.encode()).hexdigest()
        return json.dumps({"applied_files": [{"path": path, "sha256": digest}]})

    def write(root: Path, relative: str, content: str) -> None:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def link(root: Path, relative: str, destination: str) -> None:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(destination)

    def precheck(root: Path, base: str, head: str, guard_programs: str | None):
        env = {
            key: value
            for key, value in os.environ.items()
            if key != "GUARD_PROGRAMS_ROOT"
        } | {
            "BASE_SHA": base,
            "GITHUB_SHA": head,
            "GITHUB_REPOSITORY": "TheAxiomFoundation/rulespec-us",
            "EVENT_NAME": "pull_request",
            "RUN_GENERATED_GUARD": "true",
        }
        if guard_programs is not None:
            env["GUARD_PROGRAMS_ROOT"] = guard_programs
        git(root, "checkout", "-q", head)
        return subprocess.run(
            ["bash", "-c", step["run"]],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )

    def program_spec(
        program: str,
        *,
        scope: str = "regulations/7-cfr/273/9",
        extra: str = "",
        header: str = "",
        state: str = "us-xx:policies/manual/page-1",
    ) -> str:
        return (
            f"program: {program}\n"
            "period: 2026-01\n"
            "outputs:\n  - snap_eligible\n"
            f"scope:\n{header}  federal:\n    - {scope}\n"
            f"  state:\n    - {state}\n"
            "  jurisdictions:\n    - us\n    - us-xx\n"
            "transformations:\n"
            "  - pattern: derived_formula\n"
            "    name: annual_snap_benefit\n"
            "    effective_from: '2026-01-01'\n"
            "    entity: Household\n"
            "    dtype: Money\n"
            "    period: Year\n"
            "    unit: USD\n"
            "    formula: snap_benefit * 12\n"
            "  - pattern: conditional_value\n"
            "    name: snap_benefit\n"
            "    effective_from: '2026-01-01'\n"
            "    condition: snap_eligible\n"
            "    when_true: snap_monthly_allotment\n"
            "    when_false: 0\n"
            "  - pattern: derived_formula\n"
            "    name: assistance_group_size\n"
            "    effective_from: '2026-01-01'\n"
            "    dtype: Count\n"
            "    source: 'FL ESS 2210.0301 (SFU = household); 7 CFR 273.1'\n"
            "    formula: |-\n"
            "      household_size  # Appendix A-1 rows 1-10 + 1 per member\n"
            "  - pattern: sum_terms\n"
            "    name: snap_gross_monthly_income\n"
            "    effective_from: '2026-01-01'\n"
            "    unit: USD\n"
            "    terms:\n      - snap_countable_earned_income\n      - snap_countable_unearned_income\n"
            "  - pattern: table_lookup_with_extension\n"
            "    name: bounded_limit\n"
            "    effective_from: '2026-01-01'\n"
            "    index: household_size\n"
            "    table: limit_table\n"
            "    extension: limit_each_additional_member\n"
            "    minimum_index: 1\n"
            "    maximum_index: 8\n"
            + extra
        )

    def branch(root: Path, base: str, name: str, files: dict[str, str], links: dict[str, str] | None = None) -> str:
        git(root, "checkout", "-q", base)
        git(root, "checkout", "-q", "-B", name)
        for relative, content in files.items():
            write(root, relative, content)
        for relative, destination in (links or {}).items():
            link(root, relative, destination)
        return commit(root, name)

    spec = "programs/us-xx/snap/fy-2026.yaml"
    federal = "regulations/7-cfr/273/9.yaml"
    statute = "statutes/7/2014/a.yaml"
    state = "us-xx/policies/manual/page-1.yaml"
    module = "format: rulespec/v1\nrules: []\n"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")
        for relative, content, manifest_path, applied in [
            (spec, program_spec("us-xx/snap"), ".axiom/encoding-manifests/programs/us-xx/snap/fy-2026.json", spec),
            (federal, module, ".axiom/encoding-manifests/regulations/7-cfr/273/9.json", federal),
            (statute, module, ".axiom/encoding-manifests/statutes/7/2014/a.json", statute),
            (state, module, "us-xx/.axiom/encoding-manifests/policies/manual/page-1.json", "policies/manual/page-1.yaml"),
        ]:
            write(root, relative, content)
            write(root, manifest_path, manifest(applied, content))
        base = commit(root, "manifested base")

        # Assembled ProgramSpec edits: top-level and jurisdiction-nested, with
        # the root, `prefix:` and jurisdiction-prefixed entry forms, all
        # resolving to encoded modules. No manifest needed on the opt-out.
        program_edit = branch(root, base, "edit-program-specs", {
            spec: program_spec("us-xx/snap", scope="us-xx/policies/manual/page-1"),
            "programs/us-xx/tanf/fy-2026.yaml": program_spec("us-xx/tanf", scope="us:statutes/7/2014/a"),
            # An unqualified `state` entry resolves under the program's
            # jurisdiction (us-xx), not the federal prefix.
            "us-xx/programs/snap/fy-2027.yaml": program_spec("us-xx/snap", state="policies/manual/page-1"),
        })
        for opt_out in ("false", None):
            result = precheck(root, base, program_edit, opt_out)
            assert result.returncode == 0, result.stderr
            assert "3 changed ProgramSpec file(s) have the ProgramSpec shape" in result.stdout
            assert "No guarded RuleSpec content in scope" in result.stdout
        result = precheck(root, base, program_edit, "true")
        assert result.returncode != 0
        assert f"{spec} content matches no sha256" in result.stderr
        assert "programs/us-xx/tanf/fy-2026.yaml has no tracked encoder apply manifest" in result.stderr
        assert "us-xx/programs/snap/fy-2027.yaml has no tracked encoder apply manifest" in result.stderr

        # Each case is a change a hand-written module or amount could ride in
        # on; every one must fail on the opt-out with the named reason.
        bbce = "format: rulespec/v1\nrules:\n  - name: bbce_limit\n    versions:\n      - formula: 2.0 * snap_poverty_line\n"
        cases = [
            (
                "smuggled-module",
                {"programs/us/helpers/bbce.yaml": bbce, spec: program_spec("us-xx/snap", scope="programs/us/helpers/bbce")},
                {},
                [
                    "programs/us/helpers/bbce.yaml lacks ProgramSpec keys: outputs, period, program",
                    "programs/us/helpers/bbce.yaml has keys a ProgramSpec does not take: format, rules",
                    f"{spec} scope.federal entry 'programs/us/helpers/bbce' resolves to programs/us/helpers/bbce.yaml, which is not an encoded module",
                ],
            ),
            (
                "scopeless",
                {"bulk/bbce.yaml": bbce, spec: "program: us-xx/snap\nperiod: 2026-01\noutputs:\n  - smuggled_bbce_eligible\n"},
                {},
                [f"{spec} has no import scope"],
            ),
            (
                "double-nested",
                {"us/us-xx/policies/bbce.yaml": bbce, spec: program_spec("us-xx/snap", scope="us-xx/policies/bbce")},
                {},
                ["entry 'us-xx/policies/bbce' resolves to us/us-xx/policies/bbce.yaml, which is not an encoded module"],
            ),
            (
                "symlinked-root",
                {"bulk/bbce.yaml": bbce, spec: program_spec("us-xx/snap", scope="policies/ext.json/bbce")},
                {"us/policies/ext.json": "../../bulk"},
                ["entry 'policies/ext.json/bbce' resolves to us/policies/ext.json/bbce.yaml, which is not an encoded module"],
            ),
            (
                "dangling-symlink-spec",
                {},
                {"programs/us-xx/dangling/fy-2026.yaml": "../../../nowhere.yaml"},
                ["programs/us-xx/dangling/fy-2026.yaml is a symlink or sits under one"],
            ),
            (
                "symlinked-spec",
                {"bulk/specs/tanf.yaml": program_spec("us-xx/tanf")},
                {"programs/us-xx/tanf/fy-2026.yaml": "../../../bulk/specs/tanf.yaml"},
                ["programs/us-xx/tanf/fy-2026.yaml is a symlink or sits under one"],
            ),
            (
                "scope-key-import",
                {
                    "programs/us-xx/snap/helpers/bbce.test.yaml": bbce,
                    spec: program_spec("us-xx/snap", header='  "us:programs/us-xx/snap/helpers/bbce.test#":\n    - statutes/7/2014/a\n'),
                },
                {},
                ["scope key 'us:programs/us-xx/snap/helpers/bbce.test#' is neither federal, state nor a jurisdiction"],
            ),
            ("relative-entry", {spec: program_spec("us-xx/snap", scope="policies/../programs/x")}, {}, ["entry 'policies/../programs/x' (import us:policies/../programs/x) does not resolve"]),
            # An import that resolves to a directory, not a module file.
            (
                "directory-import",
                {"regulations/directory.yaml/README.txt": "not a module\n", spec: program_spec("us-xx/snap", scope="regulations/directory")},
                {},
                ["entry 'regulations/directory' resolves to regulations/directory.yaml, which is not a regular file"],
            ),
            ("null-outputs", {spec: program_spec("us-xx/snap").replace("outputs:\n  - snap_eligible\n", "outputs:\n", 1)}, {}, [f"{spec} outputs must be a non-empty list of rule names"]),
            (
                "invalid-date",
                {spec: program_spec("us-xx/snap", extra="  - pattern: sum_terms\n    name: dated\n    effective_from: '2026-02-30'\n    terms:\n      - snap_benefit\n")},
                {},
                ["(dated) effective_from '2026-02-30' is not a date"],
            ),
            # A foreign prefix never falls back to the repo root, and the
            # engine's rulespec-<prefix>/ shadow is tried first and refused.
            ("foreign-prefix-root", {spec: program_spec("us-xx/snap", scope="us-yy:regulations/7-cfr/273/9")}, {}, ["entry 'us-yy:regulations/7-cfr/273/9' (import us-yy:regulations/7-cfr/273/9) does not resolve"]),
            (
                "foreign-prefix-shadow",
                {"rulespec-us-xx/policies/manual/page-1.yaml": bbce, spec: program_spec("us-xx/snap", scope="statutes/7/2014/a")},
                {},
                ["entry 'us-xx:policies/manual/page-1' resolves to rulespec-us-xx/policies/manual/page-1.yaml, which is not an encoded module"],
            ),
            ("missing-entry", {spec: program_spec("us-xx/snap", scope="regulations/7-cfr/999")}, {}, ["entry 'regulations/7-cfr/999' (import us:regulations/7-cfr/999) does not resolve"]),
            (
                "test-entry",
                {"us-xx/policies/manual/page-1.test.yaml": bbce, spec: program_spec("us-xx/snap", scope="us-xx/policies/manual/page-1.test")},
                {},
                ["resolves to us-xx/policies/manual/page-1.test.yaml, which is not an encoded module"],
            ),
            ("tools-entry", {"tools/bbce.yaml": bbce, spec: program_spec("us-xx/snap", scope="us:tools/bbce")}, {}, ["resolves to tools/bbce.yaml, which is not an encoded module"]),
            ("test-file", {"programs/us-xx/snap/fy-2026.test.yaml": "- name: not a spec\n"}, {}, ["programs/us-xx/snap/fy-2026.test.yaml is not a ProgramSpec mapping"]),
            ("program-prefix", {"us/bulk:policies/bbce.yaml": bbce, spec: program_spec("us:bulk/snap")}, {}, ["program 'us:bulk/snap' is not <jurisdiction>/<name>"]),
            (
                "entity-injection",
                {spec: program_spec("us-xx/snap", extra="  - pattern: derived_formula\n    name: injected\n    effective_from: '2026-01-01'\n    entity: \"Household\\n    from 2026-01-01:\\n        2610\"\n    formula: snap_monthly_allotment\n")},
                {},
                ["(injected) entity 'Household\\n    from 2026-01-01:\\n        2610' is not a plain identifier"],
            ),
            (
                "unknown-pattern",
                {spec: program_spec("us-xx/snap", extra="  - pattern: raw_rule\n    name: anything\n")},
                {},
                ["(anything) uses unknown pattern 'raw_rule'"],
            ),
            (
                "negative-when-false",
                {spec: program_spec("us-xx/snap", extra="  - pattern: conditional_value\n    name: floor\n    effective_from: '2026-01-01'\n    condition: snap_eligible\n    when_true: snap_monthly_allotment\n    when_false: -24\n")},
                {},
                ["(floor) when_false carries the literal -24"],
            ),
            (
                "literal-term",
                {spec: program_spec("us-xx/snap", extra="  - pattern: sum_terms\n    name: padded\n    effective_from: '2026-01-01'\n    terms:\n      - snap_benefit\n      - 2610\n")},
                {},
                ["(padded) terms carries the literal 2610"],
            ),
        ]
        # Formatting must not hide a literal: operators, slashes, digit
        # separators, exponents, decimals, a `#` inside a string, and a
        # trailing comment glued to the amount.
        for index, (formula, literal) in enumerate([
            ("snap_poverty_line/2", "2"),
            ("snap_poverty_line-24", "24"),
            ("snap_poverty_line * 2_00", "2_00"),
            ("snap_poverty_line * 2e0", "2"),
            ("min(snap_benefit, 23.99)", "23.99"),
            ("if snap_eligible: snap_monthly_allotment else:2610#x", "2610"),
            ('if snap_eligible == " #": snap_monthly_allotment else: 2610', "2610"),
        ]):
            cases.append((
                f"literal-{index}",
                {spec: program_spec("us-xx/snap", extra=f"  - pattern: derived_formula\n    name: smuggled\n    effective_from: '2026-01-01'\n    formula: {json.dumps(formula)}\n")},
                {},
                [f"(smuggled) formula carries the literal {literal}"],
            ))
        # No formula needs a string, so quotes and backslashes are refused:
        # the engine lexes all rules as one source with escapes, and an open
        # string could otherwise hide a `#` or a literal from this scan.
        for index, (formula, character) in enumerate([
            ('if "\\" #" == "": snap_monthly_allotment else: snap_monthly_allotment + 1', '\\'),
            ("if 'x' == '", "'"),
            ('snap_benefit # "', '"'),
        ]):
            cases.append((
                f"quoted-{index}",
                {spec: program_spec("us-xx/snap", extra=f"  - pattern: derived_formula\n    name: quoted\n    effective_from: '2026-01-01'\n    formula: {json.dumps(formula)}\n")},
                {},
                [f"(quoted) formula carries a quote or backslash {character!r}; formulas take no strings"],
            ))
        for name, files, links, messages in cases:
            head = branch(root, base, name, files, links)
            for guard_programs in ("false", "true", None):
                result = precheck(root, base, head, guard_programs)
                assert result.returncode != 0, (name, result.stdout)
                for message in messages:
                    assert message in result.stderr, (name, message, result.stderr)

        # A gitlink (submodule) named like a spec is not a regular file.
        git(root, "checkout", "-q", base)
        git(root, "checkout", "-q", "-B", "gitlink-spec")
        git(root, "update-index", "--add", "--cacheinfo", f"160000,{base},programs/us-xx/sub.yaml")
        (root / "programs/us-xx/sub.yaml").mkdir(parents=True)
        git(root, "commit", "-qm", "gitlink spec")
        gitlink = git(root, "rev-parse", "HEAD")
        for guard_programs in ("false", "true"):
            result = precheck(root, base, gitlink, guard_programs)
            assert result.returncode != 0, guard_programs
            assert "programs/us-xx/sub.yaml is not a regular file" in result.stderr

        # A gitlink at an import's resolved path is a directory, not a module.
        git(root, "checkout", "-q", base)
        git(root, "checkout", "-q", "-B", "gitlink-import")
        git(root, "update-index", "--add", "--cacheinfo", f"160000,{base},regulations/sub.yaml")
        (root / "regulations/sub.yaml").mkdir(parents=True)
        write(root, spec, program_spec("us-xx/snap", scope="regulations/sub"))
        git(root, "add", spec)
        git(root, "commit", "-qm", "gitlink import")
        gitlink_import = git(root, "rev-parse", "HEAD")
        for guard_programs in ("false", "true"):
            result = precheck(root, base, gitlink_import, guard_programs)
            assert result.returncode != 0, guard_programs
            assert "entry 'regulations/sub' resolves to regulations/sub.yaml, which is not a regular file" in result.stderr

        # Atomic modules stay manifest-guarded whatever the programs opt-in says.
        for relative in (federal, statute, state):
            atomic_edit = branch(root, base, f"edit-{relative.replace('/', '-')}", {
                relative: "format: rulespec/v1\nrules: []\n# edited\n",
            })
            for guard_programs in ("false", "true", None):
                result = precheck(root, base, atomic_edit, guard_programs)
                assert result.returncode != 0, (relative, guard_programs)
                assert f"{relative} content matches no sha256" in result.stderr

        # A re-manifested atomic edit still passes under the opt-out.
        edited = "format: rulespec/v1\nrules: []\n# edited\n"
        manifested_edit = branch(root, base, "re-manifested", {
            federal: edited,
            ".axiom/encoding-manifests/regulations/7-cfr/273/9.json": manifest(federal, edited),
        })
        result = precheck(root, base, manifested_edit, "false")
        assert result.returncode == 0, result.stderr
        assert "every one carries an encoder apply manifest" in result.stdout


def test_waiver_bootstrap_uses_authenticated_head_toolchain() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Enforce validation waiver ratchet")
    end = workflow.index("      - name: Reject manual RuleSpec changes")
    audit_step = workflow[start:end]
    assert 'if [ -n "$BOOTSTRAP_SHA256" ]; then' in audit_step
    assert 'cp .axiom/toolchain.toml "$protected_base_toolchain"' in audit_step


def test_retired_schema_freeze_classifies_only_plural_citations() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Verify immutable retired-schema freeze")
    end = workflow.index("      - name: Fetch pinned signed corpus release object")
    freeze_step = workflow[start:end]

    assert '"corpus_citation_paths" in source_verification' in freeze_step
    assert "upstream_source_check" not in freeze_step


def test_retired_schema_prefreeze_bridge_is_fail_closed() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Verify immutable retired-schema freeze")
    end = workflow.index("      - name: Fetch pinned signed corpus release object")
    freeze_step = workflow[start:end]

    assert "allow-retired-schema-prefreeze" in workflow
    assert 'default: false' in workflow
    assert "pre-freeze compatibility is restricted to rulespec-us" in freeze_step
    assert "pre-freeze compatibility requires the generated guard" in freeze_step
    assert "pre-freeze compatibility cannot be used with a freeze" in freeze_step


def test_validation_waiver_audit_is_exhaustively_partitioned_across_matrix() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Enforce validation waiver ratchet")
    # Check the waiver step itself; the following base-manifest preparation
    # deliberately runs once and must not be mistaken for waiver partitioning.
    end = workflow.index("\n      - name:", start + 1)
    audit_step = workflow[start:end]

    assert "matrix.shard == needs.shards.outputs.first" not in audit_step
    assert "needs.shards.outputs.first" not in audit_step
    assert '--partition-key "${{ matrix.shard }}"' in audit_step
    assert "--partition-keys-json '${{ needs.shards.outputs.matrix }}'" in audit_step
    assert (
        "AXIOM_ENCODE_WAIVER_AUDIT_WORKERS: "
        "${{ github.repository == 'TheAxiomFoundation/rulespec-us' "
        "&& matrix.shard == 'us-wa' && '2' || '1' }}"
    ) in audit_step


def test_lane_registry_regressions_run_from_shared_workflow_entrypoint() -> None:
    """The shared CI entry point must include the lane publication regressions."""
    import ast
    from types import SimpleNamespace

    entrypoint = ast.parse(Path(__file__).read_text()).body[-1]
    calls = []

    def record_registry(command, **options):
        calls.append(("registry", command, options))

    scope = {
        **globals(),
        "__name__": "__main__",
        "main": lambda: calls.append(("main",)),
        "subprocess": SimpleNamespace(run=record_registry),
    }
    exec(compile(ast.Module(body=[entrypoint], type_ignores=[]), __file__, "exec"), scope)
    assert calls == [
        ("main",),
        ("registry", [sys.executable, str(ROOT / "scripts/test_generate_lanes.py")],
         {"check": True, "timeout": 300}),
    ]
    assert calls[1][2]["check"] is True
    assert type(calls[1][2]["timeout"]) is int
    assert (ROOT / "scripts/test_generate_lanes.py").is_file()


def run_waiver_audit_cli(
    *,
    capability: str,
    shard: str = "uk",
    probe_status: int = 0,
    audit_status: int = 0,
) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    """Run the workflow's audit shell with strict old/new CLI stand-ins."""
    import yaml

    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    step = next(step for step in steps if step.get("name") == "Enforce validation waiver ratchet")
    shell = step["run"].split("# waiver-ratchet-python-end\n", 1)[1]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        protected = root / "protected"
        protected.mkdir()
        workspace = root / "rulespec-uk"
        workspace.mkdir()
        calls = root / "calls.jsonl"
        # No RuleSpec fixtures are needed: the fake CLI reports the modules
        # whose runtime checks it would perform under the supplied options.
        base = root / "protected-ledger.txt"
        base.write_text("protected base ledger\n")
        changed = root / "audit-changed-paths.txt"
        changed.write_text("known-validation-gaps.yaml\n")
        supervisor = protected / "axiom-encode-signing-supervisor"
        supervisor.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent("""\
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
                    "--trusted-python-import-root", protected + "/python/lib/python3.14/site-packages",
                    "--trusted-python-package-root", protected + "/python/lib/python3.14/site-packages/axiom_encode",
                ], args
                command = args[boundary + 1:]
                assert command[0] == protected + "/axiom-encode", command
                os.execv(command[0], command)
                """)
        )
        encoder = protected / "axiom-encode"
        encoder.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent("""\
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
                for option in (
                    "--root", "--corpus-path", "--protected-base", "--changed-paths",
                    "--axiom-rules-engine-path",
                ):
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
                modules = [
                    "uk/statutes/active.yaml",
                    "uk-ashford/policies/pending.yaml",
                    "uk/statutes/removed.yaml",
                ]
                key = getattr(args, "partition_key", None)
                keys = getattr(args, "partition_keys_json", None)
                if key is not None:
                    assert json.loads(keys) == ["uk", "uk-ashford"]
                    modules = [module for module in modules if module.split("/")[0] == key]
                else:
                    assert keys is None
                print(json.dumps({"checked_modules": modules}))
                sys.exit(int(os.environ["AUDIT_STATUS"]))
                """)
        )
        supervisor.chmod(0o755)
        encoder.chmod(0o755)
        shell = shell.replace("/opt/axiom-verification", str(protected))
        for expression, value in (
            ("${{ inputs.python-version }}", "3.14"),
            ("${{ matrix.shard }}", shard),
            ("${{ needs.shards.outputs.matrix }}", '["uk", "uk-ashford"]'),
        ):
            shell = shell.replace(expression, value)
        assert "${{" not in shell
        env = {
            **os.environ,
            "RUNNER_TEMP": str(root),
            "GITHUB_WORKSPACE": str(workspace),
            "AXIOM_DEPENDENCY_ROOT": str(root / "dependencies with spaces"),
            "AXIOM_COMPOSE_REF": "",
            "PROTECTED_RUNTIME": str(protected),
            "AUDIT_CALLS": str(calls),
            "AUDIT_CAPABILITY": capability,
            "PROBE_STATUS": str(probe_status),
            "AUDIT_STATUS": str(audit_status),
            "protected_base": str(base),
            "audit_changed_paths": str(changed),
        }
        result = subprocess.run(
            ["bash", "-c", "set -euo pipefail\n" + shell],
            cwd=workspace, env=env, capture_output=True, text=True,
        )
        return result, [json.loads(line) for line in calls.read_text().splitlines()]


def test_old_waiver_audit_cli_checks_complete_ledger_on_every_shard() -> None:
    for capability in ("old", "key-only", "keys-only"):
        for shard in ("uk", "uk-ashford"):
            result, calls = run_waiver_audit_cli(capability=capability, shard=shard)
            assert result.returncode == 0, result.stderr
            assert len(calls) == 4  # Both probe and audit use the supervisor.
            assert calls[1]["cli"] == ["validation-waivers", "audit", "--help"]
            assert not any(arg.startswith("--partition-") for arg in calls[3]["cli"])
            report = json.loads(result.stdout.splitlines()[-1])
            assert report["checked_modules"] == [
                "uk/statutes/active.yaml",
                "uk-ashford/policies/pending.yaml",
                "uk/statutes/removed.yaml",
            ]
            assert "complete unpartitioned waiver audit on this shard" in result.stdout


def test_new_waiver_audit_cli_preserves_partition_arguments_and_coverage() -> None:
    checked = []
    for shard in ("uk", "uk-ashford"):
        result, calls = run_waiver_audit_cli(capability="new", shard=shard)
        assert result.returncode == 0, result.stderr
        assert len(calls) == 4
        assert calls[1]["cli"] == ["validation-waivers", "audit", "--help"]
        args = calls[3]["cli"]
        assert args[args.index("--partition-key") + 1] == shard
        assert json.loads(args[args.index("--partition-keys-json") + 1]) == ["uk", "uk-ashford"]
        assert "unpartitioned" not in result.stdout
        checked.extend(json.loads(result.stdout)["checked_modules"])
    assert sorted(checked) == [
        "uk-ashford/policies/pending.yaml",
        "uk/statutes/active.yaml",
        "uk/statutes/removed.yaml",
    ]


def test_waiver_audit_probe_fails_closed_and_audit_failure_propagates() -> None:
    for capability in ("old", "new"):
        result, calls = run_waiver_audit_cli(capability=capability, probe_status=37)
        assert result.returncode == 37, result.stderr
        assert len(calls) == 2
        assert calls[1]["cli"] == ["validation-waivers", "audit", "--help"]
        assert "capability probe failed (exit 37)" in result.stderr
        assert "unpartitioned" not in result.stdout

        result, calls = run_waiver_audit_cli(capability=capability, audit_status=41)
        assert result.returncode == 41, result.stderr
        assert len(calls) == 4
        assert "--json" in calls[3]["cli"]

    result, calls = run_waiver_audit_cli(capability="empty")
    assert result.returncode != 0
    assert len(calls) == 2
    assert "capability probe returned no help" in result.stderr
    assert "unpartitioned" not in result.stdout


def test_validation_jobs_are_bounded_in_time_and_parallelism() -> None:
    import yaml

    runner_default_minutes = 360
    org_concurrent_jobs = 60
    # Minutes a leg spends before a long step starts (checkouts, toolchains,
    # engine build).
    setup_allowance_minutes = 20
    legacy = WORKFLOW.with_name("validate-rulespec-legacy-pending-safe.yml")
    for path in (WORKFLOW, legacy):
        jobs = yaml.safe_load(path.read_text())["jobs"]
        for name, job in jobs.items():
            timeout = job.get("timeout-minutes")
            assert type(timeout) is int, f"{path.name}:{name} needs timeout-minutes"
            assert 0 < timeout < runner_default_minutes, (path.name, name, timeout)

        validate = jobs["validate"]
        strategy = validate["strategy"]
        assert validate["timeout-minutes"] == 180, path.name
        assert strategy["fail-fast"] is False, path.name
        assert strategy["max-parallel"] == 20, path.name
        # Two concurrent runs of one repository must leave hosted runners for
        # every other repository in the org.
        assert 2 * strategy["max-parallel"] < org_concurrent_jobs, path.name

        step_limits = {
            step["name"]: step["timeout-minutes"]
            for step in validate["steps"]
            if "timeout-minutes" in step
        }
        assert step_limits["Validate RuleSpec YAML"] == 120, path.name
        assert step_limits["Execute RuleSpec companion tests"] == 60, path.name
        for name, limit in step_limits.items():
            assert type(limit) is int, (path.name, name)
            assert 0 < limit + setup_allowance_minutes <= validate["timeout-minutes"], (
                path.name,
                name,
                limit,
            )

    validate = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]
    ratchet = [
        step
        for step in validate["steps"]
        if step.get("name") == "Enforce validation waiver ratchet"
    ]
    assert len(ratchet) == 1
    assert ratchet[0]["timeout-minutes"] == 150


def test_parallel_validation_workers_are_bounded_and_fail_closed() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Validate RuleSpec YAML")
    end = workflow.index("      - name: Execute RuleSpec companion tests")
    validate_step = workflow[start:end]

    assert "validation-workers:" in workflow
    assert "default: 1" in workflow
    assert '[[ "$VALIDATION_WORKERS" =~ ^[1-4]$ ]]' in validate_step
    assert 'if ! wait "$pid"; then' in validate_step
    assert 'status=1' in validate_step
    assert 'for log_path in "${logs[@]}"; do' in validate_step
    assert 'exit "$status"' in validate_step


def write_authorization(root: Path, *, topic: str) -> None:
    path = root / ".axiom/reviewed-migrations.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "format": "axiom/reviewed-migrations/v1",
                "migrations": [
                    {
                        "pull_request": 911,
                        "head": topic,
                        "retired_schema_bootstrap_sha256": RETIRED,
                        "validation_waiver_bootstrap_sha256": WAIVER,
                    }
                ],
            }
        )
        + "\n"
    )


def fixture() -> tuple[tempfile.TemporaryDirectory[str], Path, str, str]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "workflow-test@example.com")
    git(root, "config", "user.name", "Workflow Test")
    (root / "base.txt").write_text("initial\n")
    common = commit(root, "common")
    git(root, "switch", "-qc", "topic")
    (root / "topic.txt").write_text("reviewed\n")
    topic = commit(root, "reviewed topic")
    git(root, "switch", "-q", "main")
    git(root, "reset", "--hard", common)
    write_authorization(root, topic=topic)
    base = commit(root, "authorize exact topic")
    return temp, root, base, topic


def run_authorization(
    root: Path,
    *,
    base: str,
    event: str,
    pr_head: str = "",
    pr_number: str = "911",
    github_sha: str = "",
    github_ref: str = "refs/pull/911/merge",
    pr_base_ref: str = "main",
    repository: str = "TheAxiomFoundation/rulespec-us",
    retired: str = RETIRED,
    waiver: str = WAIVER,
    guard: str = "false",
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "AUTHORIZATION_PATH": ".axiom/reviewed-migrations.json",
        "BASE_SHA": base,
        "EVENT_NAME": event,
        "PR_BASE_REF": pr_base_ref,
        "PR_HEAD_SHA": pr_head,
        "PR_NUMBER": pr_number,
        "RETIRED_SCHEMA_BOOTSTRAP": retired,
        "VALIDATION_WAIVER_BOOTSTRAP": waiver,
        "RUN_GENERATED_GUARD": guard,
        "GITHUB_REPOSITORY": repository,
        "GITHUB_REF": github_ref,
        "GITHUB_SHA": github_sha or pr_head,
    }
    return subprocess.run(
        [sys.executable, "-c", authorization_source()],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )


def test_conflicted_merge_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")
        conflict = root / "conflict.txt"
        conflict.write_text("common\n")
        common = commit(root, "common")
        git(root, "switch", "-qc", "topic")
        conflict.write_text("topic\n")
        topic = commit(root, "conflicting topic")
        git(root, "switch", "-q", "main")
        git(root, "reset", "--hard", common)
        conflict.write_text("main\n")
        write_authorization(root, topic=topic)
        base = commit(root, "authorize conflicting topic")
        forged_merge = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
            ],
            cwd=root,
            check=True,
            input="forged conflicted merge\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=forged_merge,
            github_ref="refs/heads/main",
        )
        assert result.returncode != 0


RETIRED_ROOT_STEPS = (
    "Provision protected verification supervisor",
    "Prepare protected-base manifest audit",
)


def retired_root_block(run: str) -> str:
    lines = run.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "retired_root_args=()")
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "fi")
    return "\n".join(line.strip() for line in lines[start : end + 1])


def test_retired_corpus_release_root_is_passed_only_when_set() -> None:
    import yaml

    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
    by_name = {step.get("name"): step for step in steps}
    for name in RETIRED_ROOT_STEPS:
        run = by_name[name]["run"]
        # The flag appears only inside the conditional array, never as a bare argument.
        assert run.count("--retired-corpus-release-root") == 1, name
        assert "retired_root_args=(--retired-corpus-release-root" in run, name
        assert '${retired_root_args[@]+"${retired_root_args[@]}"}' in run, name
        block = retired_root_block(run)
        # Expand the array exactly as the workflow passes it to the provisioner, then
        # report the argument count and each argument, so an empty argument cannot
        # pass for no argument.
        probe = (
            block
            + '\nshow() { echo "n=$#"; for arg in "$@"; do printf "<%s>\\n" "$arg"; done; }'
            + '\nshow ${retired_root_args[@]+"${retired_root_args[@]}"}'
        )
        absent = "n=0\n"
        cases = {
            None: absent,
            "": absent,
            RETIRED: f"n=2\n<--retired-corpus-release-root>\n<{RETIRED}>\n",
        }
        for value, expected in cases.items():
            env = {k: v for k, v in os.environ.items() if k != "TRUST_RETIRED_CORPUS_RELEASE_ROOT"}
            if value is not None:
                env["TRUST_RETIRED_CORPUS_RELEASE_ROOT"] = value
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", probe],
                env=env, capture_output=True, text=True, timeout=30, check=False,
            )
            assert result.returncode == 0, (name, value, result.stderr)
            assert result.stdout == expected, (name, value, result.stdout)
    print("optional retired corpus release root: ok")


def main() -> None:
    if any(argument != "--selectors-only" for argument in sys.argv[1:]):
        raise SystemExit("usage: test_validate_rulespec_workflow.py [--selectors-only]")
    run_selector_tests()
    if "--selectors-only" in sys.argv[1:]:
        return
    test_retired_corpus_release_root_is_passed_only_when_set()
    test_caller_scalar_loader_matches_ruleset_guard()
    test_literal_numeric_looking_pins_keep_exact_string_identity()
    test_binding_rejects_caller_pin_lines_outside_printable_ascii_lf()
    test_literal_pin_only_binds_proposed_pin_and_selects_every_target()
    test_table_pin_only_binds_proposed_pin_and_selects_every_target()
    test_proposed_pin_exception_rejects_content_and_helper_changes()
    test_pin_changes_with_other_files_cannot_skip_proposed_pin_audit()
    test_indirect_script_encoder_pin_cannot_validate_changed_module()
    test_reusable_workflow_input_default_cannot_validate_changed_module()
    test_reusable_workflow_env_pin_cannot_validate_changed_module()
    test_every_effective_dependency_matches_protected_workflow_toolchain()
    test_protected_workflow_toolchain_fails_closed()
    test_pin_only_candidate_uses_protected_base_and_landed_pin_uses_new_base()
    test_legacy_literal_workflow_inputs_preserve_old_encoder_compatibility()
    test_workflow_input_protection_precedes_dependency_checkout()
    test_protected_workflow_yaml_cannot_disguise_active_composer()
    test_protected_workflow_inputs_reject_untrusted_event_sources()
    test_protected_workflow_input_imports_ignore_candidate_python()
    print("protected effective workflow inputs: regression checks passed")
    test_workflow_edits_without_dependency_pin_changes_use_changed_guard()
    test_manifest_audit_flag_tracks_actual_dependency_and_validator_refs()
    test_corpus_release_metadata_companion_preserves_proposed_pin_binding()
    test_legacy_binding_validator_adoption_keeps_encoder_pin_and_enables_ratchet()
    test_corpus_placement_runs_before_supervised_gates_with_step_only_credentials()
    test_pre_switch_corpus_skips_placement_without_invoking_old_encoder()
    test_post_switch_corpus_rejects_encoder_without_corpus_fetch()
    test_post_switch_corpus_places_pinned_release_with_read_credentials()
    test_post_switch_corpus_accepts_local_artifacts_without_credentials()
    test_post_switch_corpus_fetch_failure_preserves_missing_artifact_diagnostic()
    print("pinned corpus placement: 6 regression checks passed")
    test_release_pin_companion_requires_strict_retirement()
    test_release_pin_companion_accepts_exact_staged_consumption()
    test_generated_guard_resolves_scheduled_base_to_exact_commit()
    test_unmanifested_precheck_guards_programs_only_on_opt_in()
    test_parallel_validation_workers_are_bounded_and_fail_closed()
    test_validation_jobs_are_bounded_in_time_and_parallelism()
    test_validation_waiver_audit_is_exhaustively_partitioned_across_matrix()
    test_lane_registry_regressions_run_from_shared_workflow_entrypoint()
    test_old_waiver_audit_cli_checks_complete_ledger_on_every_shard()
    test_new_waiver_audit_cli_preserves_partition_arguments_and_coverage()
    test_waiver_audit_probe_fails_closed_and_audit_failure_propagates()
    print("waiver audit CLI compatibility: 13 regression cases passed")
    test_retired_schema_freeze_classifies_only_plural_citations()
    test_retired_schema_prefreeze_bridge_is_fail_closed()
    test_pending_waiver_requires_exact_digest_only_toolchain_companion()
    test_waiver_bootstrap_uses_authenticated_head_toolchain()
    temp, root, base, topic = fixture()
    try:
        ordinary = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            retired="",
            waiver="",
            guard="true",
        )
        assert ordinary.returncode == 0, ordinary.stderr
        assert ordinary.stdout.splitlines() == ["authorized=false", "candidate="]

        approved = run_authorization(
            root, base=base, event="pull_request", pr_head=topic
        )
        assert approved.returncode == 0, approved.stderr
        assert approved.stdout.splitlines() == [
            "authorized=true",
            f"candidate={topic}",
        ]

        wrong_head = run_authorization(
            root, base=base, event="pull_request", pr_head=base
        )
        assert wrong_head.returncode != 0
        wrong_base = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            pr_base_ref="release",
        )
        assert wrong_base.returncode != 0
        wrong_digest = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            waiver="3" * 64,
        )
        assert wrong_digest.returncode != 0
        wrong_retired = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            retired="3" * 64,
        )
        assert wrong_retired.returncode != 0
        wrong_pr = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            pr_number="912",
        )
        assert wrong_pr.returncode != 0
        wrong_repository = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            repository="example/fork",
        )
        assert wrong_repository.returncode != 0

        authorization = root / ".axiom/reviewed-migrations.json"
        duplicate = authorization.read_text().replace(
            f'"head": "{topic}"',
            f'"head": "{"0" * 40}", "head": "{topic}"',
        )
        authorization.write_text(duplicate)
        duplicate_base = commit(root, "duplicate authorization key")
        duplicate_result = run_authorization(
            root, base=duplicate_base, event="pull_request", pr_head=topic
        )
        assert duplicate_result.returncode != 0

        authorization.write_text("{\"format\":")
        malformed_base = commit(root, "malformed authorization")
        malformed_result = run_authorization(
            root, base=malformed_base, event="pull_request", pr_head=topic
        )
        assert malformed_result.returncode != 0

        write_authorization(root, topic=topic)
        authorization.write_bytes(authorization.read_text().encode("utf-16"))
        utf16_base = commit(root, "non-UTF-8 authorization")
        utf16_result = run_authorization(
            root, base=utf16_base, event="pull_request", pr_head=topic
        )
        assert utf16_result.returncode != 0

        authorization.unlink()
        target = root / "authorization-target.json"
        target.write_text("{}\n")
        authorization.symlink_to(Path("..") / target.name)
        symlink_base = commit(root, "symlink authorization")
        symlink_result = run_authorization(
            root, base=symlink_base, event="pull_request", pr_head=topic
        )
        assert symlink_result.returncode != 0

        git(root, "switch", "-q", "main")
        git(root, "reset", "--hard", base)
        non_merge = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=topic,
            github_ref="refs/heads/main",
        )
        assert non_merge.returncode != 0

        altered_tree = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
            ],
            cwd=root,
            check=True,
            input="altered merge tree\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        altered_result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=altered_tree,
            github_ref="refs/heads/main",
        )
        assert altered_result.returncode != 0

        octopus = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
                "-p",
                duplicate_base,
            ],
            cwd=root,
            check=True,
            input="octopus\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        octopus_result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=octopus,
            github_ref="refs/heads/main",
        )
        assert octopus_result.returncode != 0

        git(root, "merge", "--no-ff", "-qm", "merge reviewed topic", topic)
        merge = git(root, "rev-parse", "HEAD")
        approved_push = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=merge,
            github_ref="refs/heads/main",
        )
        assert approved_push.returncode == 0, approved_push.stderr
        wrong_first_parent = run_authorization(
            root,
            base=git(root, "rev-parse", f"{base}^"),
            event="push",
            github_sha=merge,
            github_ref="refs/heads/main",
        )
        assert wrong_first_parent.returncode != 0

        (root / "later.txt").write_text("later\n")
        later_base = commit(root, "later base")
        replay_tree = git(root, "rev-parse", f"{later_base}^{{tree}}")
        replay = subprocess.run(
            ["git", "commit-tree", replay_tree, "-p", later_base, "-p", topic],
            cwd=root,
            check=True,
            input="replay\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        replayed = run_authorization(
            root,
            base=later_base,
            event="push",
            github_sha=replay,
            github_ref="refs/heads/main",
        )
        assert replayed.returncode != 0
    finally:
        temp.cleanup()

    test_conflicted_merge_is_rejected()

    workflow = WORKFLOW.read_text()
    assert "migration-authorization-path" in workflow
    assert "bootstrap is not bound to an exact protected authorization" in workflow
    print("exact reviewed-migration authorization: ok")


if __name__ == "__main__":
    main()
    # Keep registry regressions in the existing shared-workflow CI entry point.
    subprocess.run([sys.executable, str(ROOT / "scripts/test_generate_lanes.py")], check=True, timeout=300)
