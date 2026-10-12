#!/usr/bin/env python3
"""Exercise embedded RuleSpec workflow guards and corpus placement shell."""

from __future__ import annotations

import json
import hashlib
import os
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
    assert 'python -m pip install -e "${AXIOM_DEPENDENCY_ROOT}/axiom-encode"' in install["run"]

    step = steps[index]
    assert step["shell"] == "bash"
    assert step["run"].startswith("set -euo pipefail\n")
    assert "${{" not in step["run"]
    assert "/opt/axiom-verification" not in step["run"]
    assert "axiom-encode-signing-supervisor" not in step["run"]
    assert step["working-directory"] == "${{ github.workspace }}"
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
            if other_step == step:
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
        result = subprocess.run(
            ["bash", "-c", corpus_placement_step()["run"]],
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
) -> subprocess.CompletedProcess[str]:
    actual = {**WORKFLOW_INPUT_PINS, "axiom_compose_ref": "", **(pins or {})}
    environment = {
        **os.environ,
        **{WORKFLOW_INPUT_ENV[key]: value for key, value in actual.items()},
        "EVENT_NAME": event,
        "PR_BASE_SHA": base if event in ("pull_request", "pull_request_target") else "",
        "MERGE_GROUP_BASE_SHA": base if event == "merge_group" else "",
        "CURRENT_SHA": head or git(root, "rev-parse", "HEAD"),
        "CURRENT_REF": "refs/heads/main",
        "DEFAULT_BRANCH": "main",
        "REPOSITORY": "example/rules",
        "CALLER_WORKFLOW_REF": f"example/rules/{caller_path}@refs/heads/main",
        "GITHUB_SHA": head or git(root, "rev-parse", "HEAD"),
        "RELEASE_BASE_URL": "https://example.invalid",
        "RELEASE_REGISTRY_URL": "",
        "RELEASE_REGISTRY_ANON_KEY": "",
        "PYTHON_VERSION": "3.13",
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
        "PYTHONPATH": str(root),
    }
    return subprocess.run(
        ["bash", "-c", workflow_input_step()["run"]],
        cwd=root, env=environment, capture_output=True, text=True,
    )


class WorkflowInputFixture:
    def __init__(self, *, table: str | None = None, caller: str | None = None) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="hub-.github-125-inputs-",
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
            premature = run_workflow_inputs(fixture.root, fixture.base, pins=changed, event=event)
            assert premature.returncode != 0
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
    assert "python -I -m pip install" in steps[2]["run"]
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


def test_protected_workflow_inputs_reject_untrusted_event_sources() -> None:
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        for event in ("workflow_run", "repository_dispatch", "pull_request_review"):
            result = run_workflow_inputs(fixture.root, fixture.base, event=event)
            assert result.returncode != 0, event
        shell = workflow_input_step()["run"]
        for event in ("push", "workflow_dispatch"):
            # Mutate only context fixtures, never the protected-input source.
            environment = {
                **os.environ,
                **{WORKFLOW_INPUT_ENV[key]: value for key, value in WORKFLOW_INPUT_PINS.items()},
                "AXIOM_COMPOSE_REF": "", "EVENT_NAME": event,
                "PR_BASE_SHA": "", "MERGE_GROUP_BASE_SHA": "",
                "CURRENT_SHA": fixture.base, "CURRENT_REF": "refs/heads/candidate",
                "DEFAULT_BRANCH": "main", "RELEASE_BASE_URL": "https://example.invalid",
                "RELEASE_REGISTRY_URL": "", "RELEASE_REGISTRY_ANON_KEY": "",
                "PYTHON_VERSION": "3.13",
                "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
            }
            result = subprocess.run(["bash", "-c", shell], cwd=fixture.root, env=environment, capture_output=True, text=True)
            assert result.returncode != 0, event


def test_protected_workflow_input_imports_ignore_candidate_python() -> None:
    with WorkflowInputFixture(table=workflow_toolchain(WORKFLOW_INPUT_PINS)) as fixture:
        source = 'from pathlib import Path\nPath("candidate-executed").write_text("executed")\n'
        for path in ("sitecustomize.py", "tomllib.py", "yaml.py"):
            fixture.write(path, source)
        result = run_workflow_inputs(fixture.root, fixture.base)
        assert result.returncode == 0, result.stderr
        assert not (fixture.root / "candidate-executed").exists()


def authorization_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# reviewed-migration-authorization-start")
    end = workflow.index("# reviewed-migration-authorization-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = "python - <<'PY' >> \"$GITHUB_OUTPUT\"\n"
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
    head_waiver = base_waiver + b"    pending:\n      " + metadata.encode()
    base_digest = hashlib.sha256(base_waiver).hexdigest()
    head_digest = hashlib.sha256(head_waiver).hexdigest()
    base_toolchain = (
        "[toolchain]\n"
        'axiom_corpus_release = "unchanged"\n'
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

        assert run().returncode == 0
        assert paths["audit_changed"].read_text() == "known-validation-gaps.yaml\n"

        paths["head_toolchain"].write_bytes(
            head_toolchain.replace(b'"unchanged"', b'"changed"')
        )
        assert run().returncode != 0
        paths["head_toolchain"].write_bytes(head_toolchain)

        paths["changed"].write_text("known-validation-gaps.yaml\n")
        assert run().returncode != 0

        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\nus/statutes/1.yaml\n"
        )
        assert run().returncode != 0

        # A newly introduced module can be preapproved, but still only through
        # the same exact two-file transition.
        new_base_waiver = b"validate_failures: {}\n"
        new_head_waiver = (
            b"validate_failures:\n  us/statutes/1.yaml:\n    pending:\n      "
            + metadata.encode()
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
    end = workflow.index("      - name: Select RuleSpec validation targets")
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
    end = workflow.index("      - name: Select RuleSpec validation targets")
    step = workflow[start:end]
    assert 'base_ref="HEAD~1"' not in step
    assert '--base-ref "$base_ref"' in step
    # HEAD~1 must exist in the validate job's clone for rev-parse to resolve it.
    validate_job = workflow.index("    name: validate\n")
    checkout = workflow.index("      - name: Checkout rules repository", validate_job)
    checkout_step = workflow[checkout : workflow.index("      - name:", checkout + 1)]
    assert "fetch-depth: 0" in checkout_step
    assert checkout < start

    def resolve(root: Path, *, event: str, pr_base: str = "", before: str = ""):
        source = (
            guard_base_ref_source()
            .replace("${{ github.event_name }}", event)
            .replace("${{ github.event.pull_request.base.sha }}", pr_base)
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
        # Anything that is not an exact commit identity is refused up front.
        assert resolve(root, event="pull_request", pr_base="main").returncode != 0
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
    end = workflow.index("      - name: Reject manual RuleSpec changes")
    audit_step = workflow[start:end]

    assert "matrix.shard == needs.shards.outputs.first" not in audit_step
    assert '--partition-key "${{ matrix.shard }}"' in audit_step
    assert "--partition-keys-json '${{ needs.shards.outputs.matrix }}'" in audit_step
    assert (
        "AXIOM_ENCODE_WAIVER_AUDIT_WORKERS: "
        "${{ github.repository == 'TheAxiomFoundation/rulespec-us' "
        "&& matrix.shard == 'us-wa' && '2' || '1' }}"
    ) in audit_step


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


def main() -> None:
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
    print("protected effective workflow inputs: 11 regression checks passed")
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
