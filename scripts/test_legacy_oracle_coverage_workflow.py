#!/usr/bin/env python3
"""Exercise the legacy workflow's isolated oracle-coverage compatibility path."""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec-legacy-pending-safe.yml"
ENCODER_REF = "ee2fb3ea43a7a159eaea0e500b982ce9e0af9873"
ORACLE_REF = "eeca677b4bbce143fb0a109e4b63bcce59453e3d"
ORACLE_SPEC = (
    "axiom-oracles @ git+https://github.com/"
    f"TheAxiomFoundation/axiom-oracles@{ORACLE_REF}"
)


def step_source(workflow: str, name: str, next_name: str) -> str:
    start = workflow.index(f"      - name: {name}")
    end = workflow.index(f"      - name: {next_name}", start)
    return workflow[start:end]


def heredoc_source(step: str, command: str) -> str:
    marker = f"{command}\n"
    start = step.index(marker) + len(marker)
    end = step.index("\n          PY", start)
    lines = step[start:end].splitlines()
    return "\n".join(
        line.removeprefix("          ") for line in lines
    )


def run_dependency_parser(source: str, dependency: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        checkout = root / "_axiom/axiom-encode-oracle-coverage"
        checkout.mkdir(parents=True)
        (checkout / "pyproject.toml").write_text(
            "[project]\n"
            'name = "fixture"\n'
            'version = "0"\n'
            f"dependencies = [{dependency!r}]\n"
        )
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            env={**os.environ, "AXIOM_DEPENDENCY_ROOT": str(root / "_axiom")},
            capture_output=True,
            text=True,
        )


def run_filter(
    source: str,
    *,
    items: str,
    changed_paths: tuple[str, ...] = (
        "us-in/policies/income_tax/2026_resident_liability_source_hold.yaml",
    ),
) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        workspace = root / "rulespec-us"
        workspace.mkdir()
        coverage = root / "coverage.json"
        coverage.write_text(f'{{"items": {items}}}')
        changed = root / "changed.txt"
        changed.write_text("".join(f"{path}\n" for path in changed_paths))
        stdout = io.StringIO()
        stderr = io.StringIO()
        previous_argv = sys.argv
        previous_workspace = os.environ.get("GITHUB_WORKSPACE")
        sys.argv = ["filter", str(coverage), str(changed)]
        os.environ["GITHUB_WORKSPACE"] = str(workspace)
        status = 0
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exec(compile(source, "<coverage-filter>", "exec"), {})
        except SystemExit as exc:
            status = int(exc.code or 0)
        finally:
            sys.argv = previous_argv
            if previous_workspace is None:
                os.environ.pop("GITHUB_WORKSPACE", None)
            else:
                os.environ["GITHUB_WORKSPACE"] = previous_workspace
        return status, stdout.getvalue(), stderr.getvalue()


def run_approval_growth_guard(
    source: str,
    *,
    semantic_pin: bool = True,
    extra_path: bool = False,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "workflow-test@example.com"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Workflow Test"],
            cwd=root,
            check=True,
        )
        waiver = root / "known-validation-gaps.yaml"
        waiver.write_text(
            "validate_failures:\n"
            '  "us-test/module.yaml":\n'
            "    active:\n"
            '      fingerprint: "sha256:'
            + "1" * 64
            + '"\n'
        )
        workflow = root / ".github/workflows/repository-checks.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "jobs:\n"
            "  validate:\n"
            "    uses: TheAxiomFoundation/.github/.github/workflows/"
            "validate-rulespec-legacy-pending-safe.yml@"
            + "2" * 40
            + "\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        waiver.write_text(
            waiver.read_text()
            + "    pending:\n"
            + '      fingerprint: "sha256:'
            + "3" * 64
            + '"\n'
        )
        if semantic_pin:
            workflow.write_text(workflow.read_text().replace("2" * 40, "4" * 40))
        else:
            workflow.write_text(workflow.read_text().replace("jobs:", "name: drift\njobs:"))
        if extra_path:
            (root / "unexpected.txt").write_text("drift\n")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "head"], cwd=root, check=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            env={
                **os.environ,
                "PR_BASE_SHA": base,
                "GITHUB_SHA": head,
            },
            capture_output=True,
            text=True,
        )


def main() -> None:
    workflow = WORKFLOW.read_text()
    assert f"default: {ENCODER_REF}" in workflow

    approval_guard = step_source(
        workflow,
        "Require approval growth to be waiver-only",
        "Report non-pull-request event",
    )
    approval_source = heredoc_source(approval_guard, "          python - <<'PY'")
    atomic = run_approval_growth_guard(approval_source)
    assert atomic.returncode == 0, atomic.stderr
    extra = run_approval_growth_guard(approval_source, extra_path=True)
    assert extra.returncode != 0
    non_pin = run_approval_growth_guard(approval_source, semantic_pin=False)
    assert non_pin.returncode != 0

    target_selection = step_source(
        workflow,
        "Select RuleSpec validation targets",
        "Validate RuleSpec YAML",
    )
    assert "is_bridge_pin_with_optional_waiver_only()" in target_selection
    assert (
        "&& ! is_bridge_pin_with_optional_waiver_only"
        in target_selection
    )
    assert (
        'if [ "$waiver_changed" = "true" ]; then\n'
        '                      mode="full-waiver-migration"'
        in target_selection
    )

    changed_coverage_start = workflow.index(
        "      - name: Checkout changed-file oracle coverage classifier"
    )
    changed_coverage_end = workflow.index(
        "\n  validate-complete:",
        changed_coverage_start,
    )
    changed_coverage = workflow[changed_coverage_start:changed_coverage_end]
    assert changed_coverage.count(
        "steps.validation_targets.outputs.mode != 'full-waiver-migration'"
    ) == 3

    install = step_source(
        workflow,
        "Install changed-file oracle coverage classifier",
        "Validate changed PolicyEngine oracle coverage classification",
    )
    assert "pip install -e" not in install
    assert 'pip install --force-reinstall --no-deps "$oracles_spec"' in install
    assert "retains legacy axiom-encode" in install

    parser = heredoc_source(install, "            python - <<'PY'")
    valid = run_dependency_parser(parser, ORACLE_SPEC)
    assert valid.returncode == 0, valid.stderr
    assert valid.stdout.strip() == ORACLE_SPEC

    mutable = run_dependency_parser(
        parser,
        "axiom-oracles @ git+https://github.com/"
        "TheAxiomFoundation/axiom-oracles@main",
    )
    assert mutable.returncode != 0

    coverage_start = workflow.index(
        "      - name: Validate changed PolicyEngine oracle coverage classification"
    )
    coverage_end = workflow.index("\n  validate-complete:", coverage_start)
    coverage = workflow[coverage_start:coverage_end]
    assert '--root "$GITHUB_WORKSPACE/.."' in coverage
    assert 'f"{repo}/{line.strip()}"' in coverage
    filter_source = heredoc_source(
        coverage,
        '          python - "$coverage_json" "$RULESPEC_FILE_LIST" <<\'PY\'',
    )
    target_file = (
        "rulespec-us/us-in/policies/income_tax/"
        "2026_resident_liability_source_hold.yaml"
    )
    comparable = (
        f'[{{"file": "{target_file}", "legal_id": "us-in:target#value", '
        '"status": "comparable", "tested": true}]'
    )
    status, stdout, stderr = run_filter(filter_source, items=comparable)
    assert status == 0, stderr
    assert "passed for 1 output(s)" in stdout

    untested_comparable = (
        f'[{{"file": "{target_file}", "legal_id": "us-in:target#value", '
        '"status": "comparable", "tested": false}]'
    )
    status, _, stderr = run_filter(filter_source, items=untested_comparable)
    assert status == 1
    assert "comparable but not covered by companion tests" in stderr

    unmapped = (
        f'[{{"file": "{target_file}", "legal_id": "us-in:target#value", '
        '"status": "unmapped", "tested": true}]'
    )
    status, _, stderr = run_filter(filter_source, items=unmapped)
    assert status == 1
    assert "us-in:target#value: unmapped" in stderr

    for rejected_status, message in (
        ("pending_classification", "pending classification"),
        ("incomplete_comparable", "incomplete comparable mapping"),
        ("bogus", "unsupported coverage status"),
    ):
        items = (
            f'[{{"file": "{target_file}", "legal_id": "us-in:target#value", '
            f'"status": "{rejected_status}", "tested": true}}]'
        )
        status, _, stderr = run_filter(filter_source, items=items)
        assert status == 1
        assert message in stderr

    status, _, stderr = run_filter(filter_source, items="[]")
    assert status == 1
    assert "no executable output for changed RuleSpec file(s)" in stderr

    unprefixed = (
        '[{"file": "us-in/policies/income_tax/'
        '2026_resident_liability_source_hold.yaml", '
        '"legal_id": "us-in:target#value", '
        '"status": "known_not_comparable", "tested": true}]'
    )
    status, _, stderr = run_filter(filter_source, items=unprefixed)
    assert status == 1
    assert target_file in stderr

    status, _, stderr = run_filter(
        filter_source,
        items=comparable,
        changed_paths=(
            "us-in/policies/income_tax/2026_resident_liability_source_hold.yaml",
            "us-ks/policies/income_tax/2026_full_year_resident_core.yaml",
        ),
    )
    assert status == 1
    assert "rulespec-us/us-ks/policies/income_tax/" in stderr

    print("legacy oracle coverage overlay: ok")


if __name__ == "__main__":
    main()
