"""Regression checks for the incremental waiver audit shadow (axiom-encode#2329).

The ratchet step passes `--incremental-shadow-report` on pull requests when the
verifier's `validation-waivers audit --help` lists it, each leg uploads one
artifact, and the `waiver shadow` job requires exactly one bound record per
matrix partition. Each check runs the real step script from
validate-rulespec.yml, like scripts/test_encoder_main_verifier_workflow.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
RATCHET = "Enforce validation waiver ratchet"
UPLOAD = "Upload incremental waiver shadow record"
STAGE = "Stage the waiver shadow preparation"
RECORD_SCHEMA = "axiom-encode/validation-waiver-incremental-shadow/v1"
HEAD = "a" * 40
BASE_DIGEST = "sha256:" + "b" * 64
CHANGED_DIGEST = "sha256:" + "c" * 64
SHARDS = ["us-ak", "us-az", "us"]
HELP_WITH_SHADOW = (
    "usage: axiom-encode validation-waivers audit [--partition-key KEY]\n"
    "  --incremental-shadow-report INCREMENTAL_SHADOW_REPORT\n"
    "  --incremental-shadow-summary INCREMENTAL_SHADOW_SUMMARY\n"
)
HELP_WITHOUT_SHADOW = "usage: axiom-encode validation-waivers audit [--partition-key KEY]\n"


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def validate_step(name: str) -> dict:
    steps = workflow()["jobs"]["validate"]["steps"]
    return next(step for step in steps if step.get("name") == name)


def between(text: str, start: str, end: str) -> str:
    assert text.count(start) == 1 and text.count(end) == 1, (start, end)
    return text.split(start, 1)[1].split(end, 1)[0]


def bash() -> str:
    # The shadow block needs only Bash 3.2 features; CI runs Bash 5.
    return shutil.which("bash") or "/bin/bash"


# Workflow shape -------------------------------------------------------------


def test_the_ratchet_passes_the_shadow_only_through_the_probed_block() -> None:
    step = validate_step(RATCHET)
    run = step["run"]
    block = between(run, "# waiver-shadow-start", "# waiver-shadow-end")
    assert '[ "${EVENT_NAME:-}" = "pull_request" ]' in block
    # A failed preparation never stops the audit.
    assert '|| shadow_reason="prepare-failed"' in block
    assert "--incremental-shadow-report" in block and "--incremental-shadow-summary" in block
    # The probe result of the same supervised verifier decides (staged script).
    assert '"$audit_help"' in block
    assert 'bash "$RUNNER_TEMP/waiver-shadow-prepare.sh"' in block
    assert "${{" not in block
    assert step["env"]["SHADOW_SHARD"] == "${{ matrix.shard }}"
    assert step["env"]["SHADOW_VERIFIER_MODE"] == "${{ needs.shards.outputs.encoder_verifier }}"
    # The scope stays full: the shadow never adds --scope.
    assert "--scope" not in run
    after = run.split("# waiver-shadow-end", 1)[1]
    assert '"${shadow_args[@]}"' in after
    assert after.index('"${restate_args[@]}"') < after.index('"${shadow_args[@]}"')
    # The record lives outside the checkout and every audit input.
    assert '"$RUNNER_TEMP/waiver-shadow/record.json"' in block
    assert "GITHUB_WORKSPACE" not in block


def test_the_preparation_is_staged_before_the_ratchet_without_expressions() -> None:
    steps = workflow()["jobs"]["validate"]["steps"]
    names = [step.get("name") for step in steps]
    # Directly before the restate stage, which must stay next to the ratchet.
    assert names.index(STAGE) == names.index("Stage the verifier restate check") - 1
    assert names.index("Stage the verifier restate check") == names.index(RATCHET) - 1
    stage = steps[names.index(STAGE)]
    assert "if" not in stage
    assert "${{" not in stage["run"]
    assert 'shadow_dir="$RUNNER_TEMP/waiver-shadow"' in stage["run"]


def test_each_leg_uploads_one_artifact_on_pull_requests_even_after_a_failure() -> None:
    steps = workflow()["jobs"]["validate"]["steps"]
    names = [step.get("name") for step in steps]
    upload = steps[names.index(UPLOAD)]
    assert names.index(UPLOAD) == names.index(RATCHET) + 1
    assert upload["if"] == "${{ always() && github.event_name == 'pull_request' }}"
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert len(upload["uses"].split("@", 1)[1].split()[0]) == 40
    assert upload["with"]["name"] == "waiver-shadow-${{ matrix.shard }}"
    assert upload["with"]["path"] == "${{ runner.temp }}/waiver-shadow/"
    # A failed upload or a re-run name clash never turns the required leg red.
    assert upload["continue-on-error"] is True
    assert upload["with"]["overwrite"] is True


def test_the_collector_is_separate_from_the_required_aggregate() -> None:
    jobs = workflow()["jobs"]
    collector = jobs["waiver-shadow"]
    assert collector["name"] == "waiver shadow"
    assert collector["needs"] == ["shards", "validate"]
    assert "github.event_name == 'pull_request'" in collector["if"]
    # A superseded (cancelled) run shows no red collector.
    assert "!cancelled()" in collector["if"] and "always()" not in collector["if"]
    assert collector["permissions"] == {"contents": read_only()}
    # `validate / validate` (the required context) does not wait for it.
    assert jobs["validate-complete"]["needs"] == "validate"
    assert jobs["validate-complete"]["name"] == "validate"
    download = collector["steps"][0]
    assert download["uses"].startswith("actions/download-artifact@")
    assert download["with"]["pattern"] == "waiver-shadow-*"
    assert download["continue-on-error"] is True
    check = collector["steps"][1]
    assert check["env"]["SHADOW_MATRIX"] == "${{ needs.shards.outputs.matrix }}"
    assert check["env"]["SHADOW_HEAD"] == "${{ github.sha }}"
    assert "${{" not in check["run"]


def read_only() -> str:
    return "read"


# Ratchet shadow block -------------------------------------------------------


def run_shadow_block(
    *,
    event: str = "pull_request",
    help_text: str = HELP_WITH_SHADOW,
    partitioned: bool = True,
    comparison_base: str = "1" * 40,
    base_ref: str = "1" * 40,
    version: str | None = "0.2.2248",
    mode: str = "pinned",
    break_prepare: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, list[str]]:
    stage = validate_step(STAGE)["run"]
    block = between(
        validate_step(RATCHET)["run"], "# waiver-shadow-start", "# waiver-shadow-end"
    )
    temporary = Path(tempfile.mkdtemp(prefix="waiver-shadow-block-"))
    repo = temporary / "rulespec-us"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=T",
         "commit", "-q", "--allow-empty", "-m", "head"],
        check=True,
    )
    runner_temp = temporary / "runner-temp"
    runner_temp.mkdir()
    (runner_temp / "help.txt").write_text(help_text)
    (runner_temp / "base.yaml").write_text("validate_failures: {}\n")
    (runner_temp / "changed.txt").write_text("us-az/policies/x.yaml\n")
    summary = temporary / "summary.md"
    summary.write_text("")
    dependencies = temporary / "deps"
    (dependencies / "axiom-encode").mkdir(parents=True)
    if version is not None:
        (dependencies / "axiom-encode/pyproject.toml").write_text(
            f'[project]\nname = "axiom-encode"\nversion = "{version}"\n'
        )
    if break_prepare:
        stage = stage + '\nprintf "exit 7\\n" > "$RUNNER_TEMP/waiver-shadow-prepare.sh"\n'
    partition = "partition_args=(--partition-key us-az --partition-keys-json '[]')" if partitioned else "partition_args=()"
    script = stage + f"""
set -euo pipefail
audit_help="$RUNNER_TEMP/help.txt"
protected_base="$RUNNER_TEMP/base.yaml"
audit_changed_paths="$RUNNER_TEMP/changed.txt"
comparison_base="{comparison_base}"
base_ref="{base_ref}"
{partition}
{block}
printf 'ARGS:'
for arg in ${{shadow_args[@]+"${{shadow_args[@]}}"}}; do printf ' %s' "$arg"; done
printf '\\n'
echo AUDIT-RUNS
"""
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(temporary),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_STEP_SUMMARY": str(summary),
        "EVENT_NAME": event,
        "SHADOW_SHARD": "us-az",
        "SHADOW_VERIFIER_MODE": mode,
        "AXIOM_DEPENDENCY_ROOT": str(dependencies),
    }
    result = subprocess.run(
        [bash(), "-c", script], cwd=repo, env=env, capture_output=True, text=True
    )
    args_line = next(
        (line for line in result.stdout.splitlines() if line.startswith("ARGS:")), "ARGS:"
    )
    return result, runner_temp / "waiver-shadow", args_line[len("ARGS:"):].split()


def test_shadow_block_passes_the_flags_and_writes_the_expected_binding() -> None:
    result, directory, args = run_shadow_block()
    assert result.returncode == 0, result.stderr
    assert args[0] == "--incremental-shadow-report"
    assert args[1] == str(directory / "record.json")
    assert args[2] == "--incremental-shadow-summary"
    assert sorted(item.name for item in directory.iterdir()) == ["expected.json"]
    expected = json.loads((directory / "expected.json").read_text())
    head = subprocess.run(
        ["git", "-C", str(directory.parent.parent / "rulespec-us"), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert expected == {
        "schema": "validate-rulespec/waiver-shadow-expected/v1",
        "partition": "us-az",
        "head_commit": head,
        "protected_base_sha256": "sha256:" + hashlib.sha256(b"validate_failures: {}\n").hexdigest(),
        "changed_paths_sha256": "sha256:" + hashlib.sha256(b"us-az/policies/x.yaml\n").hexdigest(),
    }


def test_shadow_block_does_nothing_outside_pull_requests() -> None:
    for event in ("push", "schedule", "workflow_dispatch", "merge_group"):
        result, directory, args = run_shadow_block(event=event)
        assert result.returncode == 0, result.stderr
        assert args == []
        assert not directory.exists()
        assert (directory.parent / "waiver-shadow-prepare.sh").is_file()


def assert_marker(reason: str, *, version: str | None = "0.2.2248", mode: str = "pinned", **options) -> None:
    result, directory, args = run_shadow_block(version=version, mode=mode, **options)
    assert result.returncode == 0, result.stderr
    assert "AUDIT-RUNS" in result.stdout
    assert args == []
    assert sorted(item.name for item in directory.iterdir()) == ["expected.json", "unavailable.json"]
    marker = json.loads((directory / "unavailable.json").read_text())
    assert marker == {
        "schema": "validate-rulespec/waiver-shadow-unavailable/v1",
        "partition": "us-az",
        "reason": reason,
        "verifier_version": version,
        "verifier_mode": mode,
    }


def test_a_verifier_without_the_option_leaves_a_marker_not_a_flag() -> None:
    assert_marker("verifier-without-shadow", help_text=HELP_WITHOUT_SHADOW)
    # A help that names only one of the two options is not enough.
    assert_marker(
        "verifier-without-shadow",
        help_text=HELP_WITHOUT_SHADOW + "  --incremental-shadow-report-old X\n",
    )


def test_the_marker_names_the_verifier_version_and_mode() -> None:
    assert_marker("verifier-without-shadow", help_text=HELP_WITHOUT_SHADOW, version="0.2.2396", mode="main")
    assert_marker("verifier-without-shadow", help_text=HELP_WITHOUT_SHADOW, version=None)


def test_detection_needs_both_options() -> None:
    only_report = "usage: x\n  --incremental-shadow-report REPORT\n"
    only_summary = "usage: x\n  --incremental-shadow-summary SUMMARY\n"
    for text in (only_report, only_summary):
        assert_marker("verifier-without-shadow", help_text=text)


def test_a_failed_preparation_leaves_a_marker_and_the_audit_runs() -> None:
    result, directory, args = run_shadow_block(break_prepare=True)
    assert result.returncode == 0, result.stderr
    assert "AUDIT-RUNS" in result.stdout
    assert args == []
    marker = json.loads((directory / "unavailable.json").read_text())
    assert marker["reason"] == "prepare-failed" and marker["partition"] == "us-az"


def test_the_block_runs_without_event_or_shard_variables() -> None:
    # Older callers' test harnesses run the ratchet script with neither set.
    block = between(validate_step(RATCHET)["run"], "# waiver-shadow-start", "# waiver-shadow-end")
    result = subprocess.run(
        [bash(), "-c", "set -euo pipefail\npartition_args=()\n" + block + "\necho OK"],
        env={"PATH": os.environ["PATH"]}, capture_output=True, text=True,
    )
    assert result.returncode == 0 and "OK" in result.stdout, result.stderr


def test_an_unpartitioned_audit_or_another_comparison_base_leaves_a_marker() -> None:
    assert_marker("unpartitioned-audit", partitioned=False)
    assert_marker("comparison-base-differs-from-event-base", comparison_base="2" * 40)


# Collector ------------------------------------------------------------------


def collector_script() -> str:
    run = workflow()["jobs"]["waiver-shadow"]["steps"][1]["run"]
    return run


def record(shard: str, verdict: str = "agree", **changes) -> dict:
    value = {
        "schema": RECORD_SCHEMA,
        "report_only": True,
        "verdict": verdict,
        "unsafe": verdict not in ("agree", "incremental_extra"),
        "missed": ["us/statutes/x.yaml"] if verdict == "incremental_missed" else [],
        "extra": [],
        "errors": ["the full audit did not complete"] if verdict == "inconclusive" else [],
        "partition": {"key": shard, "count": len(SHARDS)},
        "binding": {
            "encoder_version": "0.2.2396",
            "head_commit": HEAD,
            "github_sha": None,
            "protected_base_sha256": BASE_DIGEST,
            "changed_paths_sha256": CHANGED_DIGEST,
        },
        "full": {"checked": 37, "flagged": 0, "success": True},
        "incremental": {"scope": "incremental", "selected": 3, "unselected": 34, "flagged": 0},
    }
    value.update(changes)
    return value


def expected(shard: str, **changes) -> dict:
    value = {
        "schema": "validate-rulespec/waiver-shadow-expected/v1",
        "partition": shard,
        "head_commit": HEAD,
        "protected_base_sha256": BASE_DIGEST,
        "changed_paths_sha256": CHANGED_DIGEST,
    }
    value.update(changes)
    return value


def run_collector(
    files: dict[str, dict[str, dict]],
    *,
    matrix: list[str] = SHARDS,
    validate_result: str = "success",
    extra_paths: dict[str, str] | None = None,
    workflows_changed: str | None = "false",
) -> tuple[subprocess.CompletedProcess[str], str]:
    temporary = Path(tempfile.mkdtemp(prefix="waiver-shadow-collector-"))
    root = temporary / "waiver-shadow"
    root.mkdir()
    for artifact, contents in files.items():
        directory = root / artifact
        directory.mkdir()
        for name, payload in contents.items():
            (directory / name).write_text(json.dumps(payload))
    for relative, kind in (extra_paths or {}).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "file":
            target.write_text("{}")
        elif kind.startswith("symlink:"):
            target.symlink_to(kind.split(":", 1)[1])
        elif kind == "dir":
            target.mkdir()
    summary = temporary / "summary.md"
    summary.write_text("")
    env = {
        "PATH": os.environ["PATH"],
        "SHADOW_ROOT": str(root),
        "SHADOW_MATRIX": json.dumps(matrix),
        "SHADOW_HEAD": HEAD,
        "SHADOW_VALIDATE_RESULT": validate_result,
        **({"SHADOW_WORKFLOWS_CHANGED": workflows_changed} if workflows_changed is not None else {}),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    result = subprocess.run(
        [bash(), "-c", collector_script()], env=env, capture_output=True, text=True
    )
    return result, summary.read_text()


def complete(**overrides: dict[str, dict]) -> dict[str, dict[str, dict]]:
    files = {
        f"waiver-shadow-{shard}": {"expected.json": expected(shard), "record.json": record(shard)}
        for shard in SHARDS
    }
    files.update(overrides)
    return files


def assert_unsafe(files: dict, needle: str, **options) -> None:
    result, summary = run_collector(files, **options)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert needle in result.stdout, (needle, result.stdout)
    assert needle in summary


def test_collector_passes_when_every_partition_agrees() -> None:
    result, summary = run_collector(complete())
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "All 3 partitions agree." in summary
    assert "| us-az | agree | incremental | - | 0.2.2396 |" in summary


def test_collector_accepts_incremental_extra_as_safe() -> None:
    files = complete(**{
        "waiver-shadow-us": {
            "expected.json": expected("us"),
            "record.json": record("us", "incremental_extra", extra=["us/statutes/y.yaml"]),
        }
    })
    result, _ = run_collector(files)
    assert result.returncode == 0, result.stdout


def test_collector_fails_on_incremental_missed() -> None:
    files = complete(**{
        "waiver-shadow-us": {"expected.json": expected("us"), "record.json": record("us", "incremental_missed")}
    })
    assert_unsafe(files, "us: incremental_missed (unsafe): us/statutes/x.yaml")


def test_collector_fails_on_inconclusive() -> None:
    files = complete(**{
        "waiver-shadow-us-az": {"expected.json": expected("us-az"), "record.json": record("us-az", "inconclusive")}
    })
    assert_unsafe(files, "us-az: inconclusive (unsafe)")
    # The verdict alone decides: an inconclusive record is unsafe even if its
    # `unsafe` field says otherwise.
    for verdict in ("inconclusive", "incremental_missed", "unknown", None):
        files = complete(**{
            "waiver-shadow-us-az": {
                "expected.json": expected("us-az"),
                "record.json": {**record("us-az"), "verdict": verdict, "unsafe": False},
            }
        })
        assert_unsafe(files, f"us-az: {verdict} (unsafe)")


def test_collector_fails_on_a_record_that_claims_safe_but_is_marked_unsafe() -> None:
    files = complete(**{
        "waiver-shadow-us-az": {"expected.json": expected("us-az"), "record.json": record("us-az", unsafe=True)}
    })
    assert_unsafe(files, "us-az: agree (unsafe)")


def test_collector_fails_on_a_missing_leg_or_a_leg_without_a_record() -> None:
    files = complete()
    del files["waiver-shadow-us-ak"]
    assert_unsafe(files, "us-ak: missing (the leg uploaded no shadow artifact)")
    files = complete(**{"waiver-shadow-us-ak": {"expected.json": expected("us-ak")}})
    assert_unsafe(files, "us-ak: missing (no record")
    assert_unsafe({}, "us-ak: missing")


def test_collector_fails_on_a_duplicate_or_foreign_artifact() -> None:
    files = complete(**{
        "waiver-shadow-us-az": {
            "expected.json": expected("us-az"),
            "record.json": record("us-az"),
            "unavailable.json": {
                "schema": "validate-rulespec/waiver-shadow-unavailable/v1",
                "partition": "us-az",
                "reason": "verifier-without-shadow",
            },
        }
    })
    assert_unsafe(files, "us-az: duplicate")
    files = complete(**{"waiver-shadow-us-zz": {"expected.json": expected("us-zz"), "record.json": record("us-zz")}})
    assert_unsafe(files, "us-zz: artifact for a partition that is not in the matrix")
    files = complete(**{
        "waiver-shadow-us-az": {
            "expected.json": expected("us-az"), "record.json": record("us-az"), "record-2.json": record("us-az"),
        }
    })
    assert_unsafe(files, "us-az: unexpected files")


def test_collector_fails_on_an_unbound_record() -> None:
    cases = {
        "partition key": record("us-az", partition={"key": "us-ak", "count": 3}),
        "partition count": record("us-az", partition={"key": "us-az", "count": 52}),
        "unpartitioned": record("us-az", partition={"key": None, "count": 1}),
        "head": record("us-az", binding={**record("us-az")["binding"], "head_commit": "f" * 40}),
        "no head": record("us-az", binding={**record("us-az")["binding"], "head_commit": None}),
        "base ledger": record("us-az", binding={**record("us-az")["binding"], "protected_base_sha256": "sha256:" + "d" * 64}),
        "changed paths": record("us-az", binding={**record("us-az")["binding"], "changed_paths_sha256": None}),
        "no binding": {key: value for key, value in record("us-az").items() if key != "binding"},
        "schema": record("us-az", schema="axiom-encode/validation-waiver-incremental-shadow/v0"),
    }
    for label, payload in cases.items():
        files = complete(**{"waiver-shadow-us-az": {"expected.json": expected("us-az"), "record.json": payload}})
        result, _ = run_collector(files)
        assert result.returncode == 1, label
        assert "us-az:" in result.stdout, (label, result.stdout)


def test_collector_refuses_an_expectation_for_another_head() -> None:
    files = complete(**{
        "waiver-shadow-us-az": {"expected.json": expected("us-az", head_commit="e" * 40), "record.json": record("us-az")}
    })
    assert_unsafe(files, "us-az: expected.json does not describe this leg")


def unavailable(
    shard: str,
    reason: str = "verifier-without-shadow",
    version: str | None = "0.2.2248",
    mode: str | None = "pinned",
) -> dict[str, dict]:
    return {
        "expected.json": expected(shard),
        "unavailable.json": {
            "schema": "validate-rulespec/waiver-shadow-unavailable/v1",
            "partition": shard,
            "reason": reason,
            "verifier_version": version,
            "verifier_mode": mode,
        },
    }


def tally(result: subprocess.CompletedProcess[str]) -> dict:
    line = next(line for line in result.stdout.splitlines() if line.startswith("WAIVER_SHADOW_TALLY "))
    return json.loads(line.split(" ", 1)[1])


def test_collector_passes_with_a_notice_for_an_old_pinned_verifier() -> None:
    files = {f"waiver-shadow-{shard}": unavailable(shard) for shard in SHARDS}
    result, summary = run_collector(files)
    assert result.returncode == 0, result.stdout
    assert "::notice::Waiver shadow off: pinned verifier 0.2.2248 has no shadow option." in result.stdout
    assert "Shadow off on all 3 legs" in summary
    assert tally(result)["off"] is True


def test_collector_fails_when_a_shadow_capable_or_main_verifier_has_no_shadow() -> None:
    cases = [
        ("0.2.2395", "pinned"), ("0.2.2396", "pinned"), ("0.3.0", "pinned"),
        ("0.2.2248", "main"), (None, "pinned"), ("garbage", "pinned"), ("0.2.2248", None),
    ]
    for version, mode in cases:
        files = {f"waiver-shadow-{shard}": unavailable(shard, version=version, mode=mode) for shard in SHARDS}
        result, _ = run_collector(files)
        assert result.returncode == 1, (version, mode, result.stdout)
        assert "no shadow (verifier-without-shadow" in result.stdout, (version, mode)


def test_collector_fails_on_any_other_no_shadow_reason() -> None:
    for reason in ("prepare-failed", "unpartitioned-audit", "comparison-base-differs-from-event-base"):
        files = {f"waiver-shadow-{shard}": unavailable(shard, reason=reason) for shard in SHARDS}
        result, _ = run_collector(files)
        assert result.returncode == 1, reason
        assert f"no shadow ({reason}" in result.stdout


def test_collector_fails_when_only_some_legs_ran_the_shadow() -> None:
    files = complete(**{"waiver-shadow-us": unavailable("us")})
    assert_unsafe(files, "mixed: some legs did not run the shadow: us")


def test_collector_refuses_a_malformed_marker() -> None:
    good = unavailable("us")["unavailable.json"]
    for broken in (
        {**good, "schema": "validate-rulespec/waiver-shadow-unavailable/v0"},
        {**good, "partition": "us-ak"},
        {**good, "reason": 7},
        {**good, "reason": ""},
    ):
        files = {f"waiver-shadow-{shard}": unavailable(shard) for shard in SHARDS}
        files["waiver-shadow-us"]["unavailable.json"] = broken
        assert_unsafe(files, "us: malformed unavailable marker")


def test_collector_refuses_a_malformed_matrix() -> None:
    for matrix in ([], ["us", "us"], [""], ["us", "us-ak", "us"]):
        result, _ = run_collector(complete(), matrix=matrix)
        assert result.returncode == 1, matrix
        assert "the shard matrix is not a list of distinct names" in result.stdout


def test_collector_reports_legs_of_a_failed_matrix_as_incomplete_not_unsafe() -> None:
    files = complete()
    del files["waiver-shadow-us-ak"]
    result, summary = run_collector(files, validate_result="failure")
    assert result.returncode == 0, result.stdout
    assert "::warning::Waiver shadow: us-ak: incomplete (leg not audited" in result.stdout
    assert "Incomplete (1), validation matrix failure" in summary
    counts = tally(result)
    assert counts["incomplete"] == 1 and counts["unsafe"] == 0 and counts["missing"] == 0
    # An unsafe record still fails, also when the matrix failed.
    files["waiver-shadow-us"] = {"expected.json": expected("us"), "record.json": record("us", "incremental_missed")}
    result, _ = run_collector(files, validate_result="failure")
    assert result.returncode == 1


def test_collector_tally_counts_verdicts() -> None:
    files = complete(**{
        "waiver-shadow-us": {"expected.json": expected("us"), "record.json": record("us", "incremental_extra", extra=["x"])}
    })
    result, _ = run_collector(files)
    assert result.returncode == 0
    assert tally(result) == {
        "incomplete": 0, "matrix": 3, "missing": 0, "off": False, "records": 3, "unavailable": 0,
        "unsafe": 0, "untrusted": False, "validate_result": "success",
        "verdicts": {"agree": 2, "incremental_extra": 1},
    }


def caller_workflows_changed(path: str, text: str) -> str:
    sys.path.insert(0, str(ROOT / "scripts"))
    import test_validate_rulespec_workflow as base

    with base.WorkflowInputFixture(
        table=base.workflow_toolchain(base.WORKFLOW_INPUT_PINS),
        caller=base.literal_pin_caller(base.WORKFLOW_INPUT_PINS),
    ) as fixture:
        fixture.write(path, text)
        head = base.commit(fixture.root, "head")
        output = fixture.root / "output"
        result = base.run_workflow_inputs(fixture.root, fixture.base, head=head, output=output)
        assert result.returncode == 0, result.stderr
        bound = dict(line.split("=", 1) for line in output.read_text().splitlines())
        return bound["caller_workflows_changed"]


def test_the_dependency_step_flags_changes_under_github_from_the_event_diff() -> None:
    assert caller_workflows_changed("README.md", "changed\n") == "false"
    assert caller_workflows_changed(".github/workflows/extra.yml", "name: x\n") == "true"
    assert caller_workflows_changed(".github/actions/a/action.yml", "name: x\n") == "true"
    jobs = workflow()["jobs"]
    assert jobs["shards"]["outputs"]["caller_workflows_changed"] == "${{ steps.dependency_inputs.outputs.caller_workflows_changed }}"
    assert jobs["waiver-shadow"]["steps"][1]["env"]["SHADOW_WORKFLOWS_CHANGED"] == "${{ needs.shards.outputs.caller_workflows_changed }}"


def test_collector_marks_a_run_that_changes_github_paths_as_untrusted() -> None:
    for value in ("true", "", None):
        result, summary = run_collector(complete(), workflows_changed=value)
        assert result.returncode == 0, result.stdout
        assert tally(result)["untrusted"] is True, value
        assert "Untrusted evidence" in summary
    result, _ = run_collector(complete())
    assert tally(result)["untrusted"] is False


def test_collector_refuses_a_record_without_its_expectation() -> None:
    files = complete(**{"waiver-shadow-us-az": {"record.json": record("us-az")}})
    assert_unsafe(files, "us-az: expected.json not a regular file")


def test_collector_tally_line_comes_first_and_record_text_cannot_forge_one() -> None:
    forged = 'x\nWAIVER_SHADOW_TALLY {"unsafe": 0, "untrusted": false}\n'
    files = complete(**{
        "waiver-shadow-us": {
            "expected.json": expected("us"),
            "record.json": {**record("us", "incremental_missed", missed=[forged]), "verdict": "weird\nverdict"},
        }
    })
    result, _ = run_collector(files)
    assert result.returncode == 1
    lines = result.stdout.splitlines()
    tallies = [line for line in lines if line.startswith("WAIVER_SHADOW_TALLY ")]
    assert len(tallies) == 1 and lines.index(tallies[0]) == 0, result.stdout
    counts = json.loads(tallies[0].split(" ", 1)[1])
    assert counts["verdicts"] == {"agree": 2, "other": 1} and counts["unsafe"] == 1


def test_collector_escapes_carriage_returns_and_terminal_escapes_in_record_text() -> None:
    hostile = [
        "a\rWAIVER_SHADOW_TALLY {\"unsafe\": 0}",
        "b\x1b[2K\x1b[1Gall partitions agree",
        "c\u2028WAIVER_SHADOW_TALLY {}",
        "d\x00e\x7f",
        "f\x1b]0;title\x07",
    ]
    files = complete(**{
        "waiver-shadow-us": {
            "expected.json": expected("us"),
            "record.json": record("us", "incremental_missed", missed=hostile),
        }
    })
    result, summary = run_collector(files)
    assert result.returncode == 1
    for text in (result.stdout, summary):
        for raw in ("\r", "\x1b", "\u2028", "\x00", "\x7f", "\x07"):
            assert raw not in text, (repr(raw), text)
    # The escaped form is shown, so a reader still sees what the record said.
    assert "\\r" in result.stdout and "\\x1b" in result.stdout
    tallies = [line for line in result.stdout.splitlines() if "WAIVER_SHADOW_TALLY" in line]
    assert tallies[0].startswith("WAIVER_SHADOW_TALLY ") and result.stdout.splitlines()[0] == tallies[0]


def test_collector_checks_unsafe_as_exactly_false() -> None:
    for value in (None, 0, "false", [], True):
        files = complete(**{
            "waiver-shadow-us-az": {"expected.json": expected("us-az"), "record.json": {**record("us-az"), "unsafe": value}}
        })
        assert_unsafe(files, "us-az: agree (unsafe)")


def test_collector_requires_a_well_formed_encoder_version() -> None:
    for value in (None, "", 2396, "0.2", "v0.2.2396"):
        payload = record("us-az", binding={**record("us-az")["binding"], "encoder_version": value})
        files = complete(**{"waiver-shadow-us-az": {"expected.json": expected("us-az"), "record.json": payload}})
        assert_unsafe(files, "us-az: unbound")


def test_collector_checks_the_expectation_partition_and_digest_format() -> None:
    for changes in (
        {"partition": "us-ak"},
        {"schema": "validate-rulespec/waiver-shadow-expected/v0"},
        {"protected_base_sha256": "b" * 64},
        {"protected_base_sha256": "sha256:" + "B" * 64},
        {"changed_paths_sha256": "sha256:" + "c" * 63},
        {"changed_paths_sha256": None},
    ):
        files = complete(**{
            "waiver-shadow-us-az": {"expected.json": expected("us-az", **changes), "record.json": record("us-az")}
        })
        assert_unsafe(files, "us-az: expected.json does not describe this leg")


def test_collector_refuses_a_marker_beside_a_record_even_when_both_are_valid() -> None:
    files = complete()
    files["waiver-shadow-us"]["unavailable.json"] = unavailable("us")["unavailable.json"]
    assert_unsafe(files, "us: duplicate (both a record and an unavailable marker)")


def test_collector_refuses_unexpected_top_level_entries_and_symlinks() -> None:
    assert_unsafe_extra = lambda extra, needle: (  # noqa: E731
        lambda result: (result[0].returncode == 1 and needle in result[0].stdout)
    )(run_collector(complete(), extra_paths=extra))
    assert assert_unsafe_extra({"stray.json": "file"}, "unexpected artifact stray.json")
    assert assert_unsafe_extra({"other-artifact": "dir"}, "unexpected artifact other-artifact")
    assert assert_unsafe_extra({"waiver-shadow-us-zz": "symlink:/tmp"}, "unexpected artifact waiver-shadow-us-zz")
    # A symlinked file inside a leg's artifact is refused.
    files = complete()
    del files["waiver-shadow-us"]["record.json"]
    result, _ = run_collector(files, extra_paths={"waiver-shadow-us/record.json": "symlink:/etc/hosts"})
    assert result.returncode == 1 and "us: unexpected files" in result.stdout, result.stdout


def main() -> None:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print(f"{name}: ok")


if __name__ == "__main__":
    sys.exit(main())
