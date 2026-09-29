#!/usr/bin/env python3
"""Exercise validate-rulespec.yml's changed-file PolicyEngine oracle coverage gate.

The gate runs ``axiom-encode oracle-coverage --root "$GITHUB_WORKSPACE" --json``
and keeps report items for the pull request's changed RuleSpec modules. The
classifier reports ``items[].file`` relative to the root it was given, so the
filter must anchor on the report's ``root`` rather than assume a layout. Until
this test existed the filter keyed on ``<repo>/<path>`` while the hardened
workflow's exact-checkout root yields repo-relative paths: every pull request
passed with "0 output(s)" and unmapped outputs only failed on main after merge
(rulespec-et PR #15, rulespec-rw c10b566).

Invariants checked for every generated scenario:

* Specification: the gate fails iff a changed module that defines executable
  outputs matched no report item, or a matched item is unmapped, or a matched
  item is comparable but untested. Otherwise it passes and reports the number
  of matched outputs.
* No vacuous pass: a passing gate matched at least one item for every changed
  module that defines executable outputs.
* Layout invariance: the verdict is identical whether the classifier ran on
  the exact checkout (repo-relative paths) or on the parent workspace
  (``<repo>/...`` paths, the nested rulespec-us/rulespec-us layout).
* Isolation: items for unchanged modules and for sibling checkouts never
  change the verdict.
* Push-gate parity (differential): when every module changed and every module
  was classified, the gate agrees with the whole-repository push gate
  (``--fail-on-unmapped --fail-on-untested-comparable``).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
STEP = "Validate changed PolicyEngine oracle coverage classification"
PUSH_STEP = "Validate PolicyEngine oracle coverage classification"
ET_MODULE = "et/regulations/dir-1021-2024/vat-electricity-water-exemption-directive.yaml"
STATUSES = (
    "comparable",
    "unmapped",
    "known_not_comparable",
    "pending_classification",
    "incomplete_comparable",
)


def step_source(workflow: str, name: str, next_name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    end = workflow.index(f"      - name: {next_name}\n", start)
    return workflow[start:end]


def heredoc_source(step: str, command: str) -> str:
    marker = f"{command}\n"
    start = step.index(marker) + len(marker)
    end = step.index("\n          PY", start)
    return "\n".join(
        line.removeprefix("          ") for line in step[start:end].splitlines()
    )


WORKFLOW_TEXT = WORKFLOW.read_text()
GATE_STEP = step_source(WORKFLOW_TEXT, STEP, "Run repository tests")
GATE_SOURCE = heredoc_source(
    GATE_STEP,
    '          python - "$coverage_json" "$RULESPEC_FILE_LIST" <<\'PY\'',
)
GATE_CODE = compile(GATE_SOURCE, "<changed-oracle-coverage-gate>", "exec")


@dataclass
class Result:
    status: int
    stdout: str
    stderr: str


def write_module(workspace: Path, path: str, rules: list[dict], *, fmt: str = "rulespec/v1") -> None:
    target = workspace / path
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"format: {fmt}", "rules:"] if rules else [f"format: {fmt}", "rules: []"]
    for rule in rules:
        lines.append(f"  - name: {rule.get('name', '')!r}")
        lines.append(f"    kind: {rule['kind']}")
    target.write_text("\n".join(lines) + "\n")


def layout(base: Path, repo: str, root_kind: str) -> tuple[Path, Path]:
    """Return (workspace, classifier root) the way GitHub Actions lays them out."""
    workspace = base / repo / repo
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace, workspace if root_kind == "exact" else workspace.parent


def display(workspace: Path, root: Path, path: str) -> str:
    """Mirror axiom-oracles' _display_file_path: relative to the --root."""
    return (workspace / path).relative_to(root).as_posix()


def item(file: str, legal_id: str, status: str, tested: bool = True, repo: str = "") -> dict:
    return {
        "file": file,
        "legal_id": legal_id,
        "repo": repo,
        "status": status,
        "tested": tested,
    }


def run_gate(
    workspace: Path,
    *,
    root: Path | str | None,
    items: list[dict],
    changed: list[str],
) -> Result:
    with tempfile.TemporaryDirectory() as scratch:
        coverage = Path(scratch) / "coverage.json"
        payload: dict = {"items": items}
        if root is not None:
            payload["root"] = str(root)
        coverage.write_text(json.dumps(payload))
        file_list = Path(scratch) / "rulespec-files.txt"
        file_list.write_text("".join(f"{path}\n" for path in changed))
        stdout, stderr = io.StringIO(), io.StringIO()
        previous_argv = sys.argv
        previous_workspace = os.environ.get("GITHUB_WORKSPACE")
        sys.argv = ["-", str(coverage), str(file_list)]
        os.environ["GITHUB_WORKSPACE"] = str(workspace)
        status = 0
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exec(GATE_CODE, {"__name__": "__main__"})
        except SystemExit as exc:
            status = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        finally:
            sys.argv = previous_argv
            if previous_workspace is None:
                os.environ.pop("GITHUB_WORKSPACE", None)
            else:
                os.environ["GITHUB_WORKSPACE"] = previous_workspace
        return Result(status, stdout.getvalue(), stderr.getvalue())


def et_pr15_fixture(base: Path, root_kind: str, status: str, tested: bool = True):
    workspace, root = layout(base, "rulespec-et", root_kind)
    names = [f"output_{index}" for index in range(5)]
    write_module(workspace, ET_MODULE, [{"name": name, "kind": "derived"} for name in names])
    legal = ET_MODULE.removesuffix(".yaml")
    items = [
        item(display(workspace, root, ET_MODULE), f"{legal}#{name}", status, tested, "rulespec-et")
        for name in names
    ]
    return workspace, root, items


# --- Example regressions -------------------------------------------------


def test_rulespec_et_pr15_unmapped_outputs_fail_on_the_pull_request() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items = et_pr15_fixture(Path(temp), "exact", "unmapped")
        # The pre-fix key set never intersected repo-relative report paths.
        assert not {f"rulespec-et/{ET_MODULE}"} & {entry["file"] for entry in items}
        result = run_gate(workspace, root=root.resolve(), items=items, changed=[ET_MODULE])
        assert result.status == 1, result
        assert result.stderr.count(": unmapped") == 5, result.stderr
        assert "passed for" not in result.stdout


def test_parent_workspace_root_gives_the_same_verdict() -> None:
    for status, expected in (("unmapped", 1), ("comparable", 0)):
        with tempfile.TemporaryDirectory() as temp:
            workspace, root, items = et_pr15_fixture(Path(temp), "parent", status)
            assert items[0]["file"] == f"rulespec-et/{ET_MODULE}"
            result = run_gate(workspace, root=root.resolve(), items=items, changed=[ET_MODULE])
            assert result.status == expected, result
            if expected == 0:
                assert "passed for 5 output(s) in 1 changed RuleSpec file(s)" in result.stdout


def test_sibling_checkout_items_never_match() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items = et_pr15_fixture(Path(temp), "parent", "comparable")
        # A sibling rulespec-us symlink in the parent workspace contributes
        # items whose path differs from a changed file only in its first part.
        sibling = [
            item(f"rulespec-us/{ET_MODULE}", "et:sibling#x", "unmapped", False, "rulespec-us"),
            item(f"../rulespec-et/{ET_MODULE}", "et:dotdot#x", "unmapped"),
            item(f"/abs/rulespec-et/{ET_MODULE}", "et:absolute#x", "unmapped"),
        ]
        result = run_gate(workspace, root=root.resolve(), items=items + sibling, changed=[ET_MODULE])
        assert result.status == 0, result
        assert "passed for 5 output(s)" in result.stdout


def test_nested_rulespec_us_layout_in_both_roots() -> None:
    module = "us-ca/regulations/mpp/63-300/1.yaml"
    for root_kind in ("exact", "parent"):
        with tempfile.TemporaryDirectory() as temp:
            workspace, root = layout(Path(temp), "rulespec-us", root_kind)
            write_module(workspace, module, [{"name": "benefit", "kind": "derived"}])
            file = display(workspace, root, module)
            assert file == (module if root_kind == "exact" else f"rulespec-us/{module}")
            unmapped = [item(file, "us-ca:regulations/mpp/63-300/1#benefit", "unmapped")]
            result = run_gate(workspace, root=root.resolve(), items=unmapped, changed=[module])
            assert result.status == 1 and "#benefit: unmapped" in result.stderr, result
            mapped = [item(file, "us-ca:regulations/mpp/63-300/1#benefit", "comparable")]
            result = run_gate(workspace, root=root.resolve(), items=mapped, changed=[module])
            assert result.status == 0 and "passed for 1 output(s)" in result.stdout, result


def test_unresolved_root_spelling_is_accepted() -> None:
    with tempfile.TemporaryDirectory() as temp:
        real = Path(temp) / "real"
        real.mkdir()
        link = Path(temp) / "link"
        link.symlink_to(real, target_is_directory=True)
        workspace, root, items = et_pr15_fixture(link, "exact", "comparable")
        result = run_gate(workspace, root=root, items=items, changed=[ET_MODULE])
        assert result.status == 0, result


def test_untested_comparable_fails() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items = et_pr15_fixture(Path(temp), "exact", "comparable", tested=False)
        result = run_gate(workspace, root=root.resolve(), items=items, changed=[ET_MODULE])
        assert result.status == 1, result
        assert "comparable but not covered by companion tests" in result.stderr


def test_statuses_outside_the_push_gate_do_not_fail() -> None:
    for status in ("known_not_comparable", "pending_classification", "incomplete_comparable"):
        with tempfile.TemporaryDirectory() as temp:
            workspace, root, items = et_pr15_fixture(Path(temp), "exact", status, tested=False)
            result = run_gate(workspace, root=root.resolve(), items=items, changed=[ET_MODULE])
            assert result.status == 0, (status, result)


def test_changed_module_missing_from_report_fails_loudly() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items = et_pr15_fixture(Path(temp), "exact", "comparable")
        for report_items in ([], [dict(entry, file=f"rulespec-et/{entry['file']}") for entry in items]):
            result = run_gate(workspace, root=root.resolve(), items=report_items, changed=[ET_MODULE])
            assert result.status == 1, result
            assert f"{ET_MODULE}: defines 5 executable output(s) but matched no" in result.stderr


def test_module_without_executable_outputs_needs_no_item() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root = layout(Path(temp), "rulespec-et", "exact")
        modules = {
            "et/statutes/empty.yaml": ([], "rulespec/v1"),
            "et/statutes/other-format.yaml": ([{"name": "x", "kind": "derived"}], "other/v1"),
            "et/statutes/unnamed.yaml": ([{"name": " ", "kind": "parameter"}], "rulespec/v1"),
            "et/statutes/non-executable.yaml": ([{"name": "x", "kind": "enum"}], "rulespec/v1"),
        }
        for path, (rules, fmt) in modules.items():
            write_module(workspace, path, rules, fmt=fmt)
        result = run_gate(workspace, root=root.resolve(), items=[], changed=sorted(modules))
        assert result.status == 0, result
        assert "passed for 0 output(s) in 4 changed RuleSpec file(s)" in result.stdout


def test_executable_kinds_and_counts_match_the_classifier() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root = layout(Path(temp), "rulespec-et", "exact")
        path = "et/policies/mixed.yaml"
        write_module(
            workspace,
            path,
            [
                {"name": "a", "kind": "parameter"},
                {"name": "b", "kind": "derived"},
                {"name": "c", "kind": "derived_relation"},
                {"name": "d", "kind": "enum"},
            ],
        )
        result = run_gate(workspace, root=root.resolve(), items=[], changed=[path])
        assert result.status == 1
        assert "defines 3 executable output(s)" in result.stderr


def test_unchanged_module_items_do_not_gate_the_pull_request() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items = et_pr15_fixture(Path(temp), "exact", "comparable")
        write_module(workspace, "et/statutes/old.yaml", [{"name": "x", "kind": "derived"}])
        stale = [item("et/statutes/old.yaml", "et:statutes/old#x", "unmapped")]
        result = run_gate(workspace, root=root.resolve(), items=items + stale, changed=[ET_MODULE])
        assert result.status == 0, result


def test_report_root_must_be_stated_and_contain_the_workspace() -> None:
    with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as other:
        workspace, _, items = et_pr15_fixture(Path(temp), "exact", "comparable")
        missing = run_gate(workspace, root=None, items=items, changed=[ET_MODULE])
        assert missing.status == 1 and "coverage report has no root" in missing.stderr
        elsewhere = run_gate(workspace, root=Path(other).resolve(), items=items, changed=[ET_MODULE])
        assert elsewhere.status == 1 and "does not contain" in elsewhere.stderr


def test_unreadable_changed_module_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root = layout(Path(temp), "rulespec-et", "exact")
        path = "et/statutes/broken.yaml"
        (workspace / path).parent.mkdir(parents=True)
        (workspace / path).write_text("rules: [\n")
        result = run_gate(workspace, root=root.resolve(), items=[], changed=[path])
        assert result.status == 1 and "cannot read changed RuleSpec file" in result.stderr


def test_belgium_remains_skipped() -> None:
    with tempfile.TemporaryDirectory() as temp:
        workspace, root = layout(Path(temp), "rulespec-be", "exact")
        result = run_gate(workspace, root=None, items=[], changed=["be/statutes/x.yaml"])
        assert result.status == 0 and "skipped for Belgium" in result.stdout


def test_gate_wiring_matches_the_push_gate() -> None:
    assert '--root "$GITHUB_WORKSPACE" \\\n            --json > "$coverage_json"' in GATE_STEP
    assert (
        "if: ${{ github.event_name == 'pull_request' && "
        "steps.validation_targets.outputs.mode != 'full-toolchain-bump' }}"
    ) in GATE_STEP
    push = step_source(WORKFLOW_TEXT, PUSH_STEP, "Checkout changed-file oracle coverage classifier")
    assert (
        "if: ${{ github.event_name != 'pull_request' || "
        "steps.validation_targets.outputs.mode == 'full-toolchain-bump' }}"
    ) in push
    assert '--root "$GITHUB_WORKSPACE"' in push
    # The changed-file gate enforces exactly the push gate's statuses. Adding
    # a --fail-on flag to the push gate must come with the matching check here.
    assert set(re.findall(r"--fail-on-[a-z-]+", push)) == {
        "--fail-on-unmapped",
        "--fail-on-untested-comparable",
    }


# --- Property-based invariants -------------------------------------------

MODULE_POOL = (
    "et/statutes/income-tax/rate.yaml",
    "et/regulations/dir-1021-2024/vat.yaml",
    "et/policies/benefits/child.yaml",
    "et-aa/statutes/levy/base.yaml",
    "et-aa/policies/levy/relief.yaml",
    "et/legislation/proclamation-979/exemptions.yaml",
)

output_strategy = st.tuples(st.sampled_from(STATUSES), st.booleans())
module_strategy = st.fixed_dictionaries(
    {
        "outputs": st.lists(output_strategy, max_size=3),
        "non_executable": st.integers(min_value=0, max_value=2),
        "changed": st.booleans(),
        "reported": st.booleans(),
    }
)
scenario_strategy = st.fixed_dictionaries(
    {
        "modules": st.lists(module_strategy, min_size=1, max_size=len(MODULE_POOL)),
        "siblings": st.lists(output_strategy, max_size=3),
    }
)


def build(base: Path, scenario: dict, root_kind: str) -> tuple[Path, Path, list[dict], list[str]]:
    workspace, root = layout(base, "rulespec-et", root_kind)
    items: list[dict] = []
    changed: list[str] = []
    for path, module in zip(MODULE_POOL, scenario["modules"]):
        rules = [{"name": f"out_{index}", "kind": "derived"} for index in range(len(module["outputs"]))]
        rules += [{"name": f"enum_{index}", "kind": "enum"} for index in range(module["non_executable"])]
        write_module(workspace, path, rules)
        if module["changed"]:
            changed.append(path)
        if module["reported"]:
            for index, (status, tested) in enumerate(module["outputs"]):
                legal = f"{path.split('/', 1)[0]}:{path.split('/', 1)[1].removesuffix('.yaml')}"
                items.append(item(display(workspace, root, path), f"{legal}#out_{index}", status, tested))
    for index, (status, tested) in enumerate(scenario["siblings"]):
        # Same tail as a real module, under a sibling checkout of the workspace
        # parent: must never be attributed to the workspace.
        path = MODULE_POOL[index % len(MODULE_POOL)]
        items.append(item(f"rulespec-us/{path}", f"us:sibling#{index}", status, tested))
    return workspace, root.resolve(), items, changed


def expected_verdict(scenario: dict) -> tuple[int, int]:
    """Reference model: (exit status, matched outputs) from the specification."""
    matched = 0
    failed = False
    for module in scenario["modules"]:
        if not module["changed"]:
            continue
        if module["outputs"] and not module["reported"]:
            failed = True
            continue
        if module["reported"]:
            matched += len(module["outputs"])
            for status, tested in module["outputs"]:
                if status == "unmapped" or (status == "comparable" and not tested):
                    failed = True
    return (1 if failed else 0), matched


def push_gate_fails(items: list[dict]) -> bool:
    """axiom-encode oracle-coverage --fail-on-unmapped --fail-on-untested-comparable."""
    return any(
        entry["status"] == "unmapped" or (entry["status"] == "comparable" and not entry["tested"])
        for entry in items
    )


def passed_outputs(result: Result) -> int | None:
    match = re.search(r"passed for (\d+) output\(s\)", result.stdout)
    return int(match.group(1)) if match else None


@settings(max_examples=150, deadline=None, database=None)
@given(scenario_strategy)
def test_property_specification_and_no_vacuous_pass(scenario: dict) -> None:
    status, matched = expected_verdict(scenario)
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items, changed = build(Path(temp), scenario, "exact")
        result = run_gate(workspace, root=root, items=items, changed=changed)
    assert result.status == status, (scenario, result)
    if result.status == 0:
        assert passed_outputs(result) == matched, (scenario, result)
        for module in scenario["modules"]:
            if module["changed"] and module["outputs"]:
                assert module["reported"], scenario


@settings(max_examples=100, deadline=None, database=None)
@given(scenario_strategy)
def test_property_layout_invariance(scenario: dict) -> None:
    results = []
    for root_kind in ("exact", "parent"):
        with tempfile.TemporaryDirectory() as temp:
            workspace, root, items, changed = build(Path(temp), scenario, root_kind)
            results.append(run_gate(workspace, root=root, items=items, changed=changed))
    exact, parent = results
    assert exact.status == parent.status, (scenario, exact, parent)
    assert passed_outputs(exact) == passed_outputs(parent), (scenario, exact, parent)


@settings(max_examples=100, deadline=None, database=None)
@given(scenario_strategy)
def test_property_agrees_with_push_gate_when_everything_changed(scenario: dict) -> None:
    scenario = {
        "modules": [dict(module, changed=True, reported=True) for module in scenario["modules"]],
        "siblings": [],
    }
    with tempfile.TemporaryDirectory() as temp:
        workspace, root, items, changed = build(Path(temp), scenario, "exact")
        result = run_gate(workspace, root=root, items=items, changed=changed)
    assert (result.status == 1) == push_gate_fails(items), (scenario, result)


def main() -> None:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
        print(f"ok {test.__name__}")
    print(f"changed-file oracle coverage gate: {len(tests)} tests ok")


if __name__ == "__main__":
    main()
