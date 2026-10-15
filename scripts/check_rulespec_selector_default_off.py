#!/usr/bin/env python3
"""Replay the review's 17 default-off scenarios against a reference workflow."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".hub-scratch"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-ref", default="origin/main")
    parser.add_argument("--bash", default="bash", help="Bash 4+ executable, matching Actions")
    parser.add_argument("--start", type=int, default=0, help="First scenario index (inclusive)")
    parser.add_argument("--stop", type=int, default=17, help="Last scenario index (exclusive)")
    parser.add_argument("-o", "--output", type=Path, help="Write a JSON differential report")
    args = parser.parse_args()
    bash = shutil.which(args.bash)
    if bash is None:
        parser.error(f"Bash executable not found: {args.bash}")
    bash = str(Path(bash).resolve())
    version = subprocess.run(
        [bash, "-c", 'printf "%s" "$BASH_VERSINFO"'], check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout
    if not version.isdigit() or int(version) < 4:
        parser.error("Use --bash with Bash 4 or newer, matching the Actions runner")
    os.umask(0o022)
    SCRATCH.mkdir(exist_ok=True)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "selector_fixtures", ROOT / "scripts/test_validate_rulespec_workflow.py",
    )
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    module = fixtures.selection_module()
    changed = module + "# changed\n"
    toolchain = fixtures.SELECTOR_TOOLCHAIN
    scenarios = [
        ("single jurisdiction", {"us-fl/statutes/local.yaml": changed}, {}),
        ("multi jurisdiction", {"us-fl/statutes/local.yaml": changed, "us-ma/statutes/local.yaml": changed}, {}),
        ("shared path", {"README.md": "after\n"}, {}),
        ("ProgramSpec", {"programs/fixture.yaml": fixtures.selection_program("us-fl", {"state": ["statutes/local"]})}, {}),
        ("manifest", {".axiom/encoding-manifests/local.json": fixtures.selection_manifest("us-fl/statutes/local.yaml")}, {}),
        ("index-only", {".axiom/index/provisions_to_rules.json": "{}\n"}, {}),
        ("empty diff", {}, {}),
        ("push", {"us-fl/statutes/local.yaml": changed}, {"event": "push"}),
        ("malformed module", {"us-fl/statutes/local.yaml": "broken: ["}, {}),
        ("corpus-only toolchain", {".axiom/toolchain.toml": toolchain.replace('axiom_corpus_release = "before"', 'axiom_corpus_release = "after"')}, {}),
        ("pin bump", {".axiom/toolchain.toml": toolchain.replace("b" * 64, "f" * 64)}, {}),
        ("explicit roots", {"us-fl/statutes/local.yaml": changed}, {"roots_input": "us-fl"}),
        ("deletion", {"us-fl/statutes/local.yaml": None}, {}),
        ("missing base ref", {"us-fl/statutes/local.yaml": changed}, {"base_override": ""}),
        ("bad base ref", {"us-fl/statutes/local.yaml": changed}, {"base_override": "f" * 40}),
        ("guard-programs-root", {"us-fl/statutes/local.yaml": changed}, {"guard_programs": True}),
        ("dependency pins changed", {"us-fl/statutes/local.yaml": changed}, {"dependency_pins_changed": True}),
    ]
    if not 0 <= args.start < args.stop <= len(scenarios):
        parser.error("Require 0 <= --start < --stop <= 17")
    scenarios = scenarios[args.start:args.stop]
    reference = subprocess.run(
        ["git", "show", f"{args.reference_ref}:.github/workflows/validate-rulespec.yml"],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=30,
    ).stdout
    current = fixtures.WORKFLOW
    started = time.perf_counter()
    comparisons = []
    # Every fixture, including Git metadata, is disposable inside this worktree.
    with tempfile.TemporaryDirectory(prefix="selector-default-off-", dir=SCRATCH) as temporary:
        temporary = Path(temporary)
        original_tempdir = tempfile.tempdir
        original_path = os.environ.get("PATH", "")
        tempfile.tempdir = str(temporary)
        try:
            bin_path = temporary / "bin"
            bin_path.mkdir()
            for name in ("python", "python3"):
                wrapper = bin_path / name
                wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n')
                wrapper.chmod(0o755)
            bash_wrapper = bin_path / "bash"
            bash_wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(bash) + ' "$@"\n')
            bash_wrapper.chmod(0o755)
            os.environ["PATH"] = str(bin_path) + os.pathsep + original_path
            reference_path = temporary / "reference-workflow.yml"
            reference_path.write_text(reference)
            for name, changes, options in scenarios:
                for enabled in (False, None):
                    fixtures.WORKFLOW = reference_path
                    expected = fixtures.run_import_aware_selection(changes, enabled=enabled, **options)
                    fixtures.WORKFLOW = current
                    actual = fixtures.run_import_aware_selection(changes, enabled=enabled, **options)
                    fields = ("matrix", "first", "roots", "allowed-extra", "targets")
                    differences = [field for field in fields if expected[field] != actual[field]]
                    assert actual.get("revalidate-shards", "[]") == "[]", actual
                    assert actual.get("full-targets", "false") == "false", actual
                    comparison = {"scenario": name, "input": "false" if enabled is False else "absent", "differences": differences}
                    comparisons.append(comparison)
                    print(json.dumps(comparison), flush=True)
        finally:
            fixtures.WORKFLOW = current
            tempfile.tempdir = original_tempdir
            os.environ["PATH"] = original_path
    report = {
        "reference_ref": args.reference_ref,
        "scenario_range": [args.start, args.stop],
        "scenarios": len(scenarios),
        "comparisons": len(comparisons),
        "differences": sum(bool(item["differences"]) for item in comparisons),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "results": comparisons,
    }
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")
    if report["differences"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
