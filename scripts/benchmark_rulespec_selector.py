#!/usr/bin/env python3
"""Time the workflow's complete shard compute shell against read-only Git trees."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
SCRATCH = ROOT / ".hub-scratch"


def git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments], check=True,
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()


def benchmark(args: argparse.Namespace) -> dict:
    repo = args.repo.resolve(strict=True)
    base = git(repo, "rev-parse", "--verify", f"{args.base}^{{commit}}")
    head = git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}")
    bash = shutil.which(args.bash)
    if bash is None:
        raise ValueError(f"Bash executable not found: {args.bash}")
    bash = str(Path(bash).resolve())
    version = subprocess.run(
        [bash, "-c", 'printf "%s" "$BASH_VERSINFO"'], check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout
    if not version.isdigit() or int(version) < 4:
        raise ValueError("Use --bash with Bash 4 or newer, matching the Actions runner")
    workflow = yaml.safe_load(args.workflow.read_text())
    step = next(
        step for step in workflow["jobs"]["shards"]["steps"]
        if step.get("id") == "compute"
    )
    if "${{" in step["run"]:
        raise ValueError("Compute shell contains unbound workflow expressions")
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="selector-benchmark-", dir=SCRATCH) as temporary:
        workspace = Path(temporary) / "workspace"
        workspace.mkdir()
        runner_temp = Path(temporary) / "runner-temp"
        runner_temp.mkdir()
        bin_path = Path(temporary) / "bin"
        bin_path.mkdir()
        # Compute discovers shard directories from the exact head tree, then
        # reads all content through Git. Reproduce its directory view without
        # checking out files or touching the source repository's metadata.
        directories = subprocess.run(
            ["git", "-C", str(repo), "ls-tree", "-r", "-d", "-z", "--name-only", head],
            check=True, capture_output=True, timeout=30,
        ).stdout
        for raw_path in directories.split(b"\0"):
            if not raw_path:
                continue
            path = PurePosixPath(os.fsdecode(raw_path))
            if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
                raise ValueError(f"Unsafe tree directory: {path}")
            workspace.joinpath(*path.parts).mkdir(parents=True, exist_ok=True)
        real_git = shutil.which("git")
        if real_git is None:
            raise ValueError("Git executable not found")
        for name, command in {
            "git": [real_git, "-C", str(repo)],
            "python3": [sys.executable],
        }.items():
            wrapper = bin_path / name
            wrapper.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
            wrapper.chmod(0o755)
        output = runner_temp / "outputs"
        environment = {
            **os.environ,
            "PATH": str(bin_path) + os.pathsep + os.environ.get("PATH", ""),
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_SHA": head,
            "VALIDATE_ROOTS_INPUT": "auto",
            "GUARD_PROGRAMS_ROOT": "false",
            "EVENT_NAME": "pull_request",
            "PR_BASE_SHA": base,
            "HEAD_SHA": head,
            "IMPORT_AWARE_SELECTION": "true",
        }
        started = time.perf_counter()
        result = subprocess.run(
            [bash, "-c", step["run"]], cwd=workspace, env=environment,
            capture_output=True, text=True, timeout=args.timeout,
        )
        elapsed = time.perf_counter() - started
        outputs = dict(
            line.split("=", 1) for line in output.read_text().splitlines()
        ) if output.exists() else {}
        report = {
            "base": base,
            "head": head,
            "elapsed_seconds": round(elapsed, 3),
            "returncode": result.returncode,
            "python": sys.version.split()[0],
            "pyyaml": yaml.__version__,
            "c_safe_loader_available": hasattr(yaml, "CSafeLoader"),
            "outputs": outputs,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if result.returncode:
            raise RuntimeError(json.dumps(report, indent=2))
        # A success with full-targets=true can be a conservative graph fallback;
        # preserve diagnostics and outputs so a replay reports that honestly.
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True, help="Read-only rules repository")
    parser.add_argument("--base", default="HEAD^", help="Base commit/ref (default: HEAD^)")
    parser.add_argument("--head", default="HEAD", help="Head commit/ref (default: HEAD)")
    parser.add_argument("--workflow", type=Path, default=WORKFLOW)
    parser.add_argument("--bash", default="bash", help="Bash 4+ executable, matching Actions")
    parser.add_argument("--timeout", type=int, default=570, help="Compute timeout, at most 570s")
    parser.add_argument("-o", "--output", type=Path, help="Write a JSON timing report")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 570:
        parser.error("--timeout must be between 1 and 570 seconds")
    os.umask(0o022)
    report = benchmark(args)
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized)
    print(serialized, end="")


if __name__ == "__main__":
    main()
