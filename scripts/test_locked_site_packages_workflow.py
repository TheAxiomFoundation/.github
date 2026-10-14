#!/usr/bin/env python3
"""Protected site-packages trees must be exactly their uv.lock sets.

The provisioners copy a caller-staged ``--site-packages`` tree into each
protected runtime's trusted import root. A resolving ``pip install --target``
ignores ``uv.lock`` and floats every ``>=`` dependency to the index's latest
release at run time: axiom-encode targeted run 36174590343 logged
``claude-agent-sdk==0.1.47`` in its locked environment and
``claude-agent-sdk==0.2.159`` in the verification tree of the same job. The
job interpreter matters as well: the head provisioner runs it as root with
site enabled, and every later step runs it with sudo available.

These tests fail on any unlocked ``--target`` install in this repository's
workflows, pin each staging block line for line, and execute every real block
against a fake ``uv`` to prove its argv sequence and its fail-closed paths.
"""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
WORKFLOW = WORKFLOWS / "validate-rulespec.yml"
TEMP_PARENT = "/private/tmp" if Path("/private/tmp").is_dir() else None

SETUP_UV = "astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b"
UV_VERSION = "0.11.7"

HEAD = "Install Python dependencies"
BASE = "Prepare protected-base manifest audit"
COMPOSE = "Build protected axiom-compose runtime"
CLASSIFIER = "Install changed-file oracle coverage classifier"
PROTECTED_RUNTIMES = (
    "/opt/axiom-verification/",
    "/opt/axiom-base-verification/",
    "/opt/axiom-compose-verification/",
)

ORACLES_PATTERN = (
    r"axiom-oracles @ git\+https://github\.com/TheAxiomFoundation/"
    r"axiom-oracles@[0-9a-f]{40}"
)
LOCKED_GIT_LINE = (
    "axiom-oracles @ git+https://github.com/TheAxiomFoundation/"
    "axiom-oracles@d3419010d9c8de6a790220bf47912d85aadc2588"
)


def logical_lines(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    lines = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(re.sub(r"\s+", " ", stripped))
    return lines


def workflow_steps():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for job_name, job in workflow.get("jobs", {}).items():
            for index, step in enumerate(job.get("steps", [])):
                yield path.name, job_name, index, step


def pip_installs(*, target: bool):
    for workflow, job, index, step in workflow_steps():
        for line in logical_lines(step.get("run", "")):
            if not re.search(r"\bpip\b.*\binstall\b", line):
                continue
            has_target = re.search(r"(^|\s)(--target|-t)(\s|=)", line) is not None
            if has_target == target:
                yield workflow, job, index, step, line


VALIDATE_STEPS = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)[
    "jobs"]["validate"]["steps"]
STEP_NAMES = [step.get("name") for step in VALIDATE_STEPS]


def step(name: str) -> dict:
    return VALIDATE_STEPS[STEP_NAMES.index(name)]


def block(name: str, first: str, last: str) -> list[str]:
    lines = logical_lines(step(name)["run"])
    start = lines.index(first)
    return lines[start:lines.index(last, start) + 1]


def raw_block(name: str, first: str, last: str) -> str:
    """The step's own shell text between two lines, for execution."""
    raw = step(name)["run"].splitlines()
    stripped = [line.strip() for line in raw]
    start = stripped.index(first)
    end = stripped.index(last, start)
    return "\n".join(raw[start:end + 1]) + "\n"


def encoder_core() -> list[str]:
    export = 'uv export --project "$encoder" --locked --no-dev --no-emit-project'
    install = 'uv pip install --python "$python_bin" --target "$site_packages"'
    return [
        'UV_PROJECT_ENVIRONMENT="$reference" uv sync --project "$encoder"'
        ' --locked --no-dev --python "$python_bin"',
        f"{export} --no-emit-package axiom-oracles --format requirements-txt"
        ' --output-file "$locked"',
        f'oracles="$({export} --no-hashes --no-annotate --no-header'
        f" --format requirements-txt | grep -xE '{ORACLES_PATTERN}')\"",
        f'{install} --require-hashes --no-deps -r "$locked"',
        f'{install} --no-deps "$oracles"',
        f'{install} --no-deps "$encoder"',
    ]


def staged_freeze(freeze: str, staged: str) -> list[str]:
    return [
        'uv pip freeze --python "$reference/bin/python" --exclude-editable'
        f' > "{freeze}"',
        'uv pip freeze --python "$python_bin" --target "$site_packages"'
        f' --exclude axiom-encode > "{staged}"',
    ]


HEAD_FIRST = 'uv_cache="$(mktemp -d "$RUNNER_TEMP/axiom-uv-cache.XXXXXXXX")"'
HEAD_LAST = 'rm -rf "$reference" "$uv_cache"'
HEAD_LOCKED_FREEZE = "$RUNNER_TEMP/axiom-verification-locked.freeze"
HEAD_STAGED_FREEZE = "$RUNNER_TEMP/axiom-verification-staged.freeze"
HEAD_INTERPRETER_FREEZE = "$RUNNER_TEMP/axiom-interpreter.freeze"
HEAD_CANONICAL = [
    HEAD_FIRST,
    'export UV_CACHE_DIR="$uv_cache"',
    'python_bin="$(command -v python)"',
    'reference="$RUNNER_TEMP/axiom-encode-locked-environment"',
    'site_packages="$RUNNER_TEMP/axiom-verification-site-packages"',
    'locked="$RUNNER_TEMP/axiom-verification-locked-requirements.txt"',
    'rm -rf "$reference" "$site_packages"',
    *encoder_core(),
    'uv pip install --python "$python_bin" --require-hashes --no-deps -r "$locked"',
    'uv pip install --python "$python_bin" --no-deps "$oracles"',
    'uv pip install --python "$python_bin" --no-deps "$encoder"',
    *staged_freeze(HEAD_LOCKED_FREEZE, HEAD_STAGED_FREEZE),
    'uv pip freeze --python "$python_bin" --exclude pip --exclude axiom-encode'
    f' > "{HEAD_INTERPRETER_FREEZE}"',
    f'test -s "{HEAD_LOCKED_FREEZE}"',
    f'diff -u "{HEAD_LOCKED_FREEZE}" "{HEAD_STAGED_FREEZE}"',
    f'diff -u "{HEAD_LOCKED_FREEZE}" "{HEAD_INTERPRETER_FREEZE}"',
    'tests_locked="$RUNNER_TEMP/axiom-repository-tests-locked-requirements.txt"',
    'uv export --project "$encoder" --locked --no-dev --extra dev --no-emit-project'
    " --no-emit-package axiom-oracles --format requirements-txt"
    ' --output-file "$tests_locked"',
    "pytest_pin=\"$(grep -oE '^pytest==[^ ]+' \"$tests_locked\")\"",
    'uv pip install --python "$python_bin" --require-hashes'
    ' --constraints "$tests_locked" "$pytest_pin"',
    HEAD_LAST,
]

BASE_FIRST = "export UV_NO_CONFIG=1"
BASE_LAST = 'rm -rf "$reference" "$uv_cache"'
BASE_CANONICAL = [
    BASE_FIRST,
    HEAD_FIRST,
    'export UV_CACHE_DIR="$uv_cache"',
    'python_bin="$(command -v python)"',
    'encoder="$audit_root/encoder-install"',
    'reference="$audit_root/locked-environment"',
    'site_packages="$audit_root/site-packages"',
    'locked="$audit_root/locked-requirements.txt"',
    'cp -a "$base_dependencies/axiom-encode" "$encoder"',
    *encoder_core(),
    *staged_freeze("$audit_root/locked.freeze", "$audit_root/staged.freeze"),
    'test -s "$audit_root/locked.freeze"',
    'diff -u "$audit_root/locked.freeze" "$audit_root/staged.freeze"',
    BASE_LAST,
]

COMPOSE_FIRST = 'compose_reference="$RUNNER_TEMP/axiom-compose-locked-environment"'
COMPOSE_LAST = 'rm -rf "$compose_reference"'
COMPOSE_PYTHON = "$RUNNER_TEMP/axiom-compose-build/bin/python"
COMPOSE_SITE_PACKAGES = "$RUNNER_TEMP/axiom-compose-site-packages"
COMPOSE_CANONICAL = [
    COMPOSE_FIRST,
    f'rm -rf "$compose_reference" "{COMPOSE_SITE_PACKAGES}"',
    'UV_PROJECT_ENVIRONMENT="$compose_reference" uv sync'
    ' --project "${AXIOM_DEPENDENCY_ROOT}/axiom-compose" --locked --no-dev'
    f' --no-install-project --python "{COMPOSE_PYTHON}"',
    'uv export --project "${AXIOM_DEPENDENCY_ROOT}/axiom-compose" --locked --no-dev'
    " --no-emit-project --format requirements.txt"
    ' --output-file "$RUNNER_TEMP/axiom-compose-requirements.txt"',
    f'uv pip install --python "{COMPOSE_PYTHON}" --target "{COMPOSE_SITE_PACKAGES}"'
    " --require-hashes --no-deps"
    ' --requirement "$RUNNER_TEMP/axiom-compose-requirements.txt"',
    'uv pip freeze --python "$compose_reference/bin/python"'
    ' > "$RUNNER_TEMP/axiom-compose-locked.freeze"',
    f'uv pip freeze --python "{COMPOSE_PYTHON}" --target "{COMPOSE_SITE_PACKAGES}"'
    ' > "$RUNNER_TEMP/axiom-compose-staged.freeze"',
    'test -s "$RUNNER_TEMP/axiom-compose-locked.freeze"',
    'diff -u "$RUNNER_TEMP/axiom-compose-locked.freeze"'
    ' "$RUNNER_TEMP/axiom-compose-staged.freeze"',
    COMPOSE_LAST,
]

# Every --target install in this repository's workflows, by staging step.
TARGET_INSTALLS = {
    HEAD: 3,
    BASE: 3,
    COMPOSE: 1,
}

# Locked forms an install may take, as (requirement suffix, hash-checked).
LOCKED_REQUIREMENTS = {
    '--require-hashes --no-deps -r "$locked"',
    '--no-deps "$oracles"',
    '--no-deps "$encoder"',
    '--require-hashes --no-deps --requirement "$RUNNER_TEMP/axiom-compose-requirements.txt"',
    '--require-hashes --constraints "$tests_locked" "$pytest_pin"',
}


FAKE_UV = r'''
import json, os, sys

argv = sys.argv[1:]
with open(os.environ["FAKE_UV_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({
        "argv": argv,
        "project_environment": os.environ.get("UV_PROJECT_ENVIRONMENT"),
        "cache_dir": os.environ.get("UV_CACHE_DIR"),
        "no_config": os.environ.get("UV_NO_CONFIG"),
        "no_cache": os.environ.get("UV_NO_CACHE"),
    }) + "\n")

def option(name):
    return argv[argv.index(name) + 1]

if argv[:1] == ["sync"]:
    if os.environ.get("FAKE_SYNC_FAIL"):
        sys.stderr.write("error: The lockfile needs to be updated\n")
        sys.exit(2)
    os.makedirs(os.path.join(os.environ["UV_PROJECT_ENVIRONMENT"], "bin"))
elif argv[:1] == ["export"]:
    if os.environ.get("FAKE_EXPORT_FAIL"):
        sys.exit(2)
    if "--no-hashes" in argv:
        sys.stdout.write(os.environ["FAKE_UNHASHED_EXPORT"])
    else:
        key = "FAKE_DEV_EXPORT" if "--extra" in argv else "FAKE_HASHED_EXPORT"
        with open(option("--output-file"), "w", encoding="utf-8") as handle:
            handle.write(os.environ[key])
elif argv[:2] == ["pip", "install"]:
    if "--target" in argv:
        os.makedirs(option("--target"), exist_ok=True)
elif argv[:2] == ["pip", "freeze"]:
    python = option("--python")
    if "--target" in argv:
        key = "FAKE_STAGED_FREEZE"
    elif "locked-environment" in python:
        key = "FAKE_LOCKED_FREEZE"
    else:
        key = "FAKE_INTERPRETER_FREEZE"
    sys.stdout.write(os.environ[key])
else:
    sys.exit(f"unexpected uv invocation: {argv}")
'''

HASH = "--hash=sha256:" + "0" * 64
LOCKED_FREEZE = f"claude-agent-sdk==0.1.47\n{LOCKED_GIT_LINE}\nrequests==2.32.5\n"
UNHASHED_EXPORT = f"claude-agent-sdk==0.1.47\n{LOCKED_GIT_LINE}\nrequests==2.32.5\n"


class Run:
    def __init__(self, result: subprocess.CompletedProcess[str], calls: list[dict],
                 root: Path) -> None:
        self.result = result
        self.calls = calls
        self.argv = [call["argv"] for call in calls]
        self.root = root

    @property
    def installed(self) -> bool:
        return any(argv[:2] == ["pip", "install"] for argv in self.argv)


def execute(name: str, *, unhashed_export: str = UNHASHED_EXPORT,
            staged_freeze: str = LOCKED_FREEZE, interpreter_freeze: str = LOCKED_FREEZE,
            locked_freeze: str = LOCKED_FREEZE,
            dev_export: str = f"pytest==9.0.2 \\\n    {HASH}\n",
            export_fails: bool = False, sync_fails: bool = False) -> Run:
    """Run the workflow's own staging shell for `name` against a fake uv."""
    directory = tempfile.mkdtemp(prefix="locked-site-packages-", dir=TEMP_PARENT)
    root = Path(directory)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    fake_uv = bin_dir / "uv"
    fake_uv.write_text(f"#!{sys.executable}\n{FAKE_UV}", encoding="utf-8")
    fake_uv.chmod(0o755)
    # Only resolved by path; a staging block must never execute it.
    python = bin_dir / "python"
    python.write_text("#!/bin/sh\necho 'interpreter executed' >&2\nexit 97\n")
    python.chmod(0o755)
    runner_temp = root / "runner-temp"
    runner_temp.mkdir()
    dependencies = root / "dependencies"
    (dependencies / "axiom-encode").mkdir(parents=True)
    (dependencies / "axiom-compose").mkdir(parents=True)
    audit_root = runner_temp / "base-manifest-audit.fixture"
    (audit_root / "dependencies/axiom-encode").mkdir(parents=True)
    log = root / "uv-argv.jsonl"
    env = {
        **{key: value for key, value in os.environ.items() if not key.startswith("UV_")},
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "RUNNER_TEMP": str(runner_temp),
        "AXIOM_DEPENDENCY_ROOT": str(dependencies),
        "FAKE_UV_LOG": str(log),
        "FAKE_UNHASHED_EXPORT": unhashed_export,
        "FAKE_HASHED_EXPORT": f"requests==2.32.5 \\\n    {HASH}\n",
        "FAKE_DEV_EXPORT": dev_export,
        "FAKE_LOCKED_FREEZE": locked_freeze,
        "FAKE_STAGED_FREEZE": staged_freeze,
        "FAKE_INTERPRETER_FREEZE": interpreter_freeze,
    }
    if export_fails:
        env["FAKE_EXPORT_FAIL"] = "1"
    if sync_fails:
        env["FAKE_SYNC_FAIL"] = "1"
    if name == HEAD:
        prelude = (
            "export UV_NO_CONFIG=1\n"
            'encoder="$RUNNER_TEMP/axiom-encode-install"\n'
            'cp -a "${AXIOM_DEPENDENCY_ROOT}/axiom-encode" "$encoder"\n'
        )
        script = raw_block(HEAD, HEAD_FIRST, HEAD_LAST)
    elif name == BASE:
        prelude = (
            f'audit_root="{audit_root}"\n'
            'base_dependencies="$audit_root/dependencies"\n'
        )
        script = raw_block(BASE, BASE_FIRST, BASE_LAST)
    else:
        prelude = "export UV_NO_CONFIG=1\nexport UV_NO_CACHE=1\n"
        script = raw_block(COMPOSE, COMPOSE_FIRST, COMPOSE_LAST)
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + prelude + script],
        cwd=runner_temp, env=env, capture_output=True, text=True, check=False,
    )
    calls = ([json.loads(line) for line in log.read_text().splitlines()]
             if log.exists() else [])
    return Run(result, calls, root)


class LockedSitePackagesTests(unittest.TestCase):
    def test_every_target_install_is_a_locked_uv_install(self):
        installs = list(pip_installs(target=True))
        # Non-vacuity: discovery sees every protected staging, and nothing else.
        found: dict[str, int] = {}
        for workflow, _job, _index, item, _line in installs:
            self.assertEqual(workflow, WORKFLOW.name)
            found[item["name"]] = found.get(item["name"], 0) + 1
        self.assertEqual(found, TARGET_INSTALLS)
        for _workflow, job, _index, item, line in installs:
            where = f"{job}/{item['name']}: {line}"
            self.assertTrue(line.startswith("uv pip install --python "), where)
            self.assertIn("--no-deps", line.split(), where)
            self.assertNotIn(".[", line, where)
            self.assertTrue(any(line.endswith(" " + form) for form in LOCKED_REQUIREMENTS), where)
            if '-r "$locked"' in line or "--requirement" in line:
                self.assertIn("--require-hashes", line.split(), where)
            else:
                self.assertNotIn("--require-hashes", line.split(), where)

    def test_staging_blocks_are_exactly_the_locked_install(self):
        self.assertEqual(block(HEAD, HEAD_FIRST, HEAD_LAST), HEAD_CANONICAL)
        self.assertEqual(block(BASE, BASE_FIRST, BASE_LAST), BASE_CANONICAL)
        self.assertEqual(block(COMPOSE, COMPOSE_FIRST, COMPOSE_LAST), COMPOSE_CANONICAL)
        head = logical_lines(step(HEAD)["run"])
        # uv reads no ambient uv.toml, and the copy is the only project it builds.
        self.assertLess(head.index("export UV_NO_CONFIG=1"), head.index(HEAD_FIRST))
        self.assertLess(head.index('encoder="$RUNNER_TEMP/axiom-encode-install"'),
                        head.index(HEAD_FIRST))
        self.assertLess(
            head.index('cp -a "${AXIOM_DEPENDENCY_ROOT}/axiom-encode" "$encoder"'),
            head.index(HEAD_FIRST))
        self.assertEqual(head[0:2], ["set -euo pipefail", 'cd "$RUNNER_TEMP"'])
        compose = logical_lines(step(COMPOSE)["run"])
        for setting in ("export UV_NO_CONFIG=1", "export UV_NO_CACHE=1"):
            self.assertLess(compose.index(setting), compose.index(COMPOSE_FIRST))

    def test_job_interpreter_installs_are_locked_until_protected_consumers_finish(self):
        consumers = [index for index, item in enumerate(VALIDATE_STEPS)
                     if any(runtime in item.get("run", "") for runtime in PROTECTED_RUNTIMES)]
        last_consumer = max(consumers)
        self.assertEqual(STEP_NAMES[last_consumer], "Require money proof atoms")
        late = []
        for workflow, job, index, item, line in pip_installs(target=False):
            if workflow != WORKFLOW.name or job != "validate":
                continue
            if index <= last_consumer:
                where = f"{item['name']}: {line}"
                self.assertTrue(line.startswith('uv pip install --python "$python_bin" '), where)
                self.assertTrue(any(line.endswith(" " + form) for form in LOCKED_REQUIREMENTS), where)
            else:
                late.append((item["name"], line))
        # After the last protected consumer the classifier still reinstalls the
        # same authenticated encoder commit, whose dependencies the locked set
        # above already satisfies. Nothing else may install there.
        self.assertEqual(late, [
            (CLASSIFIER, 'python -I -m pip --isolated install "$RUNNER_TEMP/axiom-encode-oracle-coverage-install"'),
            (CLASSIFIER, 'python -I -m pip --isolated install --force-reinstall --no-deps "$oracles_spec"'),
        ])
        self.assertGreater(STEP_NAMES.index(CLASSIFIER), last_consumer)
        installs = logical_lines(step(HEAD)["run"])
        self.assertFalse([line for line in installs if "-m pip" in line])

    def test_uv_is_pinned_and_set_up_before_every_staging(self):
        uses = [(index, item) for index, item in enumerate(VALIDATE_STEPS)
                if item.get("uses", "").startswith("astral-sh/setup-uv@")]
        self.assertEqual(len(uses), 1)
        index, item = uses[0]
        self.assertEqual(item["uses"], SETUP_UV)
        self.assertNotIn("if", item)
        self.assertEqual(item["with"]["version"], UV_VERSION)
        self.assertEqual(item["with"]["enable-cache"], "false")
        for name in (HEAD, BASE, COMPOSE):
            self.assertLess(index, STEP_NAMES.index(name), name)

    def test_every_provisioner_consumes_a_tree_staged_from_the_lock(self):
        provisions = {}
        for index, item in enumerate(VALIDATE_STEPS):
            text = " ".join(logical_lines(item.get("run", "")))
            for match in re.finditer(r"provision_(verification_supervisor|axiom_compose_runtime)\.py\b(.*?)(?:$| sudo )", text):
                site_packages = re.search(r"--site-packages (\S+)", match.group(2)).group(1)
                provisions[(item["name"], match.group(1))] = (index, site_packages)
        self.assertEqual(provisions, {
            ("Provision protected verification supervisor", "verification_supervisor"):
                (STEP_NAMES.index("Provision protected verification supervisor"),
                 '"$RUNNER_TEMP/axiom-verification-site-packages"'),
            (BASE, "verification_supervisor"):
                (STEP_NAMES.index(BASE), '"$audit_root/site-packages"'),
            (COMPOSE, "axiom_compose_runtime"):
                (STEP_NAMES.index(COMPOSE), f'"{COMPOSE_SITE_PACKAGES}"'),
        })
        self.assertLess(STEP_NAMES.index(HEAD),
                        STEP_NAMES.index("Provision protected verification supervisor"))
        base = logical_lines(step(BASE)["run"])
        self.assertLess(base.index(BASE_LAST),
                        next(i for i, line in enumerate(base) if "provision_verification_supervisor.py" in line))
        compose = logical_lines(step(COMPOSE)["run"])
        self.assertLess(compose.index(COMPOSE_LAST),
                        next(i for i, line in enumerate(compose) if "provision_axiom_compose_runtime.py" in line))

    def test_head_staging_runs_the_locked_sequence(self):
        run = execute(HEAD)
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        temp = run.root / "runner-temp"
        python = str(run.root / "bin/python")
        encoder = str(temp / "axiom-encode-install")
        site_packages = str(temp / "axiom-verification-site-packages")
        locked = str(temp / "axiom-verification-locked-requirements.txt")
        reference = str(temp / "axiom-encode-locked-environment")
        tests_locked = str(temp / "axiom-repository-tests-locked-requirements.txt")
        export = ["export", "--project", encoder, "--locked", "--no-dev", "--no-emit-project"]
        target = ["pip", "install", "--python", python, "--target", site_packages]
        system = ["pip", "install", "--python", python]
        self.assertEqual(run.argv, [
            ["sync", "--project", encoder, "--locked", "--no-dev", "--python", python],
            [*export, "--no-emit-package", "axiom-oracles", "--format", "requirements-txt",
             "--output-file", locked],
            [*export, "--no-hashes", "--no-annotate", "--no-header", "--format", "requirements-txt"],
            [*target, "--require-hashes", "--no-deps", "-r", locked],
            [*target, "--no-deps", LOCKED_GIT_LINE],
            [*target, "--no-deps", encoder],
            [*system, "--require-hashes", "--no-deps", "-r", locked],
            [*system, "--no-deps", LOCKED_GIT_LINE],
            [*system, "--no-deps", encoder],
            ["pip", "freeze", "--python", reference + "/bin/python", "--exclude-editable"],
            ["pip", "freeze", "--python", python, "--target", site_packages, "--exclude", "axiom-encode"],
            ["pip", "freeze", "--python", python, "--exclude", "pip", "--exclude", "axiom-encode"],
            ["export", "--project", encoder, "--locked", "--no-dev", "--extra", "dev",
             "--no-emit-project", "--no-emit-package", "axiom-oracles", "--format",
             "requirements-txt", "--output-file", tests_locked],
            [*system, "--require-hashes", "--constraints", tests_locked, "pytest==9.0.2"],
        ])
        self.assertEqual(run.calls[0]["project_environment"], reference)
        self.assertTrue(all(call["no_config"] == "1" for call in run.calls))
        caches = {call["cache_dir"] for call in run.calls}
        self.assertEqual(len(caches), 1)
        cache = caches.pop()
        self.assertTrue(cache.startswith(str(temp / "axiom-uv-cache.")), cache)
        # The step-local cache and the reference environment do not outlive it.
        self.assertFalse(Path(cache).exists())
        self.assertFalse(Path(reference).exists())
        self.assertTrue(Path(site_packages).is_dir())

    def test_base_staging_runs_the_locked_sequence(self):
        run = execute(BASE)
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        audit = run.root / "runner-temp/base-manifest-audit.fixture"
        python = str(run.root / "bin/python")
        encoder = str(audit / "encoder-install")
        site_packages = str(audit / "site-packages")
        locked = str(audit / "locked-requirements.txt")
        reference = str(audit / "locked-environment")
        export = ["export", "--project", encoder, "--locked", "--no-dev", "--no-emit-project"]
        target = ["pip", "install", "--python", python, "--target", site_packages]
        self.assertEqual(run.argv, [
            ["sync", "--project", encoder, "--locked", "--no-dev", "--python", python],
            [*export, "--no-emit-package", "axiom-oracles", "--format", "requirements-txt",
             "--output-file", locked],
            [*export, "--no-hashes", "--no-annotate", "--no-header", "--format", "requirements-txt"],
            [*target, "--require-hashes", "--no-deps", "-r", locked],
            [*target, "--no-deps", LOCKED_GIT_LINE],
            [*target, "--no-deps", encoder],
            ["pip", "freeze", "--python", reference + "/bin/python", "--exclude-editable"],
            ["pip", "freeze", "--python", python, "--target", site_packages, "--exclude", "axiom-encode"],
        ])
        self.assertEqual(run.calls[0]["project_environment"], reference)
        self.assertTrue(all(call["no_config"] == "1" for call in run.calls))
        self.assertFalse(Path(reference).exists())
        # The copy, not the integrity-recorded base checkout, is what uv builds.
        self.assertTrue((audit / "encoder-install").is_dir())

    def test_compose_staging_runs_the_locked_sequence(self):
        run = execute(COMPOSE)
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        temp = run.root / "runner-temp"
        project = str(run.root / "dependencies/axiom-compose")
        python = str(temp / "axiom-compose-build/bin/python")
        reference = str(temp / "axiom-compose-locked-environment")
        requirements = str(temp / "axiom-compose-requirements.txt")
        site_packages = str(temp / "axiom-compose-site-packages")
        self.assertEqual(run.argv, [
            ["sync", "--project", project, "--locked", "--no-dev", "--no-install-project",
             "--python", python],
            ["export", "--project", project, "--locked", "--no-dev", "--no-emit-project",
             "--format", "requirements.txt", "--output-file", requirements],
            ["pip", "install", "--python", python, "--target", site_packages,
             "--require-hashes", "--no-deps", "--requirement", requirements],
            ["pip", "freeze", "--python", reference + "/bin/python"],
            ["pip", "freeze", "--python", python, "--target", site_packages],
        ])
        self.assertEqual(run.calls[0]["project_environment"], reference)
        self.assertTrue(all(call["no_cache"] == "1" for call in run.calls))
        self.assertFalse(Path(reference).exists())

    def test_encoder_staging_refuses_any_but_a_commit_pinned_oracles_line(self):
        rejected = {
            "branch-ref": LOCKED_GIT_LINE.rsplit("@", 1)[0] + "@main\n",
            "foreign-repository": LOCKED_GIT_LINE.replace("TheAxiomFoundation/", "attacker/") + "\n",
            "short-sha": LOCKED_GIT_LINE[:-1] + "\n",
            "uppercase-sha": LOCKED_GIT_LINE[:-40] + LOCKED_GIT_LINE[-40:].upper() + "\n",
            "fragment-suffix": LOCKED_GIT_LINE + "#egg=axiom-oracles\n",
            "missing": "requests==2.32.5\n",
            "empty": "",
        }
        for name in (HEAD, BASE):
            for label, export in rejected.items():
                with self.subTest(step=name, export=label):
                    run = execute(name, unhashed_export=export)
                    self.assertNotEqual(run.result.returncode, 0)
                    self.assertFalse(run.installed, run.argv)

    def test_staging_fails_closed_before_installing_when_the_lock_is_unusable(self):
        for name in (HEAD, BASE, COMPOSE):
            for failure in ("export_fails", "sync_fails"):
                with self.subTest(step=name, failure=failure):
                    run = execute(name, **{failure: True})
                    self.assertNotEqual(run.result.returncode, 0)
                    self.assertFalse(run.installed, run.argv)

    def test_staging_fails_when_a_staged_tree_drifts_from_the_lock(self):
        drifted = LOCKED_FREEZE.replace("0.1.47", "0.2.159")
        for name in (HEAD, BASE, COMPOSE):
            with self.subTest(step=name):
                run = execute(name, staged_freeze=drifted)
                self.assertNotEqual(run.result.returncode, 0)
                self.assertIn("+claude-agent-sdk==0.2.159", run.result.stdout)
        for name in (HEAD, BASE, COMPOSE):
            with self.subTest(step=name, extra="unlocked distribution"):
                run = execute(name, staged_freeze=LOCKED_FREEZE + "sitecustomize-hook==1.0\n")
                self.assertNotEqual(run.result.returncode, 0)
                self.assertIn("+sitecustomize-hook==1.0", run.result.stdout)

    def test_head_staging_fails_when_the_interpreter_drifts_from_the_lock(self):
        for label, freeze in (
            ("floated", LOCKED_FREEZE.replace("0.1.47", "0.2.159")),
            ("preinstalled", LOCKED_FREEZE + "setuptools==80.9.0\n"),
        ):
            with self.subTest(interpreter=label):
                run = execute(HEAD, interpreter_freeze=freeze)
                self.assertNotEqual(run.result.returncode, 0)
                # The pytest install, the step's last, never runs.
                self.assertFalse(any("--constraints" in argv for argv in run.argv))

    def test_staging_fails_when_the_reference_environment_is_empty(self):
        for name in (HEAD, BASE, COMPOSE):
            with self.subTest(step=name):
                run = execute(name, locked_freeze="", staged_freeze="", interpreter_freeze="")
                self.assertNotEqual(run.result.returncode, 0)

    def test_head_staging_requires_the_locked_pytest_pin(self):
        run = execute(HEAD, dev_export=f"iniconfig==2.3.0 \\\n    {HASH}\n")
        self.assertNotEqual(run.result.returncode, 0)
        self.assertFalse(any("--constraints" in argv for argv in run.argv))

    def test_oracles_gate_agrees_with_its_specification(self):
        """Differential: the workflow's grep -xE gate against Python's re."""
        patterns = re.findall(r"grep -xE '([^']+)'", WORKFLOW.read_text(encoding="utf-8"))
        self.assertEqual(patterns, [ORACLES_PATTERN, ORACLES_PATTERN])
        rng = random.Random(1712)
        alphabet = "0123456789abcdefABCDEF@#/+:. -_gitaxiomracles"
        candidates = [LOCKED_GIT_LINE]
        for _ in range(400):
            line = list(LOCKED_GIT_LINE)
            for _ in range(rng.randint(1, 3)):
                position = rng.randrange(len(line) + 1)
                operation = rng.choice(("insert", "delete", "replace"))
                if operation == "insert":
                    line.insert(position, rng.choice(alphabet))
                elif line and position < len(line):
                    if operation == "delete":
                        del line[position]
                    else:
                        line[position] = rng.choice(alphabet)
            candidates.append("".join(line))
        candidates += [
            LOCKED_GIT_LINE[:-40] + "f" * 40,
            LOCKED_GIT_LINE + " ",
            " " + LOCKED_GIT_LINE,
            LOCKED_GIT_LINE + "\\",
            LOCKED_GIT_LINE.replace("https", "http"),
            LOCKED_GIT_LINE.replace("git+", ""),
        ]
        stdin = "".join(candidate + "\n" for candidate in candidates)
        grep = subprocess.run(["grep", "-xE", ORACLES_PATTERN], input=stdin,
                              capture_output=True, text=True, check=False)
        accepted_by_grep = grep.stdout.splitlines()
        accepted_by_spec = [
            candidate for candidate in candidates
            if re.fullmatch(r"axiom-oracles @ git\+https://github\.com/TheAxiomFoundation/"
                            r"axiom-oracles@[0-9a-f]{40}", candidate)
        ]
        self.assertEqual(accepted_by_grep, accepted_by_spec)
        self.assertIn(LOCKED_GIT_LINE, accepted_by_grep)
        self.assertIn(LOCKED_GIT_LINE[:-40] + "f" * 40, accepted_by_grep)
        # Most mutations break the pin; each one that does is refused.
        self.assertGreater(len(candidates) - len(accepted_by_grep), 350)


if __name__ == "__main__":
    unittest.main()
