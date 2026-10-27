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

import functools
import json
import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
WORKFLOW = WORKFLOWS / "validate-rulespec.yml"
TEMP_PARENT = tempfile.gettempdir()

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


def workflow_texts() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8")
            for path in sorted(WORKFLOWS.glob("*.yml"))}


# Any command that can put a distribution on disk or into an interpreter.
# Matched over the raw logical line as a cross-check on the parser below; it
# misses option-prefixed forms, so it may only add findings.
INSTALLER = re.compile(
    r"(?<![\w./-])(?:uv\s+pip\s+(?:install|sync)|uv\s+(?:sync|add|run|tool)\b"
    r"|uv\s+python\s+install|uvx|pip3?(?:\.\d+)?\s+install|-m\s+(?:pip|ensurepip)\b"
    r"|easy_install)(?![\w-])"
)
# Every word that can name an installer program or module. Two detectors that
# agree on zero installers prove nothing, so each raw occurrence must also turn
# up in a parsed word of a command the parser classified.
INSTALLER_TOKEN = re.compile(
    r"(?<![\w.-])(?:uvx|uv|pipx|pip3?(?:\.\d+)*|easy_install|ensurepip)(?![\w-])"
)
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "{", "}"}
DIRECTORY_OPTIONS = ("--target", "-t", "--prefix", "--root", "--user")
PLACEHOLDER = re.compile(r"__axiom_substitution_(\d+)__")


def _closing_backtick(text: str, index: int) -> int:
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == "`":
            return index
        else:
            index += 1
    raise ValueError("unterminated backtick substitution")


def _closing_paren(text: str, index: int) -> int:
    """Index of the ``)`` closing a group whose ``(`` ends just before index."""
    depth, quote = 1, None
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = None
        elif char == "\\":
            index += 1
        elif char == "`":
            index = _closing_backtick(text, index + 1)
        elif quote == '"':
            if char == '"':
                quote = None
            elif text.startswith("$(", index):
                index = _closing_paren(text, index + 2)
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError("unterminated substitution")


def split_substitutions(line: str) -> tuple[str, list[str], list[str]]:
    """The line with each ``$(...)``, backtick, ``<(...)`` and ``>(...)``
    replaced by a placeholder word, plus each one's body and original text.

    Substitutions run whether or not they sit inside double quotes, so only
    single quotes hide them. Raises ValueError on an unterminated one.
    """
    out, bodies, originals = [], [], []
    index, quote = 0, None
    while index < len(line):
        char = line[index]
        if quote == "'":
            quote = None if char == "'" else quote
            out.append(char)
            index += 1
            continue
        if char == "\\":
            out.append(line[index:index + 2])
            index += 2
            continue
        opens = line.startswith("$(", index) or (
            quote is None and char in "<>" and line.startswith("(", index + 1))
        if opens or char == "`":
            if char == "`":
                end = _closing_backtick(line, index + 1)
                body = re.sub(r"\\([`$\\])", r"\1", line[index + 1:end])
            else:
                end = _closing_paren(line, index + 2)
                body = line[index + 2:end]
            out.append(f"__axiom_substitution_{len(bodies)}__")
            bodies.append(body)
            originals.append(line[index:end + 1])
            index = end + 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
        elif char == "'" and quote is None:
            quote = "'"
        out.append(char)
        index += 1
    if quote:
        raise ValueError("unterminated quote")
    return "".join(out), bodies, originals


def simple_commands(line: str) -> list[list[str]] | None:
    """Simple commands of one substitution-free line; None if unparseable.

    Redirection targets come back as their own one-word commands, so a token
    hidden in one is still seen and attributed to no installer.
    """
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>(){}")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    commands, current, target = [], [], False
    for token in tokens:
        if target:
            target = False
            commands.append([">", token])
        elif token in SEPARATORS:
            if current:
                commands.append(current)
            current = []
        elif set(token) <= set("<>"):
            target = True
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands


ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", re.S)
# Prefixes that run the rest of the line as the command. Their own options are
# skipped; one that takes a value (sudo -u root) leaves that value as the
# command name, so any installer token after it goes unattributed.
PREFIXES = {"sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice",
            "timeout", "stdbuf", "setsid", "xargs", "if", "then", "elif", "else", "while",
            "until", "do", "!"}
PYTHON = re.compile(r"python(?:\d+(?:\.\d+)*)?")
PIP = re.compile(r"pip3?(?:\.\d+)*")
DYNAMIC = re.compile(r"[$`]|__axiom_substitution_\d+__")
DYNAMIC_VERBS = {"install", "sync", "add", "run", "tool", "pip", "python", "download", "wheel"}
DYNAMIC_ANYWHERE = {"install", "--with", "--with-requirements", "--with-editable"}

PIP_FLAGS = {"--isolated", "--quiet", "--verbose", "--no-cache-dir", "--disable-pip-version-check",
             "--no-color", "--no-input", "--require-virtualenv", "--no-python-version-warning",
             "--debug"}
PIP_VALUES = {"--python", "--log", "--log-file", "--proxy", "--retries", "--timeout",
              "--exists-action", "--trusted-host", "--cert", "--client-cert", "--cache-dir",
              "--keyring-provider", "--use-feature", "--use-deprecated", "--resume-retries"}
PIP_INSTALLING = {"install", "download", "wheel"}
PIP_READ_ONLY = {"freeze", "list", "show", "check", "help", "hash", "inspect", "debug",
                 "--version", "-V", "--help", "-h"}

UV_FLAGS = {"--quiet", "--verbose", "-n", "--no-cache", "--offline", "--no-offline",
            "--native-tls", "--no-native-tls", "--no-progress", "--no-config",
            "--no-python-downloads", "--managed-python", "--no-managed-python", "--preview",
            "--no-preview", "--isolated", "--show-settings"}
UV_VALUES = {"--cache-dir", "--color", "--directory", "--project", "--config-file",
             "--python-preference", "--allow-insecure-host", "--preview-features"}
UV_INSTALLING = {"run", "sync", "add", "remove", "tool"}
UV_READ_ONLY = {"export", "tree", "help", "--version", "-V", "--help", "-h"}
UV_PIP_INSTALLING = {"install", "sync"}
UV_PIP_READ_ONLY = {"freeze", "list", "show", "check", "tree"}


def _subcommand(rest: list[str], flags: set[str], values: set[str],
                read_only: set[str]) -> tuple[int | None, str]:
    """Index of the first non-option word, skipping only known options.

    An unknown option might take the next word as its value, so it makes the
    subcommand unknowable and the command unclassifiable.
    """
    index = 0
    while index < len(rest):
        word = rest[index]
        if word in read_only or not word.startswith("-"):
            return index, ""
        if word in values:
            index += 2
        elif word in flags or re.fullmatch(r"-[qv]+", word) or word.split("=", 1)[0] in values:
            index += 1
        else:
            return None, f"unknown option {word}"
    return None, "no subcommand"


def pip_command(rest: list[str]) -> tuple[str, str]:
    index, reason = _subcommand(rest, PIP_FLAGS, PIP_VALUES, PIP_READ_ONLY)
    if index is None:
        return "unclassified", f"pip: {reason}"
    if rest[index] in PIP_INSTALLING:
        return "install", ""
    if rest[index] in PIP_READ_ONLY:
        return "read-only", ""
    return "unclassified", f"pip subcommand {rest[index]}"


def uv_command(rest: list[str]) -> tuple[str, str]:
    index, reason = _subcommand(rest, UV_FLAGS, UV_VALUES, UV_READ_ONLY)
    if index is None:
        return "unclassified", f"uv: {reason}"
    command, after = rest[index], rest[index + 1:]
    if command in UV_INSTALLING:
        return "install", ""
    if command in UV_READ_ONLY:
        return "read-only", ""
    if command == "venv":
        return ("install", "") if "--seed" in after else ("read-only", "")
    if command == "pip":
        sub, reason = _subcommand(after, UV_FLAGS, UV_VALUES, set())
        if sub is None:
            return "unclassified", f"uv pip: {reason}"
        if after[sub] in UV_PIP_INSTALLING:
            return "install", ""
        if after[sub] in UV_PIP_READ_ONLY:
            return "read-only", ""
        return "unclassified", f"uv pip subcommand {after[sub]}"
    if command == "python":
        sub = next((word for word in after if not word.startswith("-")), None)
        if sub == "install":
            return "install", ""
        if sub in ("find", "list", "dir"):
            return "read-only", ""
        return "unclassified", f"uv python subcommand {sub}"
    return "unclassified", f"uv subcommand {command}"


def python_command(rest: list[str]) -> tuple[str, str]:
    """Only ``-m pip``, ``-m uv`` and installer modules are installer commands."""
    index = 0
    while index < len(rest):
        option = re.fullmatch(r"-([bBdEhiIOPqRsSuvVx]*)([mcWX]?)(.*)", rest[index], re.S)
        if not rest[index].startswith("-") or rest[index] == "-" or not option:
            return "foreign", ""
        letter, value = option.group(2), option.group(3)
        if not letter and value:
            return "foreign", ""
        if letter == "c":
            return "foreign", ""
        if letter in "WX" and letter:
            index += 1 if value else 2
            continue
        if letter == "m":
            if not value and index + 1 >= len(rest):
                return "unclassified", "python -m without a module"
            module = value or rest[index + 1]
            after = rest[index + 1:] if value else rest[index + 2:]
            if PIP.fullmatch(module):
                return pip_command(after)
            if module == "uv":
                return uv_command(after)
            if module in ("ensurepip", "pipx", "easy_install"):
                return "install", ""
            if INSTALLER_TOKEN.match(module):
                return "unclassified", f"python -m {module}"
            return "foreign", ""
        index += 1
    return "foreign", ""


def classify(argv: list[str]) -> tuple[str, str]:
    """install, read-only, foreign (not an installer program) or unclassified."""
    index = 0
    while index < len(argv):
        name = argv[index].rsplit("/", 1)[-1]
        if ASSIGNMENT.fullmatch(argv[index]):
            index += 1
        elif name in PREFIXES:
            index += 1
            while index < len(argv) and argv[index].startswith("-") and argv[index] != "-":
                index += 1
        else:
            break
    if index == len(argv):
        return "foreign", ""
    word, rest = argv[index], argv[index + 1:]
    name = word.rsplit("/", 1)[-1]
    if PYTHON.fullmatch(name):
        return python_command(rest)
    if PIP.fullmatch(name):
        return pip_command(rest)
    if name == "uv":
        return uv_command(rest)
    if name in ("uvx", "pipx", "easy_install"):
        return "install", ""
    if name == "eval":
        return "unclassified", "eval"
    if DYNAMIC.search(word):
        verb = next((arg for arg in rest if not arg.startswith("-")), None)
        if verb in DYNAMIC_VERBS or DYNAMIC_ANYWHERE & set(rest):
            return "unclassified", f"variable-expanded command name {word}"
    return "foreign", ""


def _parse(text: str, found: list, problems: list) -> int:
    """Classify every command in text and its substitutions, recursively.

    Returns how many installer tokens the parsed words hold, so the caller can
    compare it with the raw count.
    """
    try:
        rewritten, bodies, originals = split_substitutions(text)
    except ValueError:
        commands = None
    else:
        commands = simple_commands(rewritten)
    if commands is None:
        tokens = len(INSTALLER_TOKEN.findall(text))
        if tokens:
            problems.append(f"cannot tokenise installer-shaped text: {text}")
        return tokens

    def restore(word: str) -> str:
        return PLACEHOLDER.sub(lambda match: originals[int(match.group(1))], word)

    counted = 0
    for argv in commands:
        tokens = sum(len(INSTALLER_TOKEN.findall(word)) for word in argv)
        counted += tokens
        kind, reason = classify(argv)
        command = tuple(restore(word) for word in argv)
        if kind == "install":
            found.append(command)
        elif kind == "unclassified":
            problems.append(f"unclassifiable installer syntax ({reason}): {shlex.join(command)}")
        elif kind == "foreign" and tokens:
            problems.append(f"installer token outside an installer command: {shlex.join(command)}")
    for body in bodies:
        counted += _parse(body, found, problems)
    return counted


def installers(run: str) -> tuple[list[tuple[str, ...]], list[str]]:
    """Parsed installers, and every line the guard cannot fully account for."""
    found, hidden = _installers(run)
    return list(found), list(hidden)


@functools.lru_cache(maxsize=None)
def _installers(run: str) -> tuple[tuple[tuple[str, ...], ...], tuple[str, ...]]:
    found, hidden = [], []
    for line in logical_lines(run):
        parsed, problems = [], []
        counted = _parse(line, parsed, problems)
        raw = len(INSTALLER_TOKEN.findall(line))
        if counted != raw:
            problems.append(f"{raw} installer tokens in the raw line, {counted} in parsed words")
        # Parsing is authoritative. The raw cross-check may add a finding,
        # but must never discard a recognized installer, even with zero hits.
        if len(INSTALLER.findall(line)) != len(parsed):
            problems.append("installer detector disagreement")
        found.extend(parsed)
        hidden.extend(f"{problem} (line: {line})" for problem in problems)
    return tuple(found), tuple(hidden)


def installs_into_a_directory(argv: tuple[str, ...]) -> bool:
    return any(token == option or token.startswith(option + "=")
               or (option == "-t" and token.startswith("-t") and len(token) > 2)
               for token in argv for option in DIRECTORY_OPTIONS)


def directory_installs(texts: dict[str, str]) -> tuple[list[tuple], list[str]]:
    """Every directory install across workflow texts, and every unaccounted line."""
    directory, hidden = [], []
    for name, text in texts.items():
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        for job_name, job in workflow.get("jobs", {}).items():
            for item in job.get("steps", []):
                found, problems = installers(item.get("run", ""))
                hidden += [f"{name}:{job_name}/{item.get('name')}: {problem}"
                           for problem in problems]
                directory += [(name, job_name, item.get("name"), argv) for argv in found
                              if installs_into_a_directory(argv)]
    return directory, hidden


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
HEAD_INTERPRETER_LOCKED_FREEZE = "$RUNNER_TEMP/axiom-interpreter-locked.freeze"
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
    'uv pip freeze --python "$reference/bin/python" --exclude-editable --exclude pip'
    f' > "{HEAD_INTERPRETER_LOCKED_FREEZE}"',
    'uv pip freeze --python "$python_bin" --exclude pip --exclude axiom-encode'
    f' > "{HEAD_INTERPRETER_FREEZE}"',
    f'test -s "{HEAD_LOCKED_FREEZE}"',
    f'diff -u "{HEAD_LOCKED_FREEZE}" "{HEAD_STAGED_FREEZE}"',
    f'diff -u "{HEAD_INTERPRETER_LOCKED_FREEZE}" "{HEAD_INTERPRETER_FREEZE}"',
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
    f' --no-install-project --no-build --python "{COMPOSE_PYTHON}"',
    'uv export --project "${AXIOM_DEPENDENCY_ROOT}/axiom-compose" --locked --no-dev'
    " --no-emit-project --format requirements.txt"
    ' --output-file "$RUNNER_TEMP/axiom-compose-requirements.txt"',
    f'uv pip install --python "{COMPOSE_PYTHON}" --target "{COMPOSE_SITE_PACKAGES}"'
    " --require-hashes --no-deps --no-build"
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

def _uv_install(*args: str) -> tuple[str, ...]:
    return ("uv", "pip", "install", *args)


_TARGET = ("--python", "$python_bin", "--target", "$site_packages")
_ENCODER_SYNC = ("UV_PROJECT_ENVIRONMENT=$reference", "uv", "sync", "--project", "$encoder",
                 "--locked", "--no-dev", "--python", "$python_bin")
_ENCODER_TREE = [
    _uv_install(*_TARGET, "--require-hashes", "--no-deps", "-r", "$locked"),
    _uv_install(*_TARGET, "--no-deps", "$oracles"),
    _uv_install(*_TARGET, "--no-deps", "$encoder"),
]

# Every installer command in validate-rulespec.yml, by job and step, exactly.
# Shell quoting is removed, so `"--target=$x"` and `--target "$x"` both appear
# here as parsed arguments; any other installer anywhere fails the test.
INSTALLERS = {
    ("rollback-proof", "Install the rollback ledger parser"): [
        ("python", "-I", "-m", "pip", "--isolated", "install",
         "--disable-pip-version-check", "--only-binary=:all:", "pyyaml==6.0.3"),
    ],
    ("shards", "Install the ProgramSpec shape-check parser"): [
        ("python", "-I", "-m", "pip", "--isolated", "install",
         "--disable-pip-version-check", "pyyaml==6.0.3"),
    ],
    ("validate", "Install the rollback ledger parser"): [
        ("python", "-I", "-m", "pip", "--isolated", "install",
         "--disable-pip-version-check", "--only-binary=:all:", "pyyaml==6.0.3"),
    ],
    ("validate", HEAD): [
        _ENCODER_SYNC,
        *_ENCODER_TREE,
        _uv_install("--python", "$python_bin", "--require-hashes", "--no-deps", "-r", "$locked"),
        _uv_install("--python", "$python_bin", "--no-deps", "$oracles"),
        _uv_install("--python", "$python_bin", "--no-deps", "$encoder"),
        _uv_install("--python", "$python_bin", "--require-hashes",
                    "--constraints", "$tests_locked", "$pytest_pin"),
    ],
    ("validate", BASE): [_ENCODER_SYNC, *_ENCODER_TREE],
    ("validate", COMPOSE): [
        ("uv", "python", "install", "3.14"),
        ("UV_PROJECT_ENVIRONMENT=$compose_reference", "uv", "sync",
         "--project", "${AXIOM_DEPENDENCY_ROOT}/axiom-compose", "--locked", "--no-dev",
         "--no-install-project", "--no-build", "--python", COMPOSE_PYTHON),
        _uv_install("--python", COMPOSE_PYTHON, "--target", COMPOSE_SITE_PACKAGES,
                    "--require-hashes", "--no-deps", "--no-build",
                    "--requirement", "$RUNNER_TEMP/axiom-compose-requirements.txt"),
    ],
    # After the last protected-runtime consumer, the classifier reinstalls the
    # same authenticated encoder commit, whose dependencies the locked set
    # already satisfies.
    ("validate", CLASSIFIER): [
        ("python", "-I", "-m", "pip", "--isolated", "install",
         "$RUNNER_TEMP/axiom-encode-oracle-coverage-install"),
        ("python", "-I", "-m", "pip", "--isolated", "install", "--force-reinstall",
         "--no-deps", "$oracles_spec"),
    ],
}


def installer_violations(text: str | dict) -> list[str]:
    """Every way validate-rulespec.yml's installers differ from INSTALLERS."""
    workflow = text if isinstance(text, dict) else yaml.load(text, Loader=yaml.BaseLoader)
    violations = []
    seen = {}
    for job_name, job in workflow.get("jobs", {}).items():
        steps = job.get("steps", [])
        for item in steps:
            found, hidden = installers(item.get("run", ""))
            key = (job_name, item.get("name"))
            violations += [f"{key}: installer detector disagreement: {line}" for line in hidden]
            if found:
                seen[key] = seen.get(key, []) + found
        if job_name == "validate":
            names = [item.get("name") for item in steps]
            consumers = [index for index, item in enumerate(steps)
                         if any(runtime in item.get("run", "") for runtime in PROTECTED_RUNTIMES)]
            if not consumers or names[max(consumers)] != "Require money proof atoms":
                violations.append("the last protected-runtime consumer moved")
            elif CLASSIFIER in names and names.index(CLASSIFIER) < max(consumers):
                violations.append("the classifier's pip installs precede a protected consumer")
    for key in sorted(set(seen) | set(INSTALLERS), key=str):
        if seen.get(key, []) != INSTALLERS.get(key, []):
            violations.append(f"{key}: {seen.get(key, [])} != {INSTALLERS.get(key, [])}")
    return violations


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
    excluded = {argv[i + 1] for i, arg in enumerate(argv) if arg == "--exclude"}
    for line in os.environ[key].splitlines(keepends=True):
        if line.split("==")[0].split(" @ ")[0] not in excluded:
            sys.stdout.write(line)
else:
    sys.exit(f"unexpected uv invocation: {argv}")
'''

HASH = "--hash=sha256:" + "0" * 64
# The real locks pin pip (sqlite-utils depends on it); the toolcache
# interpreter keeps its own bundled pip unless that pin replaces it.
LOCKED_FREEZE = f"claude-agent-sdk==0.1.47\n{LOCKED_GIT_LINE}\npip==25.3\nrequests==2.32.5\n"
TOOLCACHE_FREEZE = LOCKED_FREEZE.replace("pip==25.3", "pip==26.2.1")
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
            staged_freeze: str = LOCKED_FREEZE, interpreter_freeze: str = TOOLCACHE_FREEZE,
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
    @staticmethod
    def expected_directory_installs() -> list[tuple]:
        return [(WORKFLOW.name, job, name, argv)
                for (job, name), commands in INSTALLERS.items()
                for argv in commands if installs_into_a_directory(argv)]

    def test_every_directory_install_in_any_workflow_is_a_locked_uv_install(self):
        directory, hidden = directory_installs(workflow_texts())
        self.assertEqual(hidden, [])
        expected = self.expected_directory_installs()
        # Non-vacuity: 3 head, 3 protected-base and 1 composer staging install.
        self.assertEqual(len(expected), 7)
        self.assertEqual(sorted(directory, key=str), sorted(expected, key=str))
        for *_where, argv in directory:
            self.assertEqual(argv[:3], ("uv", "pip", "install"), argv)
            self.assertIn("--no-deps", argv)
            requirement_files = [argv[i + 1] for i, token in enumerate(argv)
                                 if token in ("-r", "--requirement")]
            self.assertEqual("--require-hashes" in argv, bool(requirement_files), argv)

    def test_installers_are_exactly_the_locked_allowlist(self):
        self.assertEqual(installer_violations(WORKFLOW.read_text(encoding="utf-8")), [])

    @staticmethod
    def rollback_parser_workflow() -> dict:
        """Exercise main's parser installs even against the pre-rollback workflow."""
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for job in ("rollback-proof", "validate"):
            steps = workflow["jobs"].setdefault(job, {}).setdefault("steps", [])
            if not any(item.get("name") == "Install the rollback ledger parser" for item in steps):
                steps.insert(0, {
                    "name": "Install the rollback ledger parser",
                    "run": "python -I -m pip --isolated install --disable-pip-version-check "
                           "--only-binary=:all: pyyaml==6.0.3",
                })
        return workflow

    def test_rollback_parser_installs_are_allowed_in_both_jobs(self):
        self.assertEqual(installer_violations(yaml.dump(self.rollback_parser_workflow())), [])

    def test_rollback_parser_guard_rejects_argument_drift(self):
        text = yaml.dump(self.rollback_parser_workflow())
        self.assertEqual(installer_violations(text), [])
        mutations = {
            "python isolation": ("python -I ", "python "),
            "pip isolation": ("--isolated ", ""),
            "version check": ("--disable-pip-version-check ", ""),
            "wheels only": ("--only-binary=:all: ", ""),
            "package pin": ("pyyaml==6.0.3", "pyyaml"),
            "extra package": ("pyyaml==6.0.3", "pyyaml==6.0.3 hostile-pkg"),
        }
        for job in ("rollback-proof", "validate"):
            for label, (old, new) in mutations.items():
                with self.subTest(job=job, mutation=label):
                    workflow = yaml.load(text, Loader=yaml.BaseLoader)
                    parser = next(item for item in workflow["jobs"][job]["steps"]
                                  if item.get("name") == "Install the rollback ledger parser")
                    self.assertIn(old, parser["run"])
                    parser["run"] = parser["run"].replace(old, new)
                    self.assertNotEqual(installer_violations(yaml.dump(workflow)), [])
            for duplicate in (False, True):
                with self.subTest(job=job, duplicate=duplicate):
                    workflow = yaml.load(text, Loader=yaml.BaseLoader)
                    steps = workflow["jobs"][job]["steps"]
                    parser = next(item for item in steps
                                  if item.get("name") == "Install the rollback ledger parser")
                    if duplicate:
                        steps.append(parser)
                    else:
                        steps.remove(parser)
                    self.assertNotEqual(installer_violations(yaml.dump(workflow)), [])

    def test_installer_guard_rejects_unlocked_variants(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        head_cleanup = '          rm -rf "$reference" "$uv_cache"\n'
        self.assertEqual(text.count(head_cleanup), 2)

        def after_head_cleanup(line: str) -> str:
            return text.replace(head_cleanup, head_cleanup + "          " + line + "\n", 1)

        new_step = (
            "      - name: Late hostile install\n"
            "        run: uv pip install --python \"$(command -v python)\" hostile-pkg\n\n"
            "      - name: Require money proof atoms\n"
        )
        mutations = {
            # The independent review's bypass: a quoted --target= and an extra requirement.
            "quoted target, extra requirement": after_head_cleanup(
                'uv pip install --python "$python_bin" "--target=$site_packages" hostile-pkg --no-deps "$encoder"'),
            "short -t": after_head_cleanup('uv pip install --python "$python_bin" -t "$site_packages" --no-deps hostile-pkg'),
            "glued -t": after_head_cleanup('uv pip install --python "$python_bin" "-t$site_packages" --no-deps hostile-pkg'),
            "extra requirement file": after_head_cleanup(
                'uv pip install --python "$python_bin" --target "$site_packages" --require-hashes --no-deps -r "$locked" -r extra.txt'),
            "unlocked interpreter install": after_head_cleanup('uv pip install --python "$python_bin" --no-deps hostile-pkg'),
            "pip into the interpreter": after_head_cleanup("python -I -m pip --isolated install hostile-pkg"),
            "pip3": after_head_cleanup("pip3 install hostile-pkg"),
            "sudo pip": after_head_cleanup("sudo pip install hostile-pkg"),
            "hidden in a substitution": after_head_cleanup('noise="$(uv pip install --python "$python_bin" hostile-pkg)"'),
            "chained": after_head_cleanup('true && uv pip install --python "$python_bin" hostile-pkg'),
            "uv run --with": after_head_cleanup("uv run --with hostile-pkg python -c pass"),
            "uvx": after_head_cleanup("uvx hostile-pkg"),
            "prefix install": after_head_cleanup('uv pip install --python "$python_bin" --prefix /opt/x --no-deps "$encoder"'),
            "extras on the project": text.replace('--no-deps "$encoder"\n', '--no-deps "$encoder[api]"\n', 1),
            "dropped --require-hashes": text.replace(
                '--require-hashes --no-deps -r "$locked"', '--no-deps -r "$locked"', 1),
            "dropped composer --no-build": text.replace("            --no-build \\\n", "", 1),
            "new step before the last consumer": text.replace(
                "      - name: Require money proof atoms\n", new_step, 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(mutation=label):
                self.assertNotEqual(mutated, text)
                self.assertNotEqual(installer_violations(mutated), [])

    def test_installer_disagreements_preserve_commands_and_report_the_line(self):
        for line, parsed in (
            ('pip --isolated install --target "$site_packages" hostile-pkg',
             [("pip", "--isolated", "install", "--target", "$site_packages", "hostile-pkg")]),
            ('uv pip install one; pip --isolated install hostile-pkg',
             [("uv", "pip", "install", "one"), ("pip", "--isolated", "install", "hostile-pkg")]),
            ('uv --no-cache run --with hostile-pkg python -c pass',
             [("uv", "--no-cache", "run", "--with", "hostile-pkg", "python", "-c", "pass")]),
            ('uv pip install "unterminated', []),
            ("bash -c 'pip install hostile-pkg'", []),
            ('p"i"p install hostile-pkg', [("pip", "install", "hostile-pkg")]),
            ('eval "$installer"', []),
            ('"$PIP" install hostile-pkg', []),
        ):
            with self.subTest(command=line):
                found, hidden = installers(line)
                self.assertEqual(found, parsed)
                self.assertTrue(hidden, line)
                self.assertTrue(all(problem.endswith(f"(line: {line})") for problem in hidden))

    def test_substitutions_are_parsed_as_commands(self):
        for line, parsed in (
            ('noise="$(uv pip install hostile-pkg)"', [("uv", "pip", "install", "hostile-pkg")]),
            ('pip install "$(pip install hostile-pkg)"',
             [("pip", "install", "$(pip install hostile-pkg)"), ("pip", "install", "hostile-pkg")]),
            ("x=`uv pip install hostile-pkg`", [("uv", "pip", "install", "hostile-pkg")]),
            ('diff <(uv pip install a) >(uv pip install b)',
             [("uv", "pip", "install", "a"), ("uv", "pip", "install", "b")]),
            ('echo "$(echo "$(uv pip install hostile-pkg)")"',
             [("uv", "pip", "install", "hostile-pkg")]),
            ("echo '$(uv pip install quoted)'", None),
        ):
            with self.subTest(command=line):
                found, hidden = installers(line)
                if parsed is None:
                    # Single quotes keep it literal, but the token still counts.
                    self.assertEqual(found, [])
                    self.assertTrue(hidden)
                else:
                    self.assertEqual(found, parsed)
                    self.assertEqual(hidden, [])

    def test_review_round_three_bypasses_fail_both_guard_tests(self):
        """Each reviewer command, after the head cleanup, fails both guards."""
        text = WORKFLOW.read_text(encoding="utf-8")
        cleanup = '          rm -rf "$reference" "$uv_cache"\n'
        self.assertEqual(text.count(cleanup), 2)
        expected = sorted(self.expected_directory_installs(), key=str)
        for command, directory_install in (
            ('noise="$(pip --isolated install --target "$site_packages" hostile-pkg)"', True),
            ("uv --no-cache run --with hostile-pkg --no-project python -c pass", False),
        ):
            with self.subTest(command=command):
                mutated = text.replace(cleanup, cleanup + "          " + command + "\n", 1)
                violations = installer_violations(mutated)
                self.assertTrue(any(HEAD in violation and "hostile-pkg" in violation
                                    for violation in violations), violations)
                directory, hidden = directory_installs({**workflow_texts(),
                                                        WORKFLOW.name: mutated})
                self.assertTrue(hidden or sorted(directory, key=str) != expected)
                if directory_install:
                    self.assertIn(
                        (WORKFLOW.name, "validate", HEAD,
                         ("pip", "--isolated", "install", "--target", "$site_packages",
                          "hostile-pkg")),
                        directory)
                else:
                    self.assertTrue(any("disagreement" in problem for problem in hidden))

    # Installer forms that put option words before the subcommand, hide the
    # program name, or run it through another command.
    INSTALLER_FORMS = (
        'pip --isolated install --target "$site_packages" hostile-pkg',
        "pip3 -q install hostile-pkg",
        "pip --log /tmp/pip.log install hostile-pkg",
        "pip3.13 --no-input install hostile-pkg",
        "python -m pip --isolated install hostile-pkg",
        "python -I -m pip --no-cache-dir install hostile-pkg",
        "python3 -Im pip install hostile-pkg",
        "python -mpip install hostile-pkg",
        "python -X utf8 -m pip install hostile-pkg",
        "python -m pip._internal install hostile-pkg",
        "python -m ensurepip",
        "python -m uv pip install hostile-pkg",
        "uv --no-cache run --with hostile-pkg --no-project python -c pass",
        "uv --cache-dir /tmp/c run --with-requirements hostile.txt python -c pass",
        'uv -q pip install --target "$site_packages" hostile-pkg',
        "uv --directory /tmp pip install hostile-pkg",
        "uv --color never pip --quiet install hostile-pkg",
        "uv --no-config tool install hostile-pkg",
        "uv --offline tool run hostile-pkg",
        "uv --unknown-flag pip install hostile-pkg",
        "uv --project=/tmp sync",
        "uv venv --seed /tmp/hostile-venv",
        "uvx --with hostile-pkg ruff",
        "easy_install hostile-pkg",
        "pipx install hostile-pkg",
        '"$VENV/bin/pip" --isolated install hostile-pkg',
        '"$PIP" install hostile-pkg',
        "$UV --no-cache run --with hostile-pkg python",
        '"$python_bin" -m pip install hostile-pkg',
        "${{ inputs.installer }} install hostile-pkg",
        'eval "pip install hostile-pkg"',
        'p"i"p install hostile-pkg',
        "bash -c 'pip --isolated install hostile-pkg'",
        "sudo -u root pip install hostile-pkg",
        "env -i pip install hostile-pkg",
        "if pip install hostile-pkg; then :; fi",
    )
    # Ways to embed one command in a line; {} is the command.
    EMBEDDINGS = (
        "{}",
        'noise="$({})"',
        "noise=$({})",
        'noise="`{}`"',
        ': "$(true; {})"',
        "cat <({})",
        "tee >({}) </dev/null",
        'echo "$(echo "$({})")"',
        'x="${{y:-$({})}}"',
    )

    def test_installer_guard_mutation_table(self):
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        head = next(item for item in workflow["jobs"]["validate"]["steps"]
                    if item.get("name") == HEAD)
        original = head["run"]
        cleanup = 'rm -rf "$reference" "$uv_cache"\n'
        self.assertEqual(original.count(cleanup), 1)
        self.assertEqual(installer_violations(workflow), [])
        survivors = []
        for form in self.INSTALLER_FORMS:
            for embedding in self.EMBEDDINGS:
                line = embedding.format(form)
                head["run"] = original.replace(cleanup, cleanup + line + "\n")
                if not any(HEAD in violation for violation in installer_violations(workflow)):
                    survivors.append(line)
        head["run"] = original
        self.assertEqual(survivors, [])
        self.assertEqual(len(self.INSTALLER_FORMS) * len(self.EMBEDDINGS), 324)

        # Non-vacuity the other way: read-only uv and pip, and commands that
        # merely run an interpreter, stay accepted in the same embeddings.
        for form in (
            'uv --no-cache pip freeze --python "$python_bin"',
            'uv --quiet export --project "$encoder" --locked --format requirements-txt',
            "uv pip --quiet list",
            '"$python_bin" -I -c pass',
            'sudo "$(command -v python)" -I /opt/check.py add base "$encoder" repository',
        ):
            for embedding in self.EMBEDDINGS:
                line = embedding.format(form)
                with self.subTest(accepted=line):
                    head["run"] = original.replace(cleanup, cleanup + line + "\n")
                    self.assertEqual(installer_violations(workflow), [])
        head["run"] = original

    def test_installer_guard_reports_option_path_and_continuation_mutations(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        cleanup = '          rm -rf "$reference" "$uv_cache"\n'
        self.assertEqual(text.count(cleanup), 2)
        commands = (
            'pip --isolated install --target "$site_packages" hostile-pkg',
            'pip -q install --target "$site_packages" hostile-pkg',
            'python -m pip --no-cache-dir install --target "$site_packages" hostile-pkg',
            '/usr/bin/pip install --target "$site_packages" hostile-pkg',
            '"$VENV/bin/pip" install --target "$site_packages" hostile-pkg',
            'uv --no-cache pip install --target "$site_packages" hostile-pkg',
            'uv pip --no-cache-dir install --target "$site_packages" hostile-pkg',
            'uv --no-cache pip --quiet install --target "$site_packages" hostile-pkg',
            'pip --isolated install \\\n                --target "$site_packages" hostile-pkg',
        )
        for command in commands:
            with self.subTest(command=command):
                mutated = text.replace(cleanup, cleanup + "          " + command + "\n", 1)
                violations = installer_violations(mutated)
                self.assertTrue(any(HEAD in violation and "hostile-pkg" in violation
                                    for violation in violations), violations)

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
            ["pip", "freeze", "--python", reference + "/bin/python", "--exclude-editable",
             "--exclude", "pip"],
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
             "--no-build", "--python", python],
            ["export", "--project", project, "--locked", "--no-dev", "--no-emit-project",
             "--format", "requirements.txt", "--output-file", requirements],
            ["pip", "install", "--python", python, "--target", site_packages,
             "--require-hashes", "--no-deps", "--no-build", "--requirement", requirements],
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
        for name in (HEAD, BASE):
            with self.subTest(step=name, missing="pip"):
                run = execute(name, staged_freeze=LOCKED_FREEZE.replace("pip==25.3\n", ""))
                self.assertNotEqual(run.result.returncode, 0)
                self.assertIn("-pip==25.3", run.result.stdout)
        for name in (HEAD, BASE, COMPOSE):
            with self.subTest(step=name, extra="unlocked distribution"):
                run = execute(name, staged_freeze=LOCKED_FREEZE + "sitecustomize-hook==1.0\n")
                self.assertNotEqual(run.result.returncode, 0)
                self.assertIn("+sitecustomize-hook==1.0", run.result.stdout)

    def test_head_staging_fails_when_the_interpreter_drifts_from_the_lock(self):
        for label, freeze in (
            ("floated", TOOLCACHE_FREEZE.replace("0.1.47", "0.2.159")),
            ("preinstalled", TOOLCACHE_FREEZE + "setuptools==80.9.0\n"),
            ("missing", TOOLCACHE_FREEZE.replace("requests==2.32.5\n", "")),
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
