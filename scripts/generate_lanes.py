#!/usr/bin/env python3
"""Render the live lane board using main's curated LANES.md and GitHub data."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ORG = "TheAxiomFoundation"
LANES = ("us", "uk", "nz", "tz", "de", "dk", "be", "ca", "ng", "gh", "ug", "zm", "et", "rw")
# TODO: Auto-discover rulespec-* repositories once the registry no longer needs an explicit scope.
SOURCE = Path(__file__).resolve().parents[1] / "LANES.md"
LIVE_BOARD_URL = f"https://github.com/{ORG}/.github/blob/lanes-registry/LANES.md"
CURATED_START = "<!-- curated:start -->"
CURATED_END = "<!-- curated:end -->"
NONE = "—"


def gh_api(endpoint: str, fields: dict[str, str] | None = None) -> object | None:
    """Return decoded JSON from gh api, or None for any unavailable resource."""
    command = ["gh", "api", endpoint]
    if fields:
        command.extend(("--method", "GET"))
    for key, value in (fields or {}).items():
        command.extend(("-f", f"{key}={value}"))
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def repository_file(repo: str, path: str) -> str | None:
    payload = gh_api(f"repos/{ORG}/{repo}/contents/{path}?ref=main")
    if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
        return None
    try:
        return base64.b64decode(payload["content"], validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def toml_value(source: str, key: str) -> str | None:
    # The wanted values are strings; this small reader keeps the script compatible
    # with every Python 3 version provided by GitHub Actions.
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*(['\"])(.*?)\1\s*(?:#.*)?$", source)
    return match.group(2).strip() if match else None


def workflow_encoder_ref(repo: str) -> str | None:
    for name in ("repository-checks.yml", "repository-checks.yaml"):
        source = repository_file(repo, f".github/workflows/{name}")
        if source is None:
            continue
        matches = re.findall(r"(?m)^\s*axiom-encode-ref\s*:\s*([^#\s]+)", source)
        if matches:
            return matches[-1].strip("'\"")
    return None


def latest_commit(repo: str) -> tuple[str | None, str]:
    payload = gh_api(f"repos/{ORG}/{repo}/commits?sha=main&per_page=1")
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        return None, NONE
    commit = payload[0].get("commit", {})
    if not isinstance(commit, dict):
        return None, NONE
    author = commit.get("author", {})
    date_value = author.get("date") if isinstance(author, dict) else None
    message = commit.get("message")
    if not isinstance(date_value, str) or not isinstance(message, str):
        return None, NONE
    subject = message.splitlines()[0].strip()
    return date_value, f"{date_value[:10]} — {subject}"


def open_pr_count(repo: str) -> str:
    query = f"repo:{ORG}/{repo} is:pr is:open"
    payload = gh_api("search/issues", {"q": query, "per_page": "1"})
    count = payload.get("total_count") if isinstance(payload, dict) else None
    return str(count) if isinstance(count, int) else NONE


def checks_conclusion(repo: str) -> str:
    payload = gh_api(f"repos/{ORG}/{repo}/actions/runs?branch=main&per_page=100")
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        return NONE
    for run in runs:
        if isinstance(run, dict) and run.get("name") == "Repository Checks":
            conclusion = run.get("conclusion")
            return str(conclusion) if conclusion else str(run.get("status") or NONE)
    return NONE


def lane_data(lane: str) -> dict[str, str | None]:
    repo = f"rulespec-{lane}"
    date_value, commit = latest_commit(repo)
    toolchain = repository_file(repo, ".axiom/toolchain.toml")
    release = toml_value(toolchain, "axiom_corpus_release") if toolchain else None
    encoder = toml_value(toolchain, "axiom_encode_ref") if toolchain else None
    if not encoder:
        encoder = workflow_encoder_ref(repo)
    return {
        "lane": lane,
        "repo": repo,
        "date": date_value,
        "commit": commit,
        "prs": open_pr_count(repo),
        "release": release or NONE,
        "encoder": encoder or NONE,
        "checks": checks_conclusion(repo),
    }


def markdown_cell(value: object) -> str:
    return html.escape(str(value), quote=False).replace("|", "&#124;").replace("\n", " ")


def extract_curated(document: str) -> str:
    for marker in (CURATED_START, CURATED_END):
        if document.count(marker) != 1:
            raise ValueError(f"LANES.md must contain exactly one {marker}")
    start = document.find(CURATED_START)
    end = document.find(CURATED_END, start)
    if end < 0:
        raise ValueError(f"LANES.md has {CURATED_END} before {CURATED_START}")
    end += len(CURATED_END)
    return document[start:end]


def render_source(curated: str) -> str:
    """The stable, curated-only document kept on main."""
    return (
        "# Encoding lanes\n\n"
        f"Live board: [Encoding lane registry]({LIVE_BOARD_URL}) (updated every 6 hours).\n\n"
        + curated + "\n"
    )


def render(rows: list[dict[str, str | None]], curated: str, pending: bool = False) -> str:
    lines = [
        "# Encoding lanes",
        "",
        "<!-- generated by scripts/generate_lanes.py; edit the curated section on main by PR -->",
        "",
        "| Lane | Last main commit | Open PRs | Corpus release | Encoder ref | Repository Checks |",
        "| --- | --- | ---: | --- | --- | --- |",
    ]
    for row in rows:
        commit = "pending first scheduled run" if pending else row["commit"]
        values = (
            f"[{row['lane']}](https://github.com/{ORG}/{row['repo']})",
            commit,
            row["prs"],
            row["release"],
            row["encoder"],
            row["checks"],
        )
        lines.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
    return "\n".join(lines) + "\n\n" + curated + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true",
        help="validate main's curated-only LANES.md and rendering without network access or writes",
    )
    parser.add_argument("--output", type=Path, help="destination for the full board (required unless --check)")
    parser.add_argument(
        "--pending",
        action="store_true",
        help="render the no-network seed state (not intended for scheduled runs)",
    )
    args = parser.parse_args()
    if args.check and args.output is not None:
        parser.error("--check cannot be combined with --output")
    if not args.check and args.output is None:
        parser.error("--output is required to publish the full board separately from main's LANES.md")
    if args.output is not None and (
        args.output.resolve() == SOURCE.resolve()
        or (args.output.exists() and SOURCE.exists() and os.path.samefile(args.output, SOURCE))
    ):
        # samefile also catches hard links and other aliases that resolve() cannot see.
        parser.error("--output must not overwrite main's curated LANES.md")

    existing = SOURCE.read_text(encoding="utf-8")
    try:
        curated = extract_curated(existing)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    offline = args.pending or args.check
    rows = [lane_data(lane) for lane in LANES] if not offline else [
        {"lane": lane, "repo": f"rulespec-{lane}", "date": None, "commit": NONE,
         "prs": NONE, "release": NONE, "encoder": NONE, "checks": NONE}
        for lane in LANES
    ]
    rows.sort(key=lambda row: (row["date"] is None, "" if row["date"] is None else -dt.datetime.fromisoformat(str(row["date"]).replace("Z", "+00:00")).timestamp(), str(row["lane"])))
    generated = render(rows, curated, pending=offline)

    # This assertion is the round-trip invariant exercised by --check too: the
    # exact bytes between (and including) both fences must survive regeneration.
    if extract_curated(generated) != curated:
        print("curated section changed during regeneration", file=sys.stderr)
        return 2
    if args.check:
        if render_source(curated) != existing:
            print("LANES.md must contain only the live-board link and curated section", file=sys.stderr)
            return 1
        print("LANES.md is curated-only; curated section survived full-board rendering verbatim")
        return 0
    args.output.write_text(generated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
