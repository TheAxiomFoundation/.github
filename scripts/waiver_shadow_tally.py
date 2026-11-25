#!/usr/bin/env python3
"""Tally the incremental waiver shadow over a caller's pull-request runs.

The "waiver shadow" job of validate-rulespec.yml prints one line

    WAIVER_SHADOW_TALLY {"matrix": 52, "records": 52, "verdicts": {...}, ...}

This script lists the caller workflow's pull_request runs in a date range,
reads the conclusion of each run's `validate / waiver shadow` job and that
line from its log, and prints per-run rows and totals, so that "zero
incremental_missed records over N complete runs" is a number:

    python scripts/waiver_shadow_tally.py --repo TheAxiomFoundation/rulespec-us \
        --workflow repository-checks.yml --since 2026-12-01 --until 2026-12-15

It only reads (gh api). A run counts as complete when the collector ran,
every partition has a bound record, and nothing was missing or incomplete.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from typing import Callable, Iterable

JOB_NAME = "validate / waiver shadow"
TALLY = re.compile(r"WAIVER_SHADOW_TALLY (\{.*\})\s*$")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def parse_tally(log_text: str) -> dict | None:
    """Return the last tally object in a job log, or None."""

    found = None
    for line in log_text.splitlines():
        match = TALLY.search(line)
        if not match:
            continue
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            found = value
    return found


def classify(conclusion: str | None, tally: dict | None) -> str:
    """One state per run: complete, off, unsafe, missing, incomplete, no-tally, not-run."""

    if conclusion is None:
        return "not-run"
    if tally is None:
        return "no-tally"
    if tally.get("unsafe"):
        return "unsafe"
    if tally.get("missing"):
        return "missing"
    if tally.get("incomplete"):
        return "incomplete"
    if tally.get("off"):
        return "off"
    if tally.get("records") == tally.get("matrix") and tally.get("matrix"):
        return "complete"
    return "incomplete"


def summarize(rows: Iterable[dict]) -> dict:
    rows = list(rows)
    states = Counter(row["state"] for row in rows)
    verdicts: Counter = Counter()
    for row in rows:
        tally = row.get("tally") or {}
        if row["state"] in ("complete", "unsafe"):
            verdicts.update({str(k): int(v) for k, v in (tally.get("verdicts") or {}).items()})
    return {
        "runs": len(rows),
        "states": dict(sorted(states.items())),
        "complete_runs": states.get("complete", 0),
        "records_by_verdict": dict(sorted(verdicts.items())),
        "incremental_missed": verdicts.get("incremental_missed", 0),
        "inconclusive": verdicts.get("inconclusive", 0),
        "conclusions": dict(sorted(Counter(str(row.get("conclusion")) for row in rows).items())),
    }


def gh_json(args: list[str]) -> object:
    output = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout
    return json.loads(output)


def gh_text(path: str) -> str:
    return subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout


def collect(
    repo: str,
    workflow: str,
    since: str,
    until: str,
    *,
    fetch_json: Callable[[list[str]], object] = gh_json,
    fetch_text: Callable[[str], str] = gh_text,
) -> list[dict]:
    rows = []
    page = 1
    while True:
        runs = fetch_json([
            f"repos/{repo}/actions/workflows/{workflow}/runs"
            f"?event=pull_request&created={since}..{until}&per_page=100&page={page}"
        ])
        batch = runs.get("workflow_runs", []) if isinstance(runs, dict) else []
        for run in batch:
            jobs = fetch_json([f"repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100&filter=latest"])
            job = next(
                (item for item in (jobs.get("jobs", []) if isinstance(jobs, dict) else []) if item.get("name") == JOB_NAME),
                None,
            )
            conclusion = job.get("conclusion") if job else None
            tally = None
            if job and job.get("status") == "completed" and conclusion not in (None, "skipped", "cancelled"):
                try:
                    tally = parse_tally(fetch_text(f"repos/{repo}/actions/jobs/{job['id']}/logs"))
                except subprocess.CalledProcessError:
                    tally = None
            if job and conclusion in ("skipped", "cancelled"):
                conclusion_for_state = None
            else:
                conclusion_for_state = conclusion
            rows.append({
                "run_id": run["id"],
                "pr": [item.get("number") for item in run.get("pull_requests") or []],
                "head_sha": run.get("head_sha"),
                "created_at": run.get("created_at"),
                "conclusion": conclusion,
                "tally": tally,
                "state": classify(conclusion_for_state, tally),
            })
        if len(batch) < 100:
            break
        page += 1
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--workflow", default="repository-checks.yml")
    parser.add_argument("--since", required=True, help="YYYY-MM-DD (UTC, inclusive)")
    parser.add_argument("--until", required=True, help="YYYY-MM-DD (UTC, inclusive)")
    parser.add_argument("--json", action="store_true", help="print rows and totals as JSON")
    args = parser.parse_args(argv)
    if not DATE.fullmatch(args.since) or not DATE.fullmatch(args.until):
        parser.error("--since and --until must be YYYY-MM-DD")
    rows = collect(args.repo, args.workflow, args.since, args.until)
    totals = summarize(rows)
    if args.json:
        print(json.dumps({"rows": rows, "totals": totals}, indent=1, sort_keys=True))
    else:
        for row in rows:
            tally = row["tally"] or {}
            print(f"{row['created_at']} run {row['run_id']} PR {row['pr']} {row['state']:<10} "
                  f"{row['conclusion']} verdicts={tally.get('verdicts', {})}")
        print(json.dumps(totals, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
