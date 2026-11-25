"""Checks for scripts/waiver_shadow_tally.py (no network: fake gh fetchers)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import waiver_shadow_tally as tally  # noqa: E402


def line(**values) -> str:
    base = {
        "matrix": 52, "records": 52, "verdicts": {"agree": 52}, "unavailable": 0, "off": False,
        "unsafe": 0, "missing": 0, "incomplete": 0, "validate_result": "success",
    }
    base.update(values)
    return "2026-12-01T00:00:00.0Z WAIVER_SHADOW_TALLY " + json.dumps(base) + "\n"


def test_parse_takes_the_last_tally_line_and_ignores_noise() -> None:
    log = "noise\n" + line(records=1) + "WAIVER_SHADOW_TALLY {broken\n" + line(records=52)
    assert tally.parse_tally(log)["records"] == 52
    assert tally.parse_tally("no tally here\n") is None
    assert tally.parse_tally("WAIVER_SHADOW_TALLY [1, 2]\n") is None


def test_classify_orders_unsafe_before_everything() -> None:
    assert tally.classify(None, None) == "not-run"
    assert tally.classify("success", None) == "no-tally"
    assert tally.classify("failure", json.loads(line(unsafe=1, missing=1).split(" ", 2)[2])) == "unsafe"
    assert tally.classify("failure", json.loads(line(missing=1).split(" ", 2)[2])) == "missing"
    assert tally.classify("success", json.loads(line(incomplete=3).split(" ", 2)[2])) == "incomplete"
    assert tally.classify("success", json.loads(line(off=True, records=0, unavailable=52).split(" ", 2)[2])) == "off"
    assert tally.classify("success", json.loads(line().split(" ", 2)[2])) == "complete"
    assert tally.classify("success", json.loads(line(records=51).split(" ", 2)[2])) == "incomplete"


def fake(runs: list[dict], jobs: dict[int, list[dict]], logs: dict[int, str]):
    def fetch_json(args):
        path = args[0]
        if "/workflows/" in path:
            page = int(path.rsplit("page=", 1)[1])
            return {"workflow_runs": runs if page == 1 else []}
        run_id = int(path.split("/runs/", 1)[1].split("/", 1)[0])
        return {"jobs": jobs.get(run_id, [])}

    def fetch_text(path):
        return logs[int(path.split("/jobs/", 1)[1].split("/", 1)[0])]

    return fetch_json, fetch_text


def job(job_id: int, conclusion: str | None, status: str = "completed", name: str = tally.JOB_NAME) -> dict:
    return {"id": job_id, "name": name, "status": status, "conclusion": conclusion}


def test_collect_and_summarize_count_runs_and_verdicts() -> None:
    runs = [
        {"id": 1, "head_sha": "a", "created_at": "t1", "pull_requests": [{"number": 10}]},
        {"id": 2, "head_sha": "b", "created_at": "t2", "pull_requests": []},
        {"id": 3, "head_sha": "c", "created_at": "t3", "pull_requests": []},
        {"id": 4, "head_sha": "d", "created_at": "t4", "pull_requests": []},
        {"id": 5, "head_sha": "e", "created_at": "t5", "pull_requests": []},
    ]
    jobs = {
        1: [job(11, "success"), job(99, "success", name="validate / validate")],
        2: [job(12, "failure")],
        3: [job(13, "cancelled")],
        4: [],
        5: [job(15, "success")],
    }
    logs = {
        11: line(),
        12: line(verdicts={"agree": 51, "incremental_missed": 1}, unsafe=1),
        15: line(off=True, records=0, unavailable=52, verdicts={}),
    }
    fetch_json, fetch_text = fake(runs, jobs, logs)
    rows = tally.collect("o/r", "repository-checks.yml", "2026-12-01", "2026-12-02",
                         fetch_json=fetch_json, fetch_text=fetch_text)
    assert [row["state"] for row in rows] == ["complete", "unsafe", "not-run", "not-run", "off"]
    assert rows[0]["pr"] == [10]
    totals = tally.summarize(rows)
    assert totals["runs"] == 5
    assert totals["complete_runs"] == 1
    assert totals["incremental_missed"] == 1
    assert totals["records_by_verdict"] == {"agree": 103, "incremental_missed": 1}
    assert totals["states"] == {"complete": 1, "not-run": 2, "off": 1, "unsafe": 1}


def test_main_refuses_bad_dates() -> None:
    try:
        tally.main(["--repo", "o/r", "--since", "yesterday", "--until", "2026-12-01"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("bad date accepted")


def main() -> None:
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print(f"{name}: ok")


if __name__ == "__main__":
    main()
