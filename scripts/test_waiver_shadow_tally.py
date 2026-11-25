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
        "unsafe": 0, "missing": 0, "incomplete": 0, "validate_result": "success", "untrusted": False,
    }
    base.update(values)
    return "2026-12-01T00:00:00.0Z WAIVER_SHADOW_TALLY " + json.dumps(base) + "\n"


def test_parse_takes_the_first_exact_tally_line() -> None:
    log = "noise\n" + line(records=1) + line(records=52)
    assert tally.parse_tally(log)["records"] == 1
    # A tally text inside another line is not a tally line.
    assert tally.parse_tally("2026Z - us: missed WAIVER_SHADOW_TALLY {}\n" + line(records=7))["records"] == 7
    assert tally.parse_tally("no tally here\n") is None
    assert tally.parse_tally("WAIVER_SHADOW_TALLY [1, 2]\n") is None
    # A broken first tally line is not replaced by a later one.
    assert tally.parse_tally("WAIVER_SHADOW_TALLY {broken\n" + line()) is None


def test_classify_orders_unsafe_before_everything() -> None:
    assert tally.classify(None, None) == "not-run"
    assert tally.classify("success", None) == "no-tally"
    assert tally.classify("failure", json.loads(line(unsafe=1, missing=1).split(" ", 2)[2])) == "unsafe"
    assert tally.classify("failure", json.loads(line(missing=1).split(" ", 2)[2])) == "missing"
    assert tally.classify("success", json.loads(line(incomplete=3).split(" ", 2)[2])) == "incomplete"
    assert tally.classify("success", json.loads(line(off=True, records=0, unavailable=52).split(" ", 2)[2])) == "off"
    assert tally.classify("success", json.loads(line().split(" ", 2)[2])) == "complete"
    assert tally.classify("success", json.loads(line(records=51).split(" ", 2)[2])) == "incomplete"
    # Evidence needs the collector's success and a trusted run.
    assert tally.classify("failure", json.loads(line().split(" ", 2)[2])) == "incomplete"
    assert tally.classify("success", json.loads(line(untrusted=True).split(" ", 2)[2])) == "untrusted"
    assert tally.classify("success", {k: v for k, v in json.loads(line().split(" ", 2)[2]).items() if k != "untrusted"}) == "untrusted"


GOOD = "1" * 40
VALIDATOR = [{"path": "TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@" + GOOD, "sha": GOOD}]


def fake(runs: list[dict], jobs: dict[int, list[dict]], logs: dict[int, str], *, total: int | None = None,
         pr_files: dict[int, list[dict]] | None = None):
    pr_files = pr_files or {}
    def fetch_json(args):
        path = args[0]
        if "/workflows/" in path:
            page = int(path.rsplit("page=", 1)[1])
            day = path.split("created=", 1)[1].split("&", 1)[0]
            todays = [run for run in runs if run.get("day", "2026-12-01") == day]
            return {"workflow_runs": todays if page == 1 else [], "total_count": total if total is not None else len(todays)}
        if "/pulls/" in path:
            number = int(path.split("/pulls/", 1)[1].split("/", 1)[0])
            page = int(path.rsplit("page=", 1)[1])
            return pr_files.get(number, []) if page == 1 else []
        run_id = int(path.split("/runs/", 1)[1].split("/", 1)[0])
        return {"jobs": jobs.get(run_id, [])}

    def fetch_text(path):
        return logs[int(path.split("/jobs/", 1)[1].split("/", 1)[0])]

    return fetch_json, fetch_text


def job(job_id: int, conclusion: str | None, status: str = "completed", name: str = tally.JOB_NAME) -> dict:
    return {"id": job_id, "name": name, "status": status, "conclusion": conclusion}


def test_collect_and_summarize_count_runs_and_verdicts() -> None:
    runs = [
        *[{"id": n, "head_sha": h, "created_at": f"t{n}", "pull_requests": [{"number": 10 + n}],
         "referenced_workflows": VALIDATOR}
        for n, h in ((1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e"))]
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
                         fetch_json=fetch_json, fetch_text=fetch_text, allowed_validators=frozenset({GOOD}))
    assert [row["state"] for row in rows] == ["complete", "unsafe", "not-run", "not-run", "off"]
    assert rows[0]["pr"] == [11]
    totals = tally.summarize(rows)
    assert totals["runs"] == 5
    assert totals["complete_runs"] == 1
    assert totals["incremental_missed"] == 1
    assert totals["records_by_verdict"] == {"agree": 103, "incremental_missed": 1}
    assert totals["states"] == {"complete": 1, "not-run": 2, "off": 1, "unsafe": 1}


def test_collect_queries_one_day_at_a_time_and_warns_at_the_cap() -> None:
    runs = [
        {"id": 1, "day": "2026-12-01", "head_sha": "a", "created_at": "t1",
         "pull_requests": [{"number": 1}], "referenced_workflows": VALIDATOR},
        {"id": 2, "day": "2026-12-03", "head_sha": "b", "created_at": "t2",
         "pull_requests": [{"number": 2}], "referenced_workflows": VALIDATOR},
    ]
    fetch_json, fetch_text = fake(runs, {1: [job(11, "success")], 2: [job(12, "success")]},
                                  {11: line(), 12: line()}, total=1000)
    warnings = []
    rows = tally.collect("o/r", "w.yml", "2026-12-01", "2026-12-03",
                         fetch_json=fetch_json, fetch_text=fetch_text, warn=warnings.append)
    assert [row["run_id"] for row in rows] == [1, 2]
    assert len(warnings) == 3 and "at most 1000" in warnings[0]


def test_the_tally_checks_the_validator_pin_and_the_pr_files_itself() -> None:
    def one(run_extra, files=None):
        run = {"id": 1, "head_sha": "a", "created_at": "t", "pull_requests": [{"number": 7}],
               "referenced_workflows": VALIDATOR, **run_extra}
        fetch_json, fetch_text = fake([run], {1: [job(11, "success")]}, {11: line()},
                                      pr_files={7: files or [{"filename": "us/x.yaml"}]})
        (row,) = tally.collect("o/r", "w.yml", "2026-12-01", "2026-12-01", fetch_json=fetch_json,
                               fetch_text=fetch_text, allowed_validators=frozenset({GOOD}))
        return row

    assert one({})["state"] == "complete"
    row = one({}, files=[{"filename": "us/x.yaml"}, {"filename": ".github/workflows/repository-checks.yml"}])
    assert row["state"] == "untrusted" and "changes .github/" in row["untrusted_reasons"][0]
    other = [{"path": VALIDATOR[0]["path"].replace(GOOD, "2" * 40), "sha": "2" * 40}]
    row = one({"referenced_workflows": other})
    assert row["state"] == "untrusted" and "not an allowed pin" in row["untrusted_reasons"][0]
    assert one({"referenced_workflows": []})["state"] == "untrusted"
    assert one({"pull_requests": []})["state"] == "untrusted"
    # The collector's own tally line cannot overrule these checks.
    assert one({"referenced_workflows": other})["tally"]["untrusted"] is False


def test_main_refuses_bad_dates() -> None:
    try:
        tally.main(["--repo", "o/r", "--since", "yesterday", "--until", "2026-12-01",
                    "--allowed-validator-sha", "1" * 40])
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
