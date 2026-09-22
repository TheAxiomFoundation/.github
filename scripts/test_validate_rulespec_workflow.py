#!/usr/bin/env python3
"""Exercise the embedded exact reviewed-migration authorization guard."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate-rulespec.yml"
RETIRED = "1" * 64
WAIVER = "2" * 64


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


def authorization_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# reviewed-migration-authorization-start")
    end = workflow.index("# reviewed-migration-authorization-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = "python - <<'PY' >> \"$GITHUB_OUTPUT\"\n"
    assert block.startswith(marker)
    assert block.endswith("          PY\n") or block.endswith("PY\n")
    source = block[len(marker) :]
    source = source.rsplit("\nPY", 1)[0]
    return textwrap.dedent(source)


def waiver_ratchet_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("# waiver-ratchet-python-start")
    end = workflow.index("# waiver-ratchet-python-end")
    block = textwrap.dedent(workflow[start:end].split("\n", 1)[1])
    marker = "<<'PY'\n"
    assert marker in block
    source = block.split(marker, 1)[1]
    source = source.rsplit("\nPY", 1)[0]
    return textwrap.dedent(source)


def test_pending_waiver_requires_exact_digest_only_toolchain_companion() -> None:
    metadata = (
        'fingerprint: "sha256:' + "a" * 64 + '"\n'
        '      owner: "@owner"\n'
        '      issue: "https://github.com/TheAxiomFoundation/repo/issues/1"\n'
        '      expires: "2026-10-01"\n'
    )
    base_waiver = (
        "validate_failures:\n"
        "  us/statutes/1.yaml:\n"
        "    active:\n      "
        + metadata
    ).encode()
    head_waiver = base_waiver + b"    pending:\n      " + metadata.encode()
    base_digest = hashlib.sha256(base_waiver).hexdigest()
    head_digest = hashlib.sha256(head_waiver).hexdigest()
    base_toolchain = (
        "[toolchain]\n"
        'axiom_corpus_release = "unchanged"\n'
        f'validation_waiver_set_sha256 = "{base_digest}"\n'
    ).encode()
    head_toolchain = base_toolchain.replace(base_digest.encode(), head_digest.encode())

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = {
            "base_waiver": root / "base.yaml",
            "head_waiver": root / "head.yaml",
            "base_toolchain": root / "base.toml",
            "head_toolchain": root / "head.toml",
            "changed": root / "changed.txt",
            "audit_changed": root / "audit-changed.txt",
        }
        paths["base_waiver"].write_bytes(base_waiver)
        paths["head_waiver"].write_bytes(head_waiver)
        paths["base_toolchain"].write_bytes(base_toolchain)
        paths["head_toolchain"].write_bytes(head_toolchain)
        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"
        )

        def run() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "python",
                    "-c",
                    waiver_ratchet_source(),
                    *(str(path) for path in paths.values()),
                ],
                capture_output=True,
                text=True,
            )

        assert run().returncode == 0
        assert paths["audit_changed"].read_text() == "known-validation-gaps.yaml\n"

        paths["head_toolchain"].write_bytes(
            head_toolchain.replace(b'"unchanged"', b'"changed"')
        )
        assert run().returncode != 0
        paths["head_toolchain"].write_bytes(head_toolchain)

        paths["changed"].write_text("known-validation-gaps.yaml\n")
        assert run().returncode != 0

        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\nus/statutes/1.yaml\n"
        )
        assert run().returncode != 0

        # A newly introduced module can be preapproved, but still only through
        # the same exact two-file transition.
        new_base_waiver = b"validate_failures: {}\n"
        new_head_waiver = (
            b"validate_failures:\n  us/statutes/1.yaml:\n    pending:\n      "
            + metadata.encode()
        )
        new_base_digest = hashlib.sha256(new_base_waiver).hexdigest()
        new_head_digest = hashlib.sha256(new_head_waiver).hexdigest()
        new_base_toolchain = base_toolchain.replace(
            base_digest.encode(), new_base_digest.encode()
        )
        new_head_toolchain = new_base_toolchain.replace(
            new_base_digest.encode(), new_head_digest.encode()
        )
        paths["base_waiver"].write_bytes(new_base_waiver)
        paths["head_waiver"].write_bytes(new_head_waiver)
        paths["base_toolchain"].write_bytes(new_base_toolchain)
        paths["head_toolchain"].write_bytes(new_head_toolchain)
        paths["changed"].write_text(
            "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"
        )
        assert run().returncode == 0

        # Bootstrap mode authenticates the exact head candidate as its own
        # protected comparison baseline; the ratchet must accept that identity.
        paths["base_waiver"].write_bytes(new_head_waiver)
        paths["base_toolchain"].write_bytes(new_head_toolchain)
        assert run().returncode == 0


def test_release_pin_companion_requires_strict_retirement() -> None:
    import yaml

    entry = {"active": {"fingerprint": "sha256:" + "a" * 64}}
    base_entries = {"us/one.yaml": entry, "us/two.yaml": entry}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        paths = [root / name for name in (
            "base.yaml", "head.yaml", "base.toml", "head.toml", "changed", "audit"
        )]
        changed = "known-validation-gaps.yaml\n.axiom/toolchain.toml\nus/one.yaml\n"
        paths[4].write_text(changed)

        def run(entries=None, *, release="new-release", digest="b" * 64,
                extra="", corrupt_pin=False):
            if entries is None:
                entries = {"us/two.yaml": entry}
            for path, records in zip(paths[:2], (base_entries, entries)):
                path.write_text(yaml.safe_dump({"validate_failures": records}))
            for index, name, sha in ((0, "old-release", "a" * 64), (1, release, digest)):
                pin = hashlib.sha256(paths[index].read_bytes()).hexdigest()
                if index == 1 and corrupt_pin:
                    pin = "0" * 64
                paths[index + 2].write_text(
                    '[toolchain]\n'
                    f'axiom_corpus_release = "{name}"\n'
                    f'axiom_corpus_release_content_sha256 = "{sha}"\n'
                    f'validation_waiver_set_sha256 = "{pin}"\n'
                    + (extra if index == 1 else "")
                )
            return subprocess.run(
                ["python", "-c", waiver_ratchet_source(), *map(str, paths)],
                capture_output=True, text=True,
            )

        result = run()
        assert result.returncode == 0, result.stderr
        assert paths[5].read_text() == changed
        # Even a two-file retirement must retain the release pin in the audit.
        paths[4].write_text("known-validation-gaps.yaml\n.axiom/toolchain.toml\n")
        assert run().returncode == 0
        assert paths[5].read_text() == paths[4].read_text()
        assert run({}).returncode == 0
        assert run(base_entries).returncode != 0  # No retirement.
        assert run({"us/new.yaml": entry}).returncode != 0
        assert run({"us/two.yaml": {"pending": entry["active"]}}).returncode != 0
        assert run({"us/two.yaml": {**entry, "pending": entry["active"]}}).returncode != 0
        assert run({"us/two.yaml": {"active": {"fingerprint": "changed"}}}).returncode != 0
        assert run(extra='axiom_encode_ref = "changed"\n').returncode != 0
        assert run(extra='[other]\nsetting = true\n').returncode != 0
        assert run(corrupt_pin=True).returncode != 0
        assert run(release="../unsigned").returncode != 0
        assert run(digest="invalid").returncode != 0


def waiver_record(fingerprint: str, *, expires: str = "2026-11-01") -> dict:
    return {
        "fingerprint": "sha256:" + fingerprint * 64,
        "owner": "@owner",
        "issue": "https://github.com/TheAxiomFoundation/rulespec-us/issues/1",
        "expires": expires,
    }


def run_release_repin(
    base_entries: dict,
    head_entries: dict,
    *,
    changed: str = "known-validation-gaps.yaml\n.axiom/toolchain.toml\n",
    release: str = "new-release",
    release_sha: str = "b" * 64,
    extra: str = "",
    head_ledger_suffix: str = "",
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run the extracted ratchet over a corpus re-pin; return (result, audit)."""
    import yaml

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        base_ledger, head_ledger, base_toml, head_toml, changed_path, audit = (
            root / name
            for name in (
                "base.yaml", "head.yaml", "base.toml", "head.toml", "changed", "audit"
            )
        )
        base_ledger.write_text(yaml.safe_dump({"validate_failures": base_entries}))
        head_ledger.write_text(
            yaml.safe_dump({"validate_failures": head_entries}) + head_ledger_suffix
        )
        for ledger, toml, name, sha, suffix in (
            (base_ledger, base_toml, "old-release", "a" * 64, ""),
            (head_ledger, head_toml, release, release_sha, extra),
        ):
            toml.write_text(
                "[toolchain]\n"
                f'axiom_corpus_release = "{name}"\n'
                f'axiom_corpus_release_content_sha256 = "{sha}"\n'
                'validation_waiver_set_sha256 = '
                f'"{hashlib.sha256(ledger.read_bytes()).hexdigest()}"\n'
                + suffix
            )
        changed_path.write_text(changed)
        result = subprocess.run(
            [
                "python",
                "-c",
                waiver_ratchet_source(),
                *map(
                    str,
                    (base_ledger, head_ledger, base_toml, head_toml, changed_path, audit),
                ),
            ],
            capture_output=True,
            text=True,
        )
        return result, audit.read_text() if audit.exists() else ""


def test_release_pin_companion_accepts_exact_staged_consumption() -> None:
    old, new, other = waiver_record("a"), waiver_record("b"), waiver_record("c")
    kept = {"active": other}
    staged = {"active": old, "pending": new}
    pending_only = {"pending": new}
    base = {"us/kept.yaml": kept, "us/staged.yaml": staged, "us/fixed.yaml": kept}
    changed = "known-validation-gaps.yaml\n.axiom/toolchain.toml\n"

    def accepted(head: dict, base_entries: dict = base, **kwargs) -> None:
        result, audit = run_release_repin(base_entries, head, **kwargs)
        assert result.returncode == 0, result.stderr
        # The re-pin never narrows the audit to the ledger alone.
        assert audit == kwargs.get("changed", changed)

    def rejected(head: dict, base_entries: dict = base, **kwargs) -> str:
        result, _ = run_release_repin(base_entries, head, **kwargs)
        assert result.returncode != 0, result.stdout
        return result.stderr

    consumed = {"us/kept.yaml": kept, "us/staged.yaml": {"active": new}}

    # Positive: {active, pending} -> {active: base.pending} with the re-pin.
    accepted({**consumed, "us/fixed.yaml": kept})
    # Positive: consumption and strict retirement travel together.
    accepted(consumed)
    # Positive: strict retirement alone (the #111 path) still passes.
    accepted({"us/kept.yaml": kept, "us/staged.yaml": staged})
    # Positive: pending-only {pending} -> {active: base.pending}.
    accepted(
        {"us/new-failure.yaml": {"active": new}, "us/kept.yaml": kept},
        {"us/new-failure.yaml": pending_only, "us/kept.yaml": kept},
    )
    # Positive: several staged approvals may be consumed by one re-pin.
    accepted(
        {"us/one.yaml": {"active": new}, "us/two.yaml": {"active": other}},
        {
            "us/one.yaml": {"active": old, "pending": new},
            "us/two.yaml": {"active": old, "pending": other},
        },
    )
    # Positive: the audit keeps every changed path of a wider re-pin PR.
    accepted(consumed, changed=changed + "us/kept.yaml\n")

    # Negative: an active fingerprint change with no staged base pending.
    assert "us/kept.yaml" in rejected(
        {**consumed, "us/kept.yaml": {"active": new}}
    )
    # Negative: a new pending record, on its own or next to a consumption.
    rejected({**consumed, "us/kept.yaml": {"active": other, "pending": new}})
    rejected(
        {**base, "us/kept.yaml": {"active": other, "pending": new}},
    )
    # Negative: any other toolchain key changes with the re-pin.
    assert "toolchain key" in rejected(consumed, extra='axiom_encode_ref = "x"\n')
    rejected(consumed, extra="[other]\nsetting = true\n")
    # Negative: a new ledger entry, even a pending-only one.
    assert "new entry" in rejected({**consumed, "us/new.yaml": {"active": new}})
    rejected({**consumed, "us/new.yaml": pending_only})
    # Negative: consumption that does not match the base pending exactly.
    rejected({**consumed, "us/staged.yaml": {"active": other}})
    rejected(
        {**consumed, "us/staged.yaml": {"active": {**new, "expires": "2026-12-01"}}}
    )
    rejected({**consumed, "us/staged.yaml": {"active": {**new, "owner": "@other"}}})
    rejected(
        {**consumed, "us/staged.yaml": {"active": {**new, "extra": "field"}}}
    )
    # Type-strict: an int may not stand in for a float in a staged record.
    rejected(
        {"us/staged.yaml": {"active": {**new, "rank": 1}}},
        {"us/staged.yaml": {"active": old, "pending": {**new, "rank": 1.0}}},
    )
    # Negative: consumption must drop pending, not keep it beside active.
    rejected({**consumed, "us/staged.yaml": {"active": new, "pending": new}})
    # Negative: dropping pending while keeping the old active is not consumption.
    rejected({**consumed, "us/staged.yaml": {"active": old}})
    # Negative: a pending record from one module cannot activate another.
    rejected(
        {"us/one.yaml": {"active": new}, "us/two.yaml": {"active": old, "pending": new}},
        {"us/one.yaml": {"active": old}, "us/two.yaml": {"active": old, "pending": new}},
    )
    # Negative: a re-pin whose rewritten ledger records no transition at all.
    assert "at least one" in rejected(base, head_ledger_suffix="# comment\n")
    # Negative: a non-digest toolchain rewrite must actually move the release,
    # and the new release must stay well-formed.
    rejected(consumed, release="old-release", release_sha="a" * 64, extra="# x\n")
    rejected(consumed, release="../unsigned")
    rejected(consumed, release_sha="invalid")


def guard_base_ref_source() -> str:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Reject manual RuleSpec changes")
    end = workflow.index("      - name: Select RuleSpec validation targets")
    step = workflow[start:end]
    block_start = step.index("# generated-guard-base-ref-start")
    block_end = step.index("# generated-guard-base-ref-end")
    return textwrap.dedent(step[block_start:block_end].split("\n", 1)[1])


# Mirrors safe_ref in axiom-encode scripts/provision_verification_supervisor.py,
# the trusted git wrapper the supervised generated guard runs under.
TRUSTED_GIT_SAFE_REF = r"(?:HEAD|main|origin/main|[0-9a-f]{40})(?:\^\{commit\})?"


def test_generated_guard_resolves_scheduled_base_to_exact_commit() -> None:
    import re

    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Reject manual RuleSpec changes")
    end = workflow.index("      - name: Select RuleSpec validation targets")
    step = workflow[start:end]
    assert 'base_ref="HEAD~1"' not in step
    assert '--base-ref "$base_ref"' in step
    # HEAD~1 must exist in the validate job's clone for rev-parse to resolve it.
    validate_job = workflow.index("    name: validate\n")
    checkout = workflow.index("      - name: Checkout rules repository", validate_job)
    checkout_step = workflow[checkout : workflow.index("      - name:", checkout + 1)]
    assert "fetch-depth: 0" in checkout_step
    assert checkout < start

    def resolve(root: Path, *, event: str, pr_base: str = "", before: str = ""):
        source = (
            guard_base_ref_source()
            .replace("${{ github.event_name }}", event)
            .replace("${{ github.event.pull_request.base.sha }}", pr_base)
            .replace("${{ github.event.before }}", before)
        )
        assert "${{" not in source
        return subprocess.run(
            ["bash", "-c", "set -euo pipefail\n" + source + 'printf %s "$base_ref"\n'],
            cwd=root,
            capture_output=True,
            text=True,
        )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")
        (root / "file.txt").write_text("one\n")
        first = commit(root, "first")

        # A root commit has no parent: fail closed instead of passing HEAD~1.
        assert resolve(root, event="schedule").returncode != 0

        (root / "file.txt").write_text("two\n")
        second = commit(root, "second")
        for event in ("schedule", "workflow_dispatch"):
            result = resolve(root, event=event)
            assert result.returncode == 0, result.stderr
            assert result.stdout == first
            assert re.fullmatch(TRUSTED_GIT_SAFE_REF, result.stdout)
            assert not re.fullmatch(TRUSTED_GIT_SAFE_REF, "HEAD~1")
        # A push that created the branch reports an all-zero before SHA.
        result = resolve(root, event="push", before="0" * 40)
        assert result.returncode == 0, result.stderr
        assert result.stdout == first
        result = resolve(root, event="push", before=first)
        assert result.returncode == 0 and result.stdout == first
        result = resolve(root, event="pull_request", pr_base=second)
        assert result.returncode == 0 and result.stdout == second
        # Anything that is not an exact commit identity is refused up front.
        assert resolve(root, event="pull_request", pr_base="main").returncode != 0
        assert resolve(root, event="push", before="HEAD~1").returncode != 0


def test_waiver_bootstrap_uses_authenticated_head_toolchain() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Enforce validation waiver ratchet")
    end = workflow.index("      - name: Reject manual RuleSpec changes")
    audit_step = workflow[start:end]
    assert 'if [ -n "$BOOTSTRAP_SHA256" ]; then' in audit_step
    assert 'cp .axiom/toolchain.toml "$protected_base_toolchain"' in audit_step


def test_retired_schema_freeze_classifies_only_plural_citations() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Verify immutable retired-schema freeze")
    end = workflow.index("      - name: Fetch pinned signed corpus release object")
    freeze_step = workflow[start:end]

    assert '"corpus_citation_paths" in source_verification' in freeze_step
    assert "upstream_source_check" not in freeze_step


def test_retired_schema_prefreeze_bridge_is_fail_closed() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Verify immutable retired-schema freeze")
    end = workflow.index("      - name: Fetch pinned signed corpus release object")
    freeze_step = workflow[start:end]

    assert "allow-retired-schema-prefreeze" in workflow
    assert 'default: false' in workflow
    assert "pre-freeze compatibility is restricted to rulespec-us" in freeze_step
    assert "pre-freeze compatibility requires the generated guard" in freeze_step
    assert "pre-freeze compatibility cannot be used with a freeze" in freeze_step


def test_validation_waiver_audit_is_exhaustively_partitioned_across_matrix() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Enforce validation waiver ratchet")
    end = workflow.index("      - name: Reject manual RuleSpec changes")
    audit_step = workflow[start:end]

    assert "matrix.shard == needs.shards.outputs.first" not in audit_step
    assert '--partition-key "${{ matrix.shard }}"' in audit_step
    assert "--partition-keys-json '${{ needs.shards.outputs.matrix }}'" in audit_step
    assert 'AXIOM_ENCODE_WAIVER_AUDIT_WORKERS: "1"' in audit_step


def test_parallel_validation_workers_are_bounded_and_fail_closed() -> None:
    workflow = WORKFLOW.read_text()
    start = workflow.index("      - name: Validate RuleSpec YAML")
    end = workflow.index("      - name: Execute RuleSpec companion tests")
    validate_step = workflow[start:end]

    assert "validation-workers:" in workflow
    assert "default: 1" in workflow
    assert '[[ "$VALIDATION_WORKERS" =~ ^[1-4]$ ]]' in validate_step
    assert 'if ! wait "$pid"; then' in validate_step
    assert 'status=1' in validate_step
    assert 'for log_path in "${logs[@]}"; do' in validate_step
    assert 'exit "$status"' in validate_step


def write_authorization(root: Path, *, topic: str) -> None:
    path = root / ".axiom/reviewed-migrations.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "format": "axiom/reviewed-migrations/v1",
                "migrations": [
                    {
                        "pull_request": 911,
                        "head": topic,
                        "retired_schema_bootstrap_sha256": RETIRED,
                        "validation_waiver_bootstrap_sha256": WAIVER,
                    }
                ],
            }
        )
        + "\n"
    )


def fixture() -> tuple[tempfile.TemporaryDirectory[str], Path, str, str]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "workflow-test@example.com")
    git(root, "config", "user.name", "Workflow Test")
    (root / "base.txt").write_text("initial\n")
    common = commit(root, "common")
    git(root, "switch", "-qc", "topic")
    (root / "topic.txt").write_text("reviewed\n")
    topic = commit(root, "reviewed topic")
    git(root, "switch", "-q", "main")
    git(root, "reset", "--hard", common)
    write_authorization(root, topic=topic)
    base = commit(root, "authorize exact topic")
    return temp, root, base, topic


def run_authorization(
    root: Path,
    *,
    base: str,
    event: str,
    pr_head: str = "",
    pr_number: str = "911",
    github_sha: str = "",
    github_ref: str = "refs/pull/911/merge",
    pr_base_ref: str = "main",
    repository: str = "TheAxiomFoundation/rulespec-us",
    retired: str = RETIRED,
    waiver: str = WAIVER,
    guard: str = "false",
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "AUTHORIZATION_PATH": ".axiom/reviewed-migrations.json",
        "BASE_SHA": base,
        "EVENT_NAME": event,
        "PR_BASE_REF": pr_base_ref,
        "PR_HEAD_SHA": pr_head,
        "PR_NUMBER": pr_number,
        "RETIRED_SCHEMA_BOOTSTRAP": retired,
        "VALIDATION_WAIVER_BOOTSTRAP": waiver,
        "RUN_GENERATED_GUARD": guard,
        "GITHUB_REPOSITORY": repository,
        "GITHUB_REF": github_ref,
        "GITHUB_SHA": github_sha or pr_head,
    }
    return subprocess.run(
        ["python", "-c", authorization_source()],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )


def test_conflicted_merge_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "workflow-test@example.com")
        git(root, "config", "user.name", "Workflow Test")
        conflict = root / "conflict.txt"
        conflict.write_text("common\n")
        common = commit(root, "common")
        git(root, "switch", "-qc", "topic")
        conflict.write_text("topic\n")
        topic = commit(root, "conflicting topic")
        git(root, "switch", "-q", "main")
        git(root, "reset", "--hard", common)
        conflict.write_text("main\n")
        write_authorization(root, topic=topic)
        base = commit(root, "authorize conflicting topic")
        forged_merge = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
            ],
            cwd=root,
            check=True,
            input="forged conflicted merge\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=forged_merge,
            github_ref="refs/heads/main",
        )
        assert result.returncode != 0


def main() -> None:
    test_release_pin_companion_requires_strict_retirement()
    test_release_pin_companion_accepts_exact_staged_consumption()
    test_generated_guard_resolves_scheduled_base_to_exact_commit()
    test_parallel_validation_workers_are_bounded_and_fail_closed()
    test_pending_waiver_requires_exact_digest_only_toolchain_companion()
    test_waiver_bootstrap_uses_authenticated_head_toolchain()
    temp, root, base, topic = fixture()
    try:
        ordinary = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            retired="",
            waiver="",
            guard="true",
        )
        assert ordinary.returncode == 0, ordinary.stderr
        assert ordinary.stdout.splitlines() == ["authorized=false", "candidate="]

        approved = run_authorization(
            root, base=base, event="pull_request", pr_head=topic
        )
        assert approved.returncode == 0, approved.stderr
        assert approved.stdout.splitlines() == [
            "authorized=true",
            f"candidate={topic}",
        ]

        wrong_head = run_authorization(
            root, base=base, event="pull_request", pr_head=base
        )
        assert wrong_head.returncode != 0
        wrong_base = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            pr_base_ref="release",
        )
        assert wrong_base.returncode != 0
        wrong_digest = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            waiver="3" * 64,
        )
        assert wrong_digest.returncode != 0
        wrong_retired = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            retired="3" * 64,
        )
        assert wrong_retired.returncode != 0
        wrong_pr = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            pr_number="912",
        )
        assert wrong_pr.returncode != 0
        wrong_repository = run_authorization(
            root,
            base=base,
            event="pull_request",
            pr_head=topic,
            repository="example/fork",
        )
        assert wrong_repository.returncode != 0

        authorization = root / ".axiom/reviewed-migrations.json"
        duplicate = authorization.read_text().replace(
            f'"head": "{topic}"',
            f'"head": "{"0" * 40}", "head": "{topic}"',
        )
        authorization.write_text(duplicate)
        duplicate_base = commit(root, "duplicate authorization key")
        duplicate_result = run_authorization(
            root, base=duplicate_base, event="pull_request", pr_head=topic
        )
        assert duplicate_result.returncode != 0

        authorization.write_text("{\"format\":")
        malformed_base = commit(root, "malformed authorization")
        malformed_result = run_authorization(
            root, base=malformed_base, event="pull_request", pr_head=topic
        )
        assert malformed_result.returncode != 0

        write_authorization(root, topic=topic)
        authorization.write_bytes(authorization.read_text().encode("utf-16"))
        utf16_base = commit(root, "non-UTF-8 authorization")
        utf16_result = run_authorization(
            root, base=utf16_base, event="pull_request", pr_head=topic
        )
        assert utf16_result.returncode != 0

        authorization.unlink()
        target = root / "authorization-target.json"
        target.write_text("{}\n")
        authorization.symlink_to(Path("..") / target.name)
        symlink_base = commit(root, "symlink authorization")
        symlink_result = run_authorization(
            root, base=symlink_base, event="pull_request", pr_head=topic
        )
        assert symlink_result.returncode != 0

        git(root, "switch", "-q", "main")
        git(root, "reset", "--hard", base)
        non_merge = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=topic,
            github_ref="refs/heads/main",
        )
        assert non_merge.returncode != 0

        altered_tree = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
            ],
            cwd=root,
            check=True,
            input="altered merge tree\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        altered_result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=altered_tree,
            github_ref="refs/heads/main",
        )
        assert altered_result.returncode != 0

        octopus = subprocess.run(
            [
                "git",
                "commit-tree",
                git(root, "rev-parse", f"{base}^{{tree}}"),
                "-p",
                base,
                "-p",
                topic,
                "-p",
                duplicate_base,
            ],
            cwd=root,
            check=True,
            input="octopus\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        octopus_result = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=octopus,
            github_ref="refs/heads/main",
        )
        assert octopus_result.returncode != 0

        git(root, "merge", "--no-ff", "-qm", "merge reviewed topic", topic)
        merge = git(root, "rev-parse", "HEAD")
        approved_push = run_authorization(
            root,
            base=base,
            event="push",
            github_sha=merge,
            github_ref="refs/heads/main",
        )
        assert approved_push.returncode == 0, approved_push.stderr
        wrong_first_parent = run_authorization(
            root,
            base=git(root, "rev-parse", f"{base}^"),
            event="push",
            github_sha=merge,
            github_ref="refs/heads/main",
        )
        assert wrong_first_parent.returncode != 0

        (root / "later.txt").write_text("later\n")
        later_base = commit(root, "later base")
        replay_tree = git(root, "rev-parse", f"{later_base}^{{tree}}")
        replay = subprocess.run(
            ["git", "commit-tree", replay_tree, "-p", later_base, "-p", topic],
            cwd=root,
            check=True,
            input="replay\n",
            capture_output=True,
            text=True,
        ).stdout.strip()
        replayed = run_authorization(
            root,
            base=later_base,
            event="push",
            github_sha=replay,
            github_ref="refs/heads/main",
        )
        assert replayed.returncode != 0
    finally:
        temp.cleanup()

    test_conflicted_merge_is_rejected()

    workflow = WORKFLOW.read_text()
    assert "migration-authorization-path" in workflow
    assert "bootstrap is not bound to an exact protected authorization" in workflow
    print("exact reviewed-migration authorization: ok")


if __name__ == "__main__":
    main()
