"""Execute the protected workflow's guard selection shell against a stub boundary.

This is local evidence about the workflow's own shell only: which verifier it
selects, which refs and token file it passes, and how it maps exit statuses.
The stub supervisor returns configured statuses. It does not authenticate
producer lineage, writer eligibility, authorization or source-App binding;
those guarantees belong to the external encoder `notary-guard` and the
admission App, and are rollout requirements, not properties tested here.
"""
import os
import subprocess
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = 'a' * 40
PR_HEAD_SHA = 'b' * 40
MERGE_SHA = 'd' * 40  # GITHUB_SHA on pull_request: the synthetic merge commit.
TOKEN = 'fixture-token-é-bytes'


def run_precheck(precheck, run_generated_guard):
    """Run the cheap precheck step in an empty repo with no change set."""
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(['git', 'init', '-q', directory], check=True)
        env = os.environ | {
            'BASE_SHA': '',
            'EVENT_NAME': 'workflow_dispatch',
            'GITHUB_SHA': MERGE_SHA,
            'GUARD_PROGRAMS_ROOT': 'false',
            'RUN_GENERATED_GUARD': run_generated_guard,
        }
        return subprocess.run(['bash', '-c', precheck], cwd=directory, env=env, capture_output=True, text=True)


def main():
    body = yaml.safe_load((ROOT / '.github/workflows/validate-rulespec.yml').read_text())
    steps = [step for job in body['jobs'].values() for step in job.get('steps', [])]
    step = next(s for s in steps if s.get('name') == 'Reject manual RuleSpec changes')
    # The mandatory guard runs on exactly the first shard; no input can skip it.
    assert step['if'] == '${{ matrix.shard == needs.shards.outputs.first }}', step['if']
    assert step['env']['GUARD_HEAD_SHA'] == '${{ github.event.pull_request.head.sha || github.sha }}'
    assert step['env']['GITHUB_TOKEN'] == '${{ github.token }}'
    assert 'python -I /opt/axiom-dependency-integrity/check.py verify' in step['run']
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        stub = root / 'supervisor'
        # Configured statuses only. For notary-guard the stub also checks that
        # the token file holds exactly the job token bytes with mode 0600.
        stub.write_text('''#!/bin/bash
set -euo pipefail
test -z "${GITHUB_TOKEN+x}"
printf '%s\\n' "$*" >> "$CALL_LOG"
if [[ " $* " == *" notary-guard "* ]]; then
  token_file=""
  previous=""
  for argument in "$@"; do
    if [ "$previous" = "--github-token-file" ]; then token_file="$argument"; fi
    previous="$argument"
  done
  test -n "$token_file" || exit 91
  test -n "$(find "$token_file" -maxdepth 0 -type f -perm 0600)" || exit 92
  printf '%s' "$EXPECTED_TOKEN" | cmp -s - "$token_file" || exit 93
  exit "$NOTARY_STATUS"
fi
exit "$LEGACY_STATUS"
''')
        stub.chmod(0o755)
        script = step['run'].replace(
            'python -I /opt/axiom-dependency-integrity/check.py verify',
            ': # CI-only integrity preflight is checked above and stubbed locally',
        ).replace('/opt/axiom-verification/axiom-encode-signing-supervisor', str(stub)).replace(
            '"$runtime/axiom-encode-signing-supervisor"', str(stub)
        ).replace('${{ inputs.python-version }}', '3.13').replace('${{ github.event_name }}', 'pull_request').replace('${{ github.event.pull_request.base.sha }}', BASE_SHA).replace('${{ github.event.before }}', '').replace('${{ github.event.merge_group.base_sha }}', '')
        assert '${{' not in script, 'unsubstituted expression in the guard shell'
        for status, legacy, expected, count, effective in [(0, 1, 0, 1, ''), (78, 0, 0, 2, ''), (78, 1, 1, 2, ''), (1, 0, 1, 1, ''), (2, 0, 2, 1, ''), (78, 0, 0, 2, 'c'*40)]:
            log = root / 'calls'
            log.unlink(missing_ok=True)
            env = os.environ | {'RUNNER_TEMP': directory, 'GITHUB_WORKSPACE': directory, 'GITHUB_SHA': MERGE_SHA, 'AXIOM_DEPENDENCY_ROOT': directory, 'DEPENDENCY_PINS_CHANGED': 'false', 'EFFECTIVE_BASE': effective, 'GUARD_HEAD_SHA': PR_HEAD_SHA, 'GUARD_PR_NUMBER': '42', 'GUARD_LANE': 'TheAxiomFoundation/rulespec-nz', 'GITHUB_TOKEN': TOKEN, 'EXPECTED_TOKEN': TOKEN, 'CALL_LOG': str(log), 'NOTARY_STATUS': str(status), 'LEGACY_STATUS': str(legacy)}
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True)
            assert result.returncode == expected, (status, legacy, result.returncode, result.stderr)
            calls = log.read_text().splitlines()
            assert len(calls) == count, (status, legacy, calls, result.stderr)
            # Notary admission receives the actual PR head, never the merge SHA.
            assert ' notary-guard ' in f' {calls[0]} '
            assert '--head-ref ' + PR_HEAD_SHA in calls[0]
            assert MERGE_SHA not in calls[0]
            assert '--base-ref ' + BASE_SHA in calls[0]
            assert '--pr-number 42' in calls[0]
            if count > 1:
                # The legacy fallback still audits GITHUB_SHA.
                assert ' guard-generated ' in f' {calls[1]} '
                assert '--head-ref ' + MERGE_SHA in calls[1]
                assert '--base-ref ' + (effective or BASE_SHA) in calls[1]
            assert not list(root.glob('notary-guard-token.*'))
    precheck = next(s for s in steps if s.get('name') == 'Reject unmanifested RuleSpec content')['run']
    # Execute the retired-input check rather than matching its diagnostic.
    retired = run_precheck(precheck, 'false')
    assert retired.returncode == 1, (retired.returncode, retired.stdout, retired.stderr)
    assert 'run-generated-guard=false is retired' in retired.stderr, retired.stderr
    invalid = run_precheck(precheck, 'maybe')
    assert invalid.returncode == 1, (invalid.returncode, invalid.stderr)
    accepted = run_precheck(precheck, 'true')
    assert accepted.returncode == 0, (accepted.returncode, accepted.stderr)
    assert 'remains authoritative' in accepted.stdout, accepted.stdout
    # Only a base consumer may defer the cheap legacy precheck; malformed
    # consumers still reach the mandatory verifier, which returns failure.
    assert 'os.environ["BASE_SHA"] + ":.axiom/notary/consumer.json"' in precheck
    assert 'GITHUB_SHA"] + ":.axiom/notary/consumer.json"' not in precheck
    assert precheck.index('program_issues =') < precheck.index('Base has a notary consumer')
    print('notary guard selection and legacy fallback: ok (6 scenarios, 3 precheck inputs)')


if __name__ == '__main__':
    main()
