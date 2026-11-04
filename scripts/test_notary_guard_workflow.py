"""Execute the protected workflow's guard selection shell against a stub boundary."""
import os
import subprocess
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    body = yaml.safe_load((ROOT / '.github/workflows/validate-rulespec.yml').read_text())
    steps = [step for job in body['jobs'].values() for step in job.get('steps', [])]
    step = next(s for s in steps if s.get('name') == 'Reject manual RuleSpec changes')
    assert 'inputs.run-generated-guard' not in step['if']
    assert step['env']['GUARD_HEAD_SHA'] == '${{ github.event.pull_request.head.sha || github.sha }}'
    assert 'python -I /opt/axiom-dependency-integrity/check.py verify' in step['run']
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        stub = root / 'supervisor'
        stub.write_text('''#!/bin/bash
set -euo pipefail
test -z "${GITHUB_TOKEN+x}"
printf '%s\\n' "$*" >> "$CALL_LOG"
if [[ " $* " == *" notary-guard "* ]]; then
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
        ).replace('${{ inputs.python-version }}', '3.13').replace('${{ github.event_name }}', 'pull_request').replace('${{ github.event.pull_request.base.sha }}', 'a' * 40).replace('${{ github.event.before }}', '')
        for status, legacy, expected, count, effective in [(0, 1, 0, 1, ''), (78, 0, 0, 2, ''), (78, 1, 1, 2, ''), (1, 0, 1, 1, ''), (2, 0, 2, 1, ''), (78, 0, 0, 2, 'c'*40)]:
            log = root / 'calls'
            log.unlink(missing_ok=True)
            env = os.environ | {'RUNNER_TEMP': directory, 'GITHUB_WORKSPACE': directory, 'GITHUB_SHA': 'b'*40, 'AXIOM_DEPENDENCY_ROOT': directory, 'DEPENDENCY_PINS_CHANGED': 'false', 'EFFECTIVE_BASE': effective, 'GUARD_HEAD_SHA': 'b'*40, 'GUARD_PR_NUMBER': '42', 'GUARD_LANE': 'TheAxiomFoundation/rulespec-nz', 'GITHUB_TOKEN': 'fixture', 'CALL_LOG': str(log), 'NOTARY_STATUS': str(status), 'LEGACY_STATUS': str(legacy)}
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True)
            assert result.returncode == expected, result.stderr
            calls = log.read_text().splitlines()
            assert len(calls) == count, (status, legacy, calls, result.stderr)
            assert '--head-ref ' + 'b'*40 in calls[0]
            assert '--base-ref ' + 'a'*40 in calls[0]
            assert '--pr-number 42' in calls[0]
            if effective:
                assert '--base-ref ' + effective in calls[1]
            assert not list(root.glob('notary-guard-token.*'))
    precheck = next(s for s in steps if s.get('name') == 'Reject unmanifested RuleSpec content')['run']
    assert 'run-generated-guard=false is retired' in precheck
    # Only a base consumer may defer the cheap legacy precheck; malformed
    # consumers still reach the mandatory verifier, which returns failure.
    assert 'os.environ["BASE_SHA"] + ":.axiom/notary/consumer.json"' in precheck
    assert 'GITHUB_SHA"] + ":.axiom/notary/consumer.json"' not in precheck
    assert precheck.index('program_issues =') < precheck.index('Base has a notary consumer')
    print('notary guard selection and legacy fallback: ok')


if __name__ == '__main__':
    main()
