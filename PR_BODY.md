## Summary

- enforce pending creation as the exact semantic protected-base superset with one new `pending` field, including a new pending-only module, with no composite removal or activation
- enforce both pending-only and active-plus-pending activation as one exact, unexpired same-module consumption with no other waiver change and exactly the waiver/toolchain paths
- bind raw protected-base and head waiver bytes to their strict toolchains, allowing only the canonical waiver-digest byte replacement
- fail closed when protected-base toolchain retrieval is missing, corrupt, or unreadable, except for the exact authorized rulespec-us PR #911 pre-migration bootstrap
- remove an unused attacker-authored commit-message input and add exact extracted-source regressions for every Fable F1-F5 attack plus pending-only activation, activation batches, and pending-only cross-module replacement
- document the core reproof interface, caller up-to-date/merge-queue protection, and migration off the legacy pending-safe workflow

## Rollout status: **BLOCKED**

- Required axiom-encode core head: **BLOCKED — no reviewed compatible immutable commit has been certified for this rollout.** No work-in-progress head may be pinned or advertised as compatible.
- Reusable-workflow frozen candidate: `3e7976cc2aaab4e3e712285814e335493187a950`
- Callers must repin the reviewed core and reusable workflow together, require the PR branch to be up to date or use a merge queue, and migrate off `validate-rulespec-legacy-pending-safe.yml` before relying on this ratchet.
- The live `main` base was re-verified as `7dcdf2c5f46ee2a5d38e8f3c176eba52099a6a5a` before publishing this draft.

The final served-model Fable review approved exact head `3e7976cc2aaab4e3e712285814e335493187a950` as a draft only, with no Critical, High, or Medium findings. That approval is not merge or rollout authorization.

The eventual core must independently re-prove the raw evidence through the documented `validation-waivers audit --root --corpus-path --protected-base --protected-base-toolchain --changed-paths --partition-key --partition-keys-json --axiom-rules-engine-path` interface. Do not merge this draft or roll out its pin until that reviewed core SHA and the caller controls exist.

## Verification

- `python3 -u scripts/test_validate_rulespec_workflow.py`
- `python3 -u scripts/test_legacy_oracle_coverage_workflow.py`
- `actionlint .github/workflows/validate-rulespec.yml`
- repository-installed `ruff check scripts` (green in the implementation environment; newer unpinned Ruff versions may report style-only findings)
- parsed all four workflows as YAML
- compiled every Python script with bytecode directed to an external temporary cache
- `git diff --check origin/main...HEAD`
- `git diff --check`
- served-model Fable independently approved the exact frozen head as draft-only after rechecking F1-F5, N1-N3, shell/YAML/Git failure semantics, and extracted-source coverage

This must remain a **draft**. Do not merge.

Refs TheAxiomFoundation/axiom-encode#1558.
