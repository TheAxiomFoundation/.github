# Issue 1558 reusable-workflow final report

## Final follow-up (authoritative)

- Final head: `3e7976cc2aaab4e3e712285814e335493187a950`; protected base and merge base: `7dcdf2c5f46ee2a5d38e8f3c176eba52099a6a5a`.
- Draft PR #107 is open, green, clean/mergeable, and still draft at that exact head: https://github.com/TheAxiomFoundation/.github/pull/107.
- N1 is resolved by permitting exact pending-only consumption `{pending: metadata} -> {active: metadata}` under the same expiry, raw-evidence, two-path, digest-binding, digest-only mutation, and no-other-change proof as active-plus-pending rotation.
- N2 is resolved by removing `HEAD_COMMIT_MESSAGE` and regression-locking its absence. Exact tests now cover valid pending-only activation, a two-form activation batch, and pending creation that attempts to replace a pending-only module elsewhere.
- Both workflow self-tests, changed-workflow actionlint, repository-installed Ruff, all-workflow YAML parsing, external-cache Python compilation, diff checks, and GitHub CI passed.
- Served-model Fable approved this exact head as draft-only with no Critical, High, or Medium findings. Review: `/private/tmp/fable-review-dotgithub-107-round3.md`; concise output: `/private/tmp/fable-review-dotgithub-107-final.md`; attestation: `/private/tmp/fable-review-dotgithub-107-final.MODEL_ATTESTED`.
- The only review note was LOW documentation precision around unpinned Ruff behavior; the live PR body now scopes the local Ruff claim and notes that newer unpinned versions may report style-only findings. This body-only clarification did not change the reviewed head.
- Rollout remains **BLOCKED** on a reviewed compatible immutable axiom-encode core, coordinated core/workflow repins, caller up-to-date protection or merge queue, and migration off `validate-rulespec-legacy-pending-safe.yml`. No merge, signing, or rollout occurred.

All older frozen-head and remote-connectivity statements below are retained as historical run context and are superseded by this final follow-up.

## Outcome

The reusable-workflow remediation is implemented, reconciled, committed, and locally green on `fix/1558-waiver-transition-workflow`.

- Frozen review head: `86cfa854715676d3f844f7b61a2c0701edeb550b`
- Local `origin/main` base and merge base: `7dcdf2c5f46ee2a5d38e8f3c176eba52099a6a5a`
- Divergence: ahead 9, behind 0
- Original Fable-reviewed head: `585d57a111ac06a398850861b1195f1cb788d80e` (`REQUEST_CHANGES`, F1-F5)
- Salvage ref: `refs/codex-salvage/fix-1558-waiver-transition-workflow-20260830-212607-42656` = `9f9d6a22e609c8f07129672ac90565e3e653d87c`
- Draft PR body: `PR_BODY.md`
- Remote PR: not known or verified; no PR number was invented
- Merge status: not merged

The run used the user-required normal Standard tier with `gpt-5.6-sol`, ultra reasoning, and no `--fast`.

## Delivered

- F1: inline activation now requires a strict real future `YYYY-MM-DD` expiry; exact base `active+pending` to head `active=base.pending` with pending consumed; no mixed or unrelated waiver change; exactly `known-validation-gaps.yaml` and `.axiom/toolchain.toml`; raw base/head digest bindings; and an exact canonical toolchain-digest byte splice. The eventual core remains an independent reproof.
- F2/F3: pending creation is the exact semantic protected-base superset with one new pending field. Cross-module replacement, activation plus creation, and unrelated active/pending removals fail.
- F4: protected-base toolchain retrieval distinguishes a genuinely absent path from unreadable refs, objects, `git show`, and other Git failures. Absence fails outside the exact authorization + bootstrap guard for rulespec-us PR #911.
- F5: every transition metadata value must be a string, and expiry shape, calendar validity, and future date are checked inline for creation and activation.
- Exact extracted-source tests cover cross-module and mixed composites, isolated unrelated removals in both phases, expired/garbage/malformed/impossible/non-string expiry, non-string metadata, missing/corrupt/unreadable base toolchain, stale base and wrong head digests, activation extra paths, and base/head waiver/toolchain raw-byte mutations.
- The exact authorized PR #911 composition is tested through the extracted authorization heredoc, bootstrap guard, and protected-toolchain evidence block; ordinary missing evidence still fails.
- Generated `scripts/__pycache__` content was removed and never committed.
- README rollout documentation now states the exact eventual core CLI contract, coordinated immutable repins, required up-to-date branch protection or merge queue, and mandatory migration off `validate-rulespec-legacy-pending-safe.yml`.

## Verification

Passed on the reconciled branch:

- `python3 -u scripts/test_validate_rulespec_workflow.py` — `exact reviewed-migration authorization: ok`
- `python3 -u scripts/test_legacy_oracle_coverage_workflow.py` — `legacy oracle coverage overlay: ok`
- `actionlint .github/workflows/validate-rulespec.yml`
- `ruff check scripts` — `All checks passed!`
- YAML parsing for all four files under `.github/workflows`
- Python compilation for every file under `scripts`, with bytecode directed to and removed from an external temporary cache
- `git diff --check origin/main...HEAD`
- `git diff --check`
- cache-artifact check: no `scripts/__pycache__` remains
- independent inline-security audit: no remaining F1-F4 finding
- independent exact-test coverage audit: all requested F1-F5 attacks covered after follow-up refinements

Known unrelated baseline noise was not rewritten: whole-repository `actionlint` still has two pre-existing SC2129 findings in the untouched legacy workflow, and `ruff format --check scripts` proposes pre-existing formatting changes. The required changed-workflow `actionlint` and `ruff check scripts` pass.

## Actual committed history after rebase

1. `5c5574bb3465e8862aea5cada2a100a00f94c1a4` — `docs: start issue 1558 workflow progress log`
2. `0d4a133fa78fa160230fbd1f7c52770dbc64d417` — `Guard pending waiver toolchain transitions`
3. `1c6153b88f576f4669723fb364cac4f93bf4562c` — `docs: record issue 1558 workflow verification`
4. `788ac5c5eb83cd893af6741a33bcffabaa89cfbf` — `docs: record Fable blocker remediation`
5. `303bc86ed1896dcbbce597867feb0373db853d5f` — `docs: record resumed waiver remediation state`
6. `7e1bbdcdd8da3b3992b5c372a57eb61068cd4f53` — `Harden waiver transition proof against Fable blockers`
7. `5eb73d2e7d51ea6973b5d2ebc225149fe51c5df6` — `docs: record Fable remediation implementation`
8. `00585de36d2aeb39bbc7cd6811484a10db12927f` — `docs: require protected waiver rollout controls`
9. `86cfa854715676d3f844f7b61a2c0701edeb550b` — `docs: record post-rebase waiver verification`

The full SHAs and subjects above were read back from Git after the commits and rebase.

## Required core and rollout blockers

Rollout remains **BLOCKED**.

1. No reviewed compatible immutable axiom-encode core commit exists. The progress-only `cca60e8420596d4aeaf55b8e5a9b872f32958238` lacks `--protected-base-toolchain`; it is not a pin and must not be advertised as compatible.
2. The eventual core must hard-fail unknown or missing flags and independently enforce the documented `validation-waivers audit --root --corpus-path --protected-base --protected-base-toolchain --changed-paths --partition-key --partition-keys-json --axiom-rules-engine-path` raw-evidence contract.
3. Callers must repin that reviewed core and this workflow together, require up-to-date branches or a merge queue, and migrate off the legacy pending-safe workflow before relying on the ratchet.
4. A fresh live upstream/PR check, push, and draft-PR create/update require restored DNS and valid GitHub authentication.

## Remote state and next actions

The first live fetch attempt and the final post-verification retry both failed with `Could not resolve host: github.com`. Read-only `git ls-remote` also failed DNS; `gh pr list`, issue/PR lookup, and search could not connect to `api.github.com`; and the final `gh auth status` returned 1 because the configured `MaxGhenis` token is invalid. The local `origin/main` snapshot contains the one behind commit that existed on resume and was reconciled, but it cannot be certified as the current live tip from this environment.

Because the remote preconditions are not green, no push or PR mutation was attempted after finalization. When connectivity and authentication are restored:

1. Fetch live `origin/main`, compare it with `7dcdf2c5f46ee2a5d38e8f3c176eba52099a6a5a`, reconcile if needed, and rerun the full gate.
2. Push `fix/1558-waiver-transition-workflow`.
3. Open or update only a **draft** PR using `PR_BODY.md` and verify the actual title, body, draft state, base SHA, head SHA, and branch.
4. Freeze the resulting exact head for a second served-model-attested Fable review.
5. Do not merge or roll out until the reviewed compatible core SHA and caller controls exist.

## Frozen-review readiness

The local head `86cfa854715676d3f844f7b61a2c0701edeb550b` is ready for a second frozen Fable review: F1-F5 are implemented inline, every requested adversarial case is exercised from exact extracted workflow source, rollout limitations are explicit, and the full local gate is green. This is review readiness, not merge or rollout readiness.
