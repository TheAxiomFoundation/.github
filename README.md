# The Axiom Foundation

**The world's rules, encoded.**

Axiom builds open, machine-readable encodings of statutes, regulations, and
policy rules. The durable surface is RuleSpec YAML plus normalized law data; the
tooling is designed for transparent review, deterministic tests, and compiler
validation.

## Core Projects

| Project | Description |
| --- | --- |
| [axiom.org](https://github.com/TheAxiomFoundation/axiom.org) | Axiom website and app for navigating encoded law. |
| [axiom-rules-engine](https://github.com/TheAxiomFoundation/axiom-rules-engine) | RuleSpec compiler and runtime. |
| [axiom-encode](https://github.com/TheAxiomFoundation/axiom-encode) | AI-assisted RuleSpec encoding and validation tooling. |
| [axiom-scrapers](https://github.com/TheAxiomFoundation/axiom-scrapers) | Ingestion tooling for collecting and normalizing legal source text. |

## Rule repositories

| Repo | Coverage |
| --- | --- |
| [rulespec-us](https://github.com/TheAxiomFoundation/rulespec-us) | United States federal rules. |
| [rulespec-us-ca](https://github.com/TheAxiomFoundation/rulespec-us-ca) | California rules. |
| [rulespec-us-ny](https://github.com/TheAxiomFoundation/rulespec-us-ny) | New York rules. |
| [rulespec-ca](https://github.com/TheAxiomFoundation/rulespec-ca) | Canada rules. |

## Shared CI

Jurisdiction rule repositories should keep a small local `validate` workflow that
calls the centralized reusable workflow in this repository:

```yaml
jobs:
  validate:
    uses: TheAxiomFoundation/.github/.github/workflows/validate-rulespec.yml@<workflow-commit-sha>
    secrets: inherit
    with:
      axiom-encode-ref: <40-character-commit-sha>
      axiom-rules-engine-ref: <40-character-commit-sha>
      axiom-corpus-ref: <40-character-commit-sha>
      rulespec-us-ref: <40-character-commit-sha>
      corpus-release-base-url: <https-r2-bucket-base-url>
```

By default, the workflow validates RuleSpec YAML under `statutes/`,
`regulations/`, and `policies/`.

Pin the reusable workflow itself by commit SHA. The workflow accepts no mutable
dependency refs: each dependency input must be a full commit SHA, and the
checked-out commit must be an ancestor of that repository's remotely advertised
default branch. Format-only ref validation is not sufficient.

Rules repositories should pin their Axiom toolchain in `.axiom/toolchain.toml`:

```toml
[toolchain]
axiom_corpus_release = "us-rulespec-2026-07-10"
axiom_corpus_release_content_sha256 = "<64-character-lowercase-sha256>"
validation_waiver_set_sha256 = "<sha256-of-exact-known-validation-gaps.yaml-bytes>"
```

This table is mandatory and must contain exactly those three keys. The workflow
does not accept dependency refs, versions, selector aliases, or nested ref
tables in it. Before running the encoder, the workflow downloads the exact
signed object from
`<corpus-release-base-url>/releases/<name>/<content_sha256>.json` into the
corpus checkout's matching `releases/<name>/<content_sha256>.json` path. It
checks the content address and release name immediately; the protected
verification supervisor then verifies its Ed25519 signature and supplies all
three public trust roots without exposing signing capability.

After authenticating the corpus provenance commit, the workflow checks for
`.axiom/corpus-locks/` in the corpus checkout. When it is absent, the workflow
logs a skip and preserves the existing behavior for pre-switch corpus pins.
When it is present, the pinned encoder must include `axiom-encode corpus-fetch`
([axiom-encode#1742](https://github.com/TheAxiomFoundation/axiom-encode/pull/1742)).
The workflow runs that command outside the protected supervisor to place the
pinned release's provisions before provisioning the supervisor or running its
gates. It uses the release object already acquired above, and places only bytes
whose size and SHA-256 match both that release and the checkout's scope locks.

For provisions available only in R2, configure read-only organization or
repository secrets `R2_CORPUS_READ_ACCESS_KEY_ID` and
`R2_CORPUS_READ_SECRET_ACCESS_KEY`, and pass them with `secrets: inherit` as in
the example. The placement step exposes them only as `R2_ACCESS_KEY_ID` and
`R2_SECRET_ACCESS_KEY`; supervised gates receive no cloud credentials. Releases
whose provisions are available from the checkout's git history do not need
these secrets. The bucket comes from the release object, and the command uses
the built-in R2 account endpoint; no endpoint or account secret is required.

Configure those protected roots as `AXIOM_ENCODE_APPLY_SIGNING_PUBLIC_KEY`,
`AXIOM_ENCODE_EVAL_SIGNING_PUBLIC_KEY`, and
`AXIOM_CORPUS_RELEASE_PUBLIC_KEY` organization or repository variables. They
are deliberately not workflow-call inputs, so a caller change cannot replace
its own verification roots.

`known-validation-gaps.yaml` is mandatory and its exact bytes must hash to
`validation_waiver_set_sha256`. On a pull request, the encoder's typed waiver
audit compares it with the protected base revision and rejects any new or
broadened waiver; entries may only be removed. A toolchain or caller-workflow
change runs full RuleSpec validation so a release or waiver-set change cannot
hide behind changed-file selection.

The workflow rejects singular rule roots, separate parameter or test fixture
files, YAML fixtures under `tests/`, non-RuleSpec YAML outside the approved
roots, obsolete generated formula artifacts, manual RuleSpec YAML edits without
an Ed25519-signed `axiom-encode --apply` manifest, and unclassified PolicyEngine
oracle coverage. New executable outputs must either have
an exact PolicyEngine mapping or a harness-side `not_comparable` classification
with a rationale.

The encoder behavior in this paragraph is historical documentation for
axiom-encode `436cf3044` (2026-10-08), not an audit of the current external
implementation. Its guard rejected a `backend: manual` apply manifest that introduced a
*new* rule file unless it declares `manual_exception: composition | repair |
fixtures | <issue-ref>`. Net-new statutory encoding required an encoder
run; hand-authoring was permitted only for composition/oracle plumbing,
validator-driven repairs, and fixtures, and only by declaring itself. The local
`axiom-encode sign-applied-files` attestation command was removed in the
encoder hard cut (axiom-encode#1108, commit `bebfee404`); at the documented
`436cf3044` revision, signed manifests came from its protected
`targeted-signed-reencode` workflow. `axiom-encode manifest-census`
reported each repo's encoder-generated / manual / unmanifested coverage.

`programs/` holds axiom-compose ProgramSpecs, which are assembled rather than
encoded. The local validator's default precheck shape-checks them instead of
requiring encoding manifests. Every changed `programs/` file, `.test.yaml`
included, must have the ProgramSpec shape:

- only ProgramSpec keys, and a `program` of `<jurisdiction>/<name>...`;
- import scope keys `federal`, `state` or a jurisdiction, with at least one
  import entry;
- every import entry resolves using the order documented for axiom-compose
  `fabe0b3b` and the artifact engine `98af0dce` (the pins documented for
  rulespec-us on 2026-10-09: the checkout's own prefix at the root then under
  `<prefix>/`, any other prefix
  under `rulespec-<prefix>/` then `<prefix>/`), to an existing regular-file
  encoded module at the local precheck's allowed depth (`<root>/...` or
  `<jurisdiction>/<root>/...`), with no symlink on the way. Callers on other
  compose or engine pins should confirm their resolution order matches;
- known compose patterns, and plain-identifier or date rule metadata;
- no quotes or backslashes, and no numeric literals other than 0, 1 and 12,
  in any other transformation value (`#` comments are ignored).

This is a lexical tripwire. It catches a hand-written module or a literal
amount, but arithmetic on the allowed literals is not prevented, so review
still owns ProgramSpec formulas. Setting `guard-programs-root: true` also
requires a tracked encoding manifest for each changed `programs/` file.
That check verifies no signature. This repository supplies no ProgramSpec
manifest producer. Confirm an external producer's supported inputs and audited
revision before enabling that optional check.

Repos can opt into stricter structure checks by adding
`.axiom/repository-structure.yaml`. When present, the reusable workflow treats it
as the source of truth for allowed top-level directories, allowed top-level
files, and per-folder file extensions or sentinel filenames. This is intended
for country repos that need to keep executable oracle adapters, generated
outputs, and source dumps out of the RuleSpec corpus:

```yaml
version: 1
allowed_root_directories:
  - .axiom
  - .github
  - data
  - nz
  - tests
allowed_root_files:
  - .gitignore
  - CLAUDE.md
  - README.md
  - known-validation-gaps.yaml
  - variables.toml
path_rules:
  - patterns: [".axiom/**"]
    allow_extensions: [".toml", ".yaml"]
  - patterns: [".github/**"]
    allow_extensions: [".yml", ".yaml"]
  - patterns: ["data/**"]
    allow_extensions: [".json", ".jsonl", ".yaml", ".yml"]
  - patterns: ["nz/**"]
    allow_extensions: [".yaml"]
    allow_filenames: [".gitkeep"]
  - patterns: ["tests/**"]
    allow_extensions: [".py"]
```

### Base-anchored encoder guard

The enforcement point is an **organization ruleset** using
**Require workflows to pass before merging**, not a required status-check name. Adopt
[rulesets/rulespec-encoder-guard.json](rulesets/rulespec-encoder-guard.json)
after this workflow merges: replace its **40-zero release placeholder** in
`sha` with the full 40-character commit SHA containing the reviewed workflow.
The JSON selects this public repository (repository ID `1146671719`),
`.github/workflows/encoder-guard.yml`, and that immutable source SHA. It is
active, has no bypass actors, and targets the default branch of every
`rulespec-*` repository except `rulespec-graph-viewer`. The placeholder cannot
resolve; this file is an adoption definition, not evidence of an applied
organization setting. Its `do_not_enforce_on_create: true` permits repository
initialization before a required workflow can run. Complete the adoption
checklist below before applying it. See GitHub's
[required-workflow rule](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging)
and [ruleset API schema](https://docs.github.com/en/rest/orgs/rules#create-an-organization-repository-ruleset).

A RuleSpec PR cannot edit, delete, or impersonate that pinned workflow through
its own workflow files. GitHub records the required workflow's run conclusion
in the target repository; the ruleset requires that workflow identity. A job
named `encoder-guard / guard` is insufficient: required status checks do not
identify their workflow or event. Keep the existing validator enabled for its
additional checks. The [caller template](workflow-templates/encoder-guard-caller.yml)
is optional and only provides local visibility. If installed, replace its
separate release placeholder with the same full SHA. It is not an enforcement
point. See GitHub's
[status-check matching documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#troubleshooting-required-status-checks).

**Branch freshness is a mandatory companion policy on every targeted repository.**
Pair this workflow ruleset with branch protection that enables
**Require branches to be up to date before merging** (strict required status
checks), or require a merge queue whose actual **group head** this guard
evaluates. A workflow pass records the event's base, so a pass against an
older base must not authorize a later merge after that base advances.
The workflow rule's JSON has no branch-freshness parameter; requiring this
workflow alone does not supply strictness. Configure the companion policy
separately. See GitHub's [strict branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)
and [merge queue rule](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-merge-queue).

The workflow declares `pull_request`, `pull_request_target`, and `merge_group`,
without branch or path filters. PR activity types include `edited` for
retargeting, along with `opened`, `synchronize`, `reopened`, and
`ready_for_review`; merge groups use `checks_requested`. **GitHub currently
ignores event filters, including `types`, for ruleset workflows** and runs
only the default PR activities (`opened`, `synchronize`, `reopened`) and
`merge_group.checks_requested`. Thus declaring `edited` enables ordinary
workflow/caller runs but does not guarantee a fresh ruleset run after
retargeting. After changing a PR's base, push/update its branch or close and
reopen it to obtain a fresh required-workflow run against the current base.
This operational step is not enforced by the ruleset JSON. A base-branch push
also does not guarantee a PR `synchronize` event, which describes a head update.
The hosted acceptance test below must verify merge acceptance after both
retargeting and base advancement. Local tests verify payload handling, not
GitHub's merge decision. See
[supported ruleset events](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#supported-event-triggers).

The check uses the event payload's exact PR `base.sha` / `head.sha`, or merge
group's `base_sha` / `head_sha`. It ignores mutable refs, `GITHUB_SHA`, and the
previous base in `changes` on an edited event. Manifest inventory comes from
the proposed **merge result**, not the candidate head alone: use the event's
test merge commit only when its parents are the exact base and head, or compute
the merge in a scratch index from Git objects only. Merge groups use their
actual group head and require the event base to be its ancestor. Conflicts
fail the guard.

The guard also protects the repository's validation pins. It reads regular Git
blobs from that exact event base and proposed merge result. When
`.axiom/workflow-toolchain.toml` is present, it parses the complete
`[workflow_toolchain]` table, including the encoder and other validation pins.
Otherwise it reads literal validation ref inputs, including `axiom-encode-ref`,
from `.github/workflows/repository-checks.yml` or its `.yaml` counterpart. It
compares the pin source, the full table, and both caller files' exact bytes.
Malformed or nonregular TOML and invalid literal pins fail closed; repositories
with neither source retain initialization compatibility. No candidate workflow
expression or head content is executed.

**Pin changes must be their own pull request.** A pin source, pin value, or
caller-workflow change cannot share a PR with any changed content under
`statutes/`, `regulations/`, `policies/`, `legislation/`, or `programs/`, at the
top level or under a jurisdiction. This also covers encoding manifests and
other provenance receipts: the guard conservatively protects all root or
jurisdiction-root `.axiom/` metadata except `workflow-toolchain.toml` and
`toolchain.toml`, plus `known-validation-gaps.yaml` evidence. Caller edits are
compared by exact bytes, so cosmetic edits to those files must also be isolated
from these content changes. Pin-only PRs and module-only PRs with unchanged pins
pass this isolation check, subject to the existing manifest checks. ProgramSpecs
retain their manifest exemption below, but their content changes must still be
separate from pin changes.

This protects the trust anchor for the proposed
[axiom-encode#1844 admission rule](https://github.com/TheAxiomFoundation/axiom-encode/pull/1844),
which would accept production-signed manifests from encoder-main commits that
descend from the repository's encoder pin. Without this isolation, a PR could
lower its own pin while changing the modules or receipts validated against it.
The protected-base comparison prevents that choice in the same PR. Pin-only
updates need full repository revalidation; the workflow-toolchain bump behavior
is supplied by [.github#126](https://github.com/TheAxiomFoundation/.github/pull/126).
Callers must use a validator revision that includes that behavior. This
description does not establish that the external admission proposal is deployed
or audited.

Module selection compares the exact event base with the proposed merge result,
so candidate edits are checked at their final paths after any base-side rename,
and base-only changes are outside that diff. Three-dot comparison of base and
candidate head separately selects manifest removals and same-change receipts.
Added, modified, type-changed and renamed `.yaml` or `.yml` modules under
`<jurisdiction>/(statutes|regulations|policies|legislation)/` require a regular
manifest blob in that merge result; top-level module roots are covered too.
For `us/statutes/title/foo.yaml`, any of these mirrors counts:

- `.axiom/encoding-manifests/us/statutes/title/foo.json`
- `.axiom/encoding-manifests/statutes/title/foo.json`
- `us/.axiom/encoding-manifests/statutes/title/foo.json`

Existing tracked manifests count as well as newly changed ones. This presence
check exempts companion `.test.yaml` and `.test.yml` files and `/composed/`
pipelines. ProgramSpecs are excluded from the supervised generated guard.
The validator's separate ProgramSpec precheck includes companion files under
`programs/`; it checks their shape too. As in its default precheck,
shape-checked ProgramSpecs are assembled content outside the atomic RuleSpec
manifest gate; no manifest is required by this guard. Keep that validator
enabled to enforce the shape contract.

A change that deletes or renames away a manifest whose atomic module still
exists in the merge result is rejected. A retirement receipt cannot excuse a
surviving module. Removing a manifest with its module requires that module to
be deleted in the same candidate diff, absent from the merge result, and named
in a changed regular JSON encoding manifest's `applied_files` with
`sha256: "deleted"`. Receipt paths are relative to the checkout root or their
jurisdiction-root manifest location. This presence check does not authenticate
the receipt's signature or content. Checkout-root and jurisdiction-root
`.axiom/` metadata is outside module roots. There is no exception file.
This guard checks object presence and removal consistency; the existing
validator invokes the external supervised `guard-generated` implementation.
Audit that implementation at the pinned encoder revision for its signature,
module-hash and retirement-receipt verification contract. This checkout alone
does not establish its complete protected-root scope or the absence of an
external ProgramSpec producer. See the existing
[validator implementation](.github/workflows/validate-rulespec.yml).

The guard and optional caller grant only `contents: read`, declare no secrets,
and use no `secrets: inherit`. The ruleset pins the workflow source; checkout
explicitly selects the target event's `github.repository` and validated base
SHA, rather than this shared repository or a PR merge ref. The event's built-in
`github.token` is limited to read-only repository contents; unspecified token
permissions are disabled. A SHA-pinned checkout action acquires only base and
does not persist credentials. A transient authenticated fetch obtains head
and event merge Git objects. Actions reports the job conclusion without
granting the job `checks: write`. Isolated Python and hardened Git object queries execute no
head code or configuration and install no packages. See
[checkout's repository/token defaults](https://github.com/actions/checkout#usage),
[token permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions),
and [event SHA/ref semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

Merge-group payloads are supported regardless of current repository queue
settings. No dated repository/queue inventory or historical CI evidence is
attached here; this section makes no organization-wide audit or historical
validation claim. Historical PR-body observations must name the tested
revision and link retained evidence, or be omitted. Hosted rule enforcement
and the external implementation have not been exercised by local tests;
record its audited revision separately before adoption.

#### ADOPTION CHECKLIST

Complete and retain the evidence for every item **before the ruleset is applied
to production repositories**. Settings inspection and hosted acceptance are
adoption work; passing local fixtures does not complete these items.

- [ ] Run a hosted acceptance test on a sandbox rulespec-style repository with
  no caller workflow (caller-free). Pin the intended source workflow SHA and
  confirm the required workflow runs and governs the merge decision. A module
  change without a manifest must be blocked; a valid encoded change must pass.
  Removing the caller and adding a counterfeit named job must not bypass the
  pinned workflow identity.
- [ ] Exercise the same-head retarget case in that sandbox: open against an
  alternate base, retarget to the default branch, and verify that a prior pass
  cannot authorize the newly guarded change. Confirm the supported head-update
  or close/reopen step produces a required run bound to the new base. Do not
  adopt if the retargeted PR can merge using its old result.
- [ ] Exercise the base-advance case: let a candidate pass, independently
  advance the base, and confirm the candidate cannot merge on the older pass.
  Test deletion and rename of a manifest while its module survives, then rerun
  the candidate against the new merge result and require rejection. Record
  strict branch protection on every targeted repository, or the required
  merge queue and a passing guard run on its actual group head.
- [ ] Verify how the signed encoder workflows **create and update** RuleSpec
  PRs, recording their workflow revision and credential type. Events created
  with `GITHUB_TOKEN` **do not launch ruleset workflows**, so those PRs can
  remain blocked without a required run. If needed, change the producer to a
  narrowly scoped GitHub App installation token or suitable personal access
  token for PR creation and updates, and repeat the sandbox acceptance test
  with a real signed encoder PR. The producer workflows and credentials are
  outside this checkout. See [ruleset workflow troubleshooting](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#troubleshooting-ruleset-workflows).
- [ ] Confirm source repository workflow access settings for cross-repository use,
  including "Accessible from repositories" in this organization where
  applicable, compatible source/target visibility, and target Actions policy
  allowing the pinned actions. Confirm GitHub's cross-repository
  `pull_request` prerequisite: a workflow conditional such as `if: true`, or
  disabling the source workflow/Actions. Record which supported option was
  tested. See [source-workflow prerequisites](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#supported-directory)
  and [workflow visibility/access](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#using-a-workflow-file).
- [ ] Keep `do_not_enforce_on_create: true` and test repository initialization
  in the sandbox; required workflows cannot run while a repository is being
  initialized. Replace the zero-SHA placeholder only with the reviewed release
  commit, refresh pre-existing PRs so their required workflows run, and retain
  the acceptance results with that source SHA. See [creation behavior](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#targeting-specific-branches-with-your-ruleset-workflow).

Run the Git fixture and workflow security tests with
`python3 tests/test_encoder_guard_workflow.py`; they also run in the shared
workflow test CI.

### Run bounds

Each `validate` matrix leg stops after 180 minutes. Within a leg, "Validate
RuleSpec YAML" stops after 120 minutes, "Enforce validation waiver ratchet"
after 150, and "Execute RuleSpec companion tests" after 60. One run starts
at most 20 legs at a time. The org plan allows 60 concurrent hosted jobs, so
two runs of one repository still leave runners for the rest of the org.

A leg that reaches a limit is stopped, and the aggregate `validate` check
fails. Treat that as a hang to fix, not a limit to raise. In September 2026,
green rulespec-us legs took at most 153 minutes; those steps took at most
85, 125, and 33 minutes. A caller gets these bounds only when it moves its
pin to a workflow commit that has them.

## Links

- https://axiom.org
- hello@axiom.org
