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

The guard also rejects a `backend: manual` apply manifest that introduces a
*new* rule file unless it declares `manual_exception: composition | repair |
fixtures | <issue-ref>`. Net-new statutory encoding must come from an encoder
run; hand-authoring stays legal only for composition/oracle plumbing,
validator-driven repairs, and fixtures, and only by declaring itself. The local
`axiom-encode sign-applied-files` attestation command was removed in the
encoder hard cut (axiom-encode#1108, commit `bebfee404`); as of axiom-encode
`436cf3044` (2026-10-08), signed manifests come from its protected
`targeted-signed-reencode` workflow. `axiom-encode manifest-census`
reports each repo's encoder-generated / manual / unmanifested coverage.

`programs/` holds axiom-compose ProgramSpecs, which are assembled rather than
encoded, and the supervised guard does not cover it. The early pre-check
requires every changed `programs/` file, `.test.yaml` included, to have the
ProgramSpec shape:
- only ProgramSpec keys, and a `program` of `<jurisdiction>/<name>...`;
- import scope keys `federal`, `state` or a jurisdiction, with at least one
  import entry;
- every import entry resolves, as axiom-compose `fabe0b3b` and the artifact
  engine `98af0dce` resolve it (the pins rulespec-us used on 2026-10-09: the
  checkout's own prefix at the root then under `<prefix>/`, any other prefix
  under `rulespec-<prefix>/` then `<prefix>/`), to an existing regular-file
  encoded module at a depth the supervised guard protects (`<root>/...` or
  `<jurisdiction>/<root>/...`), with no symlink on the way. Callers on other
  compose or engine pins should confirm their resolution order matches;
- known compose patterns, and plain-identifier or date rule metadata;
- no quotes or backslashes, and no numeric literals other than 0, 1 and 12,
  in any other transformation value (`#` comments are ignored).

This is a lexical tripwire. It catches a hand-written module or a literal
amount, but arithmetic on the allowed literals is not prevented, so review
still owns ProgramSpec formulas. Setting `guard-programs-root: true` also
requires a tracked encoding manifest for each changed `programs/` file.
That check verifies no signature, and no current encoder tool can produce a
ProgramSpec manifest.

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
resolve; this file is an adoption definition, not an applied organization
setting. See GitHub's
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
Verify hosted retarget/check-freshness behavior before adoption; local tests
verify payload handling, not GitHub's merge acceptance. See
[supported ruleset events](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#supported-event-triggers).

The check compares the event payload's exact PR `base.sha` / `head.sha`, or
merge group's `base_sha` / `head_sha`, using a three-dot merge-base diff.
It ignores mutable refs, `GITHUB_SHA`, and the previous base in `changes` on
an edited event. Added, modified, type-changed and renamed `.yaml`
or `.yml` modules under `<jurisdiction>/(statutes|regulations|policies|legislation|programs)/`
require a regular manifest blob in the head commit; top-level module roots
are covered too. For `us/statutes/title/foo.yaml`, any of these mirrors counts:

- `.axiom/encoding-manifests/us/statutes/title/foo.json`
- `.axiom/encoding-manifests/statutes/title/foo.json`
- `us/.axiom/encoding-manifests/statutes/title/foo.json`

Existing tracked manifests count as well as newly changed ones. This presence
check exempts companion `.test.yaml` and `.test.yml` files and `/composed/`
pipelines. The validator's separate
ProgramSpec shape check also covers companion files under `programs/`.
It checks their shape even when this guard exempts them. Checkout-root and
jurisdiction-root `.axiom/` metadata is outside module roots; deletions are
outside this presence check. There is no exception file or programs opt-out.
It checks mirror presence only. The validator's supervised `guard-generated`
step verifies manifest contents, signatures and module hashes for its encoded
atomic module roots (statutes, regulations, policies, legislation).
ProgramSpecs are excluded from the supervised generated guard; requiring a
manifest here does not establish their authenticity. This change adds no
ProgramSpec manifest producer or signer. See the existing
[validator implementation](.github/workflows/validate-rulespec.yml).

The guard and optional caller grant only `contents: read`, declare no secrets,
and use no `secrets: inherit`. The ruleset pins the workflow source; checkout
explicitly selects the target event's `github.repository` and validated base
SHA, rather than this shared repository or a PR merge ref. The event's built-in
`github.token` is limited to read-only repository contents; unspecified token
permissions are disabled. A SHA-pinned checkout action acquires only base and
does not persist credentials. A transient authenticated fetch obtains head
Git objects. Actions reports the job conclusion without granting the job
`checks: write`. Isolated Python and hardened Git object queries execute no
head code or configuration and install no packages. See
[checkout's repository/token defaults](https://github.com/actions/checkout#usage),
[token permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions),
and [event SHA/ref semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

Merge-group payloads are supported regardless of current repository queue
settings. No dated repository/queue inventory or historical CI evidence is
attached here; this section makes no organization-wide audit or historical
validation claim. Hosted rule enforcement and external encoder implementation
status have not been exercised by these local tests.

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
