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

Changed protected RuleSpec must carry a signed model receipt from the pinned
encoder agent (`axiom-encode encode --apply`, with an allowlisted model
backend). A `backend: manual` receipt or retroactive `sign-applied-files`
attestation does not authorize new or modified protected RuleSpec. The latter
command remains only as historical inventory and specialized migration input;
fresh replacement bytes still require a new encoder-agent receipt.
`axiom-encode manifest-census` reports each repo's encoder-generated / manual /
unmanifested legacy coverage.

### Durable generated-guard rollout

Repositories can prevent a failed direct push from being hidden by a later
unrelated push by introducing this immutable caller anchor:

```toml
[generated_guard_anchor]
contract = "axiom/generated-guard-anchor/v1"
reviewed_known_good_sha = "<40-character-reviewed-commit-sha>"
```

Store it at `.axiom/generated-guard-anchor.toml`, and grant the caller workflow
both `actions: read` and `contents: read`. The reviewed SHA must predate the
commit that first introduces the anchor and must be a known-good commit on the
same ancestry chain. It must also match the repository's bootstrap SHA in the
reusable workflow's centrally reviewed `REVIEWED_SEEDS` registry. The caller
path and the SHA-normalized digest of the entire caller workflow must likewise
match `REVIEWED_CALLERS`; only the one exact reusable-workflow SHA in its
`uses:` edge is normalized. A caller therefore cannot bless its own earlier
commit, add a lookalike job, or forge the generated-guard step name. The file's
first committed blob is permanent for this contract: changing it even
temporarily, deleting it, or deleting and re-adding it fails closed.

For an anchored repository, the reusable workflow never uses `event.before`,
`origin/main`, or `HEAD~1` as the generated-guard base. It starts at the
reviewed seed and may advance only to a successful default-branch run whose
repository, commit and tree, centrally reviewed caller-workflow contract,
anchor blob, reusable workflow SHA, and completed generated-guard step all
match the current contract. Missing or inconsistent Actions evidence fails the
run. Any non-pin caller-workflow change fails closed until its normalized digest
is added to the central registry. A reusable-workflow SHA upgrade deliberately
resets the next run to the reviewed seed; successes under an older workflow
cannot bootstrap a new trust chain.

Roll this out in order:

1. Add the repository and known-good SHA to `REVIEWED_SEEDS`, plus the exact
   caller path and normalized digest of the caller bytes that will exist after
   step 2 (including its `actions: read` permission) to `REVIEWED_CALLERS`;
   then merge and validate that reviewed shared-workflow release.
2. In a reviewed caller PR, add the anchor and `actions: read` permission while
   retaining the existing reusable-workflow pin. The old workflow ignores the
   new file, so no future shared-workflow SHA needs to be guessed.
3. In another reviewed caller PR, update the reusable-workflow pin to the exact
   merged commit. Its first run scans from the reviewed seed; later exact-
   contract successes can advance the durable base.
4. Repeat the seed scan after every caller-workflow or shared-workflow change.

This is defense in depth, not a substitute for repository policy. Protect both
the caller repository and this shared-workflow repository with pull-request and
code-owner review, dismiss stale approvals (or require approval of the latest
push), block force pushes, and leave no administrator or other bypass actor.
The current resolver is explicitly a local-caller identity mode: protect and
require that reviewed caller workflow. Do not replace it with an organization
required-workflow invocation until a dedicated required-workflow identity mode
is implemented and tested. An app-bound status such as `validate / validate`
alone is insufficient: another Actions workflow can emit the same check name,
and an administrator who can bypass checks can rewrite the caller workflow or
anchor history outside the trust boundary repository code can enforce.

Set `guard-programs-root: true` on the caller to require manifests on the
composed-pilot `programs/` root too (default `false`). Enable it per repo only
after every existing `programs/` file has a manifest or manual attestation,
otherwise the guard fails on the backlog.

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

## Links

- https://axiom.org
- hello@axiom.org
