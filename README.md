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

The guard also rejects a `backend: manual` apply manifest that introduces a
*new* rule file unless it declares `manual_exception: composition | repair |
fixtures | <issue-ref>`. Net-new statutory encoding must come from an encoder
run; hand-authoring stays legal only for composition/oracle plumbing,
validator-driven repairs, and fixtures, and only by declaring itself. Attest
encoder output committed outside the `--apply` flow with `axiom-encode
sign-applied-files` (add `--manual-exception` for new files, or `--all` to
backfill a corpus that has no manifests). `axiom-encode manifest-census`
reports each repo's encoder-generated / manual / unmanifested coverage.

`programs/` holds axiom-compose ProgramSpecs, which are assembled rather than
encoded, and the supervised guard does not cover it. By default (`guard-programs-root:
false`) the early pre-check requires every changed `programs/` file to have the
ProgramSpec shape: only ProgramSpec keys, scope entries under an encoded root,
known compose patterns, and no numeric literals other than 0, 1 and 12 in
formulas. That keeps hand-written modules and amounts out of the root. Setting
`guard-programs-root: true` instead requires an encoder apply manifest on every
changed `programs/` file. No current encoder tool can produce one for a
ProgramSpec, so opting in freezes the root.

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
