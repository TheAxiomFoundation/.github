# The Axiom Foundation

**The world's rules, encoded.**

The Axiom Foundation publishes open, machine-readable encodings of the
world's rules, starting with tax and benefit policy — statutes, regulations,
and policy rules turned into cited, time-aware, executable code that anyone
can run, audit, or reform.

Start here:

- [axiom.org](https://axiom.org) — the Axiom App: explore encoded law
- [axiom.org/architecture](https://axiom.org/architecture) — the interactive
  map of how everything below fits together
- [RuleSpec format reference](https://github.com/TheAxiomFoundation/axiom-rules-engine/blob/main/docs/rulespec-format.md)
  and [operational semantics](https://github.com/TheAxiomFoundation/axiom-rules-engine/blob/main/docs/rulespec.md)
  — the encoding format itself

## Reading the code

The short path for a first read:
[axiom-local](https://github.com/TheAxiomFoundation/axiom-local) runs an
encoded corpus on your own machine in a few commands;
[axiom-rules-engine](https://github.com/TheAxiomFoundation/axiom-rules-engine)
is the compiler and runtime the whole stack shares, and its `docs/` folder
documents RuleSpec;
[axiom-corpus](https://github.com/TheAxiomFoundation/axiom-corpus) holds the
legal sources every encoding cites; and
[axiom-encode](https://github.com/TheAxiomFoundation/axiom-encode) is the
pipeline that turns sources into RuleSpec under compile, proof, and oracle
gates.

## The pipeline

Sources in, executable programs out:

| Repo | What it does |
| --- | --- |
| [axiom-scrapers](https://github.com/TheAxiomFoundation/axiom-scrapers) | Source scrapers for statutes, regulations, guidance, bills, and rulemaking; feeds corpus ingest. |
| [axiom-corpus](https://github.com/TheAxiomFoundation/axiom-corpus) | Legal source corpus: statutes, regulations, guidance, manuals, and policy documents with canonical citation paths. |
| [axiom-bills](https://github.com/TheAxiomFoundation/axiom-bills) | Live bill tracker for federal and state legislatures. |
| [axiom-encode](https://github.com/TheAxiomFoundation/axiom-encode) | AI-assisted RuleSpec encoding infrastructure with compile, proof, and oracle gates. |
| [axiom-rules-engine](https://github.com/TheAxiomFoundation/axiom-rules-engine) | RuleSpec compiler and runtime for executable law (Rust; wasm and Python bindings). |
| [axiom-compose](https://github.com/TheAxiomFoundation/axiom-compose) | Deterministic program composer: spec + encodings → runnable program. |
| [axiom-oracles](https://github.com/TheAxiomFoundation/axiom-oracles) | Oracle adapters and cross-engine validation comparisons (PolicyEngine, TAXSIM, EUROMOD-family models, and more). |
| [axiom-microsim](https://github.com/TheAxiomFoundation/axiom-microsim) | Population-scale microsimulation running on the Axiom engine. |
| [receipt](https://github.com/TheAxiomFoundation/receipt) | Verifiable custody of agent-produced records: chained manifests, timestamp witnesses, offline verification. |
| [axiom-mcp](https://github.com/TheAxiomFoundation/axiom-mcp) | MCP server so agents and assistants can query encoded rules. |
| [axiom.org](https://github.com/TheAxiomFoundation/axiom.org) | The Axiom Foundation website and the Axiom App. |

## Encodings

RuleSpec corpora live in per-country repositories. The two groups below
differ in coverage depth, not in kind — every lane carries encodings with
companion tests as it grows.

Broad country corpora:
[rulespec-us](https://github.com/TheAxiomFoundation/rulespec-us) (federal
plus state law as `us-XX/` directories),
[rulespec-uk](https://github.com/TheAxiomFoundation/rulespec-uk),
[rulespec-ca](https://github.com/TheAxiomFoundation/rulespec-ca),
[rulespec-be](https://github.com/TheAxiomFoundation/rulespec-be),
[rulespec-de](https://github.com/TheAxiomFoundation/rulespec-de),
[rulespec-gh](https://github.com/TheAxiomFoundation/rulespec-gh),
[rulespec-nz](https://github.com/TheAxiomFoundation/rulespec-nz).

Earlier-stage lanes (self-described source registries, building toward
oracle parity):
[rulespec-bo](https://github.com/TheAxiomFoundation/rulespec-bo),
[rulespec-co](https://github.com/TheAxiomFoundation/rulespec-co),
[rulespec-dk](https://github.com/TheAxiomFoundation/rulespec-dk),
[rulespec-ec](https://github.com/TheAxiomFoundation/rulespec-ec),
[rulespec-eg](https://github.com/TheAxiomFoundation/rulespec-eg),
[rulespec-et](https://github.com/TheAxiomFoundation/rulespec-et),
[rulespec-mz](https://github.com/TheAxiomFoundation/rulespec-mz),
[rulespec-ng](https://github.com/TheAxiomFoundation/rulespec-ng),
[rulespec-pe](https://github.com/TheAxiomFoundation/rulespec-pe),
[rulespec-rw](https://github.com/TheAxiomFoundation/rulespec-rw),
[rulespec-tz](https://github.com/TheAxiomFoundation/rulespec-tz),
[rulespec-ug](https://github.com/TheAxiomFoundation/rulespec-ug),
[rulespec-vn](https://github.com/TheAxiomFoundation/rulespec-vn),
[rulespec-zm](https://github.com/TheAxiomFoundation/rulespec-zm).

US state rules moved into `rulespec-us`; the old per-state repos
(`rulespec-us-ca`, `rulespec-us-ny`, …) are archived.

## Interfaces and demos

| Repo | What it shows |
| --- | --- |
| [rulespec-graph-viewer](https://github.com/TheAxiomFoundation/rulespec-graph-viewer) | Standalone RuleSpec computation-graph viewer (a scoped copy also renders graphs inside axiom.org). |
| [axiom-architecture](https://github.com/TheAxiomFoundation/axiom-architecture) | Interactive architecture viewer, served at axiom.org/architecture. |
| [axiom-local](https://github.com/TheAxiomFoundation/axiom-local) | RuleSpec executing in your browser — no data leaves the page. |
| [axiom-reg-demo](https://github.com/TheAxiomFoundation/axiom-reg-demo) | UK regulation computed in the browser on the wasm engine. |
| [dashboard-builder](https://github.com/TheAxiomFoundation/dashboard-builder) | Wizard that composes benefit-rule dashboards from selected inputs and outputs. |
| [axiom-demo-shell](https://github.com/TheAxiomFoundation/axiom-demo-shell) | Demo gallery, served at axiom.org/demos. |
| [co-snap-cliffs](https://github.com/TheAxiomFoundation/co-snap-cliffs) | Colorado SNAP cliff explorer. |
| [co-snap-workflow-checker](https://github.com/TheAxiomFoundation/co-snap-workflow-checker) | Colorado SNAP workflow checker. |
| [finbot-snap-demo](https://github.com/TheAxiomFoundation/finbot-snap-demo) | Chat demo at axiom.org/chatbot: an OpenAI model with tool access to the Axiom rules engine, for US benefit and tax estimates. |
| [encodebench.org](https://github.com/TheAxiomFoundation/encodebench.org) | EncodeBench site: how well AI models encode law. |

## Archived repos

Archived repositories (the per-state `rulespec-us-*` set, `atlas-viewer`,
`axiom-programs`, and others) stay online for history. The archive banner on
a repo is authoritative — current work lives in the repositories above.

## Links

- https://axiom.org
- hello@axiom.org

**[Encoding lane registry](../LANES.md)** — live board of every jurisdiction lane: activity, release pins, owners, standing constraints. Auto-refreshed every 6h.
