# Encoding lanes

Live board: [Encoding lane registry](https://github.com/TheAxiomFoundation/.github/blob/lanes-registry/LANES.md) (updated every 6 hours).

<!-- curated:start -->
## Lane ownership and standing constraints (curated — edit by PR only)

**Claim-before-build rule**: before building on any shared surface (encoder, corpus schema,
signing/identity, a lane's release machinery), claim it with a comment on the relevant issue.
Verbal/relayed "nobody's on this" goes stale in hours; tracker claims don't. (Adopted after
the encoder-identity collision, 2026-07-18.)

- **us** — owners: @MaxGhenis (strict-cutover / bind rulespec-us#911) + @PavelMakarchuk (encode waves).
  Landmines: large encode-wave review queue (live count in the table); release binding pending
  (see `ops/strict-cutover/founding-brief.md`).
- **uk** — CTR campaign + 296-council expansion. The
  [corpus#366](https://github.com/TheAxiomFoundation/axiom-corpus/issues/366) 22-key
  re-versioning is RESOLVED (2026-07-22: copy-forward successor scopes `-r2026-07-20-datefix`
  via corpus#477 — originals stay byte-untouched since the live 07-14 release still resolves
  them; `uk-rulespec-2026-07-22` published). Gate: the 07-22 rebind
  [rulespec-uk#162](https://github.com/TheAxiomFoundation/rulespec-uk/pull/162), held for Max.
- **nz** — district-plan expansion; self-cuts its own releases (latest pin in the table).
- **tz / de** — Path R signed-apply batch: CI legs deployed (tz#14 / de#14 merged 2026-07-17,
  de#21 workflow fix 2026-07-21). Release-mirror credential fixed + backfilled 2026-07-22
  ([corpus#441](https://github.com/TheAxiomFoundation/axiom-corpus/issues/441) stays open only
  for pre-rotation legacy-key objects). Gates: Max's GO on the billed signed-apply dispatch;
  de repin rulespec-de#22 open.
- **ca** — no longer dormant: migration landed, bound to
  `ca-rulespec-2026-07-21-oracle-complete-v2` (self-cut 2026-07-21).
- **dk / be / ng / gh / ug / zm / et / rw** — stable post-migration.
- **Org-wide**: coordination + billing directive on
  [.github#39](https://github.com/TheAxiomFoundation/.github/issues/39); migration runbook at
  `ops/1101-migration/migration-gauntlet-runbook.md` (TheAxiomFoundation mirror of Max's ops tree).
<!-- curated:end -->
