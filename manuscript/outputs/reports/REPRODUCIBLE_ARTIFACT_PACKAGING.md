# Reproducible Artifact Packaging

Date: 2026-08-30

## Decision

Author-side reproducibility status: **PASS** for the retained working tree and
hash-bound evidence chain.

Anonymous distribution status: **HOLD**. The current raw `phase*` directories
must not be uploaded. They contain absolute local paths and host, user,
environment, worktree, or Git metadata. This report documents the required
clean bundle; it does not certify that such a bundle has already been created.

## Claim-bearing components to package

| Evidence layer | Required material |
|---|---|
| Paper build | `MSN-2026-0830/main.tex.tmpl`, `sections/`, `refs.bib`, `template.json`, `blueprint.json`, `IEEEtran.cls`, `IEEEtran.bst`, `Makefile`, and `scripts/assemble_paper.py` |
| Number ledger | `results.facts.json`, `claims_map.json`, `ARTIFACT_PROVENANCE.md`, and the final audit reports |
| Formal semantics | Phase 4 classifier source and tests, plus the frozen E1a corpus, manifests, summaries, and reproducer |
| Fig. 2 | `scripts/run_partial_policy_replay.py`, the hash-pinned 587-row candidate input, the pooled/family/equal-decision source tables, `fig_partial_policy_replay.manifest.json`, and the pooled figure products |
| Section V-B handoff | `scripts/analyze_handoff_fig2.py`, both accepted 120-handoff protocol/trial/event/summary/audit sets, and `HANDOFF_FIG2_REANALYSIS_PROVENANCE.md` |
| Fig. 3 | `phase5_evaluation/processing_benchmark/run_controlled_policy_benchmark.py`, the accepted run configuration, deterministic policy and query manifests, 150 raw worker records, summary files, independent audit, retained table CSV, `scripts/build_processing_cost_figure.py`, figure manifest, and both panel products |
| Fig. 4 | `scripts/build_fig_deployment_outcomes.py`, the Phase 7 intended-only input, grid extension, Phase 9 competition overlay, generated source tables, and the Fig. 4 provenance/manifest |
| Motivation data | The retained RIPE Database/RIS visibility inputs, filtering outputs, plan, data gate, and independent recheck used by Table I |
| Frozen outputs | The active figures' component PDFs and the final `main.pdf` for byte-level comparison |

Historical pilot and inactive figure files may remain in the private author
archive. They should be omitted from the compact anonymous bundle unless they
are explicitly included under an `inactive-audit-history` directory so they
cannot be mistaken for main evidence.

## Sanitization gate

Build the release artifact in a new neutral directory, not by archiving the
working tree. Before packaging:

1. Remove `.git`, `.olcli.json`, editor state, caches, compiled temporary
   files, diagnostic logs not needed for a claim, and private source archives.
2. Replace absolute source/output paths with bundle-relative paths. Remove
   usernames, hostnames, container identifiers, home directories, and
   identity-bearing shell or Git status. Preserve non-identifying scientific
   configuration such as CPU architecture, software versions, seeds, timers,
   and policy sizes.
3. Retain only inputs whose redistribution terms permit inclusion. For inputs
   that cannot be redistributed, provide checksums, provenance, acquisition
   instructions, and deterministic preprocessing commands.
4. State at the top level that the 589-AS list is an opaque fixed scenario
   input. Also state that Fig. 4's intended-only and competition panels use
   different announcement sets.
5. Create a new bundle manifest after sanitization. Any scrubbed file has a
   new hash; map it privately to the original author-side artifact instead of
   claiming hash identity.

## Clean-room acceptance test

The anonymous bundle is releasable only after all of the following pass from a
fresh neutral path:

- identity scan finds no absolute author path, username, hostname, project
  identifier, Git history, or private remote;
- Phase 4 unit tests pass and the frozen semantic summaries reproduce;
- Figure 2 regenerates from all 587 candidate rows and reproduces the pooled
  six-scope grid, manifest gates, and the secondary family/equal-decision data;
- the Fig. 3 raw-to-summary audit reproduces all 12 bar estimates from 150
  worker records without requiring a new timed run, and both panels regenerate
  from the retained CSV artifact;
- the Section V-B handoff analysis reconstructs all 240 handoffs and both
  complete-round contrasts from raw event timestamps;
- Fig. 4 regenerates from the packaged intended-only and Phase 9 competition
  inputs;
- `make` succeeds, produces an 8-page US-Letter PDF, and passes the font,
  reference, citation, and classifier checks;
- the rebuilt manuscript values match `results.facts.json` and the bundle's
  new checksum manifest.

The current manuscript PDF hash must be refreshed after the final build. That
hash will be a comparison target for the author-side snapshot, not a
substitute for the anonymous bundle-level manifest.
