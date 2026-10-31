# Candidate selection

Which aggregate prefixes have a registry path that a subprefix announcement
could exploit. This is the experiment behind Table I.

`allocation_tree/` holds the pipeline: RIPE Database and RIS ingestion, the
allocation-tree walk, and the AS-level join. `ndss26_analysis/` replays the
published NDSS 2026 invalid-route corpus as an independent cross-check; it is
context for related work, not a source of any number in the paper.

Inputs are the RIPE snapshot and the RIS RIB and bview dumps for 24 June 2026.
They are not bundled; `EXCLUDED-RAW-DATA.md` names each one and the entry point
that fetches it. The derived candidate table is archived under
`results/tables/candidates/`.

Entry point: `allocation_tree/run_analysis.py`.
