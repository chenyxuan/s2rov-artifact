# Experiment Truthfulness Verdict

Date: 2026-08-30

Verdict: `FULLY_TRACEABLE_AND_CONSISTENT`

## Basis

- **Provenance:** Every retained Figure 2, Figure 3, and Figure 4 number traces
  to hash-bound row-level inputs, a recorded transformation, and a generated
  source table. No value was inferred from prose or copied without an artifact.
- **Recomputation:** Figure 2 is rebuilt from the pinned 587-row candidate set,
  complete policy grid, and fixed rollout orders. Section V-B handoff stages and
  complete-round contrasts are rebuilt from monotonic event timestamps. All 12
  Figure 3 bar estimates are independently recomputed from 150 raw workers.
  Figure 4 is rebuilt only after its Phase 7, extension, and Phase 9 inputs pass.
- **Completeness:** All reported conditions are present. There is no
  `CLAIMED_BUT_NOT_RUN` cell and no omitted failed trial.
- **Code-paper agreement:** The manuscript's selected-policy classifier,
  three handoff workflows, controlled load and classification scopes, live controls, and split
  routing-model lanes match their implementations and archived protocols.
- **Design correctness:** Figure 2 varies matching-ROA placement over candidate
  paths and compares six OpenScope placement levels over fixed random rollout
  orders. It reports medians in the figure and retains rollout ranges in the
  source data. The manuscript uses complete rounds for the Section V-B handoff
  comparison, medians of 20
  load workers and five classification workers per cell for Fig. 3, a
  finite-frame interval for Fig. 4(a), and a selected-unit stability interval
  for Fig. 4(b). It does not
  combine the two announcement sets into one frontier.

## Passed integrity checks

- Correctness gate: 106,218 legal vectors, 100,000 malformed trials, zero
  reported failures, and nine byte-identical deterministic outputs.
- Figure 2: 587/587 candidate rows, 83 IPv4 and 14 IPv6 root groups, complete
  target and secondary decision-budget grids, verified remaining/avoided
  identities, monotonicity, full-coverage endpoints, and hash-verified products.
- Section V-B handoff: 240/240 handoffs, 72/72 independent checks, additive
  stage reconstruction, and hash-verified artifacts.
- Figure 3: 150/150 worker records, byte-identical serialization round trips,
  fixed query hashes, fixed result hashes, fixed state vectors, all results
  OpenScope, and `all_checks_pass: true` in the independent audit.
- Figure 4: 36,800/36,800 frozen scenarios retained, the independent
  14,000-scenario extension verified, all 23 plotted source rows present, and
  corrected Phase 9 competition intervals applied.

Blocking issues: none for the claims as currently worded.

## Nonblocking boundaries

The verdict concerns traceability and internal consistency, not external
generality. The benchmark was run from a dirty worktree, but file-level hashes
bind the actual script, classifier, run configuration, and selected inputs. The
handoff remains a selected local stack, and the deployment estimates remain
conditional on a fixed routing model. Figure 2 reports counterfactual residuals
within a frozen candidate frame, not actual ROV-conflict prevalence. The manuscript
states these boundaries
and does not promote them into production or Internet-wide claims.
