# Experiment Completeness Audit

> Superseded for active Figure 2 on 2026-08-30. The partial-policy statements
> below describe the retired family-specific view; the pooled v2 replay has its
> own 10-test gate and provenance record.

Date: 2026-08-29

Result: PASS. Every numeric condition retained in the manuscript is present in
the archived results. No `CLAIMED_BUT_NOT_RUN` condition was found.

## Reported artifacts

| Artifact | Executed combinations | Metrics checked | Status |
|---|---|---|---|
| Correctness gate | 106,218 legal vectors; 100,000 generated malformed objects; production seed 20260826; reproduction seed 120260826 | Oracle/reference/round-trip agreement, rejection, nine deterministic files | `FULLY_RUN` |
| Selected-fixture gate | 124 snapshots x 7 route cases | 868 state and installed-action checks | `FULLY_RUN` |
| Fig. 2 | 504 IPv4 and 83 IPv6 candidate paths below 83 and 14 roots; complete 0%-100% exact-by-scope grid in 10% increments; 1,000 fixed rollout orders plus fanout-first and fanout-last placement | Remaining candidates across exact-endpoint deployment at the fixed 10% root-scope target, rollout percentiles, placement sensitivity, identity and monotonicity gates; equal-decision data retained as a secondary artifact | `FULLY_RUN` |
| Section V-B handoff | 3 workflows x 40 handoffs x 2 IP-version lanes, arranged in 10 complete randomized rounds per lane | Observation-to-probe time, five additive stages, signed transactions, ROA-entry changes, completion | `FULLY_RUN` |
| Table II | 2 IP versions x 3 subprefix counts; 20 fresh load workers and 5 fresh classification workers per cell = 150 workers | In-memory load time, fixed-output classification throughput, query/result hashes, state vectors, round trips | `FULLY_RUN` |
| Live-path scale control | 4 noncovering-rule counts x 2 transitions x 10 repetitions | 80 transition times and 560 route outcomes | `FULLY_RUN` |
| Relying-party outage control | One retained selected-fixture outage state with a 15-s hold | Last installed action retained | `FULLY_RUN` |
| Fig. 3(a) | 200 selected units; 11 target percentages from 0% to 100%; 5 frozen deployment orders at interior cells; 1 exact-ROA reference row | Intended-route delivery and pointwise finite-frame interval | `FULLY_RUN` |
| Fig. 3(b) | Same 200 selected units and 11 target percentages in a separate competition announcement set | Unlisted-origin delivery and pointwise selected-unit stability interval | `FULLY_RUN` |

The Figure 3 source contains 23 plotted rows: 12 for the intended-only panel,
including its exact-ROA reference, and 11 for the competition panel. The frozen
36,800-scenario archive and independent 14,000-scenario extension are both
verified before figure assembly.

## Completeness checks

- Figure 2 retains all 587 candidate rows. Its input hash, family and root
  counts, complete grids, selection identities, monotonicity, and full-coverage
  endpoints pass. The 10% target selects 8/83 IPv4 roots and 1/14 IPv6 roots.
- The Section V-B handoff evidence retains all 240 scheduled handoffs across
  the two lanes. There was no failure filtering, retry filtering, deadline
  miss, or imputation. The inferential unit is the complete randomized round
  within each lane.
- Table II contains 20 repetitions in every load cell and five repetitions in
  every classification cell. `independent_audit.json` reports the exact cell
  matrix, 150/150 worker records, fixed query and output identities, complete
  raw-to-summary recomputation, and `all_checks_pass: true`.
- Figure 3's builder verifies the frozen Phase 7 grid, the independent extension,
  and the corrected Phase 9 interval input before writing the 11-point panels.
- The main-text values in Figure 2, Table II, and Figure 3 match their generated
  source tables after one-decimal rounding.

## Not run and not claimed

The following are `NOT_RUN_BUT_NOT_CLAIMED`: multi-core or concurrent
performance, complete relying-party throughput,
router data-plane or line-rate throughput, standardized complete-object
interoperability, actual ROV-conflict prevalence, Internet-wide deployment effects, a same-scenario
benefit-exposure frontier, and statistical equivalence between preinstalled
scope and prepublished exact ROAs.
