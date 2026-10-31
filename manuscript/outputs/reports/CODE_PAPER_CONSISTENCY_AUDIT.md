# Code-Paper Consistency Audit

> Superseded for active Figure 2 on 2026-08-30. The partial-policy findings
> below describe the retired family-specific view; pooled v2 findings are
> recorded in `figures/FIG_PARTIAL_POLICY_REPLAY_PROVENANCE.md`.

Date: 2026-08-29

Result: PASS for the current manuscript and its bounded claims.

## Component mapping

| Described component or protocol | Implemented? | Code or artifact location | Consistency finding |
|---|:---:|---|---|
| Single selected-policy construction, canonical encoding, parsing, most-specific rule selection, and route classification | Yes | `phase4_encoding/scripts/utils/daroa.py` | Matches Secs. III-IV. The paper does not claim multi-object composition or relying-party behavior. |
| Independent semantic oracle and malformed-input gate | Yes | `phase10_semantic_gate/oracle.py`; `run_e1a.py`; `snapshot_oracle.py` | The oracle is separately implemented and the fresh production/reproduction pair matches all nine deterministic outputs. |
| Prefix-index lookup bounded by address width | Yes | `DAROA.find_best_stripe` and Phase 4 tests | The paper reports at most 33 probes for IPv4 and 129 for IPv6, independent of rule count, matching the ancestor walk and boundary tests. |
| Partial-policy candidate replay | Yes | `MSN-2026-0830/scripts/run_partial_policy_replay.py`; `fig_partial_policy_replay.manifest.json` | The hash-pinned 504/83 candidate counts, 83/14 root groups, complete exact-by-scope grid, and 1,000 rollout orders match Fig. 2 and Sec. V-A. The active panels hold the root-scope target at 10% and vary the exact-endpoint target; the equal-decision output remains a secondary artifact. |
| Reactive exact, preinstalled scope, and prepublished exact handoff workflows | Yes | `phase6_system/e2e/scripts/run-handoff-benefit.sh` | The preinstalled policy and pretrial map omit both endpoint origins; all arms derive the new route from Adj-RIB-In and share classifier, compiler, FRR, and probe stages. |
| Handoff timing and complete-round inference | Yes | `events.jsonl`; `summarize_handoff_benefit.py`; `audit_handoff_benefit.py`; `MSN-2026-0830/scripts/analyze_handoff_fig2.py` | Primary observation-to-probe endpoint, five additive stages, ten round clusters per IP-version lane, and bootstrap seed 20260828 match Sec. V-B. |
| Controlled dual-stack selected-policy replay | Yes | `phase5_evaluation/processing_benchmark/run_controlled_policy_benchmark.py`; run `controlled-processing-20260829T1152Z` | Three subprefix counts, separate load and classify workers, warm-up, CPU affinity, fixed queries, fixed OpenScope outputs, and medians match Table II. |
| Live scale and outage controls | Yes | `phase6_system/e2e/outputs/scale-20260823T025539Z`; `run-20260823T024129Z` | The reported 80 transitions, 560 route outcomes, median range, and 15-s retained-action control match archived samples and summaries. |
| Intended-only routing-model lane | Yes | `phase7_simulation/campaign/paper_campaign.py`; `analyze_paper_campaign.py`; Fig. 3 builder | Uses the intended route without a competing origin, aggregate-only baseline, five frozen orders, and exact-ROA reference as described. |
| Separate unlisted-origin competition lane and corrected interval | Yes | Phase 7 raw scenarios; `phase9_selected_unit_reanalysis/reanalyze.py`; Fig. 3 builder | Uses an announcement-matched baseline and selected-unit stability interval, matching Fig. 3(b). |

## Terminology and presentation mappings

- Archived runtime state `Delegated` maps exactly to manuscript state
  `OpenScope`; no outcome value changes under this rename.
- Archived handoff arm `open_dynamic` is presented as `preinstalled scope`.
  The policy is made effective before each measured block, so the manuscript
  label matches the implemented timing boundary.
- Table II's `Subprefixes` counts only additional closed subprefix entries.
  Every measured policy also has one mandatory open base entry.
- Fig. 3 uses `root-origin unit`, not the legacy field's unverified
  organizational interpretation.

## Numeric consistency

- At the 50% exact-endpoint target, exact-only placement leaves 252 (50.0%)
  IPv4 candidates and 42 (50.6%) IPv6 candidates. With the 10% root-scope
  target, random placement leaves medians of 233 (46.2%) [201.9, 244.0] and
  41 (49.4%) [27.0, 42.0], respectively. Fanout-first placement leaves
  129 (25.6%) and 25 (30.1%); fanout-last leaves 248 (49.2%) and 41 (49.4%).
- The 10% target selects 8/83 IPv4 roots and 1/14 IPv6 roots. The random bands
  are rollout percentiles, not confidence intervals.
- The Section V-B handoff means round to 2.5, 1.1, and 1.1 s; the paired
  reactive-minus-preinstalled difference rounds to 1.4 s [1.3, 1.4] s in both
  IP-version lanes.
- All six load medians and all six classification medians recompute from raw
  worker records and round to the displayed cells. Within each IP version,
  query hashes, result hashes, and state vectors are identical across sizes.
- Fig. 3's full-deployment source values round to 17.1 percentage points in
  panel (a) and 8.9 percentage points in panel (b).
- The live-path median range rounds to 3.2--3.9 s and matches the archived
  summary.

## Scope consistency

The manuscript correctly limits Figure 2 to a frozen counterfactual candidate
frame, the prototype to one selected fixture, processing to an in-process
single-core dual-stack reference replay, and the routing model to fixed
conditional scenarios. It does not claim actual conflict prevalence, complete object transport,
general object composition, native router interoperability,
Internet-wide effects, or a joint benefit-exposure frontier.

No described component needed for a retained numerical claim is
`NOT_IMPLEMENTED`, and no manuscript value lacks an executed code path.
