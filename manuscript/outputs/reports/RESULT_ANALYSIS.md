# Result Analysis

> Superseded for active Figure 2 on 2026-08-30. The partial-policy discussion
> below describes the retired family-specific view; pooled v2 results are in
> `figures/FIG_PARTIAL_POLICY_REPLAY_PROVENANCE.md`.

Date: 2026-08-29

## Overall decision

The three evaluation layers support the manuscript's bounded claims. The
partial-policy replay holds the root-scope target at 10% and measures how many
candidate conflicts remain as exact-endpoint deployment varies. The controlled
system experiments measure handoff and selected-policy costs, and the routing
model separates intended-route benefit from unlisted-origin exposure. None
supports actual ROV-conflict prevalence, Internet-wide latency,
production-router throughput, or a same-scenario benefit-exposure claim.

## Main outcomes

| Outcome | Result | Support label | Primary evidence |
|---|---|---|---|
| Fig. 2, partial-policy deployment | At the 50% exact-endpoint target, exact-only placement leaves 252 (50.0%) IPv4 candidates and 42 (50.6%) IPv6 candidates. With the 10% root-scope target, random placement leaves medians of 233 (46.2%) [201.9, 244.0] and 41 (49.4%) [27.0, 42.0]. Fanout-first placement leaves 129 (25.6%) and 25 (30.1%), while fanout-last leaves 248 (49.2%) and 41 (49.4%). | Supported within the frozen candidate frame | `MSN-2026-0830/figures/fig_partial_policy_replay.manifest.json`; `FIG_PARTIAL_POLICY_REPLAY_PROVENANCE.md` |
| Sec. V-B, handoff workflow | Mean observation-to-probe time was 2.5 s for reactive exact and 1.1 s for both preinstalled scope and prepublished exact in each IP-version lane. Reactive exact minus preinstalled scope was 1.4 s [1.3, 1.4] s. | Supported for the controlled workflow | Accepted event streams; `MSN-2026-0830/figures/HANDOFF_FIG2_REANALYSIS_PROVENANCE.md` |
| Table II, processing cost | With one fixed base plus 0, 64, or 256 additional subprefix entries, load medians were 0.3-17.8 ms for IPv4 and 0.4-29.2 ms for IPv6. Fixed-output classification remained 27.5-28.4 and 18.5-19.1 thousand pairs/s, respectively. | Supported | `phase5_evaluation/processing_benchmark/outputs/controlled-processing-20260829T1152Z`; `summary.json`; `independent_audit.json` |
| Fig. 3(a), intended-only lane | At all 589 upgrades, delivery rose from 82.1% to 99.2%, a gain of 17.1 percentage points [13.3, 21.0]. It equaled the exact-ROA reference in this lane. | Supported within the fixed model | `MSN-2026-0830/figures/source_data/fig_deployment_outcomes.csv`; `FIG_DEPLOYMENT_OUTCOMES_PROVENANCE.md` |
| Fig. 3(b), competition lane | In the separate uniform-unlisted-origin setting, delivery to that origin rose from 32.4% to 41.2%, a change of 8.9 percentage points [4.5, 13.4]. | Supported within the selected fixed units | Same Figure 3 source and provenance report; corrected competition intervals |

## Interpretation

Figure 2 fixes the OpenScope target at 10% of roots and varies the exact-ROA
target (q) from 0% to 100%. Integer selection gives 8/83 IPv4 roots and 1/14
IPv6 roots. Its vertical measure is the share of frozen candidates that remain
potential conflicts. Random curves summarize 1,000 nested rollout orders;
their 5th--95th ranges are rollout percentiles rather than confidence
intervals. The fanout-first/last separation shows that allocation-tree
placement is part of the effect. The equal-decision comparison remains
available as secondary artifact evidence but is not Figure 2's headline.

The Section V-B handoff evidence shows that preinstalled scope removes the
reactive arm's approximately 1.4-s online ROA-update stage and its one signed
transaction plus two ROA-entry changes per handoff. The paired 1.4-s contrast
is localized to this controlled online dependency. The difference between
preinstalled scope and prepublished exact is descriptive; no equivalence margin
was specified.

Table II separates policy loading from steady-state classification. Within
each IP version, all three sizes reuse the same 8,192 queries, every result is
OpenScope, and query hashes, result hashes, and state vectors remain fixed.
Load time rises with additional subprefix entries, whereas classification
stays within a 0.9-thousand-pairs/s band for IPv4 and a 0.6-thousand-pairs/s
band for IPv6. This is not a router or complete relying-party benchmark.

Fig. 3 deliberately answers two different questions. The intended-only lane
shows the possible delivery benefit when OpenScope prevents aggregate-only ROV
from suppressing the intended route. The competition lane shows the security
boundary: the same scope evidence can also preserve an eligible unlisted
origin. Because the announcement sets differ, the two deltas are not a joint
tradeoff curve.

## Correctness and live-path gates

- The independent oracle, reference engine, and encode-decode path agreed on
  106,218 legal vectors; 100,000 generated malformed inputs were rejected.
  Production and reproduction runs matched all nine deterministic outputs.
- All seven route actions matched across 124 selected-fixture snapshots, for
  868 checks.
- The live scale control completed 80 signed transitions and 560 route-outcome
  checks. Cell medians were 3.2--3.9 s over 0, 64, 256, and 1,024
  noncovering rules. The 15-s relying-party outage retained the last installed
  action.
- The controlled replay produced 150/150 worker records. All serialization
  round trips, fixed-query and fixed-output gates, CPU checks, and independent
  raw-to-summary recomputations passed.

## Evidence boundaries

- Figure 2 assumes matching aggregate ROAs, fixes the root-scope target at 10%,
  and varies hypothetical exact placement over 587 retained candidates. It does not observe current
  ROA deployment, issuer knowledge, route legitimacy, current Invalid states,
  or Internet prevalence.
- The handoff result is one controlled Krill, Routinator, compiler, FRR, and
  ICMP-probe path with two alternating endpoint origins.
- The replay is single-process, single-core, Python 3.12.3, and dual stack. It
  excludes FRR, RTR transfer, router installation, forwarding, and line rate;
  the two IP versions are not treated as matched workloads.
- The routing results are conditional on one retained 77,429-AS graph, one
  fixed 589-AS ROV set, 200 selected root-origin units, Gao-Rexford routing,
  and frozen deployment orders.
- Fig. 3(a)'s interval targets a finite candidate frame. Fig. 3(b)'s interval
  describes stability among the selected units. Neither is an Internet-wide,
  traffic-weighted, or operator-intent estimate.
