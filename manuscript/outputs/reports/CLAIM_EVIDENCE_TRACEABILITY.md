# Claim--Evidence Traceability

> Superseded for active Figure 2 on 2026-08-30. The entries below audit the
> retired family-specific, fixed-$s=10\%$ view; the pooled v2 evidence is
> recorded in `figures/FIG_PARTIAL_POLICY_REPLAY_PROVENANCE.md`.

Date: 2026-08-29

| Manuscript claim | Primary evidence | Independent or deterministic check | Main location |
|---|---|---|---|
| Layered RIPE registry paths coexist with route-side origin divergence | Status-specific RIPE Database paths joined to an RRC00 RIB | Independent path/depth implementations and candidate-level audit reproduce Table I | Section II-B, Table I |
| A 10% root-scope target can reduce the candidate conflicts remaining across partial exact-endpoint deployment, with gains depending on root fanout | 587 frozen candidate rows grouped below 83 IPv4 and 14 IPv6 roots | Input hash, complete target grids, 1,000 fixed rollout orders, fanout-first/last sensitivity, monotonicity, identity, and full-coverage gates | Figure 2, Section V-A |
| The implementation agrees with the specified classifier on the tested corpus | E1a corpus and selected-fixture snapshots | Exact reproduction and 868 fixture checks | Evaluation setup |
| Preinstalled scope does not pre-enumerate either endpoint origin | Accepted handoff policies, pretrial maps, and live Adj-RIB-In captures | All 72 independent checks across the two IP-version lanes | Sections IV-B and V-B |
| Reactive exact adds a 1.4-s mean online ROA-update path | Event timestamps for all 240 handoffs | Per-handoff additive stage reconstruction | Section V-B |
| Reactive exact minus preinstalled scope is 1.4 s [1.3, 1.4] s | Ten complete-round arm means in each IP-version lane | Independent event reconstruction and fixed-seed cluster bootstrap | Section V-B |
| Controlled policy loading is 0.3--17.8 ms for IPv4 and 0.4--29.2 ms for IPv6; fixed-output classification is 27.5--28.4 and 18.5--19.1 thousand pairs/s | Controlled run `controlled-processing-20260829T1152Z`, 150 fresh workers | Independent raw-to-summary reproduction of all 12 measurements; round trips, query hashes, result hashes, state vectors, and OpenScope outputs pass | Table II, Section V-B |
| Intended delivery gains 17.1 percentage points at 100% within the fixed 589-AS ROV set | Phase 7 intended-only lane | Hash-pinned deterministic reanalysis | Fig. 3(a), Section V-C |
| Unlisted-origin exposure gains 8.9 percentage points in the separate competition lane | Phase 7 point estimates and Phase 9 intervals | Deterministic point-estimate match | Fig. 3(b), Section V-C |

Runtime state `Delegated` maps exactly to manuscript state `OpenScope`. The
mapping changes presentation only. Figure 3's two rows describe different
announcement sets and must not be combined into a joint frontier.
