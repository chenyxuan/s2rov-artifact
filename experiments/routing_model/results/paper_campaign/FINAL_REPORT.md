# Routing model BGPy Paper Campaign: Final Report

Date: 2026-08-05

Status: **VERIFIED** for the frozen BGPy campaign and its declared conditional
estimand. This status means that the raw campaign, internal invariants, and
analysis pipeline passed their fail-closed checks. It does not establish
external validity for real business delegations or Internet traffic.

## Executive result

The 36,800-trial campaign does not support a one-sided claim that open S2-ROV
both restores delegated reachability and preserves origin-specific security.
Under random incremental deployment, open S2-ROV progressively restores
delivery to the hypothetical delegate, but from 5% deployment onward it also
produces a statistically clear increase in delivery to an eligible, unlisted
attacker. The supported result is therefore a **reachability--exposure
frontier**.

This is consistent with the formal-statement--4 semantics rather than a simulator
artifact: an open Stripe marks an eligible unnamed origin as `Delegated`, but
cannot authenticate whether that origin was selected by the legitimate
delegate. The delegate and attacker are consequently admission-equivalent
inside the open scope; BGP path competition decides which one is selected.

## Primary destination-level results

The independent unit is `holder_asn`. Values are design-weighted percentages
or percentage-point differences over the finite frame of 691 eligible
holders. Intervals are pointwise 95% intervals from 10,000 stratified paired
SRSWOR-rescaled bootstrap replicates. The five frozen random deployment orders
are averaged within holder before inference.

`Delta_R = D1 delegate delivery - B1 delegate delivery`; positive values are a
reachability benefit. `Delta_E_rov = A1 attacker delivery - B1 attacker
delivery`; positive values are an exposure penalty.

| DA-aware share of the 589 ROV ASes | B1 delegate | D1 delegate | Delta_R (pp, 95% CI) | B1 attacker | A1 attacker | Delta_E_rov (pp, 95% CI) |
|---:|---:|---:|---:|---:|---:|---:|
| 0% | 82.14 | 82.14 | 0.00 [0.00, 0.00] | 32.35 | 32.35 | 0.00 [0.00, 0.00] |
| 1% | 82.14 | 82.28 | 0.14 [0.04, 0.32] | 32.35 | 32.35 | -0.01 [-0.23, 0.21] |
| 5% | 82.14 | 83.22 | 1.08 [0.69, 1.53] | 32.35 | 33.82 | 1.46 [0.98, 1.95] |
| 10% | 82.14 | 84.49 | 2.36 [1.64, 3.15] | 32.35 | 34.88 | 2.53 [1.78, 3.29] |
| 25% | 82.14 | 89.76 | 7.62 [5.84, 9.55] | 32.35 | 39.36 | 7.00 [5.06, 8.96] |
| 50% | 82.14 | 93.54 | 11.40 [8.91, 14.05] | 32.35 | 40.35 | 7.99 [5.51, 10.53] |
| 75% | 82.14 | 96.10 | 13.96 [10.94, 17.12] | 32.35 | 41.36 | 9.00 [5.95, 12.23] |
| 100% | 82.14 | 99.23 | 17.09 [13.31, 21.03] | 32.35 | 41.23 | 8.88 [5.12, 12.76] |

At 100% deployment, D1 reaches the exact-child B2 delegate-only reference
(99.23% delivery). This equality is confined to the delegate-only lane. In
competition, A1 attacker delivery remains 29.58 pp [26.75, 32.53] above the
exact-child B2 reference, so the result must not be generalized as equivalence
to an exact ROA.

The means also hide strong holder heterogeneity. The holder-level median
`Delta_R` remains zero even at 100% deployment; the 17.09 pp mean is driven by
a subset of holders with large gains. At 100%, uniform-attacker
`Delta_E_rov` has median 3.22 pp and IQR [-9.09, 29.26] pp. Neither mean should
be described as the effect for a typical holder.

## Predeclared sensitivity results

- Degree- and customer-cone-prioritized deployment release reachability gains
  much earlier than random deployment, but also release exposure much earlier.
  At 5%, the random/degree/cone `Delta_R` values are 1.08/9.08/9.54 pp, while
  the corresponding `Delta_E_rov` values are 1.46/10.99/9.72 pp. No
  holder-paired AUC test with Holm correction was run, so strategy differences
  are descriptive rather than claims of statistical superiority.
- At 100% random deployment, the exposure penalty is 6.58 pp [3.04, 10.20]
  for edge attackers, 8.88 pp [5.12, 12.76] for uniform attackers, and
  15.62 pp [12.96, 18.24] for high-degree attackers. High degree is a declared
  sensitivity class, not a proven worst case.
- The exposure curve need not be monotone despite nested deployment sets,
  because adding validating ASes changes BGP competition. For the uniform
  attacker it is 9.00 pp at 75% and 8.88 pp at 100%.
- Child-route selection is mechanism evidence only. At 100%, child-level
  `Delta_R` is 43.51 pp, while destination-level `Delta_R` is 17.09 pp.
  Per-hop longest-prefix forwarding can reach the delegate even when the
  source AS does not install the child route locally, so these metrics are not
  interchangeable.

## Simulator decision

BGPy 13.0.10 was selected over InternetSim after both were pinned and audited.
BGPy supplies native covering-ROA validation, per-AS policy classes, mixed
deployment, multi-origin propagation, longest-prefix destination analysis,
and a reproducible policy extension point. InternetSim's available ROV model
is a static invalid-pair set, its required DA semantics and Internet-wide
destination tracer would need new engine work, and its official example built
but crashed at the first propagation batch in the evaluated environment.
InternetSim remains a vendored secondary candidate; it was not used to produce
the paper results.

## Frozen design and execution

- Topology: 77,429 ASes and 477,782 relationships.
- Fixed measured ROV set: 589 ASes.
- Finite holder frame: 691; sample: 200 holders, with 50 sampled without
  replacement from each of four degree strata.
- Per holder: one frozen root/delegate/leaf configuration and three fixed
  attacker classes (`uniform`, `edge`, and `high_degree`).
- Deployment targets: 0/1/5/10/25/50/75/100%, corresponding to
  0/5/29/58/147/294/441/589 DA-aware ASes.
- Deployment orders: degree, customer cone, and five fixed random orders;
  shared 0% and 100% endpoints are physically simulated once.
- Scenario count: 184 per holder, 36,800 total.
- Primary endpoint: destination delivery; child-route selection is secondary
  mechanism evidence.

The campaign completed all 36,800 scenarios on their first attempt, with no
retry, unresolved failure, or tail repair. Internal wall time was 29,721.98 s
(8:15:21.98), peak aggregate worker RSS was 7.666 GiB, minimum host
`MemAvailable` was 47.656 GiB, and the slowest trial was 17.927 s. The
analyzer completed in 79.32 s with 1.164 GiB maximum RSS and exit status 0.

The formal run's outer `/usr/bin/time` wrapper disappeared while the runner
continued under PID 1, leaving a zero-byte formal `external_time.txt` and no
recoverable external OS exit status. Logical completion is instead established
by the final `complete` checkpoint, the full validated result set, process
termination, and the successful fail-closed analyzer. The formal run was not
restarted.

## Verification

- Raw rows: 36,800; unique expected scenario IDs: 36,800.
- Row status: all `success`; all `attempt=1`; no failure file.
- Holder contrasts: 230,400.
- Summary cells: 1,152, each with 200 holders and design-weight sum 691.
- Analyzer checks: all 19 true; `analysis_manifest.status=VERIFIED`.
- Determinism: all four core analysis products were regenerated in a separate
  directory and matched byte-for-byte.
- Code gates: 47 the routing model tests passed; Ruff lint passed; the three modified
  analysis/statistical files pass Ruff format; `pip check` reports no broken
  requirements. Eight unrelated pre-existing routing-model files would be
  reformatted by the current Ruff formatter and were intentionally not
  rewritten.

## Material Passport

- Origin: `academic-research-suite / experiment-agent`.
- Modes: plan + run + validate.
- Version: `routing_model-paper-campaign-v1 -- SRSWOR FPC analysis amendment`.
- Simulator: BGPy 13.0.10, clean vendor commit
  `c3b1be48148e8c246a60b9dec6513b688a4736a5`.
- Imported BGPy tree SHA-256:
  `caa381c953bd38ee25e303249d86276430762c59ceb1d00c97aa3f5e3714f133`.
- Runtime: CPython 3.12.3 with 39 exact locked dependencies.
- Manifest file SHA-256:
  `a674b87afd90716521f19673c4ddbd1153c1b911ec5021a99e0eabe579bcbeae`.
- Manifest canonical SHA-256:
  `1394b5aab7020cd0ae7a8cc9d8866ecc86eb06d1bb49e5e2ec85127bb1c3f277`.
- Runner SHA-256:
  `9500cd43d7ee6a409c9d0dc83e41fc44dd85311c5b0dfd69f89ac1405d98ed50`.
- Raw-scenario SHA-256:
  `fb9ec8fa80d41b5a98b4bc956d82ebfec0514eaab27fd183f86683dfed6925b7`.
- Analyzer SHA-256:
  `c0ca2612fd1fb1dbc267257069b72826d4ec6fb36b15a7fbdc3aec43806f01fe`.
- Analysis-manifest SHA-256:
  `27298f787bfb8856b23d5c21138526dd9adbb3259a57e64067268eb2fc4c2a73`.
- Holder-contrast SHA-256:
  `407194fa21a41a7c748caf114ed81183915a538b2d6ebebdbd3805b95edc2413`.
- Summary JSON SHA-256:
  `2483ed7399cdf63914faa16aa242109368b12a70f67193b54b31845a9c358b16`.

The SRSWOR finite-population rescaling was added after propagation began but
before formal analysis. It changes only interval estimation, not the frozen
manifest, runner, raw scenarios, contrast definitions, or point estimates.
The pre-amendment contract/analyzer hashes were `0413690d...` and
`9656ad64...`; the analyzed versions are contract
`72521f48c73b5011befa432a8d701c957d525f6aa879ccb40ce85b1c8b542196`
and analyzer `c0ca2612...`. At execution time, `experiments/routing_model/` was still
untracked, so the frozen run was bound to these content hashes rather than to a
Git revision. The archived code and result commit now provide the corresponding
repository history without rewriting the immutable run manifest.

## Claim boundary

The results are conditional on one fixed AS topology, one fixed 589-AS ROV
set, Gao--Rexford steady-state routing, mechanically selected
origin-divergence candidates, one frozen within-holder scenario, fixed
attacker assignments, and five frozen random deployment orders. Candidate
pairs are not verified delegations. The campaign is AS-count weighted rather
than traffic- or user-weighted. It does not evaluate repository/RTR behavior,
protocol convergence, router throughput, or the prototype's local-preference
ranking. Pointwise intervals are not simultaneous curve bands, and the 0%
equality checks compare complete outcome partitions rather than per-AS RIB
bitwise identity.
