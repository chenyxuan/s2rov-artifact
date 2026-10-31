# Phase 7 Internet-Scale Simulation: Framework Decision and Experiment Contract

## Material Passport

- **Mode:** experiment planning and implementation-readiness audit
- **Research question:** How much intended delegated-destination delivery does
  S2-ROV restore as measured ROV networks upgrade, and how much additional
  traffic attraction does the same open scope permit for an unlisted eligible
  origin?
- **Local evidence inspected:** Phases 1--6, the AMBER topology and measured
  ROV deployment inputs, the AMBER simulation semantics, BGPy 13.0.10, and
  InternetSim at its current public `master` commit.
- **Verification status:** **ANALYZED**.  Framework source and local input
  artifacts were inspected; no Phase 7 production simulation result is
  claimed by this document.
- **Scope:** this document specifies and selects the simulator.  It does not
  modify the manuscript and does not treat AMBER's classifier output as a
  S2-ROV result.

## 1. Decision

Use **BGPy as the primary Phase 7 simulator**.  Keep InternetSim vendored and
pinned only as a build/performance reference unless a later smoke benchmark
shows that BGPy cannot run the contracted workload within available resources.

The decision is semantic, not stylistic:

1. BGPy already separates routing policies by AS, supports fixed and partial
   adoption sets, performs Gao--Rexford propagation, computes conventional ROA
   validity, and represents competing announcements explicitly.
2. BGPy's analyzer already performs longest-prefix choice across a prefix
   hierarchy and follows `next_hop_asn` for an AS-level data-plane outcome.
   A small custom analyzer is still required to distinguish the intended
   delegate from holder-aggregate fallback.
3. InternetSim's current ROV implementation is a global static set of known
   invalid `(origin, prefix)` pairs.  It does not compute covering-ROA or
   `maxLength` semantics and has no four-state provenance model.
4. InternetSim stores multiple prefixes and exposes a printed longest-prefix
   query, but it does not provide a bulk destination-outcome tracer, paired
   trial framework, confidence-interval pipeline, or regression suite.

Do not patch either vendored tree for the primary implementation.  Put S2-ROV
policy, scenario, analyzer, input-adapter, and runner code under Phase 7 and
import the pinned BGPy package.

## 2. Framework selection matrix

The inspected local pins are:

- BGPy `13.0.10`, commit
  `c3b1be48148e8c246a60b9dec6513b688a4736a5`, MIT license.
- InternetSim commit
  `a96b15716f579658b9d745c8abe1805dd869e375`, MIT license.  The public
  repository currently consists of one initial commit.

| Requirement | BGPy | InternetSim | Consequence for S2-ROV |
|---|---|---|---|
| Conventional ROV | Native covering-ROA checker and `ROV` policy | Static invalid-pair set | BGPy preserves the correct baseline without reimplementing RFC 6811 logic. |
| Custom DA validation | Override a policy validity hook and call the Phase 4 oracle | Change Cython `nogil` validation plus policy storage | BGPy keeps DA semantics outside the engine. |
| Mixed deployment | Scenario-level adopting and hard-coded AS policy classes | Per-AS ROV set exists; a separate DA set and actions must be added | Both are possible, but BGPy is already structured for comparisons. |
| Equal-prefix competition | Native announcements and deterministic Gao--Rexford selection | Native route-table competition | Both can represent the primary attack, subject to validation changes. |
| Aggregate plus child prefix | Native multi-prefix local RIB | Native multi-prefix route table | Both can propagate the routes. |
| Destination outcome after longest-prefix match | Native longest-prefix selection plus next-hop traceback in `ASGraphAnalyzer` | Printed longest-prefix lookup only; no Internet-wide tracer | BGPy directly supports the required reachability boundary. |
| Holder fallback versus delegate delivery | Small custom analyzer | New programmatic LPM API and path tracer | Material implementation gap in InternetSim. |
| Paired trials and adoption sweeps | Native trial, seed, multiprocessing, and aggregation framework | Must be built | BGPy reduces reproducibility risk. |
| Dynamic announce/withdraw experiments | Available through the heavier `BGPFull` family | First-class command DSL and scheduler | InternetSim is stronger here, but Phase 6 already covers churn with the prototype. |
| Runtime potential | Python/PyPy; documented memory checks; benchmark required | C++/Cython and multithreading | InternetSim may be faster, but speed does not compensate for missing semantics. |
| Build burden | Python package and pinned dependencies | C++17, Cython, MongoDB, and MongoDB C++ driver, with hard-coded include/link assumptions | BGPy is materially easier to reproduce. |
| Maturity | Peer-reviewed, released, documented, and regression-tested | Minimal README, no test suite or release/citation workflow | BGPy provides the defensible paper artifact. |

### Estimated implementation surface

These are engineering estimates, not completed-line counts.

| Work item | BGPy extension outside vendor | InternetSim extension |
|---|---:|---:|
| Topology/input adapter | 80--120 LOC | 30--80 LOC |
| Four-state semantic bridge and policy | 120--200 LOC | 400--700 LOC across Python/Cython/C++ |
| Deployment and paired scenarios | 200--300 LOC | 200--400 LOC |
| LPM destination tracer and metrics | 200--300 LOC | 400--700 LOC |
| Runner, provenance, and regression tests | 250--400 LOC | 500--900 LOC |
| **Expected total** | **850--1,320 new LOC; no vendor patch** | **1,530--2,780 LOC plus a vendor patch** |

InternetSim should be reconsidered only if a BGPy pilot fails the explicit
resource gate in Section 11, not merely because its core is compiled.

## 3. Existing S2-ROV assets and their Phase 7 role

| Asset | Phase 7 role | What it must not be used to claim |
|---|---|---|
| `phase2_formal/FORMAL_ANALYSIS.md` | Supplies exact aggregate protection, proper-descendant scope, precedence, and provenance requirements. | It does not identify legitimate delegates. |
| `phase3_semantics/S2-ROV_SEMANTICS.md` | Normative four-state semantics and security boundary. | `Delegated` is not ordinary RPKI `Valid`. |
| `phase4_encoding/scripts/utils/daroa.py` | Executable oracle for policy state in simulation and unit tests. | Its interpreter timing is not router performance. |
| Phase 1 allocation-tree candidates | Supplies observed holder/child prefix lengths and topological origin placements for counterfactual sampling. | A candidate is not evidence of contractual delegation or route legitimacy. |
| Phase 5 semantic cases | Supplies regression vectors for `Explicit`, `Delegated`, `Invalid`, and `NotFound`. | They are not Internet-scale propagation evidence. |
| Phase 6 Krill--Routinator--FRR prototype | Anchors actions and staged-deployment interpretation. | The simulator must not replace the signed-system experiment. |
| AMBER topology and Hlavacek ROV list | Supplies an AS graph and a measured ROV deployment set only. | AMBER's exemption/classifier result is not a S2-ROV result. |

The AMBER mixed scenario file and existing AMBER output are deliberately
excluded from the primary experiment.  AMBER's low attack cost depends on a
classifier with high precision; S2-ROV's open Stripe admits every eligible
unlisted origin in scope and has no equivalent classifier.

## 4. Simulator semantic contract

### 4.1 Per-AS policy classes

Every AS is assigned exactly one routing policy in a run:

- `BGP`: no ROV filtering;
- `ROV`: conventional ROV, rejecting `Invalid` and accepting `Valid` and
  `NotFound`; or
- `S2ROV`: conventional ROV plus the signed DA policy.

For a route `(p, a)`, `S2ROV` must apply the following composition:

1. Evaluate the Phase 4 DA policy.
2. If the result is `Explicit` or `Delegated`, admit the route subject to
   ordinary BGP loop/export checks.
3. If the result is `Invalid`, reject it.
4. If the result is `NotFound`, fall back to conventional ROV.

This fallback is necessary because one DA object does not replace validation
for unrelated prefixes.

The primary policy-action profile mirrors the prototype:

`Explicit > Delegated > NotFound`, with `Invalid` rejected.  Within the same
DA state, apply ordinary Gao--Rexford relationship preference, AS-path length,
and deterministic neighbor-AS tie breaking.  Because both the intended
unlisted delegate and an arbitrary eligible attacker are `Delegated`, this
preference must never distinguish those two routes.

Run an action-policy sensitivity in which all admitted states use ordinary
Gao--Rexford preference without the state ranking.  State ranking is a local
enforcement choice, whereas scope containment is a DA semantic invariant.

### 4.2 Legacy-safe projection and deployment

The conventional view of an open policy contains only:

- `(rho, holder, |rho|)` for the aggregate; and
- exact VRPs for explicitly named child Stripes.

Open intent itself emits no VRP.  Thus, a legacy ROV AS rejects an unlisted
child route while a DA-aware AS may classify it as `Delegated`.

For the measured deployment experiment, let `V` be the 589-AS Hlavacek ROV
set and let `S` be the subset upgraded to S2-ROV:

- ASes in `S` run `S2ROV`;
- ASes in `V - S` run conventional `ROV`; and
- all other ASes run `BGP`.

A shadow node that observes DA policy but still enforces conventional ROV is
route-outcome-equivalent to a legacy ROV node in this steady-state model.  The
simulation therefore needs no separate shadow class.  Phase 6 remains the
source for transition and rollback behavior.

### 4.3 Routing model

Use the CAIDA relationship graph with valley-free export and Gao--Rexford
selection.  All compared conditions must use the identical graph, origin
triplet, announcements, and tie breaker.

The simulation assumes a stable, globally available validated policy snapshot.
It does not simulate repository fetch delay, RTR transport, policy compilation,
or router restart; those are Phase 6 prototype questions.

## 5. Experimental unit and input construction

One paired experimental unit is

`(holder H, intended delegate D, attacker A, aggregate rho, child p,
deployment order, deployment size)`.

For the counterfactual-candidate sample:

1. retain Phase 1 rows with one root origin and one leaf origin;
2. require both origins to occur in the selected topology;
3. require `p` to be a proper descendant of `rho`;
4. set the DA maximum length to `|p|`;
5. construct the open policy `(rho, |p|, H, {(rho, {H}, open)})`; and
6. sample `A` from eligible public ASes in the graph, excluding `H` and `D`.

The current audit found 8,293 usable singleton rows and 2,762 distinct
holder--delegate AS pairs after the topology intersection.  The input builder
must regenerate and record these counts rather than hard-code them.

These are **hypothetical signed-open-policy experiments over observed
topological placements**.  The text and output schema must never label a Phase
1 row as a verified real-world delegation.

Use the actual root/leaf lengths from the row, but run one prefix hierarchy per
simulation unit.  Prefix identity has no special routing meaning beyond
covering and longest-prefix relationships.

## 6. Required scenario matrix

All rows announce the holder aggregate unless the row explicitly says
otherwise.

| ID | Policy condition | Child/attack announcements | Purpose | Required outcome at a DA-aware AS |
|---|---|---|---|---|
| B0 | No ROV anywhere | `D -> p` | Unfiltered propagation ceiling | child admitted |
| B1 | Measured ROV, aggregate-only projection | `D -> p` | Conventional policy-gap baseline | child is conventional `Invalid` at ROV ASes |
| B2 | Measured ROV plus exact child ROA | `D -> p` | Strong origin-specific reference | child is conventional `Valid` |
| D1 | Open DA policy, staged upgrade | `D -> p` | Primary reachability-benefit lane | `Delegated` |
| A1 | Evaluate aggregate-only ROV, exact-child ROV, and open DA under the same staged deployment | `D -> p` and `A -> p` | Primary equal-prefix security-cost lane | under DA, both origins are `Delegated`; under the exact child ROA, only `D` is `Valid`; under aggregate-only ROV, both are `Invalid` |
| A2 | Open DA policy | `A -> p` only | Makes the open-scope boundary visible without competition | `Delegated`, never `Explicit` |
| C1 | Open DA policy | `A -> rho` | Exact aggregate containment | `Invalid` |
| C2 | Open base plus closed child `(p,{D},closed)` | `A -> p` | Longest-prefix closed override | `Invalid` |
| C3 | Open DA policy with max length `|p|` | `A -> p'`, where `p'` is below `p` and `|p'|>|p|` | Length containment | `Invalid` |
| C4 | Route outside all DA/ROA objects | unrelated route | `NotFound` fallback regression | conventional `NotFound` action |

The paper-facing core is D1 plus A1.  B0--B2 are references; A2 and C1--C4
are security-boundary controls and should not be inflated into independent
contributions.

## 7. Staged deployment matrix

Upgrade only within the fixed measured ROV set.  Report the horizontal axis as
"DA-aware ASes among 589 measured ROV ASes," not as global Internet adoption.

Required upgrade fractions are:

`0%, 1%, 5%, 10%, 25%, 50%, 75%, 100%`.

Use nested deployment orders so that a larger cell is a strict superset of a
smaller cell:

1. descending customer-cone size;
2. descending AS degree; and
3. random order with at least five recorded seeds.

The pilot may use one random seed and fewer fractions.  Paper-facing results
must use all fractions and at least five random orders.  Holder, delegate,
attacker, and deployment order must be paired across B1, B2, D1, and A1.

Do not require a monotone measured curve.  Adding an enforcing AS changes route
availability and can change downstream best-path choices; non-monotonic
selection is possible even though the upgraded set itself is nested.

## 8. Metrics: propagation is not destination reachability

### 8.1 Control-plane route metrics

For exact child prefix `p`, report the fraction of tracked ASes whose local RIB
selects:

- the intended delegate origin (`child_selected_delegate`);
- the attacker origin (`child_selected_attacker`); or
- no exact child route (`child_absent`).

These are **route-selection/propagation metrics**.  They do not by themselves
show where packets for an address inside `p` terminate.

### 8.2 AS-level destination outcomes

Choose a deterministic address inside `p`.  At each AS, select the most
specific installed route among `p` and its covering aggregate, then follow the
simulated BGP next hops.  Partition every tracked AS into exactly one outcome:

- `delegate_delivery`: trace terminates at `D`;
- `holder_fallback`: no usable child route is selected and the aggregate trace
  terminates at `H`;
- `attacker_delivery`: trace terminates at `A`;
- `disconnected`; or
- `forwarding_loop`.

The partition must sum to the denominator.  This is an AS-level stable-routing
model, not packet-level or traffic-weighted reachability.

`holder_fallback` must not be counted as successful delegated-service
delivery.  Without evidence that the holder internally forwards or tunnels
the child traffic to the delegate, the simulator cannot claim that the
delegated service remains reachable.

Do not use "an AS has any route" as the primary reachability metric.  That
quantity hides aggregate fallback and was a central ambiguity in the AMBER
hand-written simulator.

### 8.3 Primary paired effects

For the same experimental unit and deployment set, compute:

- reachability benefit:
  `Delta_R = delegate_delivery(D1) - delegate_delivery(B1)`;
- incremental exposure relative to the conventional aggregate-only baseline:
  `Delta_E_rov = attacker_delivery(A1 under DA) - attacker_delivery(A1 under B1)`; and
- residual exposure relative to exact origin authorization:
  `Delta_E_exact = attacker_delivery(A1 under DA) - attacker_delivery(A1 under B2)`.

Also report `delegate_delivery(D1) / delegate_delivery(B2)` when the exact-ROA
denominator is nonzero.  Raw fractions remain primary; a ratio must not replace
them.

Report scenario-level distributions and paired 95% bootstrap confidence
intervals.  Do not treat ASes inside one topology run as independent samples.

## 9. Mandatory semantic and experimental invariants

The run must fail closed if any invariant fails.

1. The simulation policy state matches the Phase 4 `DAROA.validate_route`
   oracle for every generated route.
2. An unlisted origin at the exact aggregate is `Invalid` even when the base
   Stripe is open.
3. A closed longest-prefix Stripe rejects every origin outside its explicit
   set.
4. A route longer than the DA maximum length is `Invalid`.
5. An intended unlisted public delegate and an arbitrary eligible public
   attacker under the same open scope receive the same `Delegated` state.
6. Every route that is `Valid` under the conservative projection is
   `Explicit` under the DA policy.
7. With `S` empty, the DA deployment condition is bit-for-bit equivalent to
   the measured conventional-ROV baseline.
8. With `S = V`, every member of the 589-AS measured ROV set runs `S2ROV`; an
   AS outside `V` is not silently upgraded.
9. Shadow and legacy configurations have identical steady-state route
   outcomes.
10. The exact prefix, aggregate, origins, topology, and tie breaker are equal
    across paired conditions.
11. Every data-plane outcome has a valid next-hop trace or an explicit
    `disconnected`/`forwarding_loop` reason.
12. Outcome counts form a complete, non-overlapping partition of the tracked
    denominator.
13. An attacker route is never relabeled as benign because S2-ROV admitted it.
14. Every output records simulator commit, input hashes, Python/runtime
    version, seed, deployment order, and scenario identifier.

## 10. Input mapping and provenance

Use copied or normalized immutable inputs under Phase 7 and record both source
and derived hashes.  Do not read an unversioned AMBER output directory during
a production run.

| Phase 7 input | Source | Current source audit |
|---|---|---|
| AS relationships | `<home>/AMBER/data/simulation/topo/as-rel-fixed.txt` | 477,782 links, 77,429 linked ASNs; SHA-256 `fff3684dc18a3411e87f8f7cd06b9cb211322d8f7c4f169781ee664fe78b6d69` |
| Measured ROV set | `<home>/AMBER/data/simulation/deploy/hlavacek_rov.json` | one deployment containing 589 ASes, all present in the topology; SHA-256 `027c2ace3bce39a308e7d09eddcbc30f619b051af7977e9b5ff4a322cc0bbe1f` |
| Counterfactual holder/child rows | `phase1_empirical/allocation_tree/outputs/tables/allocation_tree_origin_divergence.csv` | 8,830 rows; SHA-256 `b046e31aec24b3c9e48e99f17185be211f0229a898ee00c28e72d10097079b27` |
| DA semantic oracle | `phase4_encoding/scripts/utils/daroa.py` | SHA-256 `7685f8e5583ef2da851085fe119e365255c590d59d853bd90c2068417cd494dc` |
| Staged control vectors | `phase6_system/e2e/config/staged/cases.json` | SHA-256 `ed0f88dd3d25397be25abd9dbcb121be9487ad76c3072f2b23a327c18e8b3fbb` |

The relationship file has three fields (`asn1|asn2|relationship`), whereas the
stock BGPy CAIDA parser expects a source field as well.  Implement a small
Phase 7 constructor that creates BGPy `CustomerProviderLink` and `PeerLink`
objects directly; do not rewrite the vendor parser or infer missing metadata.
The AMBER `as-ppdc.txt` file is not required because BGPy can compute degree
and customer-cone metadata from the graph.  It may be used only as a
cross-check.

## 11. Implementation and execution gates

### Gate A: deterministic semantic smoke test

Use a hand-checked small topology and run all B0--C4 cases.  Compare route
states to Phase 4 and destination outcomes to a manually specified fixture.
Run twice with the same seed and require byte-identical structured output.

### Gate B: topology and deployment audit

Load the full graph, require the expected link/ASN counts, require all 589 ROV
ASes to exist, generate nested deployment orders, and write an immutable input
manifest.  No propagation result is accepted if this gate fails.

### Gate C: resource pilot

Run at least ten paired units at `0%`, `10%`, and `100%` upgrade with one
random order.  Record wall time and peak resident memory.  Extrapolate only
execution cost, not scientific results.  Select the final trial count after
this measured pilot.

InternetSim may run an equivalent topology-load and unmodified BGP smoke test
for performance context.  It must not be used to report S2-ROV outcomes until
it passes the same semantic and destination-outcome gates.

### Gate D: paper-facing run

Use all required deployment fractions and strategies, immutable scenario
manifests, at least five random deployment orders, and paired holder/delegate/
attacker units.  Retain per-unit outcomes rather than only aggregate means.

## 12. Claim boundary for the eventual paper

The experiment can support the following claim if the results warrant it:

> Under a measured ROV deployment and a Gao--Rexford AS-level model, upgrading
> selected ROV ASes to S2-ROV changes the paired frontier between delivery to a
> hypothetical intended delegate and attraction to an unlisted eligible
> origin.

It cannot establish:

- factual authorization of the Phase 1 candidate routes;
- packet-level, user-weighted, or traffic-volume reachability;
- convergence time, repository/RTR behavior, or router throughput;
- security against an attacker inside an open scope; or
- that a holder-aggregate fallback reaches the delegated service.

The security value being tested is therefore **scoped containment plus a
measured benefit--exposure frontier**, not restoration of origin
authentication inside the open region.
