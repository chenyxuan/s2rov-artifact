# Routing model paper campaign contract

## Material Passport

- **Origin skill:** experiment-agent
- **Origin modes:** plan + run + validate
- **Origin date:** 2026-08-04
- **Version label:** routing_model-paper-campaign-v1
- **Verification status:** ANALYZED; freeze this contract before production
  propagation starts.
- **Simulator:** pinned BGPy 13.0.10; no vendored source modifications.

## 1. Research question and estimand

The campaign estimates how upgrading the fixed measured set of 589 ROV ASes
to S2-ROV changes two paired outcomes on one fixed AS-relationship graph:

1. delivery to a hypothetical intended child origin; and
2. delivery to an eligible but unlisted origin announcing the same child
   prefix.

The target estimand is the design-weighted mean paired effect over the 691
candidate-bearing holder ASes retained by the routing-model input filter.  It is
conditional on the fixed topology, fixed ROV set, Gao--Rexford routing, and
the generated counterfactual policy.  It is not an estimate over packets,
traffic volume, users, topology snapshots, or verified business delegations.

The independent sampling unit is `holder_asn`.  Prefix, delegate, attacker,
deployment fraction, deployment order, and lane are repeated conditions of
that unit.  ASes within a propagation run and the five random deployment
orders are never counted as independent observations.

## 2. Frozen holder-level sample

Draw 200 holders without replacement from the 691-holder frame.  Use total
AS degree and four strata whose boundaries do not split tied degrees:

| Stratum | Holder degree | Frame size | Sample size |
|---|---:|---:|---:|
| S1 | 1--2 | 161 | 50 |
| S2 | 3--18 | 177 | 50 |
| S3 | 19--101 | 179 | 50 |
| S4 | at least 102 | 174 | 50 |

Selection uses namespace-separated SHA-256 keyed ranks and a recorded master
seed.  It must not depend on CSV order, Python hash randomization, or container
iteration order.  For every selected holder, select exactly one scenario
hierarchically:

1. one distinct root prefix uniformly from that holder's roots;
2. one distinct delegate uniformly within that root; and
3. one leaf prefix uniformly within that `(holder, root, delegate)` group.

This produces 200 unique holders and roots.  The manifest records the input
frame hash, master seed, namespace strings, all stratum sizes, inclusion
probabilities, selected hierarchy, and design weight.  The sample cannot be
changed after any production outcome is inspected.

## 3. Attacker construction

Assign three attacker classes to every selected unit and keep each attacker
fixed across all matched lanes and deployment cells:

- `uniform`: sampled from all DAROA-encoding-eligible public ASes;
- `edge`: sampled from eligible ASes with total degree one; and
- `high_degree`: sampled from the top one percent of eligible ASes by total
  degree, with ASN as the tie breaker.

Exclude every selected holder and delegate before assignment.  Sample without
replacement within each class, require three distinct attackers within a
unit, and record pool definitions, sizes, exclusions, seeds, and assignments.
The uniform class is the primary attacker analysis.  Edge and high-degree
classes are separate sensitivity analyses; they are not pooled into an
artificial "average attacker," and high degree is not labeled worst case.

## 4. Deployment construction

Only ASes in the immutable 589-AS measured ROV set can be upgraded.  Use these
target percentages and exact floor-rule counts:

| Target | 0% | 1% | 5% | 10% | 25% | 50% | 75% | 100% |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DA-aware ASes | 0 | 5 | 29 | 58 | 147 | 294 | 441 | 589 |

Construct seven global nested deployment orders, shared by every sampled
unit and lane:

1. descending total degree;
2. descending customer-cone size; and
3. five fixed random permutations.

Ties use ASN.  Fractions are prefixes of one frozen order, so a larger cell is
a strict superset of every smaller cell.  The 0% and 100% sets are identical
across orders and are physically executed once rather than treated as extra
replicates.

## 5. Announcement-matched scenario matrix

Every unit has two fixed delegate-only references, three pairs of fixed
competition references, and staged DA lanes:

- `B1_delegate_only`: aggregate-only ROV with the delegate child route;
- `B2_exact_delegate_only`: exact child ROA with the same announcements;
- `B1_competition`: aggregate-only ROV with delegate and one fixed attacker;
- `B2_exact_competition`: exact delegate ROA with the same competition;
- `D1_open_delegate_only`: open DA policy across deployment cells; and
- `A1_open_competition`: open DA policy across deployment cells for each
  attacker class.

For one lane, the unique staged deployment cells are two shared endpoints
plus six intermediate fractions times seven deployment orders, or 44 cells.
The production plan therefore contains, per holder,

`2 + (2 x 3) + 44 + (44 x 3) = 184` trials,

for a frozen total of **36,800 full-graph trials**.  Zero-upgrade D1 must be
bit-for-bit equal to B1 delegate-only.  Zero-upgrade A1 must equal its
announcement-matched B1 competition row for every attacker class.

Boundary controls for exact-aggregate containment, a closed child override,
maximum length, and `NotFound` fallback remain mandatory semantic tests, but
are not repeated as 36,800 population trials.

Prototype installs different local actions for `Explicit`, `Delegated`, and
`NotFound`, whereas the routing-model adapter models admission followed by ordinary
Gao--Rexford selection.  This does not create an unmodeled treatment in the
declared matrix: B1/B2 do not run S2-ROV; D1 has only one child origin; both
competing A1 child origins are `Delegated`; and the `Explicit` holder
aggregate is a different prefix.  The primary outcomes are therefore
invariant to action ordering.  routing-model must not claim an Internet-scale effect
of the prototype's local-preference ranking.

## 6. Outcomes

For each trial, produce complete child-route and destination partitions for:

- all ASes;
- the fixed 589 ROV ASes; and
- the non-ROV complement.

Child-route outcomes are delegate, attacker, or absent.  Destination outcomes
are delegate, attacker, holder fallback, disconnected, or forwarding loop.
Every partition must sum exactly to its declared denominator.  Holder fallback
is never counted as delegated-service delivery.

The two co-primary all-AS paired effects are:

- `Delta_R = delegate_delivery(D1) - delegate_delivery(B1_delegate_only)`;
- `Delta_E_rov = attacker_delivery(A1) - attacker_delivery(B1_competition)`.

Key secondary outcomes are `Delta_E_exact`, comparing A1 with the matched B2
competition reference, and the absolute difference between D1 and B2 exact
delegate delivery.  Raw fractions accompany every delta.  Child-route
selection is a mechanism measure, not the primary reachability endpoint.

## 7. Statistical analysis

Compute every contrast within holder, attacker, deployment order, and
fraction before aggregation.  For random deployment, average the five global
seed blocks within a holder and cell; do not turn them into five additional
holders.

Report design-weighted means using stratum population shares, medians, and
interquartile ranges.  Obtain paired 95% intervals with 10,000 stratified
rescaled-bootstrap replicates that preserve the finite-population sampling
design.  In stratum $h$, draw ordinary multinomial counts
$m_h^*\sim\operatorname{Multinomial}(n_h;1/n_h,\ldots,1/n_h)$, then use

\[
c_{hi}^*=1+a_h(m_{hi}^*-1),\qquad
a_h=\sqrt{\frac{n_h(1-n_h/N_h)}{n_h-1}}.
\]

The rescaled counts sum to $n_h$ in every replicate.  After multiplication
by the frozen design weight $N_h/n_h$, each stratum therefore retains total
weight $N_h$, while the replicate variance of a stratum mean equals the
usual SRSWOR estimate $(1-n_h/N_h)s_h^2/n_h$.  One common replicate-weight
matrix is applied to all analysis cells, so a resampled holder carries its
complete repeated-condition vector.  Never resample individual ASes or
unpaired raw lane means.  These intervals quantify sampling uncertainty for
the finite 691-holder frame, conditional on the frozen topology, ROV set,
within-holder scenario, attacker assignments, and five deployment orders.

The primary curves are random deployment with the uniform attacker.  Report a
simultaneous bootstrap band over the eight fractions if used for inferential
curve statements; otherwise label percentile intervals as pointwise.  Degree,
customer-cone, edge, high-degree, subgroup, and control-plane results are
predeclared sensitivity or secondary analyses.  Strategy comparisons, if
tested, use holder-level curve AUC contrasts and Holm correction.

## 8. Execution and stop rules

Use persistent process workers.  Each worker builds one private AS graph and
engine because the BGPy engine contains weak references and is not picklable;
it then runs trials serially with `S2ROV.configure()` before every setup.
Threads are prohibited because the DA oracle is held in a class variable.

Start with 16 workers and eight-trial atomic chunks.  Use append-only or
atomic-shard checkpoints and merge once; never rewrite all prior rows after
each trial.  Resume only when campaign, code, vendor, and input hashes match.
The runtime contract also pins the CPython version, the exact resolved
dependency set, the logical import source and content hash of the actual
`bgpy` package tree, and the clean vendor commit.  No host-specific absolute
path is part of the manifest.

Before treating a prior result as complete, resume revalidates its immutable
trial/unit metadata, deployment order and set hashes, policy assignment
counts, all/ROV/non-ROV partitions, and attempt provenance.  The parent checks
each announcement-matched 0% equality immediately when its second row arrives.

Stop without silent retry on any of the following:

- one trial exceeds 60 seconds;
- one worker exceeds 1.5 GiB RSS or aggregate workers exceed 24 GiB;
- system available memory falls below 16 GiB;
- an outcome partition, policy assignment, deployment nesting, input hash,
  semantic boundary, or zero-upgrade equality fails; or
- duplicate, missing, or unexpected scenario identifiers are observed.

The parent records failed chunks and their reason.  Any unresolved entry in
`failures.jsonl` blocks a later run by default.  A diagnostic retry requires
the explicit `--retry-failures` option; failure and success records retain the
monotone attempt number and retry provenance and cannot silently replace an
original observation.

## 9. Claim boundary

The campaign may support a conditional safety--reachability frontier under
the declared model.  It cannot establish real-world delegation, authenticate
an origin inside open scope, infer traffic-weighted impact, generalize across
topology or ROV-measurement uncertainty, or evaluate repository, RTR,
convergence, and router-throughput behavior.  The exact-child reference is
also conditional on measured partial ROV deployment and is not an absolute
security floor.
