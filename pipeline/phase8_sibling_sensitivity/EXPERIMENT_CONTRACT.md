# Phase 8 Sibling-Prefix Endpoint Sensitivity Contract

Version: `phase8-sibling-endpoint-v1`

## Question and claim boundary

This campaign asks how changing the fixed measured ROV set from conventional
ROV to the open DA policy changes conditional AS-level route exposure for a
deterministic same-length sibling of the original Phase-7 leaf. It does not
estimate traffic, sibling-prefix utilization, delegation legitimacy, attack
prevalence, or generalization to another topology or ROV snapshot.

## Frozen design

- Independent statistical unit: holder ASN.
- Sampling frame and weights: the exact 200-holder, four-stratum Phase-7
  selection and its frozen `N_h/n_h` design weights.
- Topology and ROV population: the exact Phase-7 graph and 589-AS measured ROV
  set.
- Attacker: each holder's exact Phase-7 `uniform_attacker_asn`.
- Sibling: the other child of
  `leaf_prefix.supernet(prefixlen_diff=1)`, at the leaf's prefix length.
- Announcements in every scenario: `root@holder`, `leaf@delegate`, and
  `sibling@uniform-attacker`.
- Conventional authorization: one aggregate-only ROA for `root@holder` with
  `maxLength == root.prefixlen`.
- Physical cells per holder: conventional ROV at 0% DA, open-policy machinery
  at 0% DA, and open DA policy at 100% of the fixed ROV set. Thus the complete
  design is 200 x 3 = 600 physical trials; no random deployment orders are
  needed at endpoints.
- The open-0% cell is an incremental-equivalence control and must exactly match
  the conventional cell's outcomes for every holder.
- Original-leaf route and destination partitions must exactly match the
  corresponding frozen Phase-7 delegate-only endpoint for every holder and
  population.

## Outcomes and analysis

For all, ROV, and non-ROV AS populations, each scenario records complete,
mutually exclusive partitions for:

- sibling route: attacker or absent;
- original-leaf route: delegate or absent;
- sibling destination: attacker, holder fallback, disconnected, or loop;
- original-leaf destination: delegate, holder fallback, disconnected, or loop.

Every `all` count must equal `rov + non_rov`. The analysis computes holder-paired
open-minus-conventional deltas, applies the frozen Phase-7 design weights, and
uses 10,000 within-stratum paired SRSWOR-rescaled bootstrap replicates with
finite-population correction and seed `20260823`. Intervals are pointwise 95%
percentile intervals.

## Execution gates

The first 32 frozen scenarios form a resource benchmark covering all four
strata, both lanes, and both deployment percentages. A full run is refused
unless its self-hashed benchmark report passes all gates:

- at most 60 seconds per trial;
- at most 1.5 GiB peak RSS per worker/trial and worker graph build;
- at most 24 GiB aggregate process RSS;
- at least 16 GiB host `MemAvailable`;
- 16 workers and no retries.

Results are append-only JSONL. Any failure is written to `failures.jsonl` and
prevents automatic continuation. The manifest binds inputs, implementation,
environment, selected units, trial identities, endpoint sets, and parent
Phase-7 artifacts by hashes.
