# Full-graph BGPy resource gate

This directory implements the pre-campaign Internet-scale gate requested for
the S2-ROV reachability/exposure study.  It uses the pinned BGPy 13.0.10 clone,
the prepared fixed relationship graph, the measured 589-AS ROV baseline, and
the project-owned S2-ROV-encoding-backed `S2ROV` policy.  It does not modify either
vendored simulator.

## Scope and interpretation

The gate runs ten deterministic holder/delegate **origin-divergence candidate**
pairs.  They are selected to span endpoint-degree ranks and are not asserted to
represent observed business delegation, authorization, or routing intent.  A
fixed seed assigns five degree-one attackers and five attackers sampled from
the top one percent by total degree.

The 100-trial plan contains announcement-matched reference lanes:

- `B1_delegate_only`: delegate-only announcement set with aggregate-only ROV;
- `B2_exact_delegate_only`: the same announcements with an exact child ROA;
- `B1_competition`: delegate-plus-attacker announcements with aggregate-only ROV;
- `B2_exact_competition`: the same competition with an exact delegate ROA;
- `D1_open_delegate_only`: holder aggregate plus one child origin at 0%, 5%, and
  100% S2-ROV upgrade within the fixed ROV set; and
- `A1_open_competition`: the same child is announced by both delegate
  and eligible unlisted attacker at the same three stages.

The fail-closed equality checks compare only identical announcement sets:
`D1@0 == B1_delegate_only` and `A1@0 == B1_competition`. Reachability effects
compare D1 with the B1/B2 delegate-only references. Exposure effects compare
A1 with the B1/B2 competition references.

Both child-route selection and per-hop longest-prefix destination outcomes are
partitioned.  The latter separates delegate, attacker, holder-aggregate
fallback, disconnected, and forwarding-loop outcomes.

## Reuse and resource gate

The fixed AS graph and one `SimulationEngine` are constructed once.  Before
every trial, `engine.setup(scenario)` replaces every AS policy object and its
routing state, then seeds only that trial's announcements.  A sampled absolute
process RSS peak and wall time are recorded for every run.  The process stops
without retry if a single trial reaches 60 seconds or process RSS exceeds
8 GiB.  This gate does not start the 2,762-pair campaign.

Run from the repository root:

```bash
export PYTHONPATH="$PWD/experiments/routing_model/vendor/bgpy:$PWD"
PYTHON=experiments/routing_model/.venv-bgpy/bin/python

$PYTHON -m pytest -q experiments/routing_model/campaign/tests
$PYTHON -m ruff check experiments/routing_model/campaign
$PYTHON -m experiments.routing_model.campaign.full_graph_gate \
  --output-dir experiments/routing_model/results/full_graph_gate
```

Outputs are overwritten deterministically at the declared output directory:

- `raw_scenarios.jsonl`: nested scenario-level partitions and provenance;
- `raw_scenarios.csv`: flat scenario-level counts/fractions and resources; and
- `summary.json`: selection rules, selected inputs, hashes, deployment sets,
  checks, resource records, and across-pair summaries.

## Completed gate (2026-08-04)

The corrected announcement-matched gate completed all 100/100 trials on the
77,429-AS graph.  BGPy's internal campaign wall time was 1,107.015 s; external
`/usr/bin/time` wall time was 18:30.31.  The slowest trial took 13.409 s.  The
sampled process peak was 462.191 MiB (external maximum RSS: 473,284 KiB), so
neither the 60-s nor 8-GiB stop condition was approached.  Both zero-upgrade
equalities passed exactly and every control-plane and destination partition
summed to 77,429.

Mean paired effects over the ten mechanically selected pairs are shown below
in percentage points.  These are gate-scale observations, not population
estimates or evidence that any selected pair is a real delegation.

| S2-ROV upgrade in the 589 ROV ASes | D1 child delegate gain vs B1 | D1 destination delegate gain vs B1 | A1 child attacker increase vs B1 competition | A1 destination attacker increase vs B1 competition |
|---:|---:|---:|---:|---:|
| 0% | 0.00 | 0.00 | 0.00 | 0.00 |
| 5% (29 ASes) | 22.98 | 4.15 | 25.32 | 25.81 |
| 100% | 39.07 | 14.19 | 28.70 | 25.51 |

At 100% upgrade, the D1 delegate-only outcome equals the B2 exact-child upper
reference for both child selection and destination delivery.  In the paired
competition lane, however, open delegation also creates a large attacker
selection/delivery increase relative to the announcement-matched B1 baseline.
The full 2,762-pair campaign therefore requires a predeclared safety--reachability
trade-off analysis rather than a reachability-only claim.

## Frozen 200-holder paper campaign

`paper_campaign.py` implements the preregistered production matrix without
changing BGPy.  It selects 50 unique holders from each of four holder-degree
strata, assigns three distinct attacker classes to every holder, and freezes
36,800 physical trials (184 per holder) in `manifest.json`.  The 0% and 100%
deployments are simulated once per lane and shared across all deployment
orders; the six intermediate percentages cross degree, customer-cone, and five
seeded random orders.

Each spawned worker builds its own fixed AS graph and reuses that graph and
simulation engine across trials.  Only the parent process appends successful
rows to `raw_scenarios.jsonl`; there are no result shards to merge.  The run
fails closed on a worker exception, a 60-s trial, 1.5-GiB per-worker RSS,
24-GiB aggregate RSS, or host `MemAvailable` below 16 GiB.  Checkpoint and
`fsync` intervals default to eight rows, with the final selected row always
synced.  Resume validates the frozen manifest, artifact hashes, prior scenario
IDs, every immutable plan field, exact deployment-set hashes, policy counts,
complete population partitions, and duplicate absence before scheduling
pending trials.  Planning and every parent/worker execution also verify the
exact Python version, fully pinned dependency fingerprint, imported BGPy
source kind and package-tree hash, and the clean locked vendor commit.  Stored
source labels are repository-relative and contain no machine-specific path.

The parent compares announcement-matched aggregate partitions incrementally.
As soon as both rows exist, `B1_delegate_only` must equal `D1@0`, and each
attacker-class `B1_competition` must equal `A1@0`; a mismatch is recorded as a
failure before the second row can enter the successful checkpoint.

Run the planning and validation commands from the repository root.  `plan` is
a one-time operation for an empty output directory and launches no propagation;
`--dry-run` validates that frozen plan and the current artifacts without
launching workers:

```bash
export PYTHONPATH="$PWD/experiments/routing_model/vendor/bgpy:$PWD"
PYTHON=experiments/routing_model/.venv-bgpy/bin/python

$PYTHON -m experiments.routing_model.campaign.paper_campaign plan \
  --output-dir experiments/routing_model/results/paper_campaign
$PYTHON -m experiments.routing_model.campaign.paper_campaign run \
  --output-dir experiments/routing_model/results/paper_campaign \
  --workers 16 --dry-run
$PYTHON -m experiments.routing_model.campaign.paper_campaign status \
  --output-dir experiments/routing_model/results/paper_campaign
```

Before the production run, benchmark the declared 16-worker configuration on
a small checkpointable batch.  If that batch stays within the resource
contract, resume with 16 workers; evaluate 24 workers only from measured
headroom, not by default:

```bash
$PYTHON -m experiments.routing_model.campaign.paper_campaign run \
  --output-dir experiments/routing_model/results/paper_campaign \
  --workers 16 --max-new-trials 32
$PYTHON -m experiments.routing_model.campaign.paper_campaign run \
  --output-dir experiments/routing_model/results/paper_campaign --workers 16
```

The formal campaign outputs are:

- `manifest.json`: frozen sample, attacker assignments, deployment orders,
  complete trial plan, provenance hashes, and execution contract;
- `raw_scenarios.jsonl`: append-only parent-written successful result rows;
- `checkpoint.json`: durable progress and resource high-water marks; and
- `failures.jsonl`: fail-closed worker diagnostics, if any.

A nonempty failure history blocks an unresolved scenario on every later run.
After diagnosis, retrying it requires the explicit `--retry-failures` flag;
both failed and successful rows record the attempt number, prior-failure
count, and whether a retry was authorized.  For example:

```bash
$PYTHON -m experiments.routing_model.campaign.paper_campaign run \
  --output-dir experiments/routing_model/results/paper_campaign \
  --workers 16 --retry-failures
```

The frozen 36,800-trial production campaign completed without retry or
unresolved failure.  Its checkpoint, final report, verified analysis manifest,
and compact cell summaries are retained under `results/paper_campaign/`; the
append-only raw rows remain a local reproducibility artifact identified by the
hashes in those records.

## Frozen paper-campaign analysis

`analyze_paper_campaign.py` is the fail-closed analysis stage for the 200-holder
paper campaign.  It first requires an exact match to the runner manifest's
expected scenario IDs, binds every result row's lane/holder/attacker/deployment
metadata to that scenario's frozen `trial_plan` entry, and checks the complete
184-cell physical matrix for every holder.  Unknown or substituted lanes fail
closed even if IDs and row counts are unchanged.  It also verifies every
all/ROV/non-ROV child and destination partition and the announcement-matched
zero-upgrade equalities.  It then computes holder-paired `Delta_R`,
`Delta_R_exact`, `Delta_E_rov`, and `Delta_E_exact` using the four-stratum
design weights.  Each contrast is emitted separately at
`metric_level=destination` (the primary delivery outcome) and
`metric_level=child` (the secondary route-selection mechanism), yielding a
derived 1,152-cell production summary grid.  `Delta_R_exact` is the signed
D1-minus-exact-child-reference contrast; its absolute point difference is
emitted alongside the signed estimate.

For random deployment, the five frozen orders are averaged within each holder
and cell before aggregation.  The independent sample size is therefore
**n = 200 holders**, never the number of ASes or seeds.  The default intervals
are 10,000-replicate stratified paired rescaled-bootstrap percentile
intervals for the finite, stratified sampling without replacement holder design.  For multinomial
count `m_hi` in stratum `h`, the replicate count is
`c_hi = 1 + a_h * (m_hi - 1)`, where
`a_h = sqrt(n_h * (1 - n_h/N_h) / (n_h - 1))`.  This preserves every
stratum's total design weight `N_h` and gives the usual sampling without replacement
finite-population variance for a stratum mean.  The same replicate-weight
matrix is used for every cell, retaining all within-holder pairing.  Cell
outputs include raw treatment/reference means, paired point estimates,
pointwise 95% intervals, weighted median/IQR, and the descriptive range across
the five frozen random-order estimates.  The intervals are conditional on
those five orders and the other frozen campaign inputs; they are not
simultaneous curve bands.

After the runner has completed its append-only parent-written JSONL:

```bash
export PYTHONPATH="$PWD/experiments/routing_model/vendor/bgpy:$PWD"
PYTHON=experiments/routing_model/.venv-bgpy/bin/python

$PYTHON -m experiments.routing_model.campaign.analyze_paper_campaign \
  --manifest experiments/routing_model/results/paper_campaign/manifest.json \
  --results experiments/routing_model/results/paper_campaign/raw_scenarios.jsonl \
  --output-dir experiments/routing_model/results/paper_campaign/analysis
```

The analysis writes `holder_contrasts.jsonl`, `raw_cell_summary.json` and
`.csv`, plus `analysis_manifest.json` containing all validation flags, input
hashes, the bootstrap seed, and the explicit independent-unit declaration.

## Worker-count benchmark validation

Before the production campaign, run the same complete prefix unit under each
candidate worker count in a separate output directory.  Copy the frozen
manifest rather than replanning, and select exactly 184 new trials for one
complete unit:

```bash
for WORKERS in 1 4 8 16; do
  OUT="experiments/routing_model/results/benchmarks/w${WORKERS}"
  mkdir -p "$OUT"
  cp experiments/routing_model/results/paper_campaign/manifest.json "$OUT/manifest.json"
  $PYTHON -m experiments.routing_model.campaign.paper_campaign run \
    --output-dir "$OUT" --workers "$WORKERS" --max-new-trials 184
done
```

Validate row/ID completeness, the exact 0% aggregate-partition equalities, and
cross-worker deterministic outcomes with:

```bash
$PYTHON -m experiments.routing_model.campaign.validate_benchmark \
  --manifest experiments/routing_model/results/paper_campaign/manifest.json \
  --result 1=experiments/routing_model/results/benchmarks/w1/raw_scenarios.jsonl \
  --result 4=experiments/routing_model/results/benchmarks/w4/raw_scenarios.jsonl \
  --result 8=experiments/routing_model/results/benchmarks/w8/raw_scenarios.jsonl \
  --result 16=experiments/routing_model/results/benchmarks/w16/raw_scenarios.jsonl \
  --output experiments/routing_model/results/benchmarks/validation.json
```

Each input must contain complete rows for a contiguous prefix of frozen units.
For every included unit, the validator requires `B1_delegate_only == D1@0`
and class-matched `B1_competition == A1@0` outcomes.  The comparison hash is
computed from sorted `(scenario_id, outcomes)` records only, so timing, RSS,
PID, worker sequence, and scheduling order cannot affect it.
