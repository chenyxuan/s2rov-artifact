# Phase 7 deployment-grid extension contract

## Material Passport

- **Origin skill:** experiment-agent
- **Origin modes:** plan + run + validate
- **Version label:** phase7-deployment-grid-extension-v1
- **Verification status:** PLANNED; the manifest must be frozen before full
  propagation starts.
- **Simulator:** the same pinned BGPy runtime and full-graph propagation model
  as the accepted Phase 7 paper campaign.

## 1. Purpose and boundary

This extension fills the regular 10-percentage-point grid omitted by the
accepted Phase 7 campaign.  It is an additive experiment.  It does not alter,
replace, or append to the accepted campaign's manifest or raw results.

The extension measures the two curves used in Section V.C:

1. `D1_open_delegate_only`, which measures delivery to the intended origin;
   and
2. `A1_open_competition` with the frozen `uniform` attacker, which measures
   delivery to an eligible but unlisted origin.

The upgraded population remains the fixed measured set of 589 ROV ASes.  A
percentage is therefore a share of that fixed set, not a share of all ASes in
the topology or Internet.

## 2. Frozen inputs

The extension reads only the accepted manifest at
`phase7_simulation/results/paper_campaign/manifest.json`.  It reuses, without
resampling:

- all 200 selected holder units;
- each unit's frozen uniform attacker; and
- the five random deployment orders with seeds 1 through 5.

The extension manifest records the accepted manifest's internal digest and
file digest, canonical digests of the copied units and orders, current code and
input hashes, and the exact runtime fingerprint.  Any mismatch blocks resume.

## 3. Deployment cells and scenario matrix

The new target percentages are

`20, 30, 40, 60, 70, 80, and 90 percent`.

Counts use the same floor rule as the accepted campaign:

| Target | 20% | 30% | 40% | 60% | 70% | 80% | 90% |
|---:|---:|---:|---:|---:|---:|---:|---:|
| Upgraded ASes | 117 | 176 | 235 | 353 | 412 | 471 | 530 |

For each deployment order, every larger cell is a strict prefix superset of
the smaller cell.  The physical matrix is

`200 units x 7 percentages x 5 random orders x 2 lanes = 14,000 trials`.

No endpoint or fixed-reference trial is repeated.  Those observations remain
in the accepted campaign and are joined only during analysis.

## 4. Smoke and formal modes

Formal mode freezes the complete 14,000-trial matrix.  Smoke mode uses the
first frozen unit, random seed 1, percentages 20 and 90, and both lanes, for
four trials.  Smoke output must use a separate directory and cannot be merged
into formal output.

## 5. Execution and fail-closed rules

The runner uses spawned persistent workers.  Each worker builds one private
full graph and reuses the accepted propagation helpers.  The parent is the
only JSONL writer.  Successful rows retain the accepted campaign's raw-row
schema so that the extension can be audited and joined with the accepted
campaign without reinterpretation.

Before resume, the runner validates the complete manifest, source-manifest and
artifact hashes, runtime fingerprint, every completed row's immutable unit and
trial metadata, deployment-set hash, policy-assignment counts, outcome
partitions, and attempt provenance.

The run stops on the first worker or semantic failure.  Failure history is
append-only.  Unresolved failures block later execution by default.  Retrying
a failed scenario requires the explicit `--retry-failures` flag; there is no
automatic retry.  A damaged final JSONL line is repaired only when the user
explicitly passes `--repair-truncated-tail`.

The accepted campaign directory is never an allowed extension output
directory.  Planning refuses to overwrite a different manifest or any
nonempty result or failure checkpoint.

## 6. Analysis boundary

The five random orders are repeated deployment blocks, not independent sample
units.  Analysis must first combine extension rows with the accepted campaign's
0, 10, 25, 50, 75, and 100 percent cells, then aggregate within holder.  The
regular 0-to-100 curve may use 10-percentage-point cells; 25 and 75 percent may
remain diagnostic observations but are not part of that regular grid.

The extension remains conditional on the same fixed topology, fixed measured
ROV set, generated policy, sampled holders, frozen origins, and Gao--Rexford
routing model.  It does not estimate Internet-wide deployment prevalence or
traffic-weighted impact.
