# Reanalysis selected-unit reanalysis contract

## Purpose

Routing-model assigned eligible-unlisted competitors only after drawing 200 of the
691 root-origin units. Consequently, competition outcomes for the 491
unselected units were never defined. This reanalysis does not alter or rerun
any propagation trial. It corrects the inferential target for the
competitor-dependent interval-bearing results reported in the current
manuscript: routing-model all-AS destination/random-deployment cells and the attack-reachability
all-AS full-upgrade route and destination endpoints.

## Inputs

- `experiments/routing_model/results/paper_campaign/analysis/holder_contrasts.jsonl`
- `experiments/routing_model/results/paper_campaign/analysis/raw_cell_summary.csv`
- `experiments/attack_reachability/results/analysis/holder_contrasts.jsonl`
- `experiments/attack_reachability/results/analysis/summary.json`

The output records the SHA-256 digest of each input. Frozen routing-model and attack-reachability
artifacts are read-only.

## Estimand and interval

- Delegate-only results do not depend on the post-sample competitor assignment
  and retain their original finite-frame design-based analysis.
- Competitor-dependent results target the 200 selected synthetic units only.
  Point estimates preserve the preregistered four-stratum standardization
  (stratum shares 161/691, 177/691, 179/691, and 174/691).
- Uncertainty summaries use 10,000 ordinary multinomial bootstrap resamples
  within each 50-unit stratum. No finite-population correction is applied.
  They are descriptive resampling-stability intervals over the empirical
  selected-unit distributions, not confidence intervals for the 691-unit
  frame, the Internet, traffic, or adversaries.
- One paired replicate-weight matrix is shared by all cells from the same
  campaign. Deployment-order averages already present in the holder contrasts
  remain within-unit repeated conditions.

Seeds are 20260804 for routing-model and 20260823 for attack-reachability. Percentile endpoints
use NumPy's linear method. All expected cells must contain exactly 200 unique
units, 50 in each stratum. The script fails if recomputed point estimates do
not match the frozen summaries to numerical precision.

## Outputs

- `results/competition_cells.csv`: corrected routing-model selected-unit summaries.
- `results/sibling_cells.csv`: corrected attack-reachability selected-unit summaries.
- `results/summary.json`: contract, input hashes, audits, and headline values.
