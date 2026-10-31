# Reported results

One file per table, figure and measured section, named for what it is.
`numbers.json` is the ledger the manuscript was checked against,
`tables/` holds the full result tables as the pipeline wrote them.

| File | Manuscript item | Written by |
|---|---|---|
| `table1-registry-paths.csv` | Table I, registry paths and origin divergence | `experiments/candidates/allocation_tree/visibility_experiment/outputs/visibility_by_afi.csv` (run output; archived under `results/tables/`) |
| `fig2-conflict-rates.csv` | Fig. 2, conflicts during partial ROA issuance | `figure-data/source_data/fig_partial_policy_deployment_curves.csv` |
| `fig3-prioritization.csv` | Fig. 3, aggregate-prefix prioritization | `figure-data/source_data/fig_openscope_placement.csv` |
| `fig4-processing-cost.json` | Fig. 4, classification throughput and update latency | `experiments/cost/processing_benchmark/outputs/controlled-processing-20260830T-marker-final-v1/summary.json` (run output; archived under `results/tables/`) |
| `fig5-deployment-outcomes.csv` | Fig. 5, reachability and origin exposure | `figure-data/source_data/fig_deployment_outcomes.csv` |
| `section5c-ipv6-sensitivity.json` | Sec. V-C, IPv6 candidate sensitivity | `experiments/routing_model/results/ipv6_sensitivity/analysis/summary.json` (run output; archived under `results/tables/`) |
| `section5d-attack-reachability.json` | Sec. V-D, attack reachability | `experiments/attack_reachability/results/analysis/summary.json` (run output; archived under `results/tables/`) |
