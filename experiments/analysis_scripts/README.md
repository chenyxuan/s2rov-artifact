# Analysis scripts

The scripts that turn experiment output into the figures and tables in the
paper. They read from the archived tables under `results/tables/` and from
`figure-data/source_data/`, and write into the current directory.

| Script | Produces |
|---|---|
| `run_partial_policy_replay.py` | Figs. 2 and 3, the partial-issuance replay |
| `build_fig_deployment_outcomes.py` | Fig. 5 |
| `build_processing_cost_figure.py` | Fig. 4 |
| `analyze_handoff_fig2.py` | the handoff-benefit panel |
| `build_motivation_figure.py` | Fig. 1 source data |
| `build_prototype_path_figure.py` | the prototype path panel |
| `prepare_openscope_placement_scores.py` | Fig. 3 placement scores |
| `build_processing_cost_table.py` | the processing-cost table |

`tests/` covers the classifier boundaries and the replay.
