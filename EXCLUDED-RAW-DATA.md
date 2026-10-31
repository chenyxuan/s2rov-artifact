# Excluded raw data

The artifact ships code, configurations, aggregate tables, and figure source
data. The following inputs are public raw data or intermediate tables that
would dominate the bundle. Each row states the regenerating entry point so that
the shipped results can be rebuilt from source.

| Excluded input | Size | Why excluded | Regenerate with |
|---|---|---|---|
| `experiments/candidates/allocation_tree/data/ripe.db.gz` | 350 MB | RIPE Database snapshot | `experiments/candidates/allocation_tree/` ingest scripts, source `ripe-db` |
| `experiments/candidates/allocation_tree/data/rib.20260624.0000.bz2` | 70 MB | RIS RIB dump | `ripe-ris` MRT feed for the stated timestamp |
| `experiments/candidates/.../visibility_experiment/input/data/bview.20260624.0000.gz` | 392 MB | RIS bview dump | `ripe-ris` bview for the stated timestamp |
| `experiments/candidates/.../outputs/tables/ripe_inetnum.csv` | 626 MB | Intermediate table derived from `ripe.db` | allocation-tree pipeline |
| `experiments/candidates/.../outputs/tables/allocation_tree_with_as.csv` | 553 MB | Intermediate join result | allocation-tree pipeline |
| `experiments/candidates/.../outputs/tables/allocation_tree_pairs.csv` | 262 MB | Intermediate pair table | allocation-tree pipeline |
| `experiments/routing_model/results/**/raw_scenarios.jsonl` | 45–118 MB | Per-scenario routing dumps | `experiments/routing_model/campaign/` (fixed seeds in the contracts) |
| `implementation/prototype/e2e/outputs/*/raw/**` | — | Per-trial containers, ROA files, ping logs | `implementation/prototype/e2e/` runners |

## Scope rules

- Code, tests, contracts, documentation, configuration files, aggregate result
  tables, and every figure source file are included.
- Per-scenario dumps (`*.jsonl`, `raw/`, `trial-*`), vendored third-party trees,
  virtual environments, caches, archives, and any single file above 2 MB are
  excluded.
- Small inputs that a reader needs to follow a script (for example candidate
  CSV files under `source_data/`) are included.

## Note on hashes

Where an experiment records a `EXPERIMENT_CONTRACT.md` or a manifest with SHA-256
values, those values refer to the original full-size inputs. They are kept
unchanged in this bundle; do not edit them when regenerating the raw data.
