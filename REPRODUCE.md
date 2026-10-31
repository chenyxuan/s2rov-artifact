# Reproducing the results

Paths are relative to the bundle root. The paper itself is not bundled.

## 1. Read the numbers (no setup)

`00-reproduce/` holds one plainly named file per reported item:

| File | Manuscript item |
|---|---|
| `table1-registry-paths.csv` | Table I, registry paths and origin divergence |
| `fig2-conflict-rates.csv` | Fig. 2, conflicts during partial ROA issuance |
| `fig3-prioritization.csv` | Fig. 3, aggregate-prefix prioritization |
| `fig4-processing-cost.json` | Fig. 4, classification throughput and update latency |
| `fig5-deployment-outcomes.csv` | Fig. 5, reachability and origin exposure |
| `section5c-ipv6-sensitivity.json` | Sec. V-C, IPv6 candidate sensitivity |
| `section5d-attack-reachability.json` | Sec. V-D, attack reachability |

`00-reproduce/README.md` records the original path each file was copied from,
and `results.facts.json` lists every number quoted in the paper together with
its provenance.

The same plotted data also sits in `figure-source-data/`, next to the figure
manifests, if you want to redraw a panel.

## 2. Re-run one experiment

| Item | Entry point |
|---|---|
| Table I | `pipeline/phase1_empirical/allocation_tree/visibility_experiment/` |
| Figs. 2, 3 | `pipeline/analysis-scripts/run_partial_policy_replay.py` |
| Fig. 4 | `pipeline/phase5_evaluation/processing_benchmark/` |
| Fig. 5 | `pipeline/phase7_simulation/campaign/` |
| Sec. V-C | `pipeline/phase7_simulation/campaign/ipv6_sensitivity.py` |
| Sec. V-D | `pipeline/phase8_sibling_sensitivity/runner.py`, then `analyze.py` |

Run the analysis scripts from `pipeline/analysis-scripts/`: they resolve their
inputs as `../phase1_empirical/...` and `../phase4_encoding/...`, which is
exactly where those directories sit.

Each phase directory carries its own `README.md` and, where the campaign is
hash-bound, an `EXPERIMENT_CONTRACT.md`.

Pinned outputs: the paper reads specific timestamped run directories, for
example `pipeline/phase5_evaluation/processing_benchmark/outputs/
controlled-processing-20260830T-marker-final-v1/`. Compare against those, not
against a later run.

## 3. Rebuild from raw inputs

The per-scenario routing dumps and registry snapshots are far too large to
ship. `EXCLUDED-RAW-DATA.md` lists each input with its size and the entry point
that regenerates it. In short:

1. Fetch the RIPE Database dump and the RIS/RRC00 RIB and bview files for
   24 June 2026, plus the CAIDA AS-relationship snapshot named in the contracts.
2. Run `pipeline/phase1_empirical/` to regenerate the candidate set for Table I.
3. Run the phases in numeric order.
4. The routing model needs its own environment:

   ```bash
   cd pipeline/phase7_simulation
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements-bgpy.txt
   ```
