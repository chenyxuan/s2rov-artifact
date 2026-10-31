# Reproducing the results

Paths are relative to the bundle root. The paper itself is not bundled.

## 1. Read the numbers (no setup)

`results/` holds one plainly named file per reported item:

| File | Manuscript item |
|---|---|
| `table1-registry-paths.csv` | Table I, registry paths and origin divergence |
| `fig2-conflict-rates.csv` | Fig. 2, conflicts during partial ROA issuance |
| `fig3-prioritization.csv` | Fig. 3, aggregate-prefix prioritization |
| `fig4-processing-cost.json` | Fig. 4, classification throughput and update latency |
| `fig5-deployment-outcomes.csv` | Fig. 5, reachability and origin exposure |
| `section5c-ipv6-sensitivity.json` | Sec. V-C, IPv6 candidate sensitivity |
| `section5d-attack-reachability.json` | Sec. V-D, attack reachability |

`results/README.md` names the pipeline file each one came from, and
`results/numbers.json` is the ledger of every number quoted in the paper.

## 2. Re-run one experiment

| Item | Entry point |
|---|---|
| Table I | `experiments/candidates/` |
| Figs. 2, 3 | `experiments/analysis-scripts/run_partial_policy_replay.py` |
| Fig. 4 | `experiments/cost/processing_benchmark/` |
| Fig. 5 | `experiments/routing-model/campaign/` |
| Sec. V-C | `experiments/routing-model/campaign/ipv6_sensitivity.py` |
| Sec. V-D | `experiments/attack-reachability/runner.py`, then `analyze.py` |

Run the analysis scripts from `experiments/analysis-scripts/`; they resolve
their inputs relative to that directory, matching the layout here.

## 3. Rebuild from raw inputs

The per-scenario routing dumps and registry snapshots are far too large to
ship. `EXCLUDED-RAW-DATA.md` lists each input with its size and the entry point
that regenerates it. In short:

1. Fetch the RIPE Database dump and the RIS/RRC00 RIB and bview files for
   24 June 2026, plus the CAIDA AS-relationship snapshot named in the contracts.
2. Run `experiments/candidates/` to regenerate the candidate set for Table I.
3. Run the experiments in the order listed in `README.md`.
4. The routing model needs its own environment:

   ```bash
   cd experiments/routing-model
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements-bgpy.txt
   ```
