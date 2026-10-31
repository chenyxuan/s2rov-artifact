# Reproducing the results

Paths are relative to the bundle root. The paper itself is not bundled.

## 1. Read the numbers (no setup)

`results/` holds one plainly named file per reported item:

| File | Manuscript item |
|---|---|
| `results/table1-registry-paths.csv` | Table I, registry paths and origin divergence |
| `results/fig2-conflict-rates.csv` | Fig. 2, conflicts during partial ROA issuance |
| `results/fig3-prioritization.csv` | Fig. 3, aggregate-prefix prioritization |
| `results/fig4-processing-cost.json` | Fig. 4, classification throughput and update latency |
| `results/fig5-deployment-outcomes.csv` | Fig. 5, reachability and origin exposure |
| `results/section5c-ipv6-sensitivity.json` | Sec. V-C, IPv6 candidate sensitivity |
| `results/section5d-attack-reachability.json` | Sec. V-D, attack reachability |

`results/README.md` names the pipeline file each one came from, and
`results/numbers.json` is the ledger of every number quoted in the paper.

## 2. Re-run one experiment

| Item | Entry point |
|---|---|
| Table I | `experiments/candidates/` |
| Figs. 2, 3 | `experiments/analysis_scripts/run_partial_policy_replay.py` |
| Fig. 4 | `experiments/cost/processing_benchmark/` |
| Fig. 5 | `experiments/routing_model/campaign/` |
| Sec. V-C | `experiments/routing_model/campaign/ipv6_sensitivity.py` |
| Sec. V-D | `experiments/attack_reachability/runner.py`, then `analyze.py` under the same directory |

Run the analysis scripts from anywhere; each locates the repository root
from its own path, not from the working directory.

## 3. Rebuild from raw inputs

The per-scenario routing dumps and registry snapshots are far too large to
ship. `EXCLUDED-RAW-DATA.md` lists each input with its size and the entry point
that regenerates it. In short:

1. Fetch the RIPE Database dump and the RIS/RRC00 RIB and bview files for
   24 June 2026, plus the CAIDA AS-relationship snapshot of 1 July 2026
   (`CAIDAASGraphCollector_2026.07.25.txt`, the name recorded in
   `experiments/routing_model/evaluation/bgpy.md`).
2. Run `experiments/candidates/` to regenerate the candidate set for Table I,
   then `experiments/routing_model/scripts/prepare_inputs.py` to compile the
   topology and ROV set the routing model reads. Both are required arguments:
   pass `--topology-file` (AS-relationship graph) and `--rov-json` (the
   measured ROV deployment set of Hlavacek et al.).
3. Run the experiments in the order their inputs require: candidates, then
   cost and routing model, then reanalysis and the semantic gate.
4. The routing model needs its own environment:

   ```bash
   cd experiments/routing_model
   python3 -m venv .venv-bgpy && . .venv-bgpy/bin/activate
   pip install -r requirements-bgpy.lock.txt
   ```

   The lock file, not `requirements-bgpy.txt`, is what the runner accepts;
   it verifies every pin.

