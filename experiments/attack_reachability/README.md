# Attack reachability: Sibling-Prefix Endpoint Sensitivity

This directory is an independent, versioned sensitivity campaign. It imports
the frozen routing-model graph/policy adapters read-only and writes only under
`experiments/attack_reachability/results`. See `EXPERIMENT_CONTRACT.md` for the
frozen estimand and exclusions.

Run all commands from the repository root with the pinned routing-model environment:

```bash
export PYTHONPATH="$PWD/experiments/routing_model/vendor/bgpy:$PWD"
export ATTACK_REACHABILITY_PYTHON="$PWD/experiments/routing_model/.venv-bgpy/bin/python"

"$ATTACK_REACHABILITY_PYTHON" -m pytest -q experiments/attack_reachability/tests
"$ATTACK_REACHABILITY_PYTHON" -m ruff check experiments/attack_reachability

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.runner plan \
  --output-dir experiments/attack_reachability/results

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.runner run \
  --output-dir experiments/attack_reachability/results \
  --workers 16 \
  --max-new-trials 32 \
  --benchmark-report experiments/attack_reachability/results/benchmark_32.json

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.runner run \
  --output-dir experiments/attack_reachability/results \
  --workers 16

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.runner status \
  --output-dir experiments/attack_reachability/results

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.analyze \
  --manifest experiments/attack_reachability/results/manifest.json \
  --results experiments/attack_reachability/results/raw_scenarios.jsonl \
  --output-dir experiments/attack_reachability/results/analysis

"$ATTACK_REACHABILITY_PYTHON" -m experiments.attack_reachability.analyze \
  --manifest experiments/attack_reachability/results/manifest.json \
  --results experiments/attack_reachability/results/raw_scenarios.jsonl \
  --output-dir experiments/attack_reachability/results/analysis_recheck \
  --verify-reference experiments/attack_reachability/results/analysis
```

The benchmark command is intentionally required before the full command. The
runner has no automatic retry path. If `failures.jsonl` contains a row, inspect
and document the failure instead of rerunning silently.

Primary artifacts:

- `results/manifest.json`: self-hashed design and execution plan;
- `results/provenance.json`: parent/input/code lineage and exact commands;
- `results/raw_scenarios.jsonl`: append-only physical-trial rows;
- `results/benchmark_32.json`: self-hashed resource-gate decision;
- `results/checkpoint.json` and `results/run_history.jsonl`: progress history;
- `results/analysis/summary.json` and `.csv`: all analysis cells;
- `results/analysis/holder_contrasts.jsonl`: holder-level paired values;
- `results/analysis/leaf_invariance_audit.json`: exact routing-model leaf comparison;
- `results/analysis/analysis_manifest.json`: hashes and validation checklist;
- `results/analysis/reproduction_audit.json`: exact independent-rerun comparison;
- `results/analysis/RESULTS.md`: bounded human-readable result.

Timing, RSS, PID, and unordered raw-row arrival can vary between runs. The
analysis manifest therefore records both the raw byte hash and an order- and
resource-metadata-independent scientific digest.
