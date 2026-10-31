# Phase 8: Sibling-Prefix Endpoint Sensitivity

This directory is an independent, versioned sensitivity campaign. It imports
the frozen Phase-7 graph/policy adapters read-only and writes only under
`phase8_sibling_sensitivity/results`. See `EXPERIMENT_CONTRACT.md` for the
frozen estimand and exclusions.

Run all commands from the repository root with the pinned Phase-7 environment:

```bash
export PYTHONPATH="$PWD/phase7_simulation/vendor/bgpy:$PWD"
export PHASE8_PYTHON="$PWD/phase7_simulation/.venv-bgpy/bin/python"

"$PHASE8_PYTHON" -m pytest -q phase8_sibling_sensitivity/tests
"$PHASE8_PYTHON" -m ruff check phase8_sibling_sensitivity

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.runner plan \
  --output-dir phase8_sibling_sensitivity/results

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.runner run \
  --output-dir phase8_sibling_sensitivity/results \
  --workers 16 \
  --max-new-trials 32 \
  --benchmark-report phase8_sibling_sensitivity/results/benchmark_32.json

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.runner run \
  --output-dir phase8_sibling_sensitivity/results \
  --workers 16

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.runner status \
  --output-dir phase8_sibling_sensitivity/results

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.analyze \
  --manifest phase8_sibling_sensitivity/results/manifest.json \
  --results phase8_sibling_sensitivity/results/raw_scenarios.jsonl \
  --output-dir phase8_sibling_sensitivity/results/analysis

"$PHASE8_PYTHON" -m phase8_sibling_sensitivity.analyze \
  --manifest phase8_sibling_sensitivity/results/manifest.json \
  --results phase8_sibling_sensitivity/results/raw_scenarios.jsonl \
  --output-dir phase8_sibling_sensitivity/results/analysis_recheck \
  --verify-reference phase8_sibling_sensitivity/results/analysis
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
- `results/analysis/leaf_invariance_audit.json`: exact Phase-7 leaf comparison;
- `results/analysis/analysis_manifest.json`: hashes and validation checklist;
- `results/analysis/reproduction_audit.json`: exact independent-rerun comparison;
- `results/analysis/RESULTS.md`: bounded human-readable result.

Timing, RSS, PID, and unordered raw-row arrival can vary between runs. The
analysis manifest therefore records both the raw byte hash and an order- and
resource-metadata-independent scientific digest.
