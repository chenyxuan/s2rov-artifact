# Result Provenance Audit

> **Superseded for manuscript display on 2026-08-30.** The accepted run,
> independent recomputation, and retained table CSV below remain the evidence
> source, but Table II has been replaced in the manuscript by the two-panel
> IPv4/IPv6 processing-cost Figure 3. The active rendering chain is
> `scripts/build_processing_cost_figure.py`,
> `figures/fig_processing_cost.manifest.json`, and the load and classification
> panel products. The remainder of this report preserves the earlier table
> display audit as history.

Date: 2026-08-29

Verdict: **PASS** for the revised Table II.

## Evidence chain

| Layer | Artifact | Check |
|---|---|---|
| Frozen design | `workspace/experiments/PROCESSING_BENCHMARK_V2_PLAN.md` | Matrix, metrics, repetitions, fixed-output gates, and resource approval were recorded before execution. |
| Executed source | `phase5_evaluation/processing_benchmark/run_controlled_policy_benchmark.py` | SHA-256 `b3f83e091e5d3213ed25d64c572335fd0bfc104f2bb520d1b105a4fe2f561167`, matching the run configuration. |
| Accepted run | `phase5_evaluation/processing_benchmark/outputs/controlled-processing-20260829T1152Z` | 150 worker records cover the exact two-version, three-size matrix. |
| Summary | `summary.json` | SHA-256 `cc0e3f3fa5787cf4dda14e60238f9a7a2cc601bacf111c76d9d9650db809ac7d`. |
| Independent audit | `independent_audit.json` | SHA-256 `189ed2bc46e8c30c3fcec4059bfacf613d8de648aabc529313ea5d9a047b9f4a`; every gate passes and all 12 displayed measurements recompute. |
| Table transform | `MSN-2026-0830/scripts/build_processing_cost_table.py` | Verifies both audit layers and emits the six-row table with one-decimal display values. |
| Manuscript source | `outputs/tables/processing_cost_dual_stack.tex` | SHA-256 `15f35023c6117798151a5a50adb7dc1324950d28075c23d411607e5610e4a890`; included directly by Section V-B. |

## Cross-checks

- `Subprefixes` excludes the one mandatory open base entry in every policy.
- IPv4 and IPv6 each use one fixed 8,192-query set at all three sizes.
- Every timed result is `OpenScope`; query hashes, result hashes, and state
  vectors remain fixed within each IP version.
- Table II's six load values and six classification values match the accepted
  summary after one-decimal rounding.
- The previous five-size replays are retained only as historical artifacts and
  no longer supply the manuscript table.

No unsupported transformation or manually entered Table II value remains in
the active evidence chain.
