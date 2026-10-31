# Reanalysis: selected-unit competitor reanalysis

This read-only reanalysis corrects the uncertainty target for the competition
and sibling results used by the MSN 2026 manuscript. routing-model assigned
competitors after sampling 200 units, so competitor-dependent outcomes are not
defined for the remaining 491 frame units. reanalysis therefore reports ordinary
paired within-stratum bootstrap stability intervals over the selected units,
without finite-population correction. It does not rerun BGPy or change any
point estimate.

Run from the repository root:

```bash
python experiments/reanalysis/reanalyze.py
```

The script verifies 200 unique units, 50 units per frozen stratum, stable unit
metadata across cells, constant replicate weights, and numerical identity with
the frozen routing-model/8 point estimates. It writes:

- `results/competition_cells.csv` (48 current-manuscript routing-model cells),
- `results/sibling_cells.csv` (two current-manuscript attack-reachability endpoints), and
- `results/summary.json` (input/code hashes, audits, and headline values).

See `EXPERIMENT_CONTRACT.md` for the estimand and claim boundary.

