# Reproducing the paper

Three levels, from cheapest to heaviest.

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

Each file is a copy of the pipeline output named in `00-reproduce/README.md`,
which also records the original path. Column names follow the plotting code.

## 2. Rebuild the paper (works from this bundle alone)

The manuscript sources travel with the bundle, and the figure scripts keep their
original relative layout, so the build finds its inputs where it expects them:

```bash
cd manuscript
make refresh     # assemble main.tex and compile the PDF  -> 8 pages
make check       # page limit, fonts, classifier boundaries, unit tests
```

`make refresh` and `make check` were verified inside this bundle.

Redrawing the figures needs only what is in `00-reproduce/`: those files are the
plotted data. Regenerating them *from scratch* is the next level, because
`make figures` re-derives every curve from the per-scenario routing dumps.

Individual entry points:

| Item | Script |
|---|---|
| Fig. 2, Fig. 3 | `scripts/run_partial_policy_replay.py` |
| Fig. 4 | `phase5_evaluation/processing_benchmark/` |
| Fig. 5 | `phase7_simulation/campaign/` |
| Sec. V-C | `phase7_simulation/campaign/ipv6_sensitivity.py` |
| Sec. V-D | `phase8_sibling_sensitivity/runner.py` then `analyze.py` |
| Table I | `phase1_empirical/allocation_tree/visibility_experiment/` |

Pinned outputs: the paper uses specific timestamped run directories, for
example `phase5_evaluation/processing_benchmark/outputs/
controlled-processing-20260830T-marker-final-v1/` and
`phase7_simulation/results/deployment_grid_extension/`. Read those, not a later
run, when comparing against manuscript values.

## 3. Full rebuild (needs the raw inputs)

`make figures` inside `manuscript/` reads the per-scenario routing dumps, which
are far too large to ship. The heavy raw inputs are not shipped (`EXCLUDED-RAW-DATA.md` lists them with
their sizes). To rebuild from scratch:

1. Fetch the public inputs: the RIPE Database dump and the RIS/RRC00 RIB and
   bview files for 24 June 2026, plus the CAIDA AS-relationship snapshot named
   in the contracts.
2. Run `phase1_empirical/` to regenerate the candidate set used by Table I.
3. Run each phase in numeric order; every phase directory has a `README.md`
   and, where the campaign is hash-bound, an `EXPERIMENT_CONTRACT.md`.
4. The routing model needs its own environment:
   ```bash
   cd phase7_simulation
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements-bgpy.txt
   ```

Determinism: fixed seeds and frozen selections are recorded in each phase's
manifest. Do not edit `EXPERIMENT_CONTRACT.md` files or recorded SHA-256 values;
they refer to the original full-size inputs.

## Verifying the bundle itself

```bash
python3 tools/prepare_artifact.py --check    # from the repository root
```

Recomputes SHA-256 for every file in `MANIFEST.json`.
