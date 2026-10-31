# S²-ROV artifact

Companion artifact for the paper *Protect the Parent, Spare the Child:
Protecting Prefixes in RPKI before All Origins Are Known* (IEEE MSN 2026).

The bundle contains the reference implementation, the experiment and analysis
scripts, their configurations, aggregate result tables, and the source data
behind every figure in the manuscript.

## Layout

| Directory | Contents | Manuscript |
|---|---|---|
| `01-implementation/` | DAROA codec, four-state classifier, validator and router glue | Sections III–IV |
| `02-experiments/` | Per-phase scripts, tests, contracts, configs, and the figure/assembly pipeline | Section V |
| `03-results/` | Aggregate result tables and analysis summaries | Tables and reported numbers |
| `04-figure-source-data/` | Per-figure source data and figure manifests | Figures 1–5 |

`MANIFEST.json` lists every file with its size and SHA-256, and
`EXCLUDED-RAW-DATA.md` records the raw inputs that are not shipped here.

## Requirements

- Python 3.12
- `phase7_simulation/requirements-bgpy.txt` for the routing model, installed in
  its own environment; the other phases need only the standard library plus the
  packages pinned in their own directories.
- No network access is required to reuse the shipped result tables.

## Reproducing the manuscript items

| Item | Entry point |
|---|---|
| Table I (registry paths, origin divergence) | `02-experiments/phase1_empirical/allocation_tree/visibility_experiment/` |
| Fig. 2, Fig. 3 (conflicts, prioritization) | `02-experiments/scripts/run_partial_policy_replay.py` |
| Fig. 4 (classification and update cost) | `02-experiments/phase5_evaluation/processing_benchmark/` |
| Fig. 5 (reachability, origin exposure) | `02-experiments/phase7_simulation/campaign/` |
| Attack reachability (Sec. V-D) | `02-experiments/phase8_sibling_sensitivity/` |
| IPv6 candidate sensitivity | `02-experiments/phase7_simulation/campaign/ipv6_sensitivity.py` |
| Formal statements and semantics | `02-experiments/phase2_formal/`, `02-experiments/phase3_semantics/` |

Each phase directory keeps its own `README.md` and, where the campaign is
hash-bound, its `EXPERIMENT_CONTRACT.md`.

## Verifying the bundle

```bash
python3 tools/prepare_artifact.py --check   # from the repository root
```

The check recomputes SHA-256 for every file listed in `MANIFEST.json`.

## Notes on paths

Absolute paths, the local home directory, and the build host name were rewritten
to `<repo>`, `<home>`, and `<host>` while assembling this bundle, so the files
carry no machine-specific identifiers. Recorded hashes and manifests are
otherwise unchanged.

## License and data terms

This bundle is released under the MIT License; see `LICENSE`. It covers the
code, scripts, configurations and derived figure source data in this package.

Third-party inputs keep their own terms. Registry and routing data come from
RIPE NCC (RIPE Database, RIS/RRC00) and AS-relationship data from CAIDA; they
are not redistributed here beyond the small derived tables needed to read the
figures. Third-party tools referenced by the scripts (Krill, Routinator, FRR,
BGPy) are not vendored and must be obtained under their own licenses.

Correspondence: Yuxuan Chen (chenyuxuan@cnic.cn) and Yanbiao Li
(lybmath@cnic.cn).
