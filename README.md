# S²-ROV artifact

Code, experiment scripts, configurations, result tables and figure source data
for *Protect the Parent, Spare the Child: Protecting Prefixes in RPKI before All
Origins Are Known* (IEEE MSN 2026).

The paper itself is not bundled; it is published by the conference.

```text
00-reproduce/        one plainly named file per table, figure, measured section
figure-source-data/  the plotted data behind Figures 1-5
pipeline/            the experiment code, kept at the paths the scripts expect
results.facts.json   every number quoted in the paper, with its provenance
REPRODUCE.md         how to read the numbers and how to re-run an experiment
```

## What the paper promises, and where it is

| Promised material | In this bundle |
|---|---|
| **implementation** | `pipeline/phase4_encoding/` — DAROA codec and four-state classifier; `pipeline/phase6_system/` — Krill / Routinator / FRR prototype |
| **experiment and analysis scripts** | `pipeline/phase1_empirical/` … `pipeline/phase10_semantic_gate/`; figure and replay scripts in `pipeline/analysis-scripts/` |
| **configurations** | the `*.json` contracts and manifests inside each phase |
| **result tables** | `00-reproduce/` for the reported items, `pipeline/*/results/` and `pipeline/*/outputs/` for the full tables |
| **figure source data** | `figure-source-data/` |

## The pipeline directories

The names are the identifiers the scripts import (`from
phase4_encoding.scripts.utils.daroa import …`), so they are kept as-is.

| Directory | What it does | Reported as |
|---|---|---|
| `phase1_empirical/` | Registry and RIS analysis; candidate selection | Table I |
| `phase2_formal/`, `phase3_semantics/` | Formal statements and classifier semantics | Sections II–III |
| `phase4_encoding/` | DAROA encoding, merge, four-state classifier | Sections III–IV |
| `phase5_evaluation/` | Classification throughput and update latency | Fig. 4 |
| `phase6_system/` | Krill / Routinator / FRR end-to-end prototype | Section IV |
| `phase7_simulation/` | BGPy routing model: delivery and exposure | Fig. 5, Sec. V-C |
| `phase8_sibling_sensitivity/` | Attacker reachability for a marked region | Sec. V-D |
| `phase9_selected_unit_reanalysis/` | Selected-unit bootstrap reanalysis | Sec. V |
| `phase10_semantic_gate/` | Semantic gate on exported results | Correctness checks |

## Requirements

- Python 3.12.
- `pipeline/phase7_simulation/requirements-bgpy.txt` for the routing model, in
  its own environment.
- Nothing at all to read `00-reproduce/` or `figure-source-data/`.

## Verifying the bundle

```bash
python3 tools/prepare_artifact.py --check
```

Recomputes SHA-256 for every file in `MANIFEST.json`.

## Notes on paths

Absolute paths, the home directory and the build host name are rewritten to
`<repo>`, `<home>` and `<host>` while assembling the bundle, so it carries no
machine-specific paths. That rewriting changes file digests, so the SHA-256
values frozen inside the experiment contracts no longer match; verify the
bundle through `MANIFEST.json` instead.

## License and data terms

Code, scripts, configurations and derived figure source data are released under
the MIT License (`LICENSE`).

Third-party inputs keep their own terms: RIPE NCC (RIPE Database, RIS/RRC00) and
CAIDA data are not redistributed beyond the small derived tables needed to read
the figures, and Krill, Routinator, FRR and BGPy are not vendored.

Correspondence: Yuxuan Chen (chenyuxuan@cnic.cn) and Yanbiao Li
(lybmath@cnic.cn).
