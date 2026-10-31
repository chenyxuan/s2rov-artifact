# S²-ROV artifact

Code, experiment scripts, configurations, result tables and figure source data
for *Protect the Parent, Spare the Child: Protecting Prefixes in RPKI before All
Origins Are Known* (IEEE MSN 2026).

The paper itself is not bundled; it is published by the conference.

```text
implementation/   the DAROA codec, the four-state classifier, the prototype
experiments/      one directory per experiment, named for what it does
results/          the reported tables and the ledger of quoted numbers
figure-data/      the plotted data behind the figures
verify.py         checks this tree against MANIFEST.json
```

## What the paper promises, and where it is

| Promised material | In this bundle |
|---|---|
| **implementation** | `implementation/daroa-codec/` — encoding, merging, four-state classifier; `implementation/prototype/` — Krill / Routinator / FRR prototype |
| **experiment and analysis scripts** | `experiments/*/` and `experiments/analysis-scripts/` |
| **configurations** | the `*.json` contracts and manifests inside each experiment directory |
| **result tables** | `results/` for the reported items, `results/tables/` for the full tables |
| **figure source data** | `figure-data/` |

## Experiments

| Directory | What it does | Reported as |
|---|---|---|
| `experiments/candidates/` | Registry and RIS analysis; candidate selection | Table I |
| `experiments/formal/`, `experiments/semantics/` | Formal statements and classifier semantics | Sections II–III |
| `experiments/cost/` | Classification throughput and update latency | Fig. 4 |
| `experiments/routing-model/` | BGPy model: delivery and origin exposure | Fig. 5, Sec. V-C |
| `experiments/attack-reachability/` | Attacker reachability for a marked region | Sec. V-D |
| `experiments/reanalysis/` | Selected-unit bootstrap reanalysis | Sec. V |
| `experiments/semantic-gate/` | Semantic gate on exported results | correctness checks |
| `experiments/analysis-scripts/` | Figure and replay scripts used for the manuscript | Figs. 2–5 |

Each directory keeps its own `README.md` and, where the campaign was run under
a frozen contract, an `EXPERIMENT_CONTRACT.md`.

## Requirements

- Python 3.12.
- `experiments/routing-model/requirements-bgpy.txt` for the routing model, in
  its own environment.
- Nothing at all to read `results/` or `figure-data/`.

## Verifying the bundle

```bash
python3 verify.py
```

Recomputes SHA-256 for every bundled file against `MANIFEST.json` and exits
non-zero on any missing or modified file.

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
