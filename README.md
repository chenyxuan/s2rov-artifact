# S²-ROV artifact

Companion artifact for *Protect the Parent, Spare the Child: Protecting
Prefixes in RPKI before All Origins Are Known* (IEEE MSN 2026).

Two things a reader usually wants are separated here:

- **what the paper reports** — `00-reproduce/`, one plainly named file per
  table, figure, and measured section;
- **how it was produced** — the experiment pipeline in `phase*/`, kept at its
  original paths so the scripts still find their inputs.

Start with `REPRODUCE.md`; it walks from reading a number to re-running the
pipeline that produced it.

## Layout

| Path | Contents |
|---|---|
| `00-reproduce/` | One file per manuscript item, renamed for reading, with the original path recorded |
| `phase1_empirical/` … `phase10_semantic_gate/` | The experiment pipeline, numbered in run order |
| `manuscript/` | Paper build: figure and replay scripts, `Makefile`, figure source data |
| `MANIFEST.json` | Every file with its size and SHA-256 |
| `EXCLUDED-RAW-DATA.md` | Raw inputs that are regenerated rather than shipped |

Which phase is which: `phase1` observed candidates (Table I), `phase2`–`phase3`
formal statements, `phase4` the DAROA codec and classifier (Sections III–IV),
`phase5` cost benchmarks (Fig. 4), `phase6` the Krill/Routinator/FRR prototype,
`phase7` the routing model (Fig. 5 and the IPv6 sensitivity), `phase8` attack
reachability (Sec. V-D), `phase9` selected-unit reanalysis, `phase10` semantic
gate.

## Requirements

- Python 3.12.
- `phase7_simulation/requirements-bgpy.txt` for the routing model, installed in
  its own environment.
- No setup at all to read `00-reproduce/`.

## Reproducing

See `REPRODUCE.md` for the three levels: read the numbers, re-run one figure,
or rebuild from raw inputs. In short:

```bash
cd manuscript && make figures && make refresh && make check
```

## Verifying the bundle

```bash
python3 tools/prepare_artifact.py --check    # from the repository root
```

Recomputes SHA-256 for every file listed in `MANIFEST.json`.

## Notes on paths

Absolute paths, the local home directory, and the build host name were rewritten
to `<repo>`, `<home>`, and `<host>` while assembling this bundle, so the files
carry no machine-specific identifiers. Recorded hashes and manifests are
otherwise unchanged.

## License and data terms

Code, scripts, configurations and derived figure source data are released under
the MIT License (`LICENSE`).

Third-party inputs keep their own terms. Registry and routing data come from
RIPE NCC (RIPE Database, RIS/RRC00) and AS-relationship data from CAIDA; they
are not redistributed here beyond the small derived tables needed to read the
figures. Third-party tools referenced by the scripts (Krill, Routinator, FRR,
BGPy) are not vendored and must be obtained under their own licenses.

Correspondence: Yuxuan Chen (chenyuxuan@cnic.cn) and Yanbiao Li
(lybmath@cnic.cn).
