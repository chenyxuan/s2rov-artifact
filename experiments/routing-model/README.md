# Phase 7: Internet-scale reachability and exposure

Phase 7 evaluates the steady-state routing consequence of DA-ROV on a fixed
AS-level topology.  It measures two sides of the same open policy:

1. delivery to an intended, unlisted child origin; and
2. delivery to an eligible but unauthorized origin announcing the same child
   prefix.

The selected simulator is **BGPy 13.0.10**.  InternetSim was also downloaded,
built, and evaluated, but its public artifact did not complete its official
example on this host and its ROV model lacks covering-ROA and `maxLength`
semantics.  Detailed evidence is in `evaluation/bgpy.md` and
`evaluation/internetsim.md`; exact upstream pins are in
`third_party.lock.json`.

## Layout

- `vendor/`: local, ignored upstream checkouts of BGPy and InternetSim;
- `data/inputs/`: immutable topology, measured-ROV set, mechanically filtered
  origin-divergence candidates, and hashes;
- `darov/`: the project-owned BGPy policy adapter and deterministic 11-AS
  semantic pilot;
- `campaign/`: the fixed full-graph resource gate and its tests;
- `evaluation/`: simulator reports and the experiment contract; and
- `results/`: the frozen paper-campaign manifest, checkpoint, verified compact
  analysis, and report. High-volume raw trials and reproducible pilot/gate
  outputs are intentionally ignored.

No vendored source is patched.  The DA-aware policy calls the Phase 4 semantic
oracle in `phase4_encoding/scripts/utils/daroa.py`.

## Reproduce the verified local checks

From the repository root:

```bash
# Recreate the ignored vendor checkouts at their audited commits.
phase7_simulation/scripts/fetch_simulators.sh

python3 -m venv phase7_simulation/.venv-bgpy
phase7_simulation/.venv-bgpy/bin/python -m pip install \
  -r phase7_simulation/requirements-bgpy.lock.txt

python3 -m unittest discover -s phase7_simulation/tests -v

export PYTHONPATH="$PWD/phase7_simulation/vendor/bgpy:$PWD"
PYTHON=phase7_simulation/.venv-bgpy/bin/python

$PYTHON -m pytest -q phase7_simulation/darov/tests
$PYTHON -m phase7_simulation.darov.pilot \
  --output phase7_simulation/results/pilot/pilot.json

$PYTHON -m pytest -q phase7_simulation/campaign/tests
$PYTHON -m ruff check phase7_simulation/darov \
  phase7_simulation/campaign phase7_simulation/scripts phase7_simulation/tests
```

The full-graph gate and formal campaign commands are documented in
`campaign/README.md`. The gate completed 100/100 trials on 2026-08-04; its
regenerable output remains local. The subsequent frozen paper campaign
completed 36,800/36,800 first-attempt trials and passed fail-closed analysis.
Its scientific result, integrity hashes, and conditional estimand are recorded
in `results/paper_campaign/FINAL_REPORT.md`.

## Interpretation boundary

The Phase 1 rows are observed root/leaf origin-divergence structures, not
verified delegations.  Results are conditional counterfactuals on one AS
relationship snapshot, one measured 589-AS ROV set, and Gao--Rexford routing.
`holder_fallback` is kept separate from delivery to the delegate; merely
having an aggregate route is not counted as delegated-service reachability.
