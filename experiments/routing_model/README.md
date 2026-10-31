# Routing model: Internet-scale reachability and exposure

The routing model evaluates the steady-state routing consequence of S2-ROV on a fixed
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
- `s2rov/`: the project-owned BGPy policy adapter and deterministic 11-AS
  semantic pilot;
- `campaign/`: the fixed full-graph resource gate and its tests;
- `evaluation/`: simulator reports and the experiment contract; and
- `results/`: the frozen paper-campaign manifest, checkpoint, verified compact
  analysis, and report. High-volume raw trials and reproducible pilot/gate
  outputs are intentionally ignored.

No vendored source is patched.  The S2-ROV-aware policy calls the S2-ROV-encoding semantic
oracle in `implementation/s2rov_codec/scripts/utils/s2rov.py`.

## Reproduce the verified local checks

From the repository root:

```bash
# Recreate the ignored vendor checkouts at their audited commits.
experiments/routing_model/scripts/fetch_simulators.sh

python3 -m venv experiments/routing_model/.venv-bgpy
experiments/routing_model/.venv-bgpy/bin/python -m pip install \
  -r experiments/routing_model/requirements-bgpy.lock.txt

python3 -m unittest discover -s experiments/routing_model/tests -v

export PYTHONPATH="$PWD/experiments/routing_model/vendor/bgpy:$PWD"
PYTHON=experiments/routing_model/.venv-bgpy/bin/python

$PYTHON -m pytest -q experiments/routing_model/s2rov/tests
$PYTHON -m experiments.routing_model.s2rov.pilot \
  --output experiments/routing_model/results/pilot/pilot.json

$PYTHON -m pytest -q experiments/routing_model/campaign/tests
$PYTHON -m ruff check experiments/routing_model/s2rov \
  experiments/routing_model/campaign experiments/routing_model/scripts experiments/routing_model/tests
```

The full-graph gate and formal campaign commands are documented in
`campaign/README.md`. The gate completed 100/100 trials on 2026-08-04; its
regenerable output remains local. The subsequent frozen paper campaign
completed 36,800/36,800 first-attempt trials and passed fail-closed analysis.
Its scientific result, integrity hashes, and conditional estimand are recorded
in `results/paper_campaign/FINAL_REPORT.md`.

## Interpretation boundary

The candidate-selection rows are observed root/leaf origin-divergence structures, not
verified delegations.  Results are conditional counterfactuals on one AS
relationship snapshot, one measured 589-AS ROV set, and Gao--Rexford routing.
`holder_fallback` is kept separate from delivery to the delegate; merely
having an aggregate route is not counted as delegated-service reachability.
