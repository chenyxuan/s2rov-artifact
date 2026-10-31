# S2-ROV BGPy pilot

This directory contains the project-owned Phase 7 policy adapter, deterministic
small AS graph, outcome analyzer, command-line runner, and regression tests.
It imports BGPy from the pinned vendor checkout and does not modify either
vendored simulator.

From the repository root, run the tests with:

```bash
PYTHONPATH="$PWD/phase7_simulation/vendor/bgpy:$PWD" \
  phase7_simulation/.venv-bgpy/bin/python -m pytest -q \
  phase7_simulation/s2rov/tests
```

Run the pilot and write its machine-readable result with:

```bash
PYTHONPATH="$PWD/phase7_simulation/vendor/bgpy:$PWD" \
  phase7_simulation/.venv-bgpy/bin/python -m phase7_simulation.s2rov.pilot \
  --output phase7_simulation/results/pilot/pilot.json
```

The pilot runs an 11-AS Gao--Rexford graph at 0%, 50%, and 100% DA upgrade
within a fixed four-AS ROV set.  It includes a delegate-only lane and a paired
delegate/attacker equal-prefix lane.  Every run reports the exact child-route
selection partition and a per-hop longest-prefix destination partition,
including holder-aggregate fallback.  These are implementation checks, not
Internet-scale evidence; the production campaign remains gated on this pilot.
