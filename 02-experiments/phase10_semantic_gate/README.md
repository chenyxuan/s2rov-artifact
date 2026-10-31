# Phase 10: Frozen E1a V3 Semantic Gate

This package preserves the historical E1a V3 gate. It compares an independent
oracle with the versioned implementation snapshot in `frozen_v3/`,
its canonical encoder/decoder, faithful conventional/exact/wildcard baselines,
and an independent pure snapshot lifecycle oracle. V1 and V2 are retained as
diagnostic audit history; V3 is the accepted contract.

V3 models the archived longest-prefix rule profile and is not a conformance
claim for the current conventional-ROV-first OpenScope profile. Current profile
version 2 is tested in Phase 4 and the later replay suites; it requires a new
E1a contract before a comparable differential-gate claim can be made.

From the repository root:

```bash
python3 -m unittest discover -s phase10_semantic_gate/tests -v
python3 -m phase10_semantic_gate.run_e1a \
  --output-dir MSN-2026-0830/experiment_redesign/execution/e1a-v3-production \
  --seed 20260826 --generated-vectors 100000 \
  --invalid-seed 120260826 --invalid-objects 100000
```

The output directory must not already contain files. Production success
requires every hard endpoint to be zero, including the broad-projection
negative control, and the final files to equal the startup allowlist. Run the
bundled reproducer into a fresh directory and verify the pair with
`python3 -m phase10_semantic_gate.compare_runs`. This phase makes no full-object,
RP/router, performance, or deployment claim.
