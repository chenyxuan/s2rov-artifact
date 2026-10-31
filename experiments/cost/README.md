# Processing cost Evaluation Boundaries

The processing cost contains reference-semantic checks and scenario analyses.  It does not
replace the signed prototype-system experiments under `implementation/prototype/`.

## Scripts

- `08_semantic_boundary.py` checks the open/closed semantic boundary.  The
  NDSS corpus has no attack ground truth, so the script does not claim hijack
  detection.
- `09_label_coverage_adoption.py` reports a strong-assumption holder-adoption
  scenario over relationship-labeled occurrence rows.  It is not an FPR
  estimate or deployment forecast.
- `10_s2rov_reference_eval.py` checks eight four-state policy cases before and
  after serialization and records interpreter-only lookup diagnostics.  Those
  timings are not used as router or end-to-end performance evidence.

System claims in the manuscript must come from the Krill–Routinator–FRR
prototype run, with all route-level checks and trial logs preserved.
