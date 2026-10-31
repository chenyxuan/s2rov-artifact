## Material Passport

- **Material ID:** `daroa-prototype-run-20260729T023834Z`
- **Material type:** experiment result
- **Verification status:** VERIFIED
- **Experiment type:** controlled end-to-end system experiment
- **System under test:** Krill–Routinator–policy-agent–FRR prototype
- **Run command:** `RECOVERY_TRIALS=30 FRR_RECOVERY_TRIALS=30 UPDATE_TRIALS=30 OUTAGE_HOLD_SECONDS=15 bash scripts/run-experiment.sh experiment`
- **Run status:** completed, exit code 0

## Result

- Conventional and DA semantic checks passed for all seven live routes.
- Thirty closed-Stripe removals reached `Delegated` in FRR; thirty
  restorations returned to `Explicit`.
- Thirty Routinator restarts and thirty FRR restarts restored and verified the
  complete DA enforcement matrix.
- The installed FRR policy remained enforced during the 15-second Routinator
  outage.

## Independent verification

- Trial identifiers are unique and complete from 1 through 30 for every timing
  condition.
- The raw medians and nearest-rank p95 values reproduce `summary.json`.
- The run contains 124 enforcement files and 868 route-level enforcement
  records; every record has `pass: true`.
- No timing observation was removed or replaced.

## Outputs

- `summary.json`, `summary.csv`, and `REPORT.md`
- `override-update-samples.csv`
- `recovery-samples.csv`
- `frr-recovery-samples.csv`
- per-trial Routinator payloads, decisions, generated FRR policies, live RIBs,
  and enforcement checks

## Anomalies and exclusions

The verified run has no failed trial. An earlier one-trial smoke run
(`run-20260729T023531Z`) stopped during harness validation because a shell
variable shadowed the output directory. That run remains on disk as a failed
audit record and contributes no manuscript data.
