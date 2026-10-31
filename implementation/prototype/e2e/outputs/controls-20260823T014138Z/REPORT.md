# Four-arm churn-control report: controls-20260823T014138Z

Overall result: **PASS**

## Direct result

| Arm | Trials | Signed updates | Invalid median / p95 (ms) | Unavailable median / p95 (ms) | Completion median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Reactive exact ROA | 30 | 30 | 3256.059 / 3393.854 | 3491.693 / 3620.664 | 3719.542 / 3841.385 | Valid / accept |
| Open S2-ROV policy | 30 | 0 | 0.000 / 0.000 | 619.852 / 667.395 | 850.269 / 913.851 | Delegated / accept |
| BGP-only | 30 | 0 | 0.000 / 0.000 | 625.822 / 670.198 | 856.865 / 907.452 | BGPOnly / accept |
| Prepublished exact ROAs | 30 | 0 | 0.000 / 0.000 | 625.791 / 677.006 | 860.357 / 916.363 | Valid / accept |

Timing uses a persistent monotonic clock. Policy setup is outside the handoff intervals and is retained separately in `setup.csv`.

## Acceptance checks

| Check | Result |
|---|:---:|
| all trials retained | PASS |
| lane counts match | PASS |
| all trial assertions pass | PASS |
| randomized complete block schedule | PASS |
| trial blocks match schedule | PASS |
| exact updates each transition | PASS |
| controls issue no handoff updates | PASS |
| static policy digests unchanged | PASS |
| final states and actions match | PASS |
| exact exposes invalid new route | PASS |
| nonreactive arms have no invalid interval | PASS |

## Design boundary

The randomized complete-block schedule balances slow drift across the four controlled workflows. BGP-only isolates the same local break-before-make handoff without inbound RPKI enforcement. Prepublished exact ROAs represent advance knowledge of both candidate origins; they are not a solution to an origin that cannot be named before the handoff. Results remain laboratory control-plane measurements, not Internet propagation measurements.
