# Four-arm churn-control report: controls-20260823T021709Z

Overall result: **PASS**

## Direct result

| Arm | Trials | Signed updates | Invalid median / p95 (ms) | Unavailable median / p95 (ms) | Completion median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Reactive exact ROA | 40 | 40 | 3148.666 / 3448.776 | 3402.805 / 3681.909 | 3647.451 / 3918.050 | Valid / accept |
| Open S2-ROV policy | 40 | 0 | 0.000 / 0.000 | 623.193 / 651.995 | 863.255 / 912.746 | Delegated / accept |
| BGP-only | 40 | 0 | 0.000 / 0.000 | 625.524 / 660.934 | 866.841 / 915.205 | BGPOnly / accept |
| Prepublished exact ROAs | 40 | 0 | 0.000 / 0.000 | 619.928 / 655.447 | 854.730 / 989.736 | Valid / accept |

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
