# Four-arm churn-control report: controls-20260823T013955Z

Overall result: **PASS**

## Direct result

| Arm | Trials | Signed updates | Invalid median / p95 (ms) | Unavailable median / p95 (ms) | Completion median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Reactive exact ROA | 1 | 1 | 1823.597 / 1823.597 | 2055.708 / 2055.708 | 2281.268 / 2281.268 | Valid / accept |
| Open S2-ROV policy | 1 | 0 | 0.000 / 0.000 | 606.481 / 606.481 | 864.275 / 864.275 | Delegated / accept |
| BGP-only | 1 | 0 | 0.000 / 0.000 | 615.993 / 615.993 | 845.042 / 845.042 | BGPOnly / accept |
| Prepublished exact ROAs | 1 | 0 | 0.000 / 0.000 | 625.815 / 625.815 | 846.354 / 846.354 | Valid / accept |

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
