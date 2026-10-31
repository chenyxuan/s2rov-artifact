# Four-arm churn-control report: controls-20260823T022857Z

Overall result: **PASS**

## Direct result

| Arm | Trials | Signed updates | Invalid median / p95 (ms) | Unavailable median / p95 (ms) | Completion median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Reactive exact ROA | 40 | 40 | 3210.706 / 3427.367 | 3440.550 / 3654.334 | 3668.491 / 3896.766 | Valid / accept |
| Open DA policy | 40 | 0 | 0.000 / 0.000 | 616.142 / 645.290 | 843.229 / 899.814 | Delegated / accept |
| BGP-only | 40 | 0 | 0.000 / 0.000 | 624.587 / 648.030 | 854.211 / 998.312 | BGPOnly / accept |
| Prepublished exact ROAs | 40 | 0 | 0.000 / 0.000 | 622.596 / 652.129 | 855.567 / 887.448 | Valid / accept |

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
