# Origin-churn prototype report: churn-20260804T030043Z

Overall result: **PASS**

## Direct result

| Lane | Trials | Signed updates | Invalid exposure, median / p95 (ms) | Unavailable, median / p95 (ms) | Completion, median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Exact child ROA | 2 | 2 | 76218.760 / 98110.865 | 76453.036 / 98339.430 | 76685.560 / 98580.233 | Valid / accept |
| Open S2-ROV policy | 2 | 0 | 0.000 / 0.000 | 719.894 / 751.191 | 962.032 / 980.780 | Delegated / accept |

One signed update is one atomic Krill authorization transaction. Each exact transition changes two entries (remove old, add new); the open-policy setup publication is excluded from S2-ROV handoff counts.

## Acceptance checks

| Check | Result |
|---|:---:|
| all trials retained | PASS |
| lane counts match | PASS |
| all trial assertions pass | PASS |
| exact updates each transition | PASS |
| da policy unchanged during churn | PASS |
| exact finishes valid and accepted | PASS |
| da finishes delegated and accepted | PASS |
| exact exposes invalid new route | PASS |
| da has no invalid state | PASS |

## Fairness and order

Both lanes use the same `/24`, origin ASes, FRR topology, break-before-make BGP commands, polling path, and final-state stop condition. The recorded order sandwiches the S2-ROV block between two exact-ROA blocks; no timing observation is discarded.

## Boundary

This experiment measures a reactive handoff after the new origin appears. Pre-authorizing both exact origins can avoid its Invalid interval when the handoff is known in advance, but needs additional signed authorization and temporarily broadens the exact set. Results are laboratory control-plane measurements, not Internet propagation or native four-state RTR measurements. Delegated does not authenticate which downstream origin is legitimate.
