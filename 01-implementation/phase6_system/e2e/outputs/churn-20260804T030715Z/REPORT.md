# Origin-churn prototype report: churn-20260804T030715Z

Overall result: **PASS**

## Direct result

| Lane | Trials | Signed updates | Invalid exposure, median / p95 (ms) | Unavailable, median / p95 (ms) | Completion, median / p95 (ms) | Final state / action |
|---|---:|---:|---:|---:|---:|---|
| Exact child ROA | 30 | 30 | 3021.660 / 3372.742 | 3265.471 / 3624.048 | 3585.577 / 3859.481 | Valid / accept |
| Open DA policy | 30 | 0 | 0.000 / 0.000 | 621.276 / 660.527 | 864.321 / 1016.273 | Delegated / accept |

One signed update is one atomic Krill authorization transaction. Each exact transition changes two entries (remove old, add new); the open-policy setup publication is excluded from DA handoff counts.

### Exact-update path

| Segment | Median / p95 (ms) |
|---|---:|
| Signed request to Routinator validation | 2142.186 / 2507.182 |
| Routinator validation to FRR RTR table | 123.460 / 149.499 |
| RTR table to verified FRR enforcement | 387.172 / 399.676 |

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

Both lanes use the same `/24`, origin ASes, FRR topology, break-before-make BGP commands, polling path, and final-state stop condition. The recorded order sandwiches the DA block between two exact-ROA blocks; no timing observation is discarded.

## Boundary

This experiment measures a reactive handoff after the new origin appears. Pre-authorizing both exact origins can avoid its Invalid interval when the handoff is known in advance, but needs additional signed authorization and temporarily broadens the exact set. Results are laboratory control-plane measurements, not Internet propagation or native four-state RTR measurements. Delegated does not authenticate which downstream origin is legitimate.
