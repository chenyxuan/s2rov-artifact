# Matched unknown-origin handoff: handoff-benefit-ipv6-20260829T002536Z

Overall acceptance: **PASS**

| Workflow | Trials | Passed | Signed updates | ROA-entry changes | Observed to action, median / p95 (ms) | Observed to probe, median / p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Reactive exact ROA | 40 | 40 | 40 | 80 | 2342.606 / 2489.894 | 2441.911 / 2581.848 |
| Dynamic OpenScope | 40 | 40 | 0 | 0 | 974.233 / 1022.983 | 1070.611 / 1119.831 |
| Prepublished exact ROAs | 40 | 40 | 0 | 0 | 975.039 / 1011.764 | 1067.513 / 1104.77 |

## Primary complete-round contrast

Reactive exact minus dynamic OpenScope for observed-to-action time: 1377.401 ms, 95% cluster-bootstrap CI [1334.967, 1440.075]; n=10 complete rounds.

Every failed trial remains in the JSON output and in the lane counts. Missing timing values are not imputed.
