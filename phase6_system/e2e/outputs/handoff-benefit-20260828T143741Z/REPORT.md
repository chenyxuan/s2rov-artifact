# Matched unknown-origin handoff: handoff-benefit-20260828T143741Z

Overall acceptance: **PASS**

| Workflow | Trials | Passed | Signed updates | ROA-entry changes | Observed to action, median / p95 (ms) | Observed to probe, median / p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Reactive exact ROA | 40 | 40 | 40 | 80 | 2346.217 / 2527.953 | 2446.736 / 2621.287 |
| Dynamic OpenScope | 40 | 40 | 0 | 0 | 976.179 / 1016.231 | 1075.251 / 1107.648 |
| Prepublished exact ROAs | 40 | 40 | 0 | 0 | 972.21 / 1010.552 | 1068.714 / 1103.813 |

## Primary complete-round contrast

Reactive exact minus dynamic OpenScope for observed-to-action time: 1374.954 ms, 95% cluster-bootstrap CI [1343.811, 1415.752]; n=10 complete rounds.

Every failed trial remains in the JSON output and in the lane counts. Missing timing values are not imputed.
