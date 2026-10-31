# Matched unknown-origin handoff: handoff-benefit-20260828T143645Z

Overall acceptance: **PASS**

| Workflow | Trials | Passed | Signed updates | ROA-entry changes | Observed to action, median / p95 (ms) | Observed to probe, median / p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Reactive exact ROA | 2 | 2 | 2 | 4 | 2246.727 / 2324.658 | 2341.591 / 2418.428 |
| Dynamic OpenScope | 2 | 2 | 0 | 0 | 983.049 / 995.318 | 1080.003 / 1087.969 |
| Prepublished exact ROAs | 2 | 2 | 0 | 0 | 933.503 / 937.888 | 1029.705 / 1033.144 |

## Primary complete-round contrast

Reactive exact minus dynamic OpenScope for observed-to-action time: 1263.677 ms, 95% cluster-bootstrap CI [1263.677, 1263.677]; n=1 complete rounds.

Every failed trial remains in the JSON output and in the lane counts. Missing timing values are not imputed.
