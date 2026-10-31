# Matched unknown-origin handoff: handoff-benefit-ipv6-20260828T232235Z

Overall acceptance: **PASS**

| Workflow | Trials | Passed | Signed updates | ROA-entry changes | Observed to action, median / p95 (ms) | Observed to probe, median / p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Reactive exact ROA | 2 | 2 | 2 | 4 | 2125.86 / 2182.064 | 2220.51 / 2279.274 |
| Dynamic OpenScope | 2 | 2 | 0 | 0 | 930.151 / 939.104 | 1017.093 / 1025.368 |
| Prepublished exact ROAs | 2 | 2 | 0 | 0 | 948.813 / 950.097 | 1061.336 / 1078.714 |

## Primary complete-round contrast

Reactive exact minus dynamic OpenScope for observed-to-action time: 1195.709 ms, 95% cluster-bootstrap CI [1130.551, 1260.866]; n=2 complete rounds.

Every failed trial remains in the JSON output and in the lane counts. Missing timing values are not imputed.
