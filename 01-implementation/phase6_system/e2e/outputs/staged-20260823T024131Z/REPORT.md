# Staged-deployment prototype report

- Passed: `true`
- Stages checked: 12
- Assertions checked: 213
- Upgrade/rollback cycles: 30
- Capability transitions: 60
- Complete transition matrix: `true`

| Stage | Publication | Pattern | Sink outcome | Passed |
|---|---|---:|---|:---:|
| conventional-LLL | conventional | `LLL` | covering_aggregate | yes |
| dual-LLL | dual | `LLL` | covering_aggregate | yes |
| dual-SSS | dual | `SSS` | covering_aggregate | yes |
| dual-DLL | dual | `DLL` | covering_aggregate | yes |
| dual-LDL | dual | `LDL` | covering_aggregate | yes |
| dual-LLD | dual | `LLD` | covering_aggregate | yes |
| dual-DDL | dual | `DDL` | covering_aggregate | yes |
| dual-DLD | dual | `DLD` | covering_aggregate | yes |
| dual-LDD | dual | `LDD` | covering_aggregate | yes |
| dual-DDD | dual | `DDD` | correct_delegate | yes |
| rollback-LLL | dual | `LLL` | covering_aggregate | yes |
| withdraw-LLL | conventional | `LLL` | covering_aggregate | yes |

| Transition | Observations | Median (ms) | p95 (ms) |
|---|---:|---:|---:|
| rollback | 30 | 8125.000 | 8255 |
| upgrade | 30 | 9197.500 | 9378 |

`Delegated` denotes holder-authorized open scope, not authentication of
the observed public origin. The arbitrary eligible-origin control is
therefore expected to follow the same staged reachability boundary as
the intended delegated route.
