# Prototype Policy-Scale Report: scale-20260804T020941Z

Overall result: **PASS**

The experiment retained 4 signed update observations, 4 complete enforcement snapshots, and 28 route-outcome checks.

| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |
|---:|---|---:|---:|---:|
| 0 | remove | 1 | 3558.293 | 3558.293 |
| 0 | restore | 1 | 3763.993 | 3763.993 |
| 4 | remove | 1 | 3545.151 | 3545.151 |
| 4 | restore | 1 | 3583.149 | 3583.149 |

| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |
|---:|---:|---:|---:|
| 0 | 2 | 362 | 2.723 |
| 4 | 6 | 859 | 896.731 |

These measurements include Krill publication, Routinator validation, prototype evaluation, FRR installation, and the complete seven-route check. They vary signed-policy entries, not live-route count or Internet propagation.
