# Prototype Policy-Scale Report: scale-20260823T025539Z

Overall result: **PASS**

The experiment retained 80 signed update observations, 80 complete enforcement snapshots, and 560 route-outcome checks.

| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |
|---:|---|---:|---:|---:|
| 0 | remove | 10 | 3157.781 | 3695.419 |
| 0 | restore | 10 | 3672.977 | 3905.445 |
| 64 | remove | 10 | 3622.630 | 3710.327 |
| 64 | restore | 10 | 3725.728 | 4003.749 |
| 256 | remove | 10 | 3690.517 | 4768.594 |
| 256 | restore | 10 | 3805.055 | 3948.349 |
| 1024 | remove | 10 | 3741.957 | 3843.403 |
| 1024 | restore | 10 | 3853.016 | 4078.133 |

| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |
|---:|---:|---:|---:|
| 0 | 2 | 362 | 2.466 |
| 64 | 66 | 8338 | 9246.999 |
| 256 | 258 | 32386 | 2097.048 |
| 1024 | 1026 | 129202 | 2185.245 |

These measurements include Krill publication, Routinator validation, prototype evaluation, FRR installation, and the complete seven-route check. They vary signed-policy entries, not live-route count or Internet propagation.
