# Prototype Policy-Scale Report: scale-20260804T021737Z

Overall result: **PASS**

The experiment retained 80 signed update observations, 80 complete enforcement snapshots, and 560 route-outcome checks.

| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |
|---:|---|---:|---:|---:|
| 0 | remove | 10 | 3494.135 | 3561.596 |
| 0 | restore | 10 | 2529.462 | 3726.175 |
| 64 | remove | 10 | 2454.664 | 3496.065 |
| 64 | restore | 10 | 3647.534 | 3724.920 |
| 256 | remove | 10 | 2593.806 | 3584.075 |
| 256 | restore | 10 | 3133.370 | 3889.518 |
| 1024 | remove | 10 | 3660.872 | 3783.006 |
| 1024 | restore | 10 | 3609.842 | 3738.961 |

| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |
|---:|---:|---:|---:|
| 0 | 2 | 362 | 2.918 |
| 64 | 66 | 8338 | 9077.304 |
| 256 | 258 | 32386 | 3150.201 |
| 1024 | 1026 | 129202 | 2694.827 |

These measurements include Krill publication, Routinator validation, prototype evaluation, FRR installation, and the complete seven-route check. They vary signed-policy entries, not live-route count or Internet propagation.
