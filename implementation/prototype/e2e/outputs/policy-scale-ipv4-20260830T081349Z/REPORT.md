# Prototype Policy-Scale Report: policy-scale-ipv4-20260830T081349Z

Overall result: **PASS**
Address family: **ipv4**

The experiment retained 80 signed update observations, 80 complete enforcement snapshots, and 80 route-outcome checks.

| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |
|---:|---|---:|---:|---:|
| 0 | remove | 10 | 2031.527 | 2145.700 |
| 0 | restore | 10 | 1971.788 | 2184.236 |
| 64 | remove | 10 | 2015.767 | 2881.089 |
| 64 | restore | 10 | 2038.818 | 2152.363 |
| 256 | remove | 10 | 2020.930 | 2927.825 |
| 256 | restore | 10 | 1995.916 | 2120.664 |
| 1024 | remove | 10 | 2029.665 | 2905.512 |
| 1024 | restore | 10 | 1977.557 | 2099.221 |

| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |
|---:|---:|---:|---:|
| 0 | 3 | 488 | 1.709 |
| 64 | 67 | 8464 | 9379.541 |
| 256 | 259 | 32512 | 3156.532 |
| 1024 | 1027 | 129328 | 3167.299 |

These measurements include Krill publication, Routinator validation, prototype evaluation, FRR installation, and the complete live-route check (1 route(s) per transition). They vary signed-policy entries, not live-route count or Internet propagation.
