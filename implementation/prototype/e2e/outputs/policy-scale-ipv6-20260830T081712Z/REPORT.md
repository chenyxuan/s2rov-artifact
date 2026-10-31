# Prototype Policy-Scale Report: policy-scale-ipv6-20260830T081712Z

Overall result: **PASS**
Address family: **ipv6**

The experiment retained 80 signed update observations, 80 complete enforcement snapshots, and 80 route-outcome checks.

| Additional closed Stripes | Transition | n | Median (ms) | p95 (ms) |
|---:|---|---:|---:|---:|
| 0 | remove | 10 | 1935.486 | 2035.294 |
| 0 | restore | 10 | 2047.206 | 2141.923 |
| 64 | remove | 10 | 2011.647 | 3009.941 |
| 64 | restore | 10 | 2053.381 | 2132.529 |
| 256 | remove | 10 | 2051.188 | 3026.508 |
| 256 | restore | 10 | 1990.955 | 2078.078 |
| 1024 | remove | 10 | 2033.165 | 3019.621 |
| 1024 | restore | 10 | 1992.867 | 2209.910 |

| Additional closed Stripes | Validated entries | JSON bytes | Setup (ms) |
|---:|---:|---:|---:|
| 0 | 3 | 497 | 1.800 |
| 64 | 67 | 8863 | 9099.611 |
| 256 | 259 | 34015 | 2979.034 |
| 1024 | 1027 | 135391 | 2866.170 |

These measurements include Krill publication, Routinator validation, prototype evaluation, FRR installation, and the complete live-route check (1 route(s) per transition). They vary signed-policy entries, not live-route count or Internet propagation.
