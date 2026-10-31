# End-to-End Experiment Report: run-20260729T023834Z

Overall result: **PASS**

## Semantic and enforcement checks

| Check | Result |
|---|:---:|
| baseline semantics | PASS |
| baseline frr enforcement | PASS |
| all bgp cases observed | PASS |
| da semantics | PASS |
| da frr enforcement | PASS |
| closed override removal to delegated | PASS |
| closed override restored to explicit | PASS |
| routinator outage policy retained | PASS |

## Route decisions

| Case | Prefix | Origin | RFC 6811 baseline | S2-ROV |
|---|---|---:|---|---|
| holder_aggregate | `10.0.0.0/16` | AS64501 | Valid | Explicit |
| listed_customer | `10.0.1.0/24` | AS8075 | Invalid | Explicit |
| open_delegate | `10.0.2.0/24` | AS18403 | Invalid | Delegated |
| public_subprefix_attacker | `10.0.3.0/24` | AS15169 | Invalid | Delegated |
| aggregate_attacker | `10.0.0.0/16` | AS13335 | Invalid | Invalid |
| private_origin | `10.0.4.0/24` | AS64513 | Invalid | Invalid |
| unrelated | `192.0.2.0/24` | AS64496 | NotFound | NotFound |

## Timing

| Metric | Milliseconds |
|---|---:|
| baseline krill to routinator | 5782.734 |
| baseline krill to frr | 5890.080 |
| da krill to routinator | 2873.797 |
| da evaluate and frr enforce | 612.835 |
| Routinator restart to DA policy recovery in FRR (n=30, median/p95) | 11676.243 / 11729.229 |
| FRR restart to DA policy recovery (n=30, median/p95) | 7695.101 / 7761.632 |
| Closed override removal to Delegated in FRR (n=30, median/p95) | 2433.879 / 3567.822 |
| Closed override restoration to Explicit in FRR (n=30, median/p95) | 3539.439 / 3848.264 |
| Routinator outage policy hold (15 s) | PASS |

## Security boundary

Open policy preserves self-protection at the exact aggregate and excludes non-public origins, but it cannot authenticate or distinguish an arbitrary eligible public subprefix origin.

In particular, the public-AS subprefix test is **Delegated**, not Explicit or Valid. This is an intentional negative control.
