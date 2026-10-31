# End-to-End Experiment Report: run-20260729T011350Z

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

## Route decisions

| Case | Prefix | Origin | RFC 6811 baseline | DA-ROV |
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
| baseline krill to routinator | 7035.063 |
| baseline krill to frr | 7134.427 |
| da krill to routinator | 2649.876 |
| da evaluate and frr enforce | 3512.286 |
| Routinator restart to FRR recovery (n=5, median/p95) | 10758.143 / 10784.679 |
| Closed override removal (n=30, median/p95) | 2450.479 / 2552.213 |
| Closed override restoration (n=30, median/p95) | 1548.983 / 2574.578 |

## Security boundary

Open policy preserves self-protection at the exact aggregate and excludes non-public origins, but it cannot authenticate or distinguish an arbitrary eligible public subprefix origin.

In particular, the public-AS subprefix test is **Delegated**, not Explicit or Valid. This is an intentional negative control.
