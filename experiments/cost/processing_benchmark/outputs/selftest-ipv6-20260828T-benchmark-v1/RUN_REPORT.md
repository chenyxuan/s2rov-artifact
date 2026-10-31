# IPv6 reference-classifier processing benchmark

Generated: 2026-08-28T23:20:37Z

## Scope

This run measures the Python `S2ROV.validate_route` reference classifier on
8,192 valid scalar-origin IPv6 prefix-origin pairs derived from
8,192 IPv6 rows encountered in the mixed RRC00 CSV.
Preprocessing excluded 0 rows
whose origin is the explicit `{AMBIGUOUS}` marker. It does not measure FRR, RTR
transfer, router installation, forwarding, or line rate.

`parse_excluded` preloads IPv6 `(prefix string, origin integer)` pairs and times
classifier calls plus state capture. `parse_included` additionally times CSV decoding
and ASN integer conversion. Internal textual IPv6 CIDR parsing remains in both scopes.

Each policy contains one open `::/0` base with `max_length=128` and the first
`size-1` unique non-`::/0` prefixes in source order as closed exact-origin rules.
These are deterministic benchmark policies, not observed published authorizations.

## Configuration

- Repetitions per condition: 1
- Batch size: 512 routes
- Warm-up: 256 routes per fresh worker
- Schedule seed: 20260828
- Fixed worker CPU: 0
- Python: 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]
- Platform: Linux-6.8.0-90-generic-aarch64-with-glibc2.39
- Source SHA-256: `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- IPv6 workload SHA-256: `110603ebad621d9caa655930d6756a5311a5f1110c87c5013bdab0dc73aa10f5`
- IPv6 driver SHA-256: `86d593cbb87f4cd8127421611cef2c715d3a6d578d1f91cbf030b3fc404b390c`
- Classifier SHA-256: `fb0e251573979653a54ea79b1b2c3398bf30c4c99aed2a66c8edda458c544395`
- Reused family-neutral helper SHA-256: `53246ca76fccbe48ff3d4579e8cd12ffcb72a4f861b3b469cab2a9ae81ca19a1`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized values obtained by dividing a
full-batch duration by 512; they are not individually instrumented
request latencies. Peak RSS is the maximum fresh-worker high-water mark.

| Rules | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |
|---:|:---|---:|---:|:---|:---|---:|
| 1 | parse_excluded | 37 | 16189 | 31.613/32.393/32.416 | 61.745/63.267/63.312 | 22.4 |
| 1 | parse_included | 37 | 15904 | 31.948/33.084/33.095 | 62.398/64.616/64.638 | 22.4 |
| 64 | parse_excluded | 834 | 17130 | 29.712/31.380/31.499 | 58.031/61.289/61.521 | 22.4 |
| 64 | parse_included | 834 | 16497 | 31.013/31.900/32.026 | 60.572/62.304/62.552 | 22.4 |

## Integrity checks

- Worker records present: 4/4
- Exact condition matrix: True
- Fresh worker per condition: True
- Every worker pinned to CPU 0: True
- Every policy uses IPv6 `::/0`, `max_length=128`: True
- Serialization round trips identical: True
- Independent IPv6 oracle spot checks pass: True
- One result checksum per policy size across scopes and repetitions: True
- One state-count vector per policy size across scopes and repetitions: True
- Overall recomputation audit: True

## Artifacts

- `raw/`: one immutable JSON record per fresh worker, including every batch duration
- `raw_runs.csv`: one row per condition
- `raw_batch_samples.csv`: one row per measured batch
- `summary.csv`: recomputed aggregate values
- `recomputation_audit.json`: completeness, affinity, oracle, round-trip, and checksum checks
- `policies/`: IPv6 policy payloads, transparent specifications, and oracle spots
- `paper_table_ipv6.tex`: compact LaTeX suggestion, not inserted automatically

## Claim boundary

These results support only single-process, single-core IPv6 processing-cost claims
for the Python reference implementation on this RRC00-derived workload. They do not
measure full-RIB FRR processing, router data planes, native RTR/RPKI interoperability,
or Internet-wide production capacity.
