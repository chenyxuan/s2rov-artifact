# IPv6 reference-classifier processing benchmark

Generated: 2026-08-29T00:54:15Z

## Scope

This run measures the Python `DAROA.validate_route` reference classifier on
257,550 valid scalar-origin IPv6 prefix-origin pairs derived from
257,583 IPv6 rows encountered in the mixed RRC00 CSV.
Preprocessing excluded 33 rows
whose origin is the explicit `{AMBIGUOUS}` marker. It does not measure FRR, RTR
transfer, router installation, forwarding, or line rate.

`parse_excluded` preloads IPv6 `(prefix string, origin integer)` pairs and times
classifier calls plus state capture. `parse_included` additionally times CSV decoding
and ASN integer conversion. Internal textual IPv6 CIDR parsing remains in both scopes.

Each policy contains one open `::/0` base with `max_length=128` and the first
`size-1` unique non-`::/0` prefixes in source order as closed exact-origin rules.
These are deterministic benchmark policies, not observed published authorizations.

## Configuration

- Repetitions per condition: 3
- Batch size: 4096 routes
- Warm-up: 8192 routes per fresh worker
- Schedule seed: 20260828
- Fixed worker CPU: 31
- Python: 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]
- Platform: Linux-6.8.0-90-generic-aarch64-with-glibc2.39
- Source SHA-256: `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- IPv6 workload SHA-256: `9890d18dcc552f39d0b73ad9328231d7b855afa5da5e4b82335f4bf20e4de37e`
- IPv6 driver SHA-256: `86d593cbb87f4cd8127421611cef2c715d3a6d578d1f91cbf030b3fc404b390c`
- Classifier SHA-256: `fb0e251573979653a54ea79b1b2c3398bf30c4c99aed2a66c8edda458c544395`
- Reused family-neutral helper SHA-256: `53246ca76fccbe48ff3d4579e8cd12ffcb72a4f861b3b469cab2a9ae81ca19a1`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized values obtained by dividing a
full-batch duration by 4096; they are not individually instrumented
request latencies. Peak RSS is the maximum fresh-worker high-water mark.

| Rules | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |
|---:|:---|---:|---:|:---|:---|---:|
| 1 | parse_excluded | 37 | 16508 | 247.033/268.970/285.341 | 60.311/65.666/69.663 | 63.2 |
| 1 | parse_included | 37 | 15854 | 258.768/281.914/295.555 | 63.176/68.827/72.157 | 35.4 |
| 64 | parse_excluded | 834 | 16560 | 247.456/275.027/287.281 | 60.414/67.145/70.137 | 63.2 |
| 64 | parse_included | 834 | 15741 | 259.143/284.433/297.127 | 63.267/69.442/72.541 | 35.4 |
| 256 | parse_excluded | 3302 | 15962 | 256.696/275.290/290.725 | 62.670/67.210/70.978 | 63.5 |
| 256 | parse_included | 3302 | 15619 | 262.877/271.996/297.982 | 64.179/66.405/72.750 | 35.4 |
| 1024 | parse_excluded | 13306 | 16349 | 251.079/265.190/283.470 | 61.298/64.744/69.207 | 64.5 |
| 1024 | parse_included | 13306 | 15684 | 261.508/281.010/298.947 | 63.845/68.606/72.985 | 35.4 |
| 4097 | parse_excluded | 53021 | 15907 | 257.899/284.703/292.336 | 62.964/69.507/71.371 | 68.2 |
| 4097 | parse_included | 53021 | 15436 | 267.424/277.516/301.140 | 65.289/67.753/73.521 | 35.4 |

## Integrity checks

- Worker records present: 30/30
- Exact condition matrix: True
- Fresh worker per condition: True
- Every worker pinned to CPU 31: True
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
