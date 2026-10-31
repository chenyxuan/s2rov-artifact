# Phase-4 reference-classifier processing benchmark

Generated: 2026-08-28T23:48:11Z

## Scope

This run measures the existing Python `DAROA.validate_route` reference classifier on
1,135,467 valid scalar-origin IPv4 prefix-origin pairs derived from
1,135,687 IPv4 rows in the local RRC00 CSV. Preprocessing
excluded 220 rows whose origin is
the explicit `{AMBIGUOUS}` marker; they are not counted in classifier throughput.
It does not measure FRR, RTR transfer, router installation, forwarding, or line rate.

`parse_excluded` preloads `(prefix string, origin integer)` pairs and times classifier
calls plus state capture. `parse_included` additionally times CSV decoding and ASN
integer conversion. The classifier internally parses textual CIDRs in both modes.

Each policy contains one open `/0` base and the first `size-1` unique non-`/0`
prefixes in source order as closed exact-origin Stripes. These are deterministic
benchmark policies, not observed published authorizations. Policy size means total
Stripe count. Serialized bytes refer only to the experimental Phase-4 binary format.

## Configuration

- Repetitions per condition: 3
- Batch size: 4096 routes
- Warm-up: 8192 routes per worker
- Schedule seed: 20260828
- Worker CPU: 31
- Python: 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]
- Platform: Linux-6.8.0-90-generic-aarch64-with-glibc2.39
- Source SHA-256: `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- IPv4 workload SHA-256: `cb623f332f10788c1b403fd78a48b3ae47f69b3190825c6ab200cc172c1fe963`
- Script SHA-256: `53246ca76fccbe48ff3d4579e8cd12ffcb72a4f861b3b469cab2a9ae81ca19a1`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized per-route times obtained by
dividing each full-batch duration by 4096; they are not individually
instrumented request latencies. Peak RSS is the maximum fresh-worker high-water mark.

| Stripes | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |
|---:|:---|---:|---:|:---|:---|---:|
| 1 | parse_excluded | 21 | 26875 | 152.547/160.819/186.351 | 37.243/39.262/45.496 | 204.2 |
| 1 | parse_included | 21 | 24769 | 164.877/175.547/204.040 | 40.253/42.858/49.814 | 35.1 |
| 64 | parse_excluded | 651 | 26805 | 151.577/160.244/186.422 | 37.006/39.122/45.513 | 204.2 |
| 64 | parse_included | 651 | 24804 | 164.179/169.684/196.897 | 40.083/41.427/48.071 | 35.1 |
| 256 | parse_excluded | 2567 | 26473 | 153.580/157.924/184.852 | 37.495/38.556/45.130 | 204.5 |
| 256 | parse_included | 2567 | 24855 | 163.743/166.940/195.986 | 39.976/40.757/47.848 | 35.1 |
| 1024 | parse_excluded | 10217 | 26043 | 156.663/161.062/190.873 | 38.248/39.322/46.600 | 205.5 |
| 1024 | parse_included | 10217 | 24855 | 164.539/172.901/201.307 | 40.171/42.212/49.147 | 35.1 |
| 4097 | parse_excluded | 40967 | 26374 | 154.830/161.436/188.869 | 37.800/39.413/46.111 | 209.0 |
| 4097 | parse_included | 40967 | 23884 | 170.505/176.063/206.956 | 41.627/42.984/50.526 | 35.1 |

## Integrity checks

- Worker records present: 30/30
- Serialization round trips identical: True
- Independent oracle spot checks pass: True
- One result checksum per policy size across modes and repetitions: True
- One state-count vector per policy size across modes and repetitions: True
- Overall recomputation audit: True

The independent spot oracle uses a linear most-specific-prefix scan and separately
implements the origin-eligibility boundary. Each timed worker repeats the checks before
measurement. Full-output checksums and state counts must match across parse scopes and
repetitions for the same policy size.

## Artifacts

- `raw/`: immutable per-condition JSON, including every batch duration
- `raw_runs.csv`: one row per condition
- `raw_batch_samples.csv`: one row per measured batch
- `summary.csv`: recomputed aggregate values
- `recomputation_audit.json`: cross-run checksum and completeness checks
- `policies/`: serialized benchmark policies, transparent JSON specs, oracle spots
- `paper_table.tex`: compact LaTeX data suggestion; not inserted into the manuscript

## Claim boundary

These results support only single-process, single-core processing-cost claims for the
Python reference implementation on this RRC00-derived IPv4 workload. They do not
support claims about full-RIB FRR processing, router data planes, native RTR/RPKI
interoperability, IPv6 support, or Internet-wide production capacity.
