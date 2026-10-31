# DAROA encoding reference-classifier processing benchmark

Generated: 2026-08-28T15:51:02Z

## Scope

This run measures the existing Python `DAROA.validate_route` reference classifier on
8,192 IPv4 prefix-origin pairs derived from the local RRC00 CSV.
It does not measure FRR, RTR transfer, router installation, forwarding, or line rate.

`parse_excluded` preloads `(prefix string, origin integer)` pairs and times classifier
calls plus state capture. `parse_included` additionally times CSV decoding and ASN
integer conversion. The classifier internally parses textual CIDRs in both modes.

Each policy contains one open `/0` base and the first `size-1` unique non-`/0`
prefixes in source order as closed exact-origin Stripes. These are deterministic
benchmark policies, not observed published authorizations. Policy size means total
Stripe count. Serialized bytes refer only to the experimental DAROA-encoding binary format.

## Configuration

- Repetitions per condition: 1
- Batch size: 512 routes
- Warm-up: 256 routes per worker
- Schedule seed: 20260828
- Worker CPU: 0
- Python: 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]
- Platform: Linux-6.8.0-90-generic-aarch64-with-glibc2.39
- Source SHA-256: `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- IPv4 workload SHA-256: `14e5af0518705ea2731803e07d8ee2b3aee42349ac17f842e7000fb0e18ad15c`
- Script SHA-256: `9e1f6e7f66ca25763d1aa8e276dda3c3e4c8a9cb1a8fe7e59564ca849a4cd903`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized per-route times obtained by
dividing each full-batch duration by 512; they are not individually
instrumented request latencies. Peak RSS is the maximum fresh-worker high-water mark.

| Stripes | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |
|---:|:---|---:|---:|:---|:---|---:|
| 1 | parse_excluded | 21 | 27779 | 18.409/18.944/18.989 | 35.955/37.000/37.089 | 22.1 |
| 1 | parse_included | 21 | 25244 | 20.287/20.613/20.636 | 39.623/40.259/40.305 | 22.1 |
| 64 | parse_excluded | 651 | 27681 | 18.546/18.889/18.895 | 36.223/36.892/36.904 | 22.1 |
| 64 | parse_included | 651 | 25528 | 20.071/20.540/20.553 | 39.200/40.117/40.143 | 22.1 |

## Integrity checks

- Worker records present: 4/4
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
