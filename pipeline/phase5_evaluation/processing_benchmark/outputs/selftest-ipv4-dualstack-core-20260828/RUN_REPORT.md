# Phase-4 reference-classifier processing benchmark

Generated: 2026-08-28T23:21:13Z

## Scope

This run measures the existing Python `DAROA.validate_route` reference classifier on
8,192 valid scalar-origin IPv4 prefix-origin pairs derived from
8,192 IPv4 rows in the local RRC00 CSV. Preprocessing
excluded 0 rows whose origin is
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

- Repetitions per condition: 1
- Batch size: 512 routes
- Warm-up: 256 routes per worker
- Schedule seed: 20260828
- Worker CPU: 31
- Python: 3.12.3 (main, Jun 19 2026, 12:46:00) [GCC 13.3.0]
- Platform: Linux-6.8.0-90-generic-aarch64-with-glibc2.39
- Source SHA-256: `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- IPv4 workload SHA-256: `14e5af0518705ea2731803e07d8ee2b3aee42349ac17f842e7000fb0e18ad15c`
- Script SHA-256: `53246ca76fccbe48ff3d4579e8cd12ffcb72a4f861b3b469cab2a9ae81ca19a1`

## Results

Throughput is the median across repetitions. Batch percentiles pool full batches
across repetitions. Route percentiles are amortized per-route times obtained by
dividing each full-batch duration by 512; they are not individually
instrumented request latencies. Peak RSS is the maximum fresh-worker high-water mark.

| Stripes | Scope | Bytes | routes/s p50 | Batch ms p50/p95/p99 | Route us p50/p95/p99 | Peak RSS MiB |
|---:|:---|---:|---:|:---|:---|---:|
| 1 | parse_excluded | 21 | 27425 | 18.672/19.007/19.058 | 36.469/37.123/37.223 | 22.2 |
| 1 | parse_included | 21 | 25403 | 20.182/20.629/20.639 | 39.417/40.290/40.310 | 22.2 |
| 64 | parse_excluded | 651 | 27547 | 18.495/19.110/19.192 | 36.122/37.325/37.484 | 22.2 |
| 64 | parse_included | 651 | 25430 | 20.016/20.932/21.761 | 39.093/40.883/42.502 | 22.2 |

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
