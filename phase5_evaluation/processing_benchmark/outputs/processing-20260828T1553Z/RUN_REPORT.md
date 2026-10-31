# Phase-4 reference-classifier processing benchmark

Generated: 2026-08-28T16:17:08Z

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
| 1 | parse_excluded | 21 | 26211 | 155.626/161.661/190.601 | 37.995/39.468/46.533 | 204.2 |
| 1 | parse_included | 21 | 24065 | 168.915/174.419/203.157 | 41.239/42.583/49.599 | 35.1 |
| 64 | parse_excluded | 651 | 26042 | 155.572/162.082/190.326 | 37.981/39.571/46.466 | 204.2 |
| 64 | parse_included | 651 | 24371 | 167.050/172.833/202.161 | 40.784/42.195/49.356 | 35.1 |
| 256 | parse_excluded | 2567 | 26332 | 154.505/160.604/187.149 | 37.721/39.210/45.691 | 204.8 |
| 256 | parse_included | 2567 | 24257 | 168.289/171.943/202.943 | 41.086/41.978/49.547 | 35.1 |
| 1024 | parse_excluded | 10217 | 26243 | 156.241/163.120/191.463 | 38.145/39.824/46.744 | 205.5 |
| 1024 | parse_included | 10217 | 23680 | 171.541/175.915/206.003 | 41.880/42.948/50.294 | 35.1 |
| 4097 | parse_excluded | 40967 | 26010 | 156.832/164.523/194.514 | 38.289/40.167/47.489 | 209.0 |
| 4097 | parse_included | 40967 | 23853 | 171.011/176.838/206.373 | 41.751/43.173/50.384 | 35.1 |

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
