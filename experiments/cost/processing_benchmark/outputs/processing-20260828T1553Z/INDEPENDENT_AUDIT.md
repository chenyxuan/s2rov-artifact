# Independent audit

Verdict: **PASS** for the stated single-core Python reference-classifier scope.

## Completeness and recomputation

- 30/30 scheduled workers produced raw JSON.
- The raw CSV contains three repetitions for every `rules × parse scope` cell.
- An independent read of `raw_runs.csv` recomputed all 10 throughput medians;
  every value matched `summary.csv` exactly before presentation rounding.
- Every worker passed binary serialization round-trip checks and its independent
  linear most-specific-rule oracle spots.
- For each rule count, all six workers produced one identical full-output
  SHA-256 and one identical four-state count vector.
- The automated recomputation audit reports `all_checks_pass: true`.

## Table II values

| Rules | Serialized KiB | Parse excluded k routes/s | Parse included k routes/s | Peak RSS MiB |
|---:|---:|---:|---:|---:|
| 1 | 0.02 | 26.2 | 24.1 | 204.2 |
| 64 | 0.64 | 26.0 | 24.4 | 204.2 |
| 256 | 2.51 | 26.3 | 24.3 | 204.8 |
| 1,024 | 9.98 | 26.2 | 23.7 | 205.5 |
| 4,097 | 40.01 | 26.0 | 23.9 | 209.0 |

Throughput is the median of three fresh-worker repetitions. Peak RSS is the
maximum fresh-worker high-water mark across both parse scopes. The presentation
table is a deterministic projection of `summary.csv`; a post-run note was added
to `paper_table.tex` to make the RSS aggregation explicit, without changing any
numeric cell.

The p95 amortized per-route time spans 39.21--40.17 microseconds with CSV
parsing excluded and 41.98--43.17 microseconds with CSV parsing included.

## Input and code provenance

- Source IPv4 rows: 1,135,687
- Explicit `{AMBIGUOUS}` origin markers excluded: 220
- Timed valid scalar-origin IPv4 pairs: 1,135,467
- Source CSV SHA-256:
  `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29`
- Derived IPv4 workload SHA-256:
  `cb623f332f10788c1b403fd78a48b3ae47f69b3190825c6ab200cc172c1fe963`
- Benchmark script SHA-256:
  `53246ca76fccbe48ff3d4579e8cd12ffcb72a4f861b3b469cab2a9ae81ca19a1`
- DAROA-encoding classifier SHA-256:
  `4aa40fb8736de32d28041ba3b87260e96cbc91ea2e8ed20d8550d17706dff7e8`
- Raw-run CSV SHA-256:
  `f8a4bd012d0dc522b4f29e95cfee21a7131e26193724b02a7cf4dcdce60d45fc`
- Raw-batch CSV SHA-256:
  `015be0a3d12c90eb634495ea94bc2944a8f58edb3da0bd07f6f409798d53a299`
- Summary CSV SHA-256:
  `73bcb39b890d5f5b03c325a7e84d4a030ae7c131b81305c3bff7e7754e04a204`

The recorded Git worktree was dirty, so the commit identifier alone is not an
exact source identifier. The file-level hashes above bind the actual benchmark,
classifier, source input, and derived workload used by the run.

## Claim boundary

The policies are deterministic transparent benchmark rules, not a sample of
published ROAs. Serialized size is the custom DAROA-encoding reference payload, not a
CMS or RTR size. `parse_excluded` removes CSV decoding and ASN conversion but
does not bypass the classifier's internal CIDR parsing. The result therefore
supports only single-process, single-core Python processing-cost claims. It is
not evidence of full-RIB FRR, router data-plane, line-rate, native RTR, or IPv6
performance.
