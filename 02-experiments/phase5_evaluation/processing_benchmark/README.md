# Phase-4 processing benchmark

The independent IPv6 companion is documented in
[`README_IPV6.md`](README_IPV6.md); it does not modify this IPv4 driver or its
existing outputs.

This directory contains a reproducible, single-core microbenchmark for the
existing Phase-4 Python `DAROA.validate_route` classifier. It uses the local
RRC00 prefix-origin CSV as the route workload and deterministic benchmark
policies with 1, 64, 256, 1,024, and 4,097 total Stripes.

It is not an FRR, RTR, router data-plane, or line-rate benchmark.

## Timing scopes

- `parse_excluded`: load the IPv4 CSV into `(prefix string, origin integer)`
  tuples before timing; time classifier calls and state capture.
- `parse_included`: time CSV decoding, ASN conversion, classifier calls, and
  state capture.

The public classifier accepts a textual prefix, so its internal CIDR parsing
remains present in both scopes. “Parse excluded” refers only to workload CSV
parsing.

## Small self-test

```bash
python3 phase5_evaluation/processing_benchmark/run_processing_benchmark.py run \
  --run-id selftest-YYYYMMDDTHHMMSSZ \
  --sizes 1 64 \
  --repetitions 1 \
  --batch-size 512 \
  --warmup-routes 256 \
  --limit 8192
```

## Formal local run

```bash
python3 phase5_evaluation/processing_benchmark/run_processing_benchmark.py run \
  --run-id processing-YYYYMMDDTHHMMSSZ
```

The source contains 1,135,687 IPv4 rows. The default formal run excludes the
220 rows carrying the explicit `{AMBIGUOUS}` origin marker and processes the
remaining 1,135,467 valid scalar-origin prefix-origin pairs. It uses 4,096-route
batches, performs 8,192 warm-up queries per fresh worker, and runs three
repetitions per condition. Conditions are shuffled reproducibly within each
repetition and pinned to one CPU where supported.

Each immutable run directory contains per-worker JSON, raw CSVs, transparent
policy specifications and payloads, checksums, a recomputation audit, a run
report, and a compact LaTeX table suggestion. The script refuses to overwrite
an existing run directory.

## Same-size policy update benchmark

`run_policy_update_benchmark.py` aligns the update condition with the five
total-rule counts used by the controlled load and classification experiment:
1, 64, 256, 1,024, and 4,096. It consumes the accepted IPv4 and IPv6 marked
payloads and query files from
`outputs/controlled-processing-20260830T-marker-final-v1`. For every marked payload it
constructs an unmarked counterpart with exactly the same entries; only the base
record's serialized marker bit changes from true to false. Existing fields and
paths named `open` or `closed` are retained as compatibility aliases for the
frozen output schema.

Every cell has twenty fresh worker processes on CPU 31. File reads, unmarked
policy loading, the Invalid probe precheck, and garbage collection occur before
timing. The timed interval contains marked-policy deserialization, active-pointer
replacement, and the first classification, which must return
`Delegated` (`OpenScope`). All 200 conditions are shuffled once with a fixed
seed.

Formal run:

```bash
python3 phase5_evaluation/processing_benchmark/run_policy_update_benchmark.py run \
  --run-id policy-update-YYYYMMDDTHHMMSSZ
```

Independent rerun of the raw audit:

```bash
python3 phase5_evaluation/processing_benchmark/audit_policy_update_benchmark.py \
  phase5_evaluation/processing_benchmark/outputs/policy-update-YYYYMMDDTHHMMSSZ
```

The run emits the frozen inputs and their hashes, derived unmarked payloads,
schedule and configuration, 200 raw worker records, JSON/CSV summaries with
mean, median, Q1, and Q3, an artifact hash manifest, a claim-boundary report,
and the independent audit result. This is a reference-engine policy replacement
microbenchmark, not a measurement of distribution, RTR, router installation,
forwarding, or end-to-end convergence.
