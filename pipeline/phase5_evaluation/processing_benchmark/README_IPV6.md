# IPv6 RRC00 marker-policy replay

This is the IPv6 companion to `run_processing_benchmark.py`. It is deliberately
separate from the existing IPv4 driver and outputs, while preserving the same
policy sizes, timing scopes, batch method, CPU pinning, and integrity checks.

The input is the same mixed-family RRC00 CSV. A formal run scans all 1,393,270
rows, selects the 257,583 IPv6 rows, excludes the 33 explicit `{AMBIGUOUS}`
origin markers, and replays the remaining 257,550 scalar-origin IPv6 pairs.

Each deterministic benchmark policy uses a `::/0` entry carrying an OpenScope
marker with `max_length=128`. Additional exact-origin records are unmarked. The
tested sizes are 1, 64, 256, 1,024, and 4,097 total policy records. These policies
are workload controls, not observed published ROAs.

## Timing scopes

- `parse_excluded`: preload IPv6 `(prefix string, origin integer)` pairs, then
  time classification and state capture.
- `parse_included`: also time CSV decoding and ASN integer conversion.

The classifier's internal textual IPv6 CIDR parsing is included in both scopes.

## Unit tests

```bash
python3 -m unittest \
  phase5_evaluation/processing_benchmark/test_ipv6_processing_benchmark.py
```

The tests cover mixed-family filtering, ambiguous-origin exclusion, IPv6
`::/0`/128 policy construction, binary round trips, the independent IPv6
semantic oracle, and matching result checksums across the two processing paths.

## Small self-test

Use a new run identifier. The driver refuses to overwrite an existing directory
and never retries a failed or timed-out worker.

```bash
python3 phase5_evaluation/processing_benchmark/run_ipv6_processing_benchmark.py run \
  --run-id selftest-ipv6-YYYYMMDDTHHMMSSZ \
  --sizes 1 64 \
  --repetitions 1 \
  --batch-size 512 \
  --warmup-routes 256 \
  --limit 8192
```

This executes four fresh workers: two policy sizes times the two timing scopes.

## Formal local run

```bash
python3 phase5_evaluation/processing_benchmark/run_ipv6_processing_benchmark.py run \
  --run-id processing-ipv6-YYYYMMDDTHHMMSSZ
```

The formal defaults are five policy sizes, two timing scopes, three repetitions,
4,096-route batches, and 8,192 warm-up routes per fresh worker. The schedule is
seeded and shuffled within each repetition. All workers are pinned to the same
available CPU; a platform without CPU-affinity support fails closed.

Every run records source, derived-workload, script, reused-helper, classifier,
policy, and result checksums. Before timing, each fresh worker verifies an exact
binary round trip and independent IPv6 oracle spots. Aggregation requires one
checksum and one state-count vector per policy size across both scopes and all
repetitions.

Outputs are written under `outputs/<run-id>/`. The generated
`paper_table_ipv6.tex` is a suggestion and is not inserted into the manuscript
automatically.

## Claim boundary

The replay measures the single-process, single-core Python reference classifier.
It does not measure FRR, RTR transfer, router installation, forwarding, or line
rate. The IPv6 handoff experiment is a separate Phase 6 artifact.
