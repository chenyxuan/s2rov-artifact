# Visibility-path experiment run report

## Outcome

The experiment completed successfully and the independent RRC00 extraction
path reproduced both manuscript-bearing CSV files byte for byte.

| AFI | Registry-indirect paths | Exact-observed pairs | Origin-disjoint candidates | Three-handle subset | Candidate roots |
|---|---:|---:|---:|---:|---:|
| IPv4 | 51,371 | 622 (1.2108%) | 504 (81.028939%) | 82 | 83 |
| IPv6 | 122,180 | 140 (0.114585%) | 83 (59.285714%) | 0 | 14 |

The percentage beside Exact-observed uses all registry-indirect paths as its
denominator. The percentage beside Origin-disjoint uses Exact-observed pairs
as its denominator. Neither percentage estimates the prevalence of issuer
visibility failures or ROV conflicts.

On 2026-08-28, a full depth-extension run reproduced these counts while
measuring registry-containment depth.  It used the same frozen RIPE Database
dump and the independently extracted RRC00 origin CSV.  This later run does
not replace the primary MRT-run provenance below.

## Frozen inputs

| Input | Timestamp | Bytes | SHA-256 |
|---|---|---:|---|
| `ripe.db.gz` | captured 2026-06-25 00:18:29 UTC | 367,373,318 | `a385cf65c40109992e7c54a5dfabd6036470ffce866cb6ab6b22dd5126bac17c` |
| RRC00 `bview.20260624.0000.gz` | RIB 2026-06-24 00:00 UTC | 411,493,623 | `ad2fe1094df70c2d0f2ddb39cf5ab22b10add9073ee1cf6213c6d132ddfb04b9` |
| Independent origin CSV | derived 2026-08-28 | 30,978,869 | `cafac01fa95e4d5e7eef4da22d2fa26b32216c110fe3a3073312bc79762edb29` |

The RIB came from RIPE RIS RRC00 at
`https://data.ris.ripe.net/rrc00/2026.06/bview.20260624.0000.gz` after explicit
user approval on 2026-08-28. `gzip -t` passed. The parser host used
`bgpdump` 1.6.2 on a 32-core aarch64 Kunpeng-920 system.

## Method frozen before the run

- IPv4 root/intermediate/endpoint statuses are `ALLOCATED PA`,
  `SUB-ALLOCATED PA`, and `ASSIGNED PA`.
- IPv6 root/intermediate/endpoint statuses are `ALLOCATED-BY-RIR`,
  `ALLOCATED-BY-LIR`, and `ASSIGNED`.
- Each canonical assigned endpoint is paired with its nearest strict eligible
  root. A nearer non-CIDR or conflicting root is an exclusion barrier rather
  than permission to fall through to a wider root.
- A path is registry-indirect only if at least one eligible intermediate range
  lies strictly between root and endpoint. `LIR-PARTITIONED PA` and
  `AGGREGATED-BY-LIR` do not create that classification.
- Root and endpoint must be exact canonical prefixes. A non-CIDR IPv4
  intermediate range can establish the intermediate hop.
- All scalar origins observed across RRC00 peers are retained. Any terminal
  AS-SET, confederation, missing, or unparseable segment makes its prefix
  ambiguous and excludes that prefix from the Exact-observed denominator.
- A candidate is registry-indirect, Exact-observed at both endpoints, and has
  disjoint root and endpoint origin sets. The three-handle subset additionally
  has pairwise-distinct exact `org:` handles at the root, one containing
  intermediate object, and the endpoint.
- Registry-containment depth is the maximum number `d` of clean eligible
  intermediate ranges in a strict chain `root > h1 > ... > hd > endpoint`.
  The output names it `longest_strict_nested_chain`; direct paths have depth
  zero and registry-indirect paths have depth at least one.  The complementary
  `containing_eligible_objects` measure counts all clean eligible intermediate
  ranges strictly inside the selected root and strictly containing the
  endpoint.  A difference between the two measures identifies a non-laminar
  path.  Equal ranges do not add a level, and a same-range hop conflict
  excludes the endpoint before depth is recorded.
- Both depth measures are reported for three nested cohorts: all
  registry-indirect paths, the exact-observed registry-indirect subset, and
  the origin-disjoint candidate subset.

## Commands and resource use

Primary MRT run:

```bash
/usr/bin/time -v python \
  experiments/candidates/allocation_tree/visibility_experiment/scripts/analyze_visibility.py \
  --ripe experiments/candidates/allocation_tree/data/ripe.db.gz \
  --mrt experiments/candidates/allocation_tree/visibility_experiment/input/data/bview.20260624.0000.gz \
  --output experiments/candidates/allocation_tree/visibility_experiment/outputs \
  --progress-every 500000
```

- Wall time: 42:57.67; user/system CPU: 2,369.21/731.60 seconds.
- Maximum process RSS: 303,816 KiB.
- Observed temporary SQLite size: 1,770,348,544 bytes.
- Exit status: 0; the temporary database was removed automatically.

Independent-origin rerun:

```bash
/usr/bin/time -v python \
  experiments/candidates/allocation_tree/visibility_experiment/scripts/analyze_visibility.py \
  --ripe experiments/candidates/allocation_tree/data/ripe.db.gz \
  --bgp-csv experiments/candidates/allocation_tree/visibility_experiment/input/derived/rrc00_20260624_origins_fast.csv \
  --output experiments/candidates/allocation_tree/visibility_experiment/outputs_recheck \
  --progress-every 500000
```

- Wall time: 13:16.83; user/system CPU: 772.80/23.87 seconds.
- Maximum process RSS: 304,820 KiB; exit status 0.

Depth-extension full run (2026-08-28, using the independent-origin CSV):

```bash
/usr/bin/time -v python3 \
  experiments/candidates/allocation_tree/visibility_experiment/scripts/analyze_visibility.py \
  --ripe experiments/candidates/allocation_tree/data/ripe.db.gz \
  --bgp-csv experiments/candidates/allocation_tree/visibility_experiment/input/derived/rrc00_20260624_origins_fast.csv \
  --output experiments/candidates/allocation_tree/visibility_experiment/outputs_depth \
  --progress-every 500000
```

- Wall time: 13:13.18.
- Maximum process RSS: 305,192 KiB; exit status 0.

## Registry-containment depth

The table reports every observed depth in each AFI and cohort.  Each cell is
`paths (share of cohort)`.  Because the run found zero non-laminar paths in
all six AFI--cohort combinations, the complete
`containing_eligible_objects` distribution is identical cell by cell to the
headline `longest_strict_nested_chain` distribution shown here.

| AFI | Depth | All registry-indirect | Exact-observed indirect | Origin-disjoint candidate |
|---|---:|---:|---:|---:|
| IPv4 | 1 | 49,724 (96.793911%) | 601 (96.623794%) | 483 (95.833333%) |
| IPv4 | 2 | 1,630 (3.172996%) | 21 (3.376206%) | 21 (4.166667%) |
| IPv4 | 3 | 17 (0.033093%) | 0 (0%) | 0 (0%) |
| IPv6 | 1 | 48,645 (39.814209%) | 98 (70.000000%) | 60 (72.289157%) |
| IPv6 | 2 | 65,366 (53.499754%) | 42 (30.000000%) | 23 (27.710843%) |
| IPv6 | 3 | 7,712 (6.311999%) | 0 (0%) | 0 (0%) |
| IPv6 | 4 | 213 (0.174333%) | 0 (0%) | 0 (0%) |
| IPv6 | 5 | 185 (0.151416%) | 0 (0%) | 0 (0%) |
| IPv6 | 6 | 7 (0.005729%) | 0 (0%) | 0 (0%) |
| IPv6 | 7 | 52 (0.042560%) | 0 (0%) | 0 (0%) |

The cohort totals are 51,371/622/504 for IPv4 and 122,180/140/83
for IPv6 (all indirect/exact-observed/candidate, respectively).  Every column
sums to its cohort total.  `non_laminar_paths` is zero for both depth metrics,
both AFIs, and all three cohorts.

## Audit funnel

- RIPE IP objects scanned: 5,092,311; eligible objects: 4,873,358.
- Canonical matched endpoints: 3,417,197 IPv4 and 844,614 IPv6.
- Registry-indirect paths: 51,371 IPv4 and 122,180 IPv6.
- Exact-observed registry-indirect pairs: 622 IPv4 and 140 IPv6.
- Ambiguous registry-indirect endpoint pairs excluded from that denominator:
  18 IPv4 and 2 IPv6.
- Origin-overlapping exact pairs: 118 IPv4 and 57 IPv6; origin-disjoint exact
  pairs: 504 IPv4 and 83 IPv6.
- Descriptive registry-direct reference: 6,790 of 21,922 IPv4 pairs
  (30.973451%) and 318 of 1,251 IPv6 pairs (25.419664%) are origin-disjoint.

The primary MRT scan read 54,843,423 peer-prefix records and retained
1,393,017 distinct prefix--origin pairs. It found 7,241 MOAS prefixes and 253
ambiguous prefixes. The main summary's `unique_prefixes=1,384,474` means
prefixes with at least one scalar origin; the union including 226
ambiguity-only prefixes is 1,384,700.

## Verification

- The end-to-end synthetic regression passed, including direct/indirect
  IPv4/IPv6 paths, same-range root and hop poison barriers, nearest non-CIDR
  root exclusion, organisation-handle normalization, MOAS, and mixed
  scalar/AS-SET ambiguity.
- Candidate-level audit performed 7,686 checks with zero failure. All 587 rows
  satisfy same-AFI strict root--hop--endpoint containment, the specified
  status chain, nonempty and disjoint sorted origin sets, registry-indirect
  classification, unique root--endpoint keys, and the stated three-handle
  condition.
- A raw-dump lookup recovered all 869 candidate root/hop/endpoint targets
  uniquely and found zero difference in exact organisation fingerprints,
  nearest eligible roots, or eligible intermediate hops.
- A separate allocation-tree implementation re-parsed all 5,092,311 RIPE IP
  objects using a compact range catalogue, independent longest-prefix root
  lookup, and per-root interval prefix-max hop index. It exactly reproduced
  the IPv4/IPv6 matched-path counts (3,417,197/844,614), registry-indirect
  counts (51,371/122,180), registry-direct counts (3,365,826/722,434), and
  three-handle path counts (3,353/2,143). Its full run took 388.69 seconds.
  Peak RSS was 953 MB. The checker did not import or reuse the main analyzer.
- The independent in-memory RRC00 extractor also produced 1,393,017
  prefix--origin pairs, 7,241 MOAS prefixes, and 253 ambiguous prefixes. Its
  compatible CSV was then fed through the allocation analysis. Scientific
  result dictionaries, containment metrics, and range-resolution metrics were
  equal. `visibility_by_afi.csv` and all 587 candidate rows were byte-identical.
- A second, independent depth checker re-parsed all 5,092,311 RIPE IP objects
  and did not import the main analyzer.  In 390.04245 seconds, it independently
  joined 762 exact-observed registry-indirect pairs and 587 candidates.  It
  matched every AFI--cohort--exact-depth cell in
  `outputs_depth/visibility_depth_by_afi.csv`, matched all six zero
  non-laminar counts, and found zero keys in either direction of the candidate
  key-set difference.  The depth run also left the compact table and all 587
  candidate rows byte-identical to the original manuscript-bearing outputs.

## Output hashes

| Output | SHA-256 |
|---|---|
| `outputs/visibility_by_afi.csv` | `4a21e4736d386d52fa5804c17f3566ab5d468b54a4b9903ac5c2c913480b7576` |
| `outputs/visibility_candidates.csv` | `0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918` |
| `outputs/visibility_audit_metrics.csv` | `9aa4e1235f45a7202e509c29b09afa46aadc492abbd4d7692cf5db100ccd22de` |
| `outputs/visibility_summary.json` | `45f50105ef44c92d25435e0e77a7a55a8366de566c630d3990c9aa9714c48088` |
| `outputs_recheck/visibility_by_afi.csv` | `4a21e4736d386d52fa5804c17f3566ab5d468b54a4b9903ac5c2c913480b7576` |
| `outputs_recheck/visibility_candidates.csv` | `0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918` |
| `outputs_depth/visibility_by_afi.csv` | `4a21e4736d386d52fa5804c17f3566ab5d468b54a4b9903ac5c2c913480b7576` |
| `outputs_depth/visibility_candidates.csv` | `0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918` |
| `outputs_depth/visibility_depth_by_afi.csv` | `fc4805415625bbd0215cd7aadadf3bbaec2dcfdfccbc58c49237d8bba12bc541` |

Original primary MRT analysis-script SHA-256:
`16dd1879d7b3db7bb706dc95d37e48284b19afcfd17a45b761cfd038acfa01e9`.
Original primary regression-test SHA-256:
`a095bb81e5cfd8a5171bd449bf415e3fdde07933514cada668f8a900f3f2c251`.

Depth-extension analysis-script SHA-256:
`40a700fada2978db7879903c6ef5639d41856da39625833f12e9e7e84b2f0d58`.
Depth-extension regression-test SHA-256:
`ab2d050532c48f8880d16cd7e814bf00ad27fb760798e998c6d2b437b5b197a9`.

## Interpretation boundary

The allocation objects and observed origins identify a structural route-side
pattern compatible with the Section II.B premise. They do not observe what a
ROA issuer knows, whether a reporting channel exists, whether the route is
permitted or legitimate, whether a matching ROA exists, or what an ROV
relying party would classify. Consequently, the 504 and 83 rows are
visibility-related potential-conflict candidates, not visibility-caused
conflicts or ROV-invalid routes. The low Exact-observed coverage also prevents
the conditional 81.0% and 59.3% rates from being generalized to either RIPE
allocation tree.

Schema note: the compact CSV explicitly records the IPv6 three-handle count
as zero. The JSON result dictionary is backed by a sparse counter and omits
that zero-valued key; this does not affect any count or manuscript table cell.
