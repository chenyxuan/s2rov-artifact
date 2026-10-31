# IPv4/IPv6 Allocation-Path Visibility Experiment

## Research question

How many RIPE PA allocation paths contain an eligible intermediate allocation
object, how many have exact-observed origin sets at both endpoints, and how
many of that selected subset have disjoint root and endpoint origin-AS sets?

The experiment measures a structural, route-side proxy.  It does not observe
the ROA issuer's information, an out-of-band reporting channel, permission,
route legitimacy, or the ROAs available to a relying party.

## Frozen inputs

- RIPE Database dump: `../data/ripe.db.gz`, captured 2026-06-25.
- RIPE RIS RRC00 RIB: `input/data/bview.20260624.0000.gz`, 2026-06-24
  00:00 UTC (downloaded after approval on 2026-08-28).

The one-day registry/RIB offset is reported as a limitation.  The existing
RouteViews input is not used because audit showed that it contains IPv4 only.

## Main PA sample

| AFI | Root status | Assigned endpoint | Eligible intermediate object |
|---|---|---|---|
| IPv4 | `ALLOCATED PA` | `ASSIGNED PA` | `SUB-ALLOCATED PA` |
| IPv6 | `ALLOCATED-BY-RIR` | `ASSIGNED` | `ALLOCATED-BY-LIR` |

For each assigned endpoint, the analysis selects its most-specific strict
containing eligible root.  A path is `direct` if no eligible intermediate
allocation range lies strictly between those endpoints and
`registry-indirect` otherwise.  `LIR-PARTITIONED PA` and
`AGGREGATED-BY-LIR` do not by themselves establish an external hop.  PI,
legacy, anycast, and hybrid statuses are outside the headline sample.

IPv4 ranges are retained as closed intervals so a non-CIDR sub-allocation can
still establish an intermediate hop.  Root and assigned endpoints must each
be a single canonical CIDR before the exact-route join.  IPv6 objects are
canonical prefixes.  Equal ranges are merged and cannot create depth;
conflicting status or organisation metadata on an equal range form a poison
barrier, so a path cannot fall through to a wider clean root or hop.

For each retained root--endpoint pair, the registry-containment depth is the
largest `d` for which the clean eligible intermediate ranges form a strict
chain

```text
root contains h1 contains ... contains hd contains endpoint.
```

Thus a direct path has depth zero and every registry-indirect path has depth
at least one.  The output calls this measure
`longest_strict_nested_chain`.  The complementary
`containing_eligible_objects` measure counts every clean eligible
intermediate range that lies strictly inside the selected root and strictly
contains the endpoint.  It can exceed the chain depth when containing ranges
overlap without forming one nested hierarchy; such endpoint paths are
audited as non-laminar.  Equal ranges cannot add a level.  A same-range hop
conflict excludes the path before either depth measure is recorded.

Depth is summarized separately for three cohorts: all registry-indirect
paths, registry-indirect paths with exact-observed origin sets at both
endpoints, and origin-disjoint potential-conflict candidates.  These are
nested analysis cohorts, not three kinds of allocation path.

## BGP join and outcome

For each canonical prefix `x`, `O(x)` is the complete set of unambiguous
scalar origins visible at RRC00 in the frozen RIB.  MOAS sets are retained.
Terminal multi-member AS_SETs, confederations, and unparseable terminal
segments are marked ambiguous instead of being coerced to one ASN.

An exact-routed pair has nonempty `O(p0)` and `O(p)`.  A
visibility-related potential-conflict candidate satisfies

```text
registry-indirect and O(p0) intersection O(p) is empty.
```

The stricter three-handle subset additionally requires known, unambiguous
RIPE `org:` handles at the root, at an eligible intermediate object, and at
the assigned endpoint, with at least three distinct handles.  This subset is a
lower bound on clearly distinct registry entities, not proof that no other
communication channel exists.

## Outputs and checks

- `outputs/visibility_by_afi.csv`: compact table source.
- `outputs/visibility_summary.json`: full funnel, definitions, hashes, and
  input provenance.
- `outputs/visibility_candidates.csv`: candidate-level evidence.
- `outputs/visibility_audit_metrics.csv`: flattened audit funnel.
- `outputs_depth/visibility_depth_by_afi.csv`: the 2026-08-28 depth-extension
  output, containing IPv4/IPv6 distributions for both depth measures and all
  three analysis cohorts, plus the non-laminar count for each cohort.  This
  full rerun used the frozen independent-origin CSV; it did not replace the
  primary MRT-run provenance recorded in the run report.
- `outputs/visibility_run_report.md`: commands, runtime, invariants, and
  interpretation boundary.
- `outputs_recheck/`: independent-origin-extractor rerun.

Required invariants include same-AFI strict containment, unique root--endpoint
pairs, mutually exclusive direct/indirect classification, nonempty and
disjoint origin sets for every candidate, and byte-identical compact and
candidate tables on an independent-origin-extractor rerun. Summary files are
not byte-compared because they intentionally record generation time, source
kind, and absolute input/output paths.
