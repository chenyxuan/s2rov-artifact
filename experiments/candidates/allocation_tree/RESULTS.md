# Allocation-Tree Analysis Results: RIPE Region

**Re-audited:** 2026-07-29
**Data sources:** RIPE Database snapshot from June 2026 and RouteViews RIB
`rib.20260624.0000.bz2`

## 1. Question and Interpretation

This analysis asks a counterfactual, not an authorization question:

> For a RIPE allocation-root/leaf pair whose two endpoint prefixes are both
> announced exactly in the selected RIB, are the complete visible origin sets
> disjoint?

A positive row identifies where a minimal parent-origin ROA *could* conflict
with an exact child announcement if no more-specific matching ROA existed.  It
does **not** show that the child is contractually delegated, that either prefix
currently has a ROA, that a future route will be Invalid, or that either route
is legitimate.

The strict definition replaces the earlier analysis, which incorrectly used
all BGP routes contained anywhere below a root as the root's origin set and
searched a fixed ±300-row interval window.  The previously reported value
`1,135` is therefore retired.

## 2. Re-audited Pipeline

1. Parse RIPE IPv4 `inetnum` ranges.
2. Pair leaf ranges with the smallest containing allocation root.
3. Exclude the `0.0.0.0/0` pseudo-root artifact.
4. Retain only pairs for which both RIPE ranges are exactly one canonical CIDR.
5. Require exact-prefix observations for both endpoints in the RouteViews RIB.
6. Compare the **complete** origin-AS sets.  Count a strict candidate only when
   both sets are non-empty and disjoint.

The implementation is
`scripts/05_bgp_conflicts.py`.  It emits a candidate table and a JSON summary
containing input/output SHA-256 hashes.

## 3. Results

| Filter or outcome | Count |
|---|---:|
| Raw root–leaf pairs | 3,950,990 |
| Pairs after excluding the `/0` pseudo-root | 3,929,262 |
| Pairs with exact-CIDR endpoints | 3,441,429 |
| Exact routes observed at both endpoints | 24,663 |
| Endpoint origin sets overlap | 15,833 |
| **Disjoint-origin counterfactual candidates** | **8,830** |

The 8,830 candidates contain 1,647 distinct root prefixes and 8,830 distinct
leaf prefixes.  Their exact BGP observations involve 731 root-origin ASNs and
2,719 leaf-origin ASNs.

Candidate leaves are unevenly distributed across roots:

| Candidate leaves per root | Value |
|---|---:|
| Mean | 5.36 |
| Median | 2 |
| Nearest-rank p90 | 11 |
| Nearest-rank p95 | 19 |
| Maximum | 207 |
| Roots with exactly one candidate leaf | 742 (45.1%) |

This fan-out distribution describes the construction corpus; it is not a
distribution of verified delegations.

### Candidate status labels

All candidate roots are `ALLOCATED PA`.  Leaf labels are:

| Leaf status | Count | Share |
|---|---:|---:|
| `ASSIGNED PA` | 7,113 | 80.6% |
| `SUB-ALLOCATED PA` | 1,631 | 18.5% |
| `LIR-PARTITIONED PA` | 86 | 1.0% |

These registry labels describe address-management status, not business intent
or route authorization.

## 4. Reproducibility

Generated artifacts:

- `outputs/tables/allocation_tree_origin_divergence.csv`
- `outputs/tables/allocation_tree_origin_divergence_summary.json`

The summary records the exact method and these hashes:

| Artifact | SHA-256 |
|---|---|
| `allocation_tree_pairs.csv` | `4125be93823ef9b179be57fffda8075218e8443c34be823a2b3643c5fe1bf02a` |
| `bgp_origins.csv` | `854deee33792067f3dab5ca7d3636d0af04be0b16206ead7443bf1c22c67d7dc` |
| `allocation_tree_origin_divergence.csv` | `b046e31aec24b3c9e48e99f17185be211f0229a898ee00c28e72d10097079b27` |

Run from the repository root:

```bash
python phase1_empirical/allocation_tree/scripts/05_bgp_conflicts.py
```

## 5. Limitations

1. The analysis covers RIPE-managed IPv4 only.
2. It uses one RouteViews RIB and exact-prefix observations; less-specific or
   more-specific routing behavior is intentionally outside this strict count.
3. MOAS endpoints are compared as sets.  Candidates require disjoint sets,
   avoiding claims when even one visible origin overlaps.
4. No contemporaneous global ROA set is joined.
5. RIPE status labels and BGP observations do not establish delegation,
   contractual intent, or legitimacy.

The result supports only an expressiveness motivation: origin-divergent
descendants exist at observable allocation-tree endpoints.  It does not supply
authorization evidence for S2-ROV on behalf of a holder.
