# Allocation-Tree Analysis Plan

**Goal:** identify conservative, observable locations where a parent-origin
authorization could cover an exact child route with a disjoint visible origin
set.

**Scope:** RIPE-managed IPv4; one RouteViews RIB dated 2026-06-24.

## 1. Claim Boundary

The analysis measures **origin-divergent counterfactual candidates**.  It does
not label a route as legitimate, infer a business relationship, determine
current ROA state, or predict that a route will become RPKI-Invalid.

For a paired RIPE allocation root `r` and leaf `l`, a strict candidate must
satisfy all of the following:

1. `r` and `l` are each exactly one canonical IPv4 CIDR;
2. neither is matched through the RIPE `0.0.0.0/0` pseudo-root;
3. both endpoint CIDRs occur exactly in the selected BGP RIB;
4. both complete visible origin sets are non-empty; and
5. the two origin sets are disjoint.

If the parent later issued only a minimal ROA for one of its visible origins,
and no more-specific matching authorization existed, a route at the child
endpoint could then be Invalid.  The conditions after “if” are not measured
here.

## 2. Data

| Data | Source | Use |
|---|---|---|
| RIPE WHOIS dump | `ripe.db.gz`, June 2026 | Allocation-root/leaf ranges and status labels |
| RouteViews RIB | `rib.20260624.0000.bz2` | Exact endpoint origin sets |

The NDSS 2026 invalid-route corpus is analyzed separately under
`../ndss26_analysis/` and is not used to infer authorization in this
allocation-tree analysis.

## 3. Pipeline

1. `01_download_ripe.py`: fetch and parse RIPE `inetnum`, `aut-num`, and
   `organisation` objects.
2. `02_build_tree.py`: assign each leaf range to the smallest containing
   allocation-root range.
3. `03_annotate_as.py`: retain registry organization/ASN annotations as
   descriptive metadata only.
4. `04_download_bgp.py`: parse the selected RIB into complete exact-prefix
   origin sets.
5. `05_bgp_conflicts.py`: apply the strict endpoint comparison, write
   candidates, counts, and SHA-256 provenance.

## 4. Required Outputs

| File | Purpose |
|---|---|
| `allocation_tree_pairs.csv` | Raw matched root–leaf ranges |
| `bgp_origins.csv` | Exact BGP prefix–origin observations |
| `allocation_tree_origin_divergence.csv` | Strict disjoint-origin candidates |
| `allocation_tree_origin_divergence_summary.json` | Method, funnel counts, statuses, and hashes |

## 5. Validation Checks

- Reject or separately count the `/0` pseudo-root.
- Do not approximate RIPE ranges as CIDRs.
- Do not use a fixed-width row window for interval lookup.
- Do not substitute origins from descendant routes for an exact root route.
- Preserve all origins for MOAS prefixes and compare sets, not one selected AS.
- Call the output “candidates,” never “active conflicts” or “legitimate
  delegations.”

## 6. Limitations

The selected RIB is a single control-plane snapshot.  Exact endpoint matching
is intentionally conservative and omits routes announced only at different
granularities.  The RIPE status taxonomy describes registry administration,
not operator intent.  A ROA/BGP/contractual join would be required for a claim
about active authorization conflicts.
