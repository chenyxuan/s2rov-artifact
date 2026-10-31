# Reanalysis of the NDSS 2026 Invalid-Route Corpus

**Re-audited:** 2026-07-29
**Role in this project:** descriptive secondary analysis; not independent
ground-truth collection

## 1. Provenance and Attribution

The daily CSVs come from the artifact associated with Li, Wan, and Chung,
*Demystifying RPKI-Invalid Prefixes: Hidden Causes and Security Risks*
(NDSS 2026).  Their collection and cause-evidence columns are prior work.  Our
scripts only normalize those columns and summarize their occurrence
composition.

This corpus must not be used to claim that we independently discovered its
root causes, that every row is a legitimate route, or that every
relationship-labeled row is a false positive.  Positive values in
`customer`, `org_transit`, `hidden_transit`, `direct_leasing`, and
`broker_leasing` are source-corpus evidence labels, not signed authorization
or contractual ground truth.

## 2. Audited Input

| Property | Value |
|---|---:|
| Daily CSV files | 552 |
| Date range | 2023-01-01 to 2024-09-20 |
| Route-occurrence rows | 2,817,046 |

Some columns contain positive evidence counts greater than one.  The audited
loader therefore maps `value > 0` to label-present; it does not use Python's
generic truth conversion and no longer skips malformed files silently.

## 3. Mutually Exclusive Reporting Rule

Rows can contain overlapping source labels.  For a compact descriptive table,
the script applies this explicit priority:

1. transit-labeled (`org_transit` or `hidden_transit`);
2. IP-leasing-labeled (`direct_leasing` or `broker_leasing`);
3. customer-labeled;
4. MaxLength-only; and
5. other/unlabeled.

This priority prevents double counting.  It is a reporting convention, not a
causal hierarchy.

| Reporting class | Occurrences | Share |
|---|---:|---:|
| Customer-labeled | 1,223,843 | 43.4% |
| Transit-labeled | 522,429 | 18.5% |
| IP-leasing-labeled | 101,453 | 3.6% |
| MaxLength-only | 969,321 | 34.4% |
| Other/unlabeled | 0 | 0.0% |

Under this convention, 65.6% of occurrence rows carry at least one of the
three relationship-oriented labels.  This is a property of the supplied
corpus and rule, not an estimate that 65.6% of all RPKI-Invalid routes are
legitimate or “uncorrectable.”

## 4. Use in the DA-ROV Paper

The corpus provides context that delegation, transit, and leasing are
operationally relevant to Invalid-route diagnosis.  It does not supply the
holder authorization needed by DA-ROV.  Accordingly, the manuscript cites the
NDSS 2026 study as related empirical work but does not present this
reclassification as our main contribution or use its 65.6% value as
authorization ground truth.

Our independent measurement claim is kept separate in
`../allocation_tree/RESULTS.md`: a RIPE/RouteViews counterfactual that measures
strict endpoint origin divergence without importing the NDSS relationship
labels.

## 5. Limitations

1. The rows are repeated daily observations, not independent routes or
   operators.
2. Source labels can overlap and can contain evidence counts rather than
   Boolean ground truth.
3. No traffic volume is available.
4. No signed delegation statement or contractual intent is present.
5. A relationship label does not by itself distinguish authorized use from
   abuse.

The safe conclusion is therefore descriptive: the supplied invalid-route
corpus contains substantial relationship-oriented labeling.  Stronger
legitimacy, false-positive, or causality claims require additional evidence.
