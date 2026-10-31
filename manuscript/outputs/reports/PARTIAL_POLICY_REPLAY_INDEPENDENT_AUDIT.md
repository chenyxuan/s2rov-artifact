# Partial-Policy Replay Independent Audit

> Historical v1 audit. It verifies the retired family-specific, fixed-$s=10\%$
> products and does not audit the pooled Figure 2 introduced on 2026-08-30.

**Audit date:** 2026-08-29 UTC

**Mode:** Independent, fail-closed verification

**Verdict:** PASS for the experiment implementation, generated outputs, and final manuscript integration.

## Scope

This audit independently checked:

- `scripts/run_partial_policy_replay.py` and its unit tests;
- the frozen visibility-candidate input;
- the complete factorial grid and secondary equal-decision data;
- the experiment manifest and all 20 outputs recorded by it;
- the two active fixed-10%-scope panels in PDF and SVG form; and
- the numerical anchors used in the active manuscript sources.

No experiment module was imported during the independent numerical reconstruction. The runner was imported only by its own unit-test suite.

## Frozen Inputs and Hashes

| Artifact | SHA-256 |
|---|---|
| Frozen candidates | `0846c5f5775e92092b445b64851918ca6f6b3e45651598d9006d3f3aeb483918` |
| Runner | `bd4159fc82e87ae472f077e648b769575470bd4c734cd6b6a710b6e08ee311bc` |
| Unit tests | `84ba4185cdfee481c4dbcae330317c539b1cd481b4a6b05bef9339e0d15b7604` |
| Experiment manifest | `693c1bc8b3bf711ef32ef8181406fb22d470e772a4ead1da2ef22ba3403c49a5` |
| Full factorial grid | `28dbb520de5488483f02f4dbb62066a495db0abb49fc92b268eff7b5d64760dc` |
| Equal-decision data | `5333969fbbe3df14e9cf96a3b51ada4bb5f01113948ff6928f0d0e1c932ef5a7` |

The runner hash equals the hash stored in the manifest. Every one of the 20 manifest-listed outputs has the recorded byte size and SHA-256.

## Independent Reconstruction Method

The audit read the frozen candidate file directly with the Python standard library and used `ipaddress` for prefix validation. It then rebuilt the analysis without importing the runner:

1. Parsed every semicolon-delimited origin set as an atomic set and preserved complete MOAS endpoint sets.
2. Grouped candidate rows independently by IP version and root prefix.
3. Reconstructed all 1,000 endpoint and root permutations from the declared seed rule. For rollout `i`, the seed is the first eight SHA-256 bytes, interpreted as an unsigned big-endian integer, of `20260829|family|i|namespace`.
4. Converted each permutation to ranks and verified that every budget selects a nested prefix of the same order.
5. Recomputed random, fanout-first, and fanout-last coverage for every budget and for all 11 by 11 exact/scope target combinations.
6. Recomputed means, medians, minima, maxima, and linear 2.5th, 5th, 95th, and 97.5th percentiles directly from the 1,000 rollout values.
7. Compared every emitted numeric field against the two generated data files with tolerance limited to their six-decimal serialization.

The result was **42,900 numeric comparisons with 0 mismatches**. The full grid contains 726 unique rows; the equal-decision data contains 297 unique rows.

All 1,000 endpoint orders and all 1,000 root orders are unique within each IP version. The independently reconstructed selection hashes equal the manifest:

- IPv4: `be57ea8f87d8fb3c479d84e69249673e435e3cd1c7b1280dc2d04b0bf0c2a1fe`
- IPv6: `d75e772ed2a286c2eee7727abac8767ced91187227eb679d37a4e4246da0008f`

The plotted 5th--95th bands are percentile ranges over the fixed rollout orders. They are not confidence intervals or population-prevalence intervals. The manuscript describes them as rollout-order percentiles.

## Structural and MOAS Invariants

The frozen file contains 504 IPv4 paths under 83 roots and 83 IPv6 paths under 14 roots. Independent checks found:

- all prefixes canonical and in the declared IP version;
- every endpoint a proper subprefix of its recorded root;
- no duplicate endpoint prefix;
- no nested retained roots;
- each endpoint covered by exactly one retained root;
- consistent root status, organization handle, and origin set within each root;
- disjoint root and endpoint origin sets for every row; and
- per-root scope lengths sufficient for all retained endpoints.

IPv4 contains exactly two multi-origin endpoints:

- `77.93.148.0/24`: origins `203576` and `219450`;
- `94.159.113.0/24`: origins `216234` and `216334`.

They account for 506 complete IPv4 prefix-origin entries across 504 endpoint-path decisions. IPv6 has no multi-origin endpoint and has 83 entries across 83 path decisions. No retained root has multiple origins.

## Independently Recomputed Paper Anchors

Figure 2 holds the root-scope target at `s=10.0%` and varies the exact-endpoint
target `q`. Integer selection gives 8/83 IPv4 roots and 1/14 IPv6 roots. At
`q=50.0%`, the independently reconstructed values are:

| Version | Exact selected | Exact-only remaining | Random remaining median [5th, 95th] | Fanout first | Fanout last |
|---|---:|---:|---:|---:|---:|
| IPv4 | 252 | 252 (50.0%) | 233 (46.2%) [201.9, 244.0] | 129 (25.6%) | 248 (49.2%) |
| IPv6 | 41 | 42 (50.6%) | 41 (49.4%) [27.0, 42.0] | 25 (30.1%) | 41 (49.4%) |

The bracketed random-placement values are 5th--95th percentiles over the 1,000
fixed rollout orders. They are not confidence intervals. These values agree
with the active Figure 2 and Section V-A sources.

The equal-decision output remains a secondary artifact. At 41 IPv4 decisions,
exact and random root-scope coverage are 8.1% and 50.2% [33.9%, 65.5%]; at
seven IPv6 decisions, they are 8.4% and 50.0% [14.5%, 85.5%]. Fanout-first and
fanout-last coverage are 87.7% and 11.7% for IPv4 and 91.6% and 8.4% for IPv6.
These secondary values are not Figure 2's headline result.

Full candidate-frame coverage corresponds to 504 endpoint-path decisions and
506 exact prefix-origin entries versus 83 root-scope decisions for IPv4; the
IPv6 values are 83, 83, and 14. This is also retained as secondary artifact
evidence rather than the active figure comparison.

## Test and Output Checks

The following command was run with bytecode writing disabled:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest MSN-2026-0830/scripts/tests/test_partial_policy_replay.py -v
```

Result: **9/9 tests passed**.

The two active panels have the following hashes:

| Panel | PDF SHA-256 | SVG SHA-256 |
|---|---|---|
| IPv4 | `527f4d08c847b54b89faa9e0355bed2cde9fdcc50b412f6509a7b7f256af7a44` | `bed2a2e46e394ca5bb67b6b2d50b8fbd355600c377d9bb285af257fecf57a9d6` |
| IPv6 | `9a20e09bdb8d3634cf00f6d8d9a0085bab0a0dc428ddb359c77131153f8b6570` | `d72edc5339811640b4c2032a6c0ec76aa5f063398ff82740428f18f3213cf0bb` |

Both PDFs are vector-only, 252 by 149.8 points, and contain one subset-embedded Unicode CID TrueType DejaVu Sans font. Extracted PDF text and SVG text contain no percentage-point abbreviation and no manual `(a)` or `(b)` panel marker. LaTeX supplies the panel labels through the `subfig` package.

The panels are legible at their native 3.5-inch width and are included side by side in a two-column `figure*`. The 5.2-point legend and 5.6-point tick labels are at the small end of print-safe sizing, and the shaded random-order band is explained as a rollout-percentile range in the preceding method text rather than represented by a separate legend entry. These are presentation advisories, not correctness blockers.

## Eligible-AS Hardening Note

The runner rejects zero and out-of-range ASNs but does not separately encode every eligible-AS exclusion listed in the design section. An independent scan found no AS_TRANS, private-use, documentation, or reserved ASN among the frozen root or endpoint origins. Because the input hash is pinned, this is **not a blocker for the reported result**. If the runner later accepts a different input hash, it should add an explicit eligible-AS gate before claiming that every selected-root candidate becomes OpenScope.

## Manuscript Integration

`MSN-2026-0830/main.pdf` was rebuilt after the active experiment source and
fixed-scope residual panels. It contains the new V-A and Figure 2, has eight letter-size
pages, contains no Type 3 font, and passes the manuscript build checks. Its
SHA-256 is
`0d4e3c21908f0becb903b0758af4e71128c2c8ab96599534a0471f09a69ce99a`.
No experiment-data, implementation, or manuscript-integration blocker remains.
