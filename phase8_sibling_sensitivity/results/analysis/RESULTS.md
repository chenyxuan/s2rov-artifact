## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate
- Origin Date: 2026-08-23
- Verification Status: ANALYZED (independent rerun required for verification)
- Version Label: phase8-sibling-endpoint-v1

## Phase-8 Sibling Endpoint Result

- Manifest: `af0041cf390d22266a65033ada7ad97fc93a713b61cb0575d9e82d67acae7d26`
- Independent unit: `holder_asn` (n=200; design population 691)
- Frozen topology: 77,429 ASes
- Fixed measured ROV set: 589 ASes
- Physical trials: 600; retries: 0

At 100% of the fixed measured ROV set, open DA-ROV increased design-weighted
sibling-prefix attacker route selection by 46.45
percentage points (pointwise 95% interval
[43.23, 49.69])
and sibling-prefix attacker destination delivery by
30.26 points
([25.96,
34.62]).

The exact original-leaf invariance audit compared
3600 population/partition pairs and found
0 mismatches.

These are conditional AS-level route-exposure results for a deterministic
same-length sibling under frozen inputs. They do not estimate traffic impact,
sibling utilization, delegation legitimacy, attack prevalence, or behavior on
other topology/ROV snapshots.
