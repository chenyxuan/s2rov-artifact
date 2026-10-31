# S2-ROV encoding: Reference Encoding and Parser Validation

**Version:** 2.3
**Re-audited:** 2026-08-30

## 1. Objectives

1. Serialize one canonical Stripe per prefix.
2. Preserve explicit origins and an optional OpenScope marker in one record.
3. Reject malformed and ambiguous inputs.
4. Preserve all four validation states across serialize–parse round trips.
5. Verify that the conservative conventional projection contains only S2-ROV
   `Explicit` outcomes.
6. Exercise policy construction over the strict allocation-tree candidate
   corpus without treating those candidates as real authorizations.
7. Preserve the version-1 IPv4 wire bytes while exercising IPv4 and IPv6
   construction, parsing, composition, and classification boundaries.

System latency, update propagation, failure recovery, and live enforcement are
measured only with the prototype system.  Python timings in this directory are
developer diagnostics and are not manuscript system evidence.

## 2. Tasks and Outputs

| Script | Audited task | Output |
|---|---|---|
| `01_encoding.py` | valid round trips and malformed-policy rejection | `encoding_sizes.csv` |
| `02_as_set_compression.py` | empty/list payload size and decode equality | `as_set_stats.csv` |
| `03_stripe_merging.py` | exact-prefix and marker preservation | `merge_ratios.csv` |
| `04_flattening.py` | conservative projection → `Explicit` invariant | `flattening_validation.csv` |
| `05_benchmark.py` | synthetic reference-payload size diagnostics only | `reference_format_sizes.csv` |
| `06_update_efficiency.py` | interpreter-only developer timing | `update_costs.csv` |
| `07_candidate_policy_corpus.py` | round trips over synthesized candidate policies | `candidate_policy_corpus.csv` |

## 3. Removed Claims

The earlier plan compared a custom S2-ROV payload with an assumed “68 bytes per
VRP,” a simplified h-ROA estimate, and a nonfunctional MaxLength baseline.
Those quantities were not representation-equivalent and are retired.

The earlier “real-world evaluation” grouped invalid-route rows by ROA origin,
selected the first unrelated prefix as a base, and could place Stripes outside
that base.  Its size reductions and conflict-resolution percentage are also
retired.  The replacement corpus uses actual allocation-root containment but
is explicitly synthetic policy construction.

## 4. Success Criteria

- all valid policy cases round-trip byte-for-byte;
- truncated, noncanonical, duplicate-prefix, out-of-base, and invalid-count
  cases raise deterministic errors;
- all eight four-state policy cases pass before and after serialization;
- every projected ROA entry evaluates to `Explicit`;
- all synthesized allocation-candidate policies pass construction and
  round-trip validation; and
- IPv4 `/0` and `/32`, IPv6 `/0`, `/32`, `/48`, `/64`, and `/128`, explicit
  records within a marked region, marker non-overlap, canonicalization, and
  address-family-specific `max_length` limits are covered; and
- no reference-only size or timing is presented as router, RTR, or
  end-to-end performance.

## 5. Interpretation

Reference payload size is useful for catching accidental growth and parser
bugs.  It is not a standards or deployment comparison.  The paper may cite the
eight semantic cases as correctness evidence, while end-to-end performance
must remain tied to the Krill–Routinator–FRR experiment logs.

For the 1,647 synthesized candidate-root policies, all round trips pass.  The
policies contain a median of 3 Stripes (nearest-rank p95 20; maximum 208).
Their custom reference payloads have median size 44 bytes, nearest-rank p95
213 bytes, and maximum 2,093 bytes.  These values exclude CMS, repository, and
transport framing and are reported only as structural corpus diagnostics.
