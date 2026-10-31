# E1a Pure Semantic Differential Contract

## Research question and hard endpoints

Does the pure S²-ROV semantic engine return one deterministic, mutually
exclusive state; preserve canonical bytes across policy input permutations;
reject malformed encodings; and prevent the conservative legacy projection
from upgrading any non-Explicit route to conventional Valid?

The three hard endpoints are:

1. `semantic_mismatch_count = 0`;
2. `order_dependent_count = 0`; and
3. `forbidden_state_upgrade_count = 0`.

Any nonzero endpoint fails E1a. A percentage pass rate cannot override one
counterexample.

## Frozen corpus

- Legal-object deterministic seed: `20260826`.
- Invalid-object deterministic seed: `120260826`.
- Legal generated semantic vectors: exactly `100,000`.
- Invalid generated objects: exactly `100,000`, evenly cycling through the 29
  frozen field, structure, wire, constructor, and truncation families in the
  V2 runner. Rejection counts only when the exception message identifies the
  intended malformed field or structure.
- Bounded exhaustive vectors: exactly `6,080`.
- Deterministic IPv4 boundary vectors: exactly `138`, including `/0`, `/1`,
  `/31`, `/32`, full `/0`--`/32` depth, and a 33-rule alternating chain.
- Generated-vector identifiers and branch choices are fixed by Python's local
  `random.Random(20260826)` instance and do not use global hash order.
- A bounded exhaustive corpus independently crosses small IPv4 prefix trees,
  `maxLength`, base mode, nested rule mode/set, route relationship, and origin
  class.
- Boundary categories required to appear: outside, exact base, proper
  descendant, exact nested rule, descendant of nested rule, and overlength;
  Explicit, OpenScope, Invalid, and NotFound; explicit, eligible-unlisted, and
  ineligible origins; open and closed selected rules.
- Route relationship and origin-class labels are derived again from the final
  policy and route before coverage is counted; generator-requested labels are
  diagnostic metadata only.
- The seeds and counts may not be changed after a mismatch is observed. A code
  fix must rerun the same frozen corpus in a new immutable output directory.

## Differential paths

Every valid vector is evaluated by:

1. an independent pure oracle in `oracle.py`;
2. the S2-ROV-encoding reference engine;
3. the reference encoder/decoder round trip; and
4. conventional aggregate, exact-child, and exact-target wildcard baseline
   oracles for recorded comparison.

The exact-child intended origin, wildcard target, and optional same-prefix
regular ROA are frozen independently from the observed route origin. Thus the
full-corpus B3/B4 fields are not constructed to authorize every observation.
The bounded corpus enumerates every rule-order permutation. Legal generated
and deep-boundary vectors check identity, reverse, rotate, even/odd, and one
ID-seeded order (deduplicated when rules are few).

For every unique legal policy, the conservative projection is fully enumerated.
Every projected VRP is checked as a singleton conventional authorization and
must have `maxLength == prefixLength` and classify Explicit in the independent
oracle. Any non-exact projection fails closed; it is not enough to test only
the VRP's own prefix. A frozen negative control broadens a root VRP through a
nested closed rule and must be detected while its critical descendant is
conventional Valid and native Invalid. The hard endpoint counts unsafe
projected VRPs, not sampled routes.

The current historical label `Delegated` is mapped mechanically to the
manuscript term `OpenScope` only in the E1a result schema. Historical routing-model
raw artifacts are not rewritten.

## Frozen wildcard baseline: B4-exact

The executable baseline follows the minimum semantics stated by Gilad et al.:
a wildcard entry admits any origin at its target prefix; a regular ROA at the
same prefix has priority. This gate names it `B4-exact`. It does not extend the
wildcard to descendants. If one or more same-prefix regular ROAs exist, an
origin matching one is `RegularValid`; a nonmatching origin is `Invalid`, and
the wildcard cannot rescue it. With no same-prefix regular ROA, any origin at
the exact target is `WildcardValid`; other prefixes are `NotFound`.

## Pure composition and lifecycle

E1a differentially compares `implementation/s2rov_codec/scripts/utils/snapshot.py` with
the implementation-independent, standard-library-only
`experiments/semantic_gate/snapshot_oracle.py`; neither is a signed carrier.
Envelopes freeze issuer, object identifier, profile version, object serial,
validity interval, revocation, and canonical payload. Nested base policies use
most-specific-base selection. Conflicting active objects at the same base are
rejected. Expired, future, or revoked objects cannot classify. Snapshot serials
are monotone; identical same-serial replay is idempotent, while rollback and
same-serial content collision are rejected. Omission in a higher serial is a
withdrawal.

These rules close G0 only at the pure semantic layer. They do not satisfy G1:
no CMS profile, certificate chain, manifest/CRL, repository transport, RP
parser, RTR/API capability negotiation, router compiler, or FIB is claimed.

## Parser mutation census

The fixed mutation families are unsupported version, nonzero header/Stripe
flags, noncanonical base/prefix/order, truncation at every byte boundary,
trailing bytes, invalid prefix length, unknown AS-set type, zero list count,
duplicate ASNs, AS0, and duplicate rule prefix. The 100,000-object invalid
stream additionally varies legal source policies and cycles through 29 frozen
wire and constructor families. Every object must be rejected for its targeted
reason.

## Output and stop rules

The runner refuses an output directory outside this repository or a nonempty
output directory. It writes vectors/results append-only during the run,
records source/input hashes and environment data, and emits failures with the
complete vector or invalid input. It copies every execution source---including
untracked sources, `as_set.py`, package initializers, this contract, and the
parent redesign---into a hash-bound source bundle. At startup it enumerates
every repository-local file in the loaded Python module closure and requires
all of them in that bundle. Its reproducer verifies current source hashes
before execution and checks every deterministic scientific output against
expected digests. The exact allowed artifact paths are frozen in the initial
manifest before vector execution; a passing run requires the final file set to
equal that allowlist. It never retries a failed vector. A production run is valid
only if its planned vector count, result count, parser census, composition
census, and all hard endpoints are complete. A passing run labels itself
unverified until a separate comparison report checks a complete second run;
the runner cannot self-assert independent reproduction.

## Claim boundary

Passing E1a supports only the archived profile-1 single-stack semantics,
encoding, composition, and lifecycle-oracle correctness over the frozen
corpus. It does not validate the current profile-2 OpenScope classifier and
does not establish
full signed-object correctness, RP/router interoperability, operational
handoff performance, Internet-scale delivery/exposure, or production readiness.
