# S2-ROV Reference Encoding Specification

**Version:** 2.1
**Re-audited:** 2026-08-26
**Status:** experimental reference format, not a standardized RPKI profile

## 1. Scope

This format exists to test canonical policy construction, round-trip parsing,
malformed-input rejection, and four-state lookup.  Byte counts describe this
custom payload only.  They must not be compared directly with CMS-encoded
ROAs, RTR PDUs, h-ROA objects, router memory, or repository storage.

## 2. Policy Header

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | canonical IPv4 base address |
| 4 | 1 | base prefix length |
| 5 | 1 | maximum route length |
| 6 | 4 | holder ASN |
| 10 | 1 | version (`0x01`) |
| 11 | 2 | Stripe count |
| 13 | 1 | reserved flags (zero) |

Total header size: 14 bytes.

The parser rejects truncated headers, noncanonical base addresses, unsupported
versions, nonzero reserved flags, invalid lengths, ASN overflow, and trailing
bytes.

## 3. Stripe Record

| Field | Size | Meaning |
|---|---:|---|
| prefix length | 1 byte | IPv4 length 0–32 |
| prefix bytes | `ceil(length/8)` | canonical network bits |
| flags | 1 byte | bit 0 open; bits 1–2 explicit-set type; others zero |
| explicit-set payload | variable | empty or counted ASN list |

Explicit-set types:

- `0`: empty set, zero payload;
- `1`: one-byte count followed by 1–255 32-bit ASNs.

The open bit is independent of the explicit set.  Therefore
`(q,{holder},open)` names the holder at `q` and delegates origin choice only
to proper descendants.  `(q,∅,closed)` is a deny-all region.

Types 2–3, list count zero, duplicate ASNs, ASN 0, truncation, noncanonical
prefix bits, and reserved flags are rejected.

## 4. Policy Invariants

The `S2ROV` constructor and deserializer require:

1. exactly one Stripe prefix per policy;
2. a base Stripe exactly at the base prefix;
3. the holder ASN in the base Stripe's explicit set;
4. every Stripe inside the base and no longer than `max_length`;
5. no more than 65,535 Stripes; and
6. no trailing or ambiguous encoded material.

The canonical record order is descending prefix length followed by ascending
network address.  Constructors normalize semantically equivalent input
permutations to this order; the wire parser rejects a payload whose records are
not already in canonical order.  Consequently, list insertion order cannot
change the signed payload bytes.

The Python constructor accepts a textual prefix with host bits and normalizes
it before encoding; this is an API convenience, not a wire rule.  The wire
parser and route-validation API require canonical network prefixes.  Boolean
lengths/origins, out-of-range origins, and non-increasing encoded AS lists are
rejected so Python's `bool`-is-`int` behavior and alternate set orderings cannot
create ambiguous semantics or bytes.

Constructed Stripe and S2-ROV values are immutable. Their explicit origin sets
and canonical Stripe sequences use immutable collections, so mutating a caller
owned input collection cannot alter policy bytes or decisions. Adding a Stripe
returns a new validated policy rather than changing an existing policy. This
also prevents an applied snapshot from changing without a new snapshot serial.

The lookup index maps each canonical prefix to its unique Stripe.  IPv4 lookup
probes at most 33 prefix lengths, independent of the number of Stripes.

## 5. Conservative Conventional Projection

For compatibility experiments, the reference code may project:

- `(base, holder, |base|)`; and
- `(q, a, |q|)` for each explicitly named origin in each Stripe.

Open intent itself emits no VRP.  Every projected Valid route must be
`Explicit` under S2-ROV.  The projection is incomplete by design: it does not
transport `Delegated` provenance.

Using the DA policy's descendant `max_length` for the base VRP is unsafe for
this property because a legacy router could accept a holder-origin descendant
that a more-specific Stripe excludes.

## 6. Merging

Sibling or redundant CIDR ranges with identical `(explicit set, open bit)` may
be collapsed.  Ranges with different semantics remain distinct.  A complete
policy is validated after merging, so any equal-prefix collision is rejected.

## 7. Standards Boundary

No object identifier, CMS profile, repository behavior, RTR PDU, or router
wire contract is allocated by this document.  The signed end-to-end prototype
retains experimental policy through a modified relying party and a
provenance-aware API; it does not claim that this 14-byte payload is deployable
as an ordinary ROA.

## 8. Pure Snapshot and Lifecycle Contract

`scripts/utils/snapshot.py` freezes E1a policy composition without claiming a
signed carrier.  Each pure envelope has an issuer, object identifier, profile
version, object serial, validity interval, revocation flag, and one canonical
policy payload.  Active objects with nested base prefixes compose by
most-specific base.  Different active objects at the same base are rejected;
input order never breaks the tie.  Expired, not-yet-valid, and revoked
envelopes remain auditable but cannot classify routes.

Snapshots have a monotone serial.  A byte-identical same-serial application is
an idempotent no-op; an older serial or different content at the same serial is
rejected.  Withdrawal is represented by omission from a higher-serial complete
snapshot.  These rules are the pure executable oracle for E1a.  They do not
satisfy E2's CMS, manifest/CRL, repository, relying-party, or router-carrier
requirements.
