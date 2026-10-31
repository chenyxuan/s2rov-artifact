# DA-ROA Reference Encoding Specification

**Version:** 2.4
**Re-audited:** 2026-08-30
**Status:** experimental reference format, not a standardized RPKI profile

## 1. Scope

This format exists to test canonical policy construction, round-trip parsing,
malformed-input rejection, and four-state lookup.  Byte counts describe this
custom payload only.  They must not be compared directly with CMS-encoded
ROAs, RTR PDUs, h-ROA objects, router memory, or repository storage.

## 2. Policy Header

The current OpenScope semantics are profile version 2.  This semantic profile
is carried by the signed-policy envelope and is included in canonical snapshot
bytes.  Profile version 1 belongs to the archived longest-prefix rule model and
must not be interpreted by the current classifier.  The byte at header offset
10 is only an address-encoding tag; it is not the semantic profile version.
Consequently, a bare payload is not a self-describing signed policy and must be
bound to profile version 2 by its envelope or artifact manifest.

IPv4 policies retain wire version `0x01` and the original 14-byte header
byte-for-byte:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | canonical IPv4 base address |
| 4 | 1 | base prefix length |
| 5 | 1 | maximum route length |
| 6 | 4 | holder ASN |
| 10 | 1 | wire version (`0x01`) |
| 11 | 2 | Stripe count |
| 13 | 1 | reserved flags (zero) |

Total header size: 14 bytes.

IPv6 policies use wire version `0x02`.  The common field offsets are retained,
the legacy four-byte address slot contains the fixed tag `IPv6`, and the full
base address follows the common header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | address-family tag (`IPv6`) |
| 4 | 1 | base prefix length |
| 5 | 1 | maximum route length |
| 6 | 4 | holder ASN |
| 10 | 1 | wire version (`0x02`) |
| 11 | 2 | Stripe count |
| 13 | 1 | reserved flags (zero) |
| 14 | 16 | canonical IPv6 base address |

Total IPv6 header size: 30 bytes.  An IPv4-only wire parser rejects this
extension rather than interpreting it as IPv4.  A parser for the current
profile accepts both address-encoding tags; it never rewrites an IPv4 payload
as IPv6.

The parser rejects truncated headers, noncanonical base addresses, unsupported
versions, nonzero reserved flags, invalid lengths, ASN overflow, and trailing
bytes.

## 3. Stripe Record

| Field | Size | Meaning |
|---|---:|---|
| prefix length | 1 byte | IPv4 length 0–32 or IPv6 length 0–128 |
| prefix bytes | `ceil(length/8)` | canonical network bits |
| flags | 1 byte | bit 0 OpenScope marker; bits 1–2 explicit-set type; others zero |
| explicit-set payload | variable | empty or counted ASN list |

Explicit-set types:

- `0`: empty set, zero payload;
- `1`: one-byte count followed by 1–255 32-bit ASNs.

Bit 0 is retained as the wire-compatible OpenScope marker bit.  A clear bit
means only that the prefix is unmarked; it does not create a closed or deny
region and does not shadow a covering marker.  The marker is independent of
the explicit set.  Thus, a record can both name explicit origins and mark its
proper descendants as OpenScope.

Types 2–3, list count zero, duplicate ASNs, ASN 0, truncation, noncanonical
prefix bits, and reserved flags are rejected.

## 4. Policy Invariants

The `DAROA` constructor and deserializer require:

1. exactly one Stripe prefix per policy;
2. a base Stripe exactly at the base prefix;
3. the holder ASN in the base Stripe's explicit set;
4. every Stripe inside the base and no longer than `max_length`;
5. all OpenScope-marked prefixes are pairwise prefix-disjoint;
6. no more than 65,535 Stripes; and
7. no trailing or ambiguous encoded material.

Unmarked explicit records may overlap one OpenScope-marked region.  The base
record carries conventional `(base, origin, max_length)` entries.  A non-base
explicit record carries an exact `(prefix, origin, |prefix|)` entry because
the wire format has no per-record maxLength.  Every covering record still
creates conventional ROA coverage.  Classification first tests these
conventional matches.  If coverage exists but no origin matches, a marker may
refine the result to OpenScope only when the route is a proper descendant of
the marker and no longer than the policy maxLength.  Otherwise the covered
route is Invalid.  Because markers cannot overlap, classification requires
neither record priority nor a most-specific record rule.

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

Constructed Stripe and DAROA values are immutable. Their explicit origin sets
and canonical Stripe sequences use immutable collections, so mutating a caller
owned input collection cannot alter policy bytes or decisions. Adding a Stripe
returns a new validated policy rather than changing an existing policy. This
also prevents an applied snapshot from changing without a new snapshot serial.

All Stripes in one policy use the base prefix's address family.  The lookup
index maps each canonical prefix to its unique Stripe.  Lookup probes at most
33 prefix lengths for IPv4 and 129 for IPv6, independent of the number of
Stripes.

## 5. Conservative Conventional Projection

For compatibility experiments, the reference code may project:

- `(base, origin, max_length)` for every origin named by the base record; and
- `(q, a, |q|)` for each explicitly named origin in a non-base Stripe.

An OpenScope marker itself emits no ROA entry.  Every projected Valid route must be
`Explicit` under S2-ROV.  Every non-base named origin is projected at its exact
record prefix.  The projection does not transport `OpenScope` provenance.

## 6. Merging

Records are not CIDR-collapsed.  A non-base explicit record represents an
exact ROA, so replacing sibling records by their parent would change which
route prefix is authorized.  OpenScope markers also retain their exact
prefixes because merging them would expand the marked region.  Canonical
ordering remains available without semantic aggregation.

## 7. Standards Boundary

No object identifier, CMS profile, repository behavior, RTR PDU, or router
wire contract is allocated by this document.  The signed end-to-end prototype
retains experimental policy through a modified relying party and a
provenance-aware API; it does not claim that this custom payload is deployable
as an ordinary ROA.

## 8. Pure Snapshot and Lifecycle Contract

`scripts/utils/snapshot.py` freezes E1a policy composition without claiming a
signed carrier.  Each pure envelope has an issuer, object identifier, profile
version, object serial, validity interval, revocation flag, and one canonical
policy payload.  Active objects with nested base prefixes compose by
most-specific base.  Different active objects at the same base are rejected;
input order never breaks the tie.  Expired, not-yet-valid, and revoked
envelopes remain auditable but cannot classify routes.

This base selection composes separate policy objects.  It is not a selection
rule among records inside one policy.

Snapshots have a monotone serial.  A byte-identical same-serial application is
an idempotent no-op; an older serial or different content at the same serial is
rejected.  Withdrawal is represented by omission from a higher-serial complete
snapshot.  These rules are the pure executable oracle for E1a.  They do not
satisfy E2's CMS, manifest/CRL, repository, relying-party, or router-carrier
requirements.
