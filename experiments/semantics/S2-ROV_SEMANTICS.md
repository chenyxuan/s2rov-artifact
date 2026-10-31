# Classifier semantics: S2-ROV Four-State Semantics

**Version:** 4.0
**Re-audited:** 2026-07-29
**Status:** specification for the reference implementation and manuscript

## 1. Design Contract

S2-ROV separates two forms of evidence:

- an **explicit** origin named in signed holder policy; and
- a **delegated choice** admitted by signed open policy but not authenticated
  as a particular origin.

The four design requirements inherited from formal-statement are exact aggregate
protection, proper-descendant scoping, longest-prefix override, and result
provenance.

S2-ROV does not infer delegation from BGP observations, WHOIS status, or
business-relationship datasets.

## 2. Policy Object

A policy object is

\[
D=(v,\rho,m,a_h,\mathcal S),
\]

where:

- \(v\) is the policy-profile version binding structural and ASN-eligibility
  rules; the prototype fixes \(v=1\);
- \(\rho\) is the base prefix;
- \(|\rho|\le m\le 32\) is the longest route length considered;
- \(a_h\) is the holder origin; and
- \(\mathcal S\) is a finite map from Stripe prefix to Stripe policy.

A Stripe is

\[
s=(q,E,\mu),
\]

with \(q\sqsubseteq\rho\), an explicit origin set
\(E\subseteq\mathcal A\), and
\(\mu\in\{\mathsf{closed},\mathsf{open}\}\).

### Structural invariants

1. Exactly one Stripe exists for each Stripe prefix.
2. A base Stripe at \(\rho\) is present and contains \(a_h\in E\).
3. Every Stripe lies within \(\rho\) and has \(|q|\le m\).
4. ASN and count fields fit their encoded ranges.
5. Equal-prefix ambiguity is rejected rather than resolved by list order.

One Stripe can simultaneously name explicit origins and be open for proper
descendants.  For example,
\((\rho,\{a_h\},\mathsf{open})\) protects the aggregate while delegating
origin choice below it.  Separate equal-prefix “self” and “open” Stripes are
neither necessary nor valid.

## 3. Stripe Selection

For route prefix \(p\sqsubseteq\rho\), let

\[
q^\star_D(p)=
\arg\max_{q\in\operatorname{dom}(\mathcal S),\ p\sqsubseteq q}|q|,
\qquad
(E^\star,\mu^\star)=\mathcal S(q^\star).
\]

The base key makes the candidate set nonempty. Canonical equal-length prefixes
that both cover \(p\) are identical, and the map has one value per key, so the
longest-prefix match is deterministic. A more-specific closed Stripe overrides
a broader open Stripe.

## 4. Four-State Validation

Let \(\mathsf{eligible}_v(a)\) reject values that cannot be ordinary public
origins in the reference profile: AS0, AS_TRANS, values outside the 32-bit
range, and documentation/private/reserved ranges.

Eligibility is a syntax and deployment filter.  It is **not** a
“not-hijack” oracle and does not prove authorization.

\[
\mathsf{DA}(D,p,a)=
\begin{cases}
\mathsf{NotFound}, & p\not\sqsubseteq\rho,\\
\mathsf{Invalid}, & |p|>m,\\
\mathsf{Explicit}, & a\in E^\star,\\
\mathsf{Delegated}, &
  \mu^\star=\mathsf{open}\land p\sqsubset q^\star
  \land\mathsf{eligible}_v(a),\\
\mathsf{Invalid}, & \text{otherwise}.
\end{cases}
\]

The proper-subprefix condition \(p\sqsubset q^\star\) is essential.  It
prevents an open Stripe from authorizing an unlisted origin for the Stripe's
exact aggregate.

### Procedural form

```text
validate(D, p, a):
    if p is outside D.base:              return NotFound
    if length(p) > D.max_length:         return Invalid
    s = longest_prefix_stripe_covering(p)
    if a in s.explicit_origins:          return Explicit
    if s.open and p is proper below s.q
       and eligible_v(a):                return Delegated
    return Invalid
```

## 5. Worked Policy

```text
D = DA-ROA(
      base = 10.0.0.0/16,
      max_length = 24,
      holder = AS64501,
      stripes = [
        (10.0.0.0/16, {AS64501}, open),
        (10.0.1.0/24, {AS64502}, closed)
      ])
```

| Route | Result | Reason |
|---|---|---|
| `(10.0.0.0/16, AS64501)` | Explicit | holder named at exact base |
| `(10.0.0.0/16, AS64502)` | Invalid | open does not apply at exact base |
| `(10.0.1.0/24, AS64502)` | Explicit | more-specific closed Stripe names it |
| `(10.0.1.0/24, AS15169)` | Invalid | closed override |
| `(10.0.2.0/24, AS18403)` | Delegated | proper descendant under open base |
| `(10.0.2.0/24, AS15169)` | Delegated | public eligibility is not authorization |
| `(10.0.2.0/24, private ASN)` | Invalid | ineligible reference-profile value |
| route outside `/16` | NotFound | policy does not cover it |

The arbitrary public-AS row is a required negative control.  It makes the
security boundary visible instead of calling every open match “Valid.”

## 6. Properties

### Lemma 1: Exact-scope containment

At the exact prefix of an open Stripe, only origins in its explicit set are
\(\mathsf{Explicit}\); every other origin is \(\mathsf{Invalid}\).

**Proof.** The proper-descendant condition disables the
\(\mathsf{Delegated}\) branch at \(p=q^\star\). \(\square\)

### Lemma 2: Closed override

If a closed Stripe is the longest-prefix cover of a route, every origin not in
its explicit set is \(\mathsf{Invalid}\).

**Proof.** Explicit membership fails and closed mode disables the only
\(\mathsf{Delegated}\) branch. \(\square\)

### Theorem 1: Isolated-VRP compatibility

Fix a supported version \(v\) and map one isolated VRP \((\rho,a,m)\) to
\[
D=(v,\rho,m,a,\{\rho\mapsto(\{a\},\mathsf{closed})\}),
\]
so \(a_h=a\). This classification-only syntactic embedding maps conventional
Valid, Invalid, and NotFound to \(\mathsf{Explicit}\),
\(\mathsf{Invalid}\), and \(\mathsf{NotFound}\).

This theorem applies to the closed mapping.  It does not claim that adding an
open Stripe preserves conventional origin-specific protection inside that
open scope.

### Theorem 2: Unknown-delegate indistinguishability

For an unnamed eligible origin under open policy, the policy and BGP route
alone cannot distinguish an authorized delegate choice from an unauthorized
origin.  Therefore \(\mathsf{Delegated}\) cannot safely collapse into
\(\mathsf{Explicit}\) or conventional Valid.

## 7. Conservative Legacy Projection

The experimental reference format is not a standardized RPKI object profile.
If a deployment nevertheless needs a conservative conventional projection,
it may emit:

1. \((\rho,a_h,|\rho|)\) for exact aggregate self-authorization; and
2. \((q,a,|q|)\) for every explicitly named origin \(a\in E_q\), deduplicated
   by complete VRP tuple.

Open intent emits no VRP.

Under the structural invariants, every route Valid under this projection is
\(\mathsf{Explicit}\) under the original DA policy.  The projection is
deliberately incomplete: open descendants remain Invalid or NotFound on a
legacy router.  Using \(m\) rather than \(|\rho|\) for the base projection
would make holder-origin descendants Valid on a legacy router even when a
more-specific DA Stripe excludes the holder, violating this property.

## 8. Security Boundary

Closed policy retains origin-specific protection.  Open policy intentionally
transfers origin selection for proper descendants and therefore admits every
eligible public origin not blocked by a more-specific Stripe.  AS0/private
filters remove nonsensical inputs but do not restore origin authentication.

S2-ROV's security claim is thus:

- aggregate and closed-scope containment are deterministic;
- open-policy provenance is never hidden; and
- local enforcement may assign \(\mathsf{Delegated}\) a weaker action than
  \(\mathsf{Explicit}\).

It is **not**:

- open policy preserves ordinary ROV hijack rejection;
- relationship datasets authenticate the origin; or
- an eligible public ASN is “not a hijacker.”

Additional delegate attestations or path evidence could strengthen a
\(\mathsf{Delegated}\) route, but that evidence is outside this object.

## 9. Prototype and Standards Boundary

The current prototype uses a modified Krill/Routinator path to retain an
experimental signed attribute and an external policy process to enforce the
four states in FRR.  Standard RTR carries only ordinary VRPs; it does not
transport \(\mathsf{Delegated}\) provenance.  A standards proposal would need
a defined signed object profile, canonical overlap rules, transport encoding,
router behavior, and downgrade semantics.

The 14-byte header and variable-length Stripe encoding in DAROA-encoding are a
reference format for round-trip and structural tests, not an allocated RPKI
profile or a wire-compatibility claim.

## 10. DAROA encoding Requirements

- serialize one unique Stripe per prefix;
- preserve explicit-set and open-mode fields together;
- reject malformed/truncated/noncanonical inputs;
- enforce base, containment, length, ASN, and count invariants;
- implement longest-prefix lookup independent of Stripe count;
- test all four states before and after serialization;
- keep interpreter timings separate from prototype-system experiments; and
- avoid byte comparisons against unrelated ROA/CMS/RTR representations.
