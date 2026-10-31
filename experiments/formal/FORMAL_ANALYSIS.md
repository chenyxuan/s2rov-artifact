# Formal statements: Formal Analysis of the ROV Policy Gap

**Version:** 2.0
**Re-audited:** 2026-07-29
**Status:** aligned with the four-state S2-ROV manuscript

## 1. ROV Preliminaries

Let \(\mathcal P\) be the set of IP prefixes and \(\mathcal A\) the set of
ASNs.  Write \(p\sqsubseteq \rho\) when route prefix \(p\) is equal to or more
specific than \(\rho\).  A BGP route is \((p,a)\).

A validated ROA payload (VRP) is

\[
v=(\rho,a_v,m_v)\in\mathcal P\times\mathcal A\times\mathbb N,
\]

where \(\rho\) is the authorized prefix, \(a_v\) the named origin, and
\(|\rho|\le m_v\le 32\).

For a VRP set \(R\), define:

\[
C_R(p)=\{(\rho,a_v,m_v)\in R:p\sqsubseteq\rho\},
\]

\[
M_R(p,a)=\{(\rho,a_v,m_v)\in C_R(p):
            a=a_v\land |p|\le m_v\}.
\]

The RFC 6811/8481 validation state is then

\[
\mathsf{ROV}_R(p,a)=
\begin{cases}
\mathsf{Valid},&M_R(p,a)\ne\varnothing,\\
\mathsf{Invalid},&M_R(p,a)=\varnothing\land C_R(p)\ne\varnothing,\\
\mathsf{NotFound},&C_R(p)=\varnothing.
\end{cases}
\]

This form matters because one nonmatching covering VRP does not make a route
Invalid when another covering VRP matches.

## 2. Positive Authorization and Negative Consequence

A VRP explicitly states a positive fact: the named AS may originate the
covered route lengths.  The validation algorithm also gives it a negative
consequence: once a route is covered, an unnamed origin is Invalid unless some
other VRP matches.

The negative consequence is often exactly what the holder wants.  The policy
gap arises only when the holder wants to protect its aggregate origin while
transferring origin selection for a descendant.

### Definition 1: Origin-choice delegation

Holder \(h\) delegates origin choice for descendant prefix \(p\sqsubset\rho\)
when it authorizes a delegate to select the current origin of \(p\) without
requiring that origin to be enumerated in the holder's policy.

This definition is an intended policy, not something a validator may infer
from WHOIS, BGP, or relationship labels.

## 3. Minimal-ROA Delegation Conflict

### Theorem 1

There exists a holder–delegate configuration in which a minimal holder-origin
VRP makes a legitimately delegated route Invalid.

### Proof

Let holder \(h\) control \(\rho\), originate it from \(a_h\), and publish

\[
R_h=\{(\rho,a_h,|\rho|)\}.
\]

Let a delegate legitimately originate a proper descendant
\((p,a_d)\), where \(p\sqsubset\rho\) and \(a_d\ne a_h\).  The VRP covers
\(p\), so \(C_{R_h}(p)\ne\varnothing\).  It cannot match: both the origin
differs and, for a proper descendant, \(|p|>|\rho|\).  If no other VRP matches
\((p,a_d)\), then \(M_{R_h}(p,a_d)=\varnothing\), and the route is Invalid.
\(\square\)

### Boundary of the theorem

The theorem is existential and conditional.  It does not imply that every
different descendant origin is legitimate.  A more-specific VRP naming
\(a_d\) resolves this particular route and is the preferred solution when the
holder can and wishes to enumerate the origin.

### Corollary 1

Increasing \(m_v\) alone does not authorize a different AS.  For
\((\rho,a_h,m_v)\), a descendant from \(a_d\ne a_h\) remains nonmatching even
when \(|p|\le m_v\).

## 4. Expressiveness Result

Consider the desired policy:

1. only \(a_h\) may originate the aggregate \(\rho\);
2. origins in explicit descendant exceptions remain named;
3. origin choice for selected proper descendants is delegated; and
4. enforcement can distinguish named authorization from delegated choice.

Conventional VRPs can express items 1 and 2.  They cannot express item 3
without naming an origin, and their three-state result cannot expose item 4.
Omitting the aggregate VRP avoids the conflict but removes the positive
aggregate authorization.  A broad `maxLength` still names the same origin.
Unsigned local exceptions are not holder-authenticated policy.

The resulting design requirements are:

- **R1 — exact aggregate protection:** opening descendant policy must not open
  the aggregate itself;
- **R2 — scoped delegation:** delegation applies only to proper descendants of
  the selected prefix;
- **R3 — precedence:** a more-specific rule can close or enumerate part of a
  broader open region; and
- **R4 — provenance:** the result distinguishes explicit origin evidence from
  open holder policy.

## 5. Authorization Impossibility

### Theorem 2: Unknown-delegate indistinguishability

Given only (i) a signed holder policy that delegates origin choice below
\(q\), and (ii) a BGP route \((p,a)\) whose origin is not named by that policy,
a validator cannot determine whether \(a\) was selected by an authorized
delegate.

### Proof

Construct two worlds with the same signed holder policy and the same observed
route.  In world \(W_1\), an authorized delegate selected \(a\).  In world
\(W_2\), \(a\) originated the route without permission.  The validator's
inputs are identical, so every deterministic validator returns the same
result in both worlds.  The distinguishing fact is an additional
delegate-origin authorization absent from the inputs. \(\square\)

Consequently, an open-policy match must not be reported as ordinary
\(\mathsf{Valid}\).  The semantics needs a separate result whose weaker
provenance remains visible.

## 6. Empirical Grounding

The RIPE/RouteViews analysis is a strict counterfactual.  After excluding the
`0.0.0.0/0` artifact, it contains 3,929,262 root–leaf pairs.  Of 3,441,429
pairs with exact-CIDR endpoints, 24,663 have exact BGP routes at both
endpoints, and 8,830 have non-empty, disjoint origin sets.

These 8,830 rows locate observable origin divergence.  They do not prove
delegation, legitimacy, current ROA state, or an active Invalid route.  The
formal result supplies an expressible policy for a holder; the measurement
does not infer that policy for the holder.

The NDSS 2026 artifact reanalysis is kept separate.  Its relationship/cause
labels are prior-work evidence and are not used as authorization ground truth.

## 7. Handoff to classifier-semantics

Classifier-semantics must define at least four states:

- \(\mathsf{Explicit}\): the selected policy names the route origin;
- \(\mathsf{Delegated}\): an open policy covers a proper descendant but does
  not name its origin;
- \(\mathsf{Invalid}\): policy covers the route and no permitted branch holds;
- \(\mathsf{NotFound}\): no DA policy covers the route.

The security target is not “open policy blocks every hijack.”  Theorem 2 shows
that this is impossible without additional evidence.  The correct target is
scope containment plus provenance preservation: aggregate and closed regions
remain origin-specific, while open matches are visibly weaker.

## 8. Limitations

The analysis does not formalize operator contracts, path authorization, or
revocation workflows.  It does not claim that per-customer ROAs are
impossible or irrational; exact ROAs remain stronger when origins are known.
It also does not derive security from public-AS eligibility filters.  Such
filters reject nonsensical values but cannot authenticate a delegate.
