# Prototype-system experiment contract

## Claim under test

The complete Krill–Routinator–FRR prototype carries signed policy changes to
the expected live routing state, preserves correctness as noncovering signed
policy grows, restores the state after control-plane component restarts, and
tests how exact and open policies respond to reactive origin churn.

## Experimental units and outcomes

- Thirty closed-Stripe removal/restoration cycles. The clock starts before the
  Krill update and stops only after Routinator validation, local policy
  compilation, FRR policy installation, the expected customer-route local
  preference, and a complete enforcement check.
- Thirty Routinator restart trials. The clock stops after validated policy is
  available again and the workflow has restored and verified DA enforcement in
  FRR.
- Thirty FRR collector restart trials. The clock stops after all seven BGP
  routes return and the workflow has restored and verified DA enforcement.
- One 15-second Routinator outage test checks whether the last installed FRR
  policy remains in force while the relying party is unavailable.
- One policy-scale run adds 0, 64, 256, or 1,024 noncovering closed /26
  Stripes.  At each level it performs ten closed-child removals and ten
  restorations, giving 80 transition-level experimental units.  Each unit
  spans signed Krill publication, Routinator validation, controller evaluation
  and installation, and the complete seven-route FRR check.
- Thirty exact-ROA and thirty open-policy origin transitions alternate the same
  `/24` between AS8075 and AS18403.  The exact lane performs one atomic signed
  authorization replacement per transition; the DA lane leaves one validated
  open policy unchanged.  The order is 15 exact, 30 DA, and 15 exact trials.
- One three-hop staged-deployment matrix covers legacy (`L`), shadow (`S`),
  and enforcing (`D`) nodes: `LLL`, `SSS`, all one- and two-node enforcing
  combinations, and `DDD`, followed by rollback and signed-policy withdrawal.
  Thirty additional rollback/upgrade cycles give 60 transition observations.

## Controls and success criteria

- The conventional lane publishes `10.0.0.0/16-24 => AS64501` and must
  reproduce the seven specified RFC 6811 outcomes.  Its `/24` controls are
  length-admissible, so their Invalid state isolates the unnamed-origin
  conflict rather than a `maxLength` violation.
- The DA lane must reproduce all seven four-state outcomes and their configured
  FRR actions.
- Every timing trial is retained. A trial succeeds only if the changed child
  reaches its target semantic state, the other six routes retain their expected
  states, and the seven-route presence/preference enforcement checker passes;
  the workflow exits on the first failed trial and does not silently retry it.
- The arbitrary eligible public-origin route remains `Delegated`, not
  `Explicit`; this is a security-boundary control rather than a success case
  for delegate authentication.
- Scale background Stripes use an isolated range and cannot cover any of the
  seven live routes.  The workflow removes them on completion or interruption
  and verifies one enforcement snapshot per transition.
- Every churn transition withdraws the old route before announcing the new
  origin.  The exact lane must capture `Invalid` plus FRR rejection before the
  Krill update, then finish `Valid` and accepted at local preference 300.  The
  DA lane must perform zero handoff-time signed updates, preserve a single open
  policy digest, and finish `Delegated` and accepted at local preference 200.
  Both lanes use the same topology, BGP commands, and final-state stop rule.
- The staged-deployment lane retains conventional exact fallback VRPs during
  dual publication.  Its legacy-safe relying party must expose the signed open
  policy through validated JSON while exporting exactly the two conventional
  VRPs over RTR.  Each transit node must have a connected RTR cache and the
  expected pre-policy Adj-RIB-In and post-policy Loc-RIB.  The delegated route
  must reach the sink only for `DDD`; all mixed patterns must retain the
  covering holder aggregate.  Every rollback and upgrade observation must pass
  the same per-hop assertions, with no silent retry.

## Reporting

Report all observations.  For 30-trial conditions, report median and
nearest-rank p95; for ten-trial scale cells, report median and maximum because
nearest-rank p95 equals the maximum.  Do not apply an inferential test to these
deterministic, sequential laboratory trials. Do not
extrapolate the results to Internet propagation, line-rate router throughput,
native RTR support, or large-RIB scalability.  Report the scale run as
signed-policy-input sensitivity: the live route count is fixed at seven, so it
does not measure route-table scale, memory cost, or concurrent-update load.
For origin churn, report signed transactions and authorization-entry changes,
Invalid exposure, route unavailability, end-to-end completion, and final
state/action.  The exact path additionally separates signed request to
Routinator validation, validation to FRR's RTR table, and RTR table to verified
enforcement.  The required FRR soft inbound re-evaluation is included in the
last interval.  Treat advance exact-ROA provisioning and Internet-scale
propagation as out of scope.  `CHURN_EXPERIMENT_CONTRACT.md` is the normative
churn protocol.  For staged deployment, report the complete capability matrix,
all 60 observations, median and nearest-rank p95 separately for rollback and
upgrade, and retain every per-hop raw capture.  Interpret `DDD`-only delegated
reachability as a deployment constraint; do not present shadow or mixed paths
as providing end-to-end DA enforcement.
