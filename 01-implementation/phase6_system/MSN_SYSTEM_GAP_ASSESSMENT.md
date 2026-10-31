# MSN 2026 System Gap Assessment

**Audit date:** 2026-07-29
**Submission deadline:** 2026-08-20 AoE
**Decision:** Completed the stock Krill → Routinator → RTR → FRR baseline and
DA-aware local-API enforcement. Native four-state RTR remains deferred.

**Completion update (2026-07-29):** all L2/L3 acceptance checks pass in
`e2e/outputs/latest/summary.json`.

## 1. What exists today

| Level | Capability | Evidence | Status |
|---|---|---|:---:|
| L0 | DA-ROV encoder and four-state reference validator | Phase 4/5 Python tests | Done |
| L1 | Krill publishes a conventional ROA; Routinator reproduces RFC 6811 conflict | Historical 2026-07-06 commands and notes | Previously demonstrated |
| L2 | Routinator exports VRPs over RTR to FRR; FRR classifies real BGP updates | `e2e/outputs/latest/baseline/` | Done |
| L3 | Live FRR routes are evaluated and enforced through the DA local API | `e2e/outputs/latest/da/` | Done |
| L4 | Standardized native DA object, negotiated RTR transport, and native FRR state | Requires standards and coordinated component changes | Deferred |

The older running environment was not reproducible:

- `testbed` (Krill 0.14.4) and `routinator` (0.13.2) containers are running.
- The repository stopped refreshing on 2026-07-24.
- Routinator reports an expired manifest certificate, zero valid ROAs, zero
  VRPs, and zero RTR connections.
- Both the holder route and delegated customer route currently return
  `not-found`, rather than the historical `valid`/`invalid` results.
- There is no FRR binary, image, container, configuration, or captured output.

The replacement `e2e/` artifact starts from a fresh dedicated volume and does
not inherit this stale state.

## 2. Recommendation

### Completed for the MSN submission

Build a deterministic **standard RPKI baseline**:

```text
Krill CA/repository
  → RRDP
  → Routinator validation
  → RFC 8210 RTR
  → FRR RPKI cache
  → BGP route-map decision
```

This closes the mismatch between the architecture figure and the artifact. It
also gives the paper defensible evidence that the semantic conflict survives
all the way to router policy.

Minimum acceptance criteria:

1. One command creates a fresh Docker network and all containers.
2. Krill issues the holder ROA and serves a fresh manifest and RRDP snapshot.
3. Routinator exports exactly the expected VRP and has one live RTR client.
4. FRR receives the VRP and classifies:
   - holder aggregate as `valid`;
   - competing aggregate as `invalid`;
   - delegated customer sub-prefix as `invalid`;
   - unrelated prefix as `notfound`.
5. A route-map produces observable, distinct policy actions for the three
   standard states.
6. Machine-readable logs and CSV results are regenerated from a clean start.

### Completed beyond shadow mode

The **DA-ROV local-API process** first audits live FRR input and then installs
observable route maps:

```text
validated DA policy + FRR Adj-RIB-In → Explicit/Delegated/Invalid/NotFound
                                      ↓
                         FRR preference/community/filter
```

The passing run shows the delegated route is Invalid in stock FRR but
`Delegated` under DA-ROV, while the competing aggregate and private origin are
rejected. It also includes the required public-AS negative control, which is
`Delegated` because open policy cannot authenticate an unknown relationship.

### Defer until after MSN 2026

Do not attempt a native four-state production implementation across Krill,
Routinator, RTR, and FRR for this deadline. `Delegated` cannot be represented
by the current three-state router interface. A sound implementation would need:

- an RPKI object content type and CMS/profile work in the CA;
- object parsing, certificate/resource validation, and policy evaluation in the
  relying party;
- negotiated RTR/API payload semantics and backward compatibility;
- a new router state, route-map match, CLI, telemetry, and cache behavior;
- update, withdrawal, stale-cache, downgrade, and mixed-deployment tests.

A shortcut that maps `Delegated` to an ordinary VRP would incorrectly present
delegation policy as origin authentication and would undermine the paper's main
security distinction.

## 3. Experiments to add

| Experiment | Repetitions | Primary outputs | Priority |
|---|---:|---|:---:|
| Correctness matrix across Krill, Routinator, and FRR | 7 deterministic cases | per-route state and FRR action | Done |
| Closed-Stripe add/remove convergence | 30 cycles | RP median/p95 latency | Done |
| RTR disconnect/reconnect | 5 restarts | recovery median/p95 | Done |
| DA policy evaluation and FRR enforcement | 7 live routes | local preference, community, filtering | Done |
| Lookup under 1–4,096 Stripes | existing scale points | reference-validator latency | Done |

## 4. Engineering work estimate

| Work package | Expected effort | Risk |
|---|---:|:---:|
| Repair Krill freshness and make startup deterministic | 1–2 days | Medium |
| Add FRR with RPKI support and BGP speakers | 1–2 days | Medium |
| Automated correctness and convergence collection | 1–2 days | Low |
| DA shadow-mode route collector and comparison | 2–4 days | Medium |
| Native DA-aware Krill + Routinator + RTR + FRR | 2–4+ weeks | High |

The recommended L2+L3 scope is feasible before submission if started
immediately. Native L4 integration is not on the critical path for an MSN paper
whose claims remain explicitly limited to a reference implementation and
incremental deployment design.

## 5. Paper-claim boundary

Until L2 is complete, the manuscript should say only that Krill and Routinator
reproduce the RFC 6811 conflict. After L2 and L3 pass, it may additionally
claim:

> A containerized Krill–Routinator–FRR testbed reproduces the conventional
> router decision, while a non-enforcing DA-ROV sidecar reclassifies the
> intended delegated route without accepting the aggregate hijack.

It must not claim native DA-aware RTR or router enforcement unless L4 is
actually implemented and evaluated.

## 6. Relevant implementation documentation

- FRR RPKI configuration:
  <https://docs.frrouting.org/en/latest/bgp.html>
- Routinator RTR service:
  <https://routinator.docs.nlnetlabs.nl/en/latest/rtr-service.html>
- Krill documentation:
  <https://krill.docs.nlnetlabs.nl/>
