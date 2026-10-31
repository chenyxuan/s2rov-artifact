# Krill–Routinator–FRR End-to-End Testbed

This directory contains the reproducible Phase 6 prototype experiments.  The
main experiment starts a fresh, isolated RPKI repository and an eight-node BGP
topology without changing the older `testbed` and `routinator` containers.
Supplemental workflows use their own Docker networks, volumes, and container
prefixes.

## What is implemented

The experiment has two sequential lanes.

```text
Conventional lane
Krill → RRDP → Routinator → RFC 8210 RTR → FRR RPKI module
                                             ↓
                                    RPKI route maps

DA-aware lane
Krill → signed experimental OpenScope ROA → RRDP → Routinator
                                                        ↓ validated JSON API
validated DA policy + FRR Adj-RIB-In → four-state decisions → FRR route maps
```

The conventional lane is fully standard after the Krill signing operation:
Routinator exports an ordinary VRP and stock FRR 10.6.1 consumes it over RTR.
The baseline ROA is `10.0.0.0/16-24 => AS64501`; therefore each tested `/24`
is permitted by `maxLength` and remains Invalid only when its origin is not
named by a matching VRP.

The DA-aware lane is a research profile. The modified Krill build signs an
`inclusive` prefix field in a CMS-protected ROA object, and the modified
Routinator validates the certificate chain, manifest, CRL, and object before
exporting the field in its JSON output. The DA evaluation process interprets
`inclusive` only as an OpenScope marker. It checks all covering entries for an
explicit origin match before applying the unique proper-ancestor marker.
OpenScope markers must be pairwise prefix-disjoint; ordinary unmarked entries
may overlap them. The process evaluates live FRR routes and installs
per-neighbor policies:

| DA state | FRR action |
|---|---|
| `Explicit` | accept, local preference 300, community `65000:10` |
| `Delegated` | accept, local preference 200, community `65000:20` |
| `Invalid` | reject |
| `NotFound` | accept, local preference 100, community `65000:40` |

This is local-API enforcement, not a native four-state RTR extension. Stock FRR
disconnects when the experimental reserved RTR flag arrives; the experiment
records that result to demonstrate why `Delegated` cannot be sent as an
ordinary VRP.

## Route matrix

The BGP collector receives seven controlled routes:

| Case | Route | Expected baseline | Expected DA-ROV |
|---|---|---|---|
| Holder | `10.0.0.0/16 → AS64501` | Valid | Explicit |
| Listed customer | `10.0.1.0/24 → AS8075` | Invalid | Explicit |
| Intended delegate | `10.0.2.0/24 → AS18403` | Invalid | Delegated |
| Public-AS negative control | `10.0.3.0/24 → AS15169` | Invalid | Delegated |
| Aggregate attacker | `10.0.0.0/16 → AS13335` | Invalid | Invalid |
| Private origin | `10.0.4.0/24 → AS64513` | Invalid | Invalid |
| Unrelated route | `192.0.2.0/24 → AS64496` | NotFound | NotFound |

The public-AS negative control is intentionally `Delegated`. Open policy cannot
distinguish an unknown legitimate delegate from an arbitrary eligible public
origin. It is never reported as `Explicit` or conventional RPKI `Valid`.

## Run

Requirements are Docker, Bash, Python 3.10 or newer, OpenSSL, `jq`, and
`unzip`.
The current host does not provide Docker Compose, so the orchestrator uses
explicit, fixed-name `docker run` commands.

```bash
cd phase6_system/e2e
make test
make experiment
make scale
make scale-benefit-v4
make scale-benefit-v6
make churn
make staged
```

If the custom images are absent, `make images` rebuilds them from
`../dockerfiles/stripe-roa-system.zip`. The FRR image is pinned to
`quay.io/frrouting/frr:10.6.1`.

The experiment creates only resources prefixed with `daroa-e2e-`, plus the
Docker network `daroa-e2e` and volume `daroa-e2e-krill-data`. A random Krill
token is generated in memory for each run and is not written to the output.

```bash
make status  # inspect the isolated stack
make down    # remove containers and network; preserve the Krill lab volume
make clean   # also remove the dedicated Krill lab volume
```

## Output and acceptance criteria

Each run is immutable under `outputs/run-<UTC timestamp>/`; `outputs/latest`
points to the newest run. A passing run contains:

- `summary.json`, `summary.csv`, and `REPORT.md`;
- Routinator payload and status JSON for both lanes;
- FRR BGP summary, Loc-RIB, per-peer Adj-RIB-In, per-prefix details, RTR cache,
  and prefix-table JSON;
- generated DA decisions and exact FRR policy commands;
- publication, full-path update, and component-recovery timing;
- an explicit relying-party-outage policy-retention check.

By default the workflow runs 30 destructive Routinator restart/recovery
trials, 30 FRR restart/recovery trials, and 30 exact-entry remove/restore
cycles.  Each update trial ends only after the policy has been recompiled,
FRR has installed it, the target route has reached the expected local
preference, and the complete enforcement matrix passes.  Override with
`RECOVERY_TRIALS`, `FRR_RECOVERY_TRIALS`, or `UPDATE_TRIALS` only for local
debugging; paper results use the defaults.

`summary.json` is marked `passed: true` only if:

1. all seven baseline states match RFC 6811;
2. baseline FRR accepts/denies the correct paths with the expected preference;
3. all seven controlled routes are observed before DA policy;
4. all seven DA states match the four-state model;
5. DA-aware FRR enforcement and preferences match the decisions;
6. removing the unmarked exact `/24` changes its listed origin from `Explicit` to
   `Delegated` in the live FRR RIB;
7. restoring the unmarked exact `/24` changes it back to `Explicit`.
8. the installed policy remains enforced during the controlled relying-party
   outage;
9. Routinator and FRR restart trials recover the complete DA policy and pass
   the enforcement checks.

The paper's fixed-code run is `run-20260823T024129Z`: 124 enforcement
snapshots (868 route outcomes), 30 remove/restore cycles, 30 Routinator
restarts, and 30 FRR restarts all passed, as did the 15 s outage-retention
check. Median / nearest-rank p95 was 3.612 / 3.786 s for exact-entry removal,
3.668 / 3.873 s for restoration, 11.832 / 11.912 s for Routinator recovery,
and 7.925 / 7.994 s for FRR recovery. The run's `source.sha256` binds the
relevant harness, compiler, fixtures, and summarizer.
The current OpenScope-marker classifier changes that bound source, so a new
`make experiment` run is required before this fixed fixture can be accepted
under the revised semantics.

## Policy-scale experiment

The matched dual-stack policy-scale workflow is entered through
`make scale-benefit-v4` and `make scale-benefit-v6`.  Both commands use the
same single-live-route topology, stopping condition, and background-policy
levels: 0, 64, 256, and 1,024 noncovering rules.  At every level, the workflow
performs ten removals and ten restorations.  Each transition produces one
timing sample, one enforcement snapshot, and one live-route check.  Each IP
version therefore contributes 80 samples, 80 enforcement snapshots, and 80
route checks.

The measured path is Krill publication → RRDP → Routinator validation →
route-derived compiler → FRR installation → live-route check.  Passing runs
retain `policy-scale-samples.csv`, `policy-scale-payloads.csv`, per-transition
enforcement records, `summary.json`, `REPORT.md`, the protocol, and independent
audit results under an immutable `outputs/policy-scale-<version>-<UTC
timestamp>/` directory.

The accepted matched runs are
`policy-scale-ipv4-20260830T081349Z` and
`policy-scale-ipv6-20260830T081712Z`.  Both pass all 80 transitions, 80
enforcement snapshots, and 80 route checks.  These runs provide the matched
IPv4 and IPv6 policy-scale evidence used for the Figure 3 address-family
panels.

The earlier `scale-20260823T025539Z` run remains immutable historical evidence.
It is an IPv4-only experiment that checks the complete seven-route matrix after
each transition, yielding 80 samples, 80 enforcement snapshots, and 560 route
checks.  It no longer supplies the Figure 3 address-family panels.

## Origin-churn comparison

`make churn` starts an independent Krill--Routinator--FRR lab and alternates
`10.0.10.0/24` between AS8075 and AS18403.  Each route-first,
break-before-make handoff uses the same BGP speakers, collector, polling path,
and final-state assertion in both lanes:

- the exact-ROA lane first observes the new route as `Invalid`, then performs
  one atomic signed Krill transaction that removes the old origin and adds the
  new origin; and
- the DA lane retains one previously signed open policy, performs no signed
  authorization update during handoff, and accepts the new route as
  `Delegated` rather than `Explicit`.

The default retains 30 observations per lane.  Their execution order is 15
exact, 30 DA, and 15 exact transitions so the control spans both sides of the
DA block.  Setup publication is excluded from transition timing and update
counts.  The system path is real Krill signing, RRDP publication, Routinator
validation, live eBGP input, and FRR enforcement; Python only compiles already
validated DA decisions, checks captures, and summarizes them.

Routinator uses its two-second testbed refresh.  The churn collector uses
one-second RTR polling/retry; the harness queries FRR route state every 50 ms
and Routinator/RTR state every 100 ms.  New runs use a persistent
`time.monotonic_ns()` helper for interval timestamps; UTC wall time is metadata
only.  The retained 2026-08-04 run used GNU `date +%s%N` wall-clock values.  FRR
10.6.1 updates its RTR prefix table but does not automatically re-run the
inbound RPKI route map for the already received path in this build, so the
workflow issues a soft inbound re-evaluation after the RTR update and includes
it in exact-lane completion time.  Returning from the experimental flag to
standards-only RTR requires a collector restart; this occurs between lanes and
is excluded as setup.

Runs are immutable under `outputs/churn-<UTC timestamp>/`, with raw per-trial
Routinator and FRR JSON, `trials.csv`, timestamped `events.jsonl`,
`summary.json`, `summary.csv`, and `REPORT.md`.  `outputs/latest-churn` points
to the newest run.  The accepted 30+30 run is
`churn-20260804T030715Z`; all 60 trials passed.  It measured 30 versus zero
handoff-time signed transactions, median Invalid exposure of 3,021.660 versus
0 ms, and median unavailability of 3,265.471 versus 621.276 ms for exact ROAs
and the open DA policy, respectively.

```bash
make churn-smoke   # two retained transitions per lane for debugging only
make churn-controls-smoke  # one transition in each of four arms
make churn-controls        # default four-arm campaign, 30 transitions per arm
# accepted direction-balanced replication (40 per arm):
CONTROL_TRIALS=40 CONTROL_BLOCK_SIZE=4 CONTROL_RANDOM_SEED=20260823 \
  bash scripts/run-churn-controls.sh
make churn-status  # inspect the isolated daroa-churn-* stack
make churn-down    # remove churn containers/network; preserve volume and outputs
```

The complete protocol and interpretation boundary are in
`CHURN_EXPERIMENT_CONTRACT.md`.  In particular, this is a reactive laboratory
handoff.  Advance exact-ROA provisioning can avoid the measured Invalid
interval at the cost of additional authorization operations and temporary
multi-origin authorization.

The matched-control campaign adds BGP-only and prepublished-exact arms.  The
paper's accepted replication is `controls-20260823T022857Z`: ten complete
temporal rounds, four randomized arm blocks per round, and four alternating
trials per arm block.  It therefore contains 40 trials per arm, exactly 20 in
each direction.  Schedule, setup work, monotonic events, policy state, and
final actions are archived and fail closed.  The independent auditor
`src/audit_churn_controls.py` reconstructs results without reading generated
summaries or `REPORT.md`.  Outputs are immutable under
`outputs/controls-<UTC timestamp>/`.

## Staged-deployment experiment

`make staged` starts an independent three-hop transit topology and tests a
mixed deployment of legacy (`L`), shadow (`S`), and DA-enforcing (`D`) nodes.
The publisher retains two conventional exact VRPs for standards-only RTR
clients while adding the signed open policy.  A dedicated legacy-safe
Routinator validates all three objects and exposes the experimental policy in
its validated JSON API, but filters that policy from RTR.  Stock FRR therefore
receives exactly the two conventional VRPs and never receives a reserved RTR
flag.

The fixed sequence covers `LLL`, `SSS`, every one- and two-node enforcing
combination, and `DDD`, followed by rollback and policy withdrawal.  It checks
pre-policy Adj-RIB-In, post-policy Loc-RIB, relying-party connection and prefix
table, generated per-peer policy, and the final sink at every transit hop.  In
particular, a delegated route can cross the complete path only at `DDD`; mixed
paths retain the covering holder aggregate.  This result characterizes the
incremental-deployment boundary rather than claiming partial-path benefit.

The default then performs 30 `DDD` upgrades and 30 `LLL` rollbacks.  Each of
the 60 observations has its own immutable directory containing all per-hop raw
JSON and exact route-map output.  Runs are stored under
`outputs/staged-<UTC timestamp>/`; `outputs/latest-staged` points to the newest
run.  `summary.json` is passing only when all stage assertions and all
transition observations pass.

The paper's fixed-code run is `staged-20260823T024131Z`: all 12 stages, 213
per-hop assertions, and 60 transition observations passed. Median / nearest-
rank p95 was 8.125 / 8.255 s for rollback to LLL and 9.198 / 9.378 s for
upgrade to DDD. Its `source.sha256` verifies the complete staged harness,
policy compiler, fixtures, and summarizer used by the run.

```bash
make staged-smoke   # one rollback and one upgrade for debugging only
make staged-status  # inspect the isolated daroa-staged-* stack
make staged-down    # remove staged containers/network; preserve volume and outputs
make staged-clean   # also remove the dedicated staged Krill volume
```

## Scope boundary

This prototype provides real signing, repository publication, relying-party
validation, live BGP input, and FRR enforcement. It does not define a production
DA-ROA OID/profile, capability-negotiated RTR PDU, or native FRR
`match da-rov delegated` command. Those require standards work and coordinated
changes to the CA, relying party, RTR library, and router.
