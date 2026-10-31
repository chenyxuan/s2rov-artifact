# Origin-churn prototype experiment contract

## Claim under test

When a legitimate `/24` moves between two eligible public origin ASes after
the routing change is observed, a conventional exact-origin ROA requires a
new signed authorization before reject-Invalid enforcement restores the
route.  A previously signed open DA policy requires no authorization update
and retains the new route as `Delegated`, while never calling it `Explicit`.

## Prototype path

Both lanes use the same live path and the same two origin speakers:

```text
Krill signing -> RRDP repository -> Routinator validation
                                         |
origin A/B -> eBGP -> FRR Adj-RIB-In -> policy -> FRR Loc-RIB
```

The conventional lane uses Routinator's RFC 8210 RTR output and FRR's native
`match rpki` enforcement.  The DA lane uses Routinator's validated JSON output
and the existing DA policy compiler to install per-neighbor FRR route maps.
Python is not a system under test; it only compiles already validated DA
states, checks captured FRR JSON, and summarizes observations.

Routinator runs with its testbed `--refresh 2` setting.  The churn-specific
FRR collector uses one-second RTR polling and retry intervals.  The harness
queries FRR route state every 50 ms and Routinator/RTR state every 100 ms.
New runs compute intervals from `time.monotonic_ns()` values served by one
persistent helper process and record UTC wall time only as event metadata.  The
2026-08-04 historical two-arm run instead used GNU `date +%s%N` POSIX wall-clock values;
its retained event field is a historical misnomer and is not rewritten.  After an exact VRP appears in
FRR's live RTR prefix table, the orchestrator issues
`clear bgp ipv4 unicast * soft in`: FRR 10.6.1 updates the prefix table but did
not re-run the inbound RPKI route map for an already received path in this
testbed.  The soft re-evaluation is part of the exact lane's measured
end-to-end interval.  When returning from an experimental open policy to an
exact-only block, the collector is restarted during unmeasured lane setup
because stock FRR closes the RTR session on the experimental reserved flag.

## Experimental unit and fair protocol

The route is `10.0.10.0/24`; AS8075 and AS18403 alternate as origin.  Each
recorded transition is break-before-make:

1. withdraw the currently accepted route and wait until it leaves FRR;
2. announce the same `/24` from the other origin and wait until it appears in
   that neighbor's live FRR Adj-RIB-In;
3. in the exact lane, verify that Routinator evaluates the new origin as
   `Invalid` and FRR rejects it, then atomically replace the exact ROA in
   Krill; in the DA lane, leave the signed open policy unchanged;
4. stop only when the expected origin, semantic state, local preference, and
   action are present in the live FRR Loc-RIB.

The topology, prefix, origins, BGP commands, polling code, and stop condition
are identical across lanes.  Setup publication is excluded from transition
timings and per-transition update counts.  By default all 30 trials per lane
are retained.  Execution is sandwiched as 15 exact, 30 DA, and 15 exact trials
so the conventional control spans both sides of the DA block; block and global
order are recorded for an order-effect audit.

## Outcomes and acceptance criteria

Each raw trial records:

- signed update transactions and authorization-entry changes;
- new-route `Invalid` exposure and FRR unavailability;
- switch request to verified final state;
- final relying-party state, FRR action, local preference, and origin;
- timestamped event records plus the relevant Routinator and FRR JSON.

Every exact transition must issue one atomic signed update transaction (remove
old and add new), show `Invalid` before that update, and finish `Valid` and
accepted at local preference 300.  Every DA transition must issue zero signed
updates, finish `Delegated` and accepted at local preference 200, and keep the
same open-policy digest throughout the DA block.  The workflow stops on the
first failed trial and does not silently retry it.

## Interpretation boundary

This is a reactive, controlled handoff: the new origin is not known in advance.
An operator with advance knowledge can overlap two exact ROAs and avoid the
Invalid interval, at the cost of additional signed authorization operations
and broader temporary authorization.  The experiment does not measure
Internet propagation, large-RIB throughput, concurrent updates, or native
four-state RTR support.  `Delegated` expresses holder-defined scope, not the
identity of a particular downstream operator; both eligible origins therefore
remain weak-provenance routes.

## Matched four-arm control campaign

`run-churn-controls.sh` retains the same topology, prefix, origins, BGP
operations, polling path, and live-state stopping rules while adding two
controls.  The BGP-only arm removes inbound RPKI policy and relevant signed
objects; the prepublished-exact arm publishes exact ROAs for both candidate
origins before timing begins.  Ten randomized complete-block rounds contain
one three-trial block per arm, for 30 retained trials per arm.  The paper's
accepted replication, `controls-20260823T022857Z`, overrides this with four
alternating trials per arm block: 40 trials per arm, exactly 20 in each
direction, and 160 total. Policy setup is
archived but excluded from handoff timing.  The campaign uses a declared
deterministic seed and monotonic timestamps; all four arms must pass
final-state and no-update assertions before their summaries are accepted.  An
unrelated `10.255.255.0/24 => AS64501` exact ROA remains fixed in every arm so
the test CA always publishes a nonempty manifest; it neither covers nor changes
the measured `10.0.10.0/24` route.
