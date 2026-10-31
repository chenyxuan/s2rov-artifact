# Dual-stack same-size policy update benchmark

Run: `policy-update-20260830T-formal-v1`  
Generated: 2026-08-30T09:01:43.145107Z

Each of the ten IPv4/IPv6-by-size cells contains twenty fresh worker
processes pinned to CPU 31.  Every worker begins with a same-size closed
policy and an Invalid fixed probe.  The timed update deserializes the accepted
open payload, replaces the active-policy pointer, and classifies that probe as
Delegated (`OpenScope`).

## Protocol

- Rules: 1, 64, 256, 1024, 4096
- Repetitions per cell: 20
- Worker records: 200
- Schedule: one seeded random permutation of all conditions
- All in-run gates pass: True

## Claim boundary

The results describe one single-process, single-core Python reference engine.
They exclude file acquisition, policy distribution, relying-party refresh, RTR,
router installation, forwarding, and end-to-end convergence.  IPv4/IPv6 values
are descriptive and do not establish address-family equivalence or causality.
