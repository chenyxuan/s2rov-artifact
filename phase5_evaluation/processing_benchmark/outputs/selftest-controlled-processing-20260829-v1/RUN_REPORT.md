# Controlled dual-stack policy processing run

Run: `selftest-controlled-processing-20260829-v1`  
Generated: 2026-08-29T11:51:31.282460Z

The run separates in-memory policy loading from steady-state classification.
Each address family reuses one fixed 8,192-pair RRC00 query set at every policy
size.  All timed classifications return the internal `Delegated` state, which
corresponds to `OpenScope` in the manuscript.

## Configuration

- Subprefix entries: 0, 2
- Load repetitions per cell: 1
- Classification repetitions per cell: 1
- Timed calls per classification worker: 32
- Warm-up calls per classification worker: 32
- CPU: 31

## Result gate

- All scheduled worker records present: True
- All workers pinned to CPU 31: True
- All policy round trips byte-identical: True
- Every timed result is OpenScope: True
- All gates pass: True

## Claim boundary

The measurements describe one single-process, single-core Python reference
implementation with one already selected policy.  They do not measure a
relying party, RTR transfer, FRR installation, forwarding, or line rate.
