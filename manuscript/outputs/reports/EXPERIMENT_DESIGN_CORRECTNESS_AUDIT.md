# Experiment Design Correctness Audit

> Superseded for active Figure 2 on 2026-08-30. The partial-policy statements
> below describe the retired family-specific view; the pooled v2 replay has its
> own 10-test gate and provenance record.

Date: 2026-08-29

Result: PASS for the claims retained in the manuscript.

## Partial-policy replay

- One retained candidate-path row is the analysis unit. IPv4 and IPv6 use
  separate 504-path/83-root and 83-path/14-root frames.
- An exact decision covers one endpoint path and its complete observed origin
  set. A root-scope decision covers all retained candidate paths below that
  root. The primary analysis fixes the root-scope target at 10% and varies the
  exact-endpoint target (q); integer selection gives 8/83 IPv4 roots and
  1/14 IPv6 roots. The equal-decision comparison remains a secondary artifact
  and does not equate the two percentage denominators.
- The exact-by-scope grid covers 0% through 100% in 10% increments. The random analysis uses 1,000 fixed
  nested rollout orders; fanout-first and fanout-last orders expose placement
  sensitivity. Its displayed 5th--95th ranges are rollout percentiles, not
  confidence intervals.
- Every root starts with a matching aggregate ROA in the counterfactual. The
  result measures candidates remaining in the frozen frame, not deployed ROAs,
  issuer knowledge, route legitimacy, or actual ROV-conflict prevalence.

## Matched handoff

- All three workflows consume live post-observation Adj-RIB-In data and share
  the classifier, compiler, FRR installation, and probe path.
- The preinstalled-scope policy and pretrial action map contain neither
  endpoint origin.
- The inferential unit is the complete randomized round within each IP-version
  lane, not the 40 individual handoffs in each arm. Ten complete rounds are
  retained per lane.
- All 240 scheduled handoffs completed across the two lanes; no failure
  filtering or imputation was used. The IPv6 lane uses an independent
  dual-stack policy model rather than the full IPv4 transport stack.

## Processing replay

- IPv4 and IPv6 policies and queries are deterministically constructed from
  retained RRC00 scalar-origin inputs.
- Every policy contains one open base entry plus 0, 64, or 256 additional
  subprefix entries. The reported count excludes the base.
- Within each IP version, all sizes reuse one fixed 8,192-query set and every
  timed result is OpenScope. Query hashes, result hashes, and state vectors
  are therefore held constant while policy size changes.
- Load and classify scopes use separate fresh workers, fixed CPU affinity,
  deterministic schedules, and warm-up. Load has 20 repetitions per cell;
  classify has five, with 131,072 timed calls per worker.
- File input is excluded from load. CIDR parsing and state capture are included
  in classification.
- This is a host-specific in-process benchmark and has no population-level
  statistical inference.

## Routing model

- Intended delivery and unlisted-origin exposure are evaluated in different
  announcement sets with announcement-matched baselines.
- Panel (a) retains its finite-frame interval; panel (b) uses the corrected
  selected-unit stability interval. Both are pointwise.
- The panels are reported as separate conditional questions, not a same-run
  joint frontier or an Internet estimate.
