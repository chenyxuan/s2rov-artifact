# Publication Polish Check

Date: 2026-08-30

Verdict: **PASS** for the current double-blind review manuscript.

## Prose and terminology

- The manuscript uses `ROA` consistently and does not introduce `VRP` as a
  competing reader-facing term.
- The aggregate/base prefix is written as \(p_0\), while \(p\) denotes the
  route prefix under evaluation.
- `OpenScope`, `Explicit`, `Invalid`, and `NotFound` retain distinct meanings.
  `OpenScope` is never presented as conventional validity or origin
  authentication.
- Visibility is described without the discarded `upstream visibility` label.
- Targeted source searches found no `ROA authorization(s)`, `Snapshot`, raw
  Unicode em dash, unresolved TODO marker, or placeholder citation.

## Experimental presentation

- Section V has three parallel, question-led subsections: Potential Conflict
  Reduction; System Cost and Live-Path Controls; and Routing Benefit and
  Exposure.
- Correctness evidence is compressed into the Section V opening and explicitly
  labeled a prerequisite.
- Every active quantitative display has one clear role: Figure 2 shows
  remaining candidate conflicts under partial policy deployment, Figure 3
  compares IPv4 and IPv6 selected-policy processing cost, and Figure 4
  separates routing benefit from exposure.
- Units and inferential bases are stated where needed: exact-endpoint target,
  six OpenScope placement levels, remaining-candidate count, and rollout
  percentile range for Figure 2;
  milliseconds and thousand pairs/s for Figure 3; and percentage-point changes
  with interval type for Figure 4.
- Captions describe what each panel or table contains without repeating the
  entire result paragraph.

## Cross-section consistency

- The Introduction's three contributions correspond to the formal result,
  classifier design, and three-layer evaluation.
- Implementation describes only capabilities exercised by the evidence and
  explicitly limits full relying-party behavior, composition, native transport,
  and the IPv6 end-to-end transport path.
- Evaluation, Discussion, and Conclusion repeat the same controlled-stack and
  fixed-model boundaries.
- The intended-only and competition lanes are never merged into a single
  tradeoff estimate.

## Typesetting

- The final PDF is 8 US-Letter pages with embedded fonts and no Type 3 fonts.
- No error, undefined reference/citation, or overfull box appears in the build
  log.
- Four underfull notices are visually non-blocking.
- All eight pages were inspected; active figures and Table I are readable
  without clipping or collision.

No publication-polish issue currently blocks review submission. The separate
anonymous-artifact sanitization gate remains outside this prose/typesetting
verdict.
