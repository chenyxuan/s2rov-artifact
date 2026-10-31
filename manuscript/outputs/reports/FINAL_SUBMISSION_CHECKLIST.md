# Final Submission Checklist

Date: 2026-08-30

## Review-manuscript gate

- [x] The locked title and protected Introduction paragraphs are preserved.
- [x] The author block and PDF author metadata remain anonymous.
- [x] The review manuscript intentionally omits Abstract and Keywords blocks.
- [x] The PDF is 8 US-Letter pages.
- [x] The PDF compiles without LaTeX errors, undefined citations, undefined
  references, overfull boxes, or Type 3 fonts.
- [x] All eight pages were visually inspected. Figures, Table I,
  equations, captions, and references are readable and do not collide.
- [x] Fig. 2 pools IPv4 and IPv6 candidate paths and compares six OpenScope
  deployment levels across ROA issuance rates. It reports rollout medians as
  counterfactual counts, not actual ROV-conflict prevalence.
- [x] Fig. 3 uses grouped bars to compare bounded single-core controlled IPv4
  and IPv6 policy loading and classification; it does not imply router or
  relying-party throughput.
- [x] Fig. 4 separates intended-only delivery from the distinct
  origin-competition exposure setting.
- [x] The Section V-B handoff comparison uses ten randomized complete rounds
  within each IP-version lane and traces to both accepted 120-handoff runs.
- [x] Claims are scoped to the frozen candidate frame, controlled workflow,
  selected-policy replay, and fixed routing model. No actual conflict
  prevalence, equivalence, line-rate, native-router, or Internet-wide benefit
  claim is made.
- [x] Targeted searches found no unresolved `AUTHOR_TODO`, `TBD`, `FIXME`, or
  placeholder citation in the manuscript sources.

Current review PDF SHA-256:
`1cad05ca4b5eba9f595ef101940bcb516a5926f29ebc81d010af9fbf9f5035ff`.

## Anonymous supplementary-artifact gate

- [ ] **Do not upload the current raw `phase*` directories.** They contain
  absolute local paths and host, user, environment, worktree, or Git metadata.
- [ ] Create a fresh identity-scrubbed bundle containing only the code, inputs,
  outputs, manifests, and documentation needed for the manuscript claims.
- [ ] Generate a new bundle-level checksum manifest after sanitization. Keep
  the original author-side hashes as a private provenance mapping rather than
  claiming that modified metadata files retain their old hashes.
- [ ] Rebuild the bundle in a clean neutral path and rerun the classifier,
  figure, benchmark-recomputation, manuscript-build, and identity-leak checks.
- [ ] Include the Phase 9 competition overlay and explain that the two Fig. 4
  panels use different announcement sets.
- [ ] Include the accepted dual-stack processing run, retained table CSV,
  independent audit, Fig. 3 builder and manifest, and both panel products.
- [ ] Include the Figure 2 candidate input, replay script, manifest, generated
  source tables, and the active pooled figure files.
- [ ] Label the 589-AS list as an opaque fixed scenario input, not a measured
  deployment estimate.

## Venue-side checks

- [ ] Confirm whether the double-blind submission system permits a separate
  anonymous artifact upload.
- [ ] Restore and verify author, affiliation, and submission metadata only
  after the venue's double-blind stage permits it.
- [ ] Repeat publisher-level reference metadata verification if `refs.bib`
  changes.
- [ ] Overleaf synchronization was not requested and was not performed.

Release decision: **the review PDF passes the local submission gate; an
anonymous supplementary artifact remains on hold until the sanitization and
clean-room checks above are completed.**
