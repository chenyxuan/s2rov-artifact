# Post-Repair Narrative Review

Date: 2026-08-30

## Overall judgment

Verdict: **PASS**. The revised paper first asks how much of the frozen
potential-conflict candidate set partial OpenScope policy can cover before every
endpoint receives exact ROAs. It then addresses system cost and routing
consequences. Correctness remains a prerequisite rather than the principal
experimental result.

## Reader-facing argument

1. Section II-A characterizes the aggregate--subprefix conflict, while
   Section II-B connects it to visibility limits and compatible RIPE
   Database/RIS structure.
2. Section II-C turns that problem into two concrete requirements. Sections
   III and IV then define the classifier and the controlled execution path.
3. The opening of Section V compresses semantic agreement, malformed-input
   rejection, fixture-action checks, and deterministic reproduction into one
   correctness gate.
4. Section V-A gives the partial-deployment payoff. Figure 2 fixes the
   compares six OpenScope placement levels across matching-ROA issuance, and reports the
   potential conflicts remaining in the retained IPv4 and IPv6 candidate
   frames. Random and fanout-ordered curves expose placement sensitivity.
5. Section V-B combines the matched handoff, controlled dual-stack fixed-output
   replay, grouped IPv4/IPv6 bars in Fig. 3, live-path scale controls, and
   outage control. The handoff evidence reports a 1.4 s [1.3, 1.4] s paired
   reduction in both lanes.
6. Section V-C separates two consequences that readers must not conflate:
   intended-route delivery benefit in an intended-only setting and
   unlisted-origin exposure in a different competition setting.
7. The Discussion and Conclusion preserve the same distinction. They present
   `OpenScope` as bounded signed scope evidence, not as origin authentication
   or a replacement for an exact ROA once the origin is known.

## Narrative improvements over the prior organization

- The experiment story is outcome-led: partial-deployment conflict reduction, system cost,
  then routing benefit and exposure.
- Figure 2 visualizes remaining candidate conflicts under partial deployment
  and allocation-tree placement sensitivity.
- Fig. 3 makes the IPv4/IPv6 loading and classification comparison visible and
  is explicitly bounded to the Python reference classifier rather than a
  router or relying party.
- Fig. 4 does not present two different announcement sets as one joint
  frontier.
- The Introduction contribution, Evaluation results, Discussion limits, and
  Conclusion use the same evidence boundaries and headline numbers.

## Remaining evidence boundary

Figure 2 is a counterfactual replay over one frozen candidate frame. It does not
measure actual ROV-conflict prevalence, ROA adoption, or issuer knowledge. The
handoff result is conditional on one controlled workflow, two endpoint origins,
fixed timers, and one configured probe path. The processing result is
a dual-stack, single-process, single-core controlled replay with different
fixed query sets for the two IP versions. The deployment results
come from one fixed model, with separate announcement sets for benefit and
exposure. These limits are stated consistently and do not undermine the
paper's narrower claims about counterfactual conflict reduction, removal of a reactive
handoff-time ROA update, and the identified routing boundary.
