# Original-to-Repaired Evaluation Changelog

Date: 2026-08-30

| Before | Repaired version | Reason |
|---|---|---|
| Correctness Gate occupied Section V-A | Conformance evidence is compressed into the Evaluation setup; Section V-A now evaluates potential-conflict reduction | Correctness is prerequisite evidence, while partial deployment is the first reader-facing outcome |
| Fig. 2 showed the controlled handoff comparison | Handoff evidence is compressed into Section V-B prose; Fig. 2 now fixes the root-scope target at 10% and plots remaining candidate conflicts across exact-endpoint deployment | Leads with partial-deployment benefit and allocation-tree placement sensitivity |
| No selected-policy processing result | Table II measures controlled dual-stack load and fixed-output classification at three subprefix counts | Adds a direct processing-cost answer without changing the query or output mix as policy size grows |
| Fig. 3 showed only an origin-competition diagnostic | Fig. 3 separates intended-only delivery benefit from competition exposure | Leads with benefit while preserving the security boundary |
| Delivery and exposure could be read as one joint tradeoff | Setup and caption state that the panels use different announcement sets and inference targets | Prevents an unsupported joint-frontier interpretation |
| Introduction and Conclusion emphasized conformance and handoff only | Both now summarize partial-deployment conflict reduction, controlled-stack benefit, and fixed-model outcomes | Aligns the paper-level contribution with the revised evidence chain |
| Processing cost appeared as compact Table II, while deployment outcomes were Fig. 3 | Processing cost is now Fig. 3 with grouped IPv4/IPv6 load and classification panels; deployment outcomes move to Fig. 4 | Makes the address-family performance comparison visible without duplicating the retained table CSV artifact |
| Fig. 2 fixed OpenScope at one placement target | Fig. 2 now compares no OpenScope, 20%, 40%, 60%, 80%, and full OpenScope across matching-ROA issuance rates | Shows the partial-deployment interaction directly instead of conditioning the conclusion on one OpenScope target |

No formal definition, classifier rule, handoff raw event, or routing-model raw
scenario was changed. The repair adds a counterfactual replay over the retained
candidate data, adds one local processing benchmark, renders that benchmark as
grouped bars, and rewrites claims to match their experimental scope. The
replay does not create an observed-conflict prevalence estimate.
