# Pre-run Plan and Approval

Date: 2026-08-29

The user approved the ICICS-inspired evaluation redesign with “改吧.”  The
approved design is recorded in
`workspace/experiments/ICICS_INSPIRED_EVALUATION_PLAN.md`.

| Experiment | Supports claim | Essential? | Runtime | Disk | Compute/cost | External data | Decision |
|---|---|---:|---:|---:|---|---|---|
| Partial-policy replay | Measures remaining candidate conflicts under partial exact and root-scope placement; equal-decision output is secondary | yes | minutes | under 50 MB | local CPU; no monetary cost | none; retained 587-row candidate input | approved by user on 2026-08-29 |
| Handoff event reanalysis | Supports the Section V-B observation-to-probe result | yes | minutes | under 20 MB | local CPU; no monetary cost | none | auto-approved: low cost, retained raw events |
| Historical RRC00 IPv4 selected-policy benchmark | Superseded because policy growth also changed the selected-state mix | no longer active | estimated 10–30 min after implementation | under 1 GB | local CPU; expected under 4 GiB RAM | none; retained local RRC00 input | historical approval; superseded for Table II |
| Phase-7/9 routing-result reanalysis | Separates intended-only delivery benefit from competition exposure | yes | about 1–2 min | under 100 MB new outputs | local CPU; about 1.2 GiB RAM | none; retained raw results | auto-approved: low cost |
| Controlled dual-stack policy processing | Separates policy loading from fixed-output steady-state classification | yes | under 10 min | under 100 MB new outputs | one local CPU core; no monetary cost | none; retained local RRC00 inputs | approved by user on 2026-08-29 and low cost |
| Full provenance-replacement routing campaign | Would support a stronger Internet-scale deployment claim | no for the bounded manuscript claim | 8–10 h | about 0.2 GB raw plus inputs | local CPU; 8–10 GiB peak RAM | official topology and ROV data would require a separate dataset gate | skip in this revision |

No external data will be downloaded in this revision. The partial-policy replay
is restricted to counterfactual residuals in the frozen candidate frame, and the
routing experiment remains a fixed-scenario model unless a later, separately
approved provenance-replacement campaign is completed.
