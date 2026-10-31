# Code and Artifact Completeness Audit

Date: 2026-08-29

## Verdict

- **Author-side claim auditability: PASS.** Each quantitative manuscript claim
  has retained code, claim-bearing input, output, and an independent or
  deterministic check in the shared working tree.
- **Anonymous one-command supplement: HOLD.** The required material spans the
  manuscript and several `phase*` directories, and those raw directories
  contain identity-bearing metadata. A sanitized bundle and clean-room wrapper
  have not yet been produced.

## Claim-to-artifact coverage

| Claim layer | Executable or transformation | Claim-bearing evidence | Completeness |
|---|---|---|---|
| Single-object classifier behavior | `phase4_encoding/scripts/utils/daroa.py` and Phase 4 tests | E1a semantic vectors, invalid inputs, composition assumptions, summaries, manifests, and reproducer | Complete for the stated classifier scope |
| Selected-fixture action agreement | Phase 6 fixture path and independent action auditor | 124 snapshots, seven route cases, and 868 retained checks | Complete for the selected fixture |
| Remaining candidate conflicts in Fig. 2 | `MSN-2026-0830/scripts/run_partial_policy_replay.py` | Hash-pinned 587-row candidate input, pooled 66-cell grid, 1,000 rollout orders, six OpenScope targets, secondary family/equal-decision data, and manifest | Complete for the frozen counterfactual candidate frame |
| Handoff benefit in Section V-B | `MSN-2026-0830/scripts/analyze_handoff_fig2.py` | Accepted protocols, 240 handoffs across two IP-version lanes, raw events, summaries, source manifests, and independent audits | Complete for the controlled workflow |
| Processing cost in Fig. 3 | `phase5_evaluation/processing_benchmark/run_controlled_policy_benchmark.py` and `MSN-2026-0830/scripts/build_processing_cost_figure.py` | 150 raw worker records, fixed policy/query manifests, load and classification summaries, independent recomputation audit, retained table CSV, figure manifest, and two panel products | Complete for the controlled single-core dual-stack reference processor |
| Intended delivery in Fig. 4(a) | Phase 7 scenario outputs and `MSN-2026-0830/scripts/build_fig_deployment_outcomes.py` | Fixed-model intended-only cells and exported figure source data | Complete for the fixed intended-only lane |
| Unlisted-origin exposure in Fig. 4(b) | Phase 9 selected-unit reanalysis and the same figure builder | Competition cells, point estimates, stability interval, and exported figure source data | Complete for the separate competition lane |
| Manuscript assembly | `MSN-2026-0830/scripts/assemble_paper.py` and `Makefile` | Section sources, active figure PDFs, bibliography, number ledger, and final PDF | Complete for the review build |

## Hash anchors

- Current review PDF:
  `1cad05ca4b5eba9f595ef101940bcb516a5926f29ebc81d010af9fbf9f5035ff`.
- Fig. 2 replay script:
  `758a99f921ca1ecd51768dbb8dbd829bbd5f04116e65cea9e9e758e84f7e9235`
- Fig. 2 manifest:
  `c884c04ab2332414ab07d9b7d4a2c505e568c82fbcd17371013ffe7eb98a49cc`
- Fig. 2 pooled single-column PDF:
  `7a22255edc84acce97eb68555afa58bd81b03925769f55d2e7dc1d635875476b`
- Processing benchmark script:
  `b3f83e091e5d3213ed25d64c572335fd0bfc104f2bb520d1b105a4fe2f561167`
- Processing benchmark summary:
  `cc0e3f3fa5787cf4dda14e60238f9a7a2cc601bacf111c76d9d9650db809ac7d`
- Processing benchmark independent audit:
  `189ed2bc46e8c30c3fcec4059bfacf613d8de648aabc529313ea5d9a047b9f4a`
- Fig. 3 builder:
  `665d707a5f4856c0840074cb3d83cf37e3dff6565d8597ccc0e35e0165576b46`
- Fig. 3 manifest:
  `8fe704bb5324a652e806d273e718677aba37e54a0d3042643d5c53981f470833`
- Fig. 3 load panel PDF:
  `793817bf641e8162d3a6afee671d4ad192d3771a2428143244b28a11134337b0`
- Fig. 3 classification panel PDF:
  `3c49f39b6a72f6a759f24fce81f9128bdbf393486eb1f7422bdb8459887fc753`
- Fig. 4 builder:
  `bbf46d2b997de5369ca6bc1b5fa155917142ac0d9389d596478c0d9bd3e3c0ac`
- Fig. 4 intended panel PDF:
  `a2c167fd181160879b02cd31269fc685cb84c78ef082f92e96f0520587f34370`
- Fig. 4 competition panel PDF:
  `b0333bf469e3b0504f590bc33656ca166418c24fee0e0d3ea14ebbc7158b05ef`

## Scope-complete, not system-complete

The artifact is complete for the claims actually made. It does not implement
or evaluate a production RPKI relying party, standardized full-object
transport, native router support, multi-object composition, concurrent
updates, atomic installation, or line-rate forwarding. Those are
explicit manuscript exclusions, not missing evidence for a supported claim.

## Remaining release work

1. Create one identity-scrubbed tree with relative paths and a top-level runner
   for the retained checks and figure/table regeneration.
2. Remove or sanitize absolute host/user metadata, Git state, local project
   identifiers, and unnecessary diagnostics from raw phase outputs.
3. Recompute a release-level checksum manifest after sanitization.
4. Validate the bundle from a clean neutral path and compare its results with
   the retained author-side ledgers.

Until those steps pass, the code and evidence are internally complete but the
raw working tree is not an acceptable anonymous supplementary artifact.
