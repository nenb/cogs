# ADR 0369: Retire failed planning and align the feasibility expiry bound

- Status: Accepted
- Date: 2026-09-25
- Decider: Nick Byrne
- Scope: terminal R planning disposition, narrow planning-feasibility correction, and successor control

## Context

Protected R `727636d61207903744aba52cb6a2325e92f13f8b`, sole parent Q `2d4b61a63cdb08a92d5fbde9095532fad2383e90`, passed exact-head CI `36091738774` and Linux foundations `36091738851` on attempt one. Its sole planning run `36096732289`, attempt one, passed admission, package authentication, exact checkout, V6 eligibility, V4 control preparation, and OIDC identity acquisition, then failed in `Produce seven read-only saved plans and canonical JSON derivations` with `stage2-production-planner: owner.failed`.

The run published zero artifacts. No approval, campaign, diagnostic continuation, apply, executor/observer bootstrap, or Stage 4 action followed. Campaign-resource inventories were exactly zero before and after the run. The transaction-owned planning variable, inline policy, and role were removed only after exact ownership and zero-resource verification; executor and observer roles were never created. The run and its authorization are terminal and cannot be retried, stitched, resumed, salvaged, or reinterpreted.

A no-resource local reproduction identified a deterministic contract mismatch. The planner emits the production approval draft with a ten-hour lifetime required by the one-run/two-job campaign: its eight-hour effect deadline plus thirty-minute cleanup reserve must fit before expiry. The production controller and campaign admission require that exact ten-hour interval. However, both the OpenTofu `bounded_expiry` assertion and `check-plan.py` still reject every expiry not strictly below eight hours. The first generated plan therefore cannot pass its mandatory feasibility check.

Reducing the draft lifetime would contradict the authenticated campaign contract and erase required execution and cleanup runway. The narrow correction is to align the two feasibility validators with the existing ten-hour production contract while preserving the thirty-minute lower bound.

## Decision

Retain exact H `ba085947eaee321dfb724d94169d42bc36d397b0`, G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, Q, qualification `36036544983`, artifact `10829051963`, and the accepted thirteen-member static package byte-for-byte. Retire only R's failed planning generation.

Change `deploy/aws-feasibility/main.tf` and `deploy/aws-feasibility/check-plan.py` from a strict eight-hour maximum to a strict ten-hour maximum. Do not change the planner's ten-hour lifetime, eight-hour effect deadline, thirty-minute cleanup reserve, maximum cycle duration, cost bound, resource graph, approval/signing contract, campaign workflow, provider behavior, evidence formats, terminators, or destructive phrase. Add a source-level regression that binds all three expiry values and rejects either stale validator. Give the deletion-blind accounting subprocess a test-only 90-second ceiling after its isolated runtime measured immediately below the old 60-second edge.

Raise the tracked-file limit only from 1,568 to 1,569 for this literal ADR. Keep source-inventory bytes, serialized-inventory bytes, and the global source-byte limit unchanged; the final readiness inventory must contain the ADR before protected review.

Classify the two feasibility validators under `local-tofu-ssm` and the regression and this decision under `governance`. Raise only measured line highs: governance from 8,680 to 8,800, product from 5,058 to 5,059, local-tofu-ssm from 6,200 to 6,220, and readiness-ci from 286 to 289; keep final-HGQ at 4,694. The remaining tranche becomes 25,062 lines and 21,500,000 bytes and the global forecast becomes 43,062 lines and 29,500,000 bytes. Transfer 250,000 prospective bytes from unused local-tofu-ssm capacity to readiness-ci, making their byte highs 2,800,000 and 10,750,000. All aggregate byte highs, non-file-count source/inventory limits, deletion-blind accounting, final-HGQ caps, and `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS=0` remain unchanged.

A successor is authoritative only after protected review and checks establish its exact tree as a direct child of R. The source revision grants no credential, IAM, planning, approval, apply, production, closure, or Stage 4 authority. Any future planning must be a fresh first-created attempt-one generation under separate explicit authorization, with fresh bounded bootstrap and zero-resource proof; it may not consume any byte or authority from run `36096732289`. Approval and the exact `authorize-seven-stage2-production-cycles` phrase remain separate later gates.

## Consequences

The failed observation remains failed and non-authorizing. The correction makes the planner's existing ten-hour draft admissible to both read-only feasibility validators without widening any resource, identity, effect, cleanup, cost, or production permission. H, G, Q, qualification, and static evidence remain immutable. Stage 4 remains separate and non-authorized.
