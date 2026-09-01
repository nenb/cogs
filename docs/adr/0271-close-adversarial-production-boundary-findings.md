# ADR 0271: Close adversarial production-boundary findings

- Status: Accepted
- Date: 2026-08-31
- Accepted by: Nick Byrne through the explicit instruction to continue every non-AWS prerequisite autonomously and stop before any AWS execution

## Context

The first whole-graph adversarial review after a clean 1,320-test run found real prerequisite defects: control-bound immutable-preparation rollback reread an intentionally absent external descriptor; two one-import failure stages were undeclared; V2 approval had been changed in place; approval signature verification was self-asserted at consumption; approved plan JSON was detached from the saved plan; explicit budget/tool/credential staging and a planning producer/campaign caller were absent; executor identity was not enforced; eight inventories reused one observation commitment; cleanup intents could strand uncertainty; remote work could exceed its effect deadline; and cost authorization was only post-hoc.

Corrections retain V2 unchanged and add V3, pin an offline Cosign verifier and trusted root, sign the complete authentication receipt, derive plan JSON from the exact binary at execution, use atomic recoverable staging, stage short-lived credentials explicitly, bind the executing role, make cleanup reconciliation idempotent but non-minting, enforce a pre-authorized per-cycle duration/cost ceiling, and add dormant first-created planning and campaign callers. No AWS workflow was dispatched and no AWS credential or API was used while implementing or testing these boundaries.

After these additions, measured no-deletion-credit totals are 19,349 deployment, 9,717 retained schema/script, 3,936 workflow, and 33,002 global lines. Physical total is 85,122 and conservative total is 88,356. The existing deployment high has 151 lines remaining, while retained, workflow, and global exceed their prior highs by 217, 236, and 602 lines. The 90,000 preferred target and 94,000 mandatory hard stop remain satisfied.

## Decision

Raise the non-transferable correction highs to 20,500 deployment, 10,500 retained schema/script, 4,500 workflow, and 35,000 global lines. Retain the 90,000 preferred target, 94,000 hard stop, and 1,350 tracked-source bound.

The capacity is restricted to correcting the enumerated review findings, hostile/provider-free tests, exact approval/plan/credential staging and recovery, and dormant future planning/campaign caller shape. It grants no AWS execution, credential use, provider call, OpenTofu plan/apply, SSM request, inventory, deployment, campaign, or release authority. Workflow definitions containing future AWS steps remain inert source until all local gates freeze and separate fresh authorization is provided.

## Post-implementation measurement

After the exact evidence readback receipt, hostile custody checks, and workflow caller tests, measured additions are 19,745 deployment, 10,084 retained schema/script, 4,158 workflow, and 33,987 global lines. Physical total is 86,092 and conservative total is 89,341. Every raised slice, the preferred target, and the hard stop are satisfied.

## Consequences

The corrected implementation must rerun complete validation and another independent adversarial review. Native producer-to-consumer validation, exactly one no-mint KVM rehearsal, readiness audit, H freeze, exact-H dual production/publication, independent G, and one formal local qualification remain mandatory. Any finding or runtime failure starts a new generation. Execution stops before AWS regardless of the presence of dormant future workflow code.
