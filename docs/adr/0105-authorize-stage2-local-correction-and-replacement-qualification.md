# ADR 0105: Authorize Stage 2 local correction and replacement qualification

- Status: Accepted by explicit owner instruction in this conversation
- Date: 2026-08-21
- Scope: Gate 0 accounting and bounded non-AWS Stage 2 correction/qualification authority

## Context

The owner instructed this branch to proceed with non-AWS correction work and local Docker/Linux testing. The instruction also authorizes, if required, one non-KVM static control/discovery event and, after exact-head review, one separate replacement Stage 2 KVM qualification. The stop before controller or AWS work remains mandatory.

The central retained-line inventory omitted three tracked schemas that already define local security boundaries:

- `schemas/stage2-local-executable-closure-v1.json` — 172 physical lines;
- `schemas/stage2-local-execution-envelope-v1.json` — 437 physical lines;
- `schemas/stage2-local-runtime-manifest-v1.json` — 390 physical lines.

After adding those exact existing files and the readable tracked-inventory assertion, Gate 0 measures **50,363 current physical lines** and **52,365 conservative no-deletion-credit lines**. Both measurements include the checker correction itself.

## Decision

Gate 0 corrects documentation and accounting only. The retained inventory must contain only files that exist and are tracked. It lists the three omitted schemas now. It must not predeclare a nonexistent future V2 or control schema and then count it conditionally. Any later V2, control, or other retained schema/script must be added as a tracked file and added to the inventory atomically in the same correction.

Set the Stage 2 preferred limit to **60,000** and the mandatory hard limit to **62,000** for both current physical and conservative no-deletion-credit measurements. Deletion, renaming, relocation to tests/workflows/data/generated files, or compression of security logic provides no credit.

Measured from the accepted Gate 0 commit, the non-transferable readable gross-addition highs are:

| Counted correction slice | Gross added-line high |
| --- | ---: |
| Local correction implementation under `deploy/aws-feasibility` | 5,000 |
| Retained security scripts and tracked schemas | 2,500 |
| Combined | 7,500 |

The combined high projects the conservative measure to at most **59,865**, below the preferred limit. These highs favor ordinary readable code; exceeding either slice requires a new measured decision even when the global hard limit would remain satisfied.

After Gate 0, the owner authorizes only:

1. non-AWS correction work and repeatable local Docker/Linux tests;
2. if correction review proves it necessary, exactly one non-KVM static control/discovery event, which cannot claim KVM qualification and cannot consume or replace the KVM event;
3. after clean exact-head review of the corrected qualification head, exactly one distinct replacement Stage 2 KVM qualification.

The first created event for each authorized event class consumes that authority. Failure, uncertainty, source mismatch, residue, cancellation, or missing evidence grants no retry or alternate event. The static event is optional; omitting it does not create a second KVM attempt.

## Mandatory stop

Stop after the replacement KVM result, or immediately after any terminal event outcome. This ADR does **not** authorize a controller, the seven-cycle campaign, AWS credentials or APIs, provider/OpenTofu/SSM activity, deployment, publication, readiness promotion, issue closure, production, or release claims. Controller implementation and every AWS action require a later explicit owner decision after review of the exact retained result.

## Consequences

Gate 0 changes no runtime implementation. Later authorized corrections remain subject to exact-head review, tracked atomic inventory updates, the per-slice highs, the centralized checker, and the mandatory controller/AWS stop.
