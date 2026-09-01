# ADR 0270: Complete retained accounting and approval custody

- Status: Accepted
- Date: 2026-08-31
- Accepted by: Nick Byrne through the explicit instruction to continue the corrected anti-fiasco sequence autonomously through every non-AWS prerequisite and stop before AWS effects

## Context

The final provider-free review found two bounded prerequisite defects after ADR 0269. First, the production approval schema required the approval to contain the digest of an authentication receipt that itself contained the approval digest. That circular commitment was not constructible. Second, retained-line inventory omitted several newly authoritative additive schemas and scripts. Completing the inventory and adding the non-AWS keyless approval issuer, exact signature custody, and fixed-root stager produces measured no-deletion-credit additions of 19,231 deployment lines, 9,372 retained schema/script lines, 3,598 workflow lines, and 32,201 global lines. Physical total is 84,321 and conservative total is 87,555.

Every individual slice remains below its existing high and both totals remain below the 90,000 preferred target and 94,000 hard stop. Only the global correction high is exceeded, by 201 lines. The completed additive graph has 1,319 tracked source files, 19 above the prior 1,300 bound. Omitting authoritative files from either inventory or compressing the security boundary would be false economy.

## Decision

Raise only the global correction high from 32,000 to 32,400 lines. Retain the 19,500 deployment, 9,500 retained schema/script, and 3,700 workflow highs and the 90,000 preferred target and 94,000 hard stop. Raise the measured tracked-source bound from 1,300 to 1,350.

The added capacity is restricted to complete retained-file accounting, removal of the impossible circular commitment, closure-private authentication custody in the consumption receipt, exact approval-signature and bundle verification, canonical provider-free approval issuance, fixed-root approval/plan staging, and hostile tests. Authentication now commits to the already-created approval; the consumed receipt carries the independently authenticated receipt digest into evidence. No field is trusted merely because it is syntactically digest-shaped.

The approval workflow performs no AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign effect. It can only authenticate a separately authorized future planning package and issue a short-lived one-shot approval. The dormant provider boundary remains non-authorizing and import-inert.

## Consequences

The corrected accounting is conservative and grants no deletion credit. The non-AWS graph still must pass complete validation, adversarial review, native producer-to-consumer validation, exactly one no-mint KVM rehearsal, and independent readiness audit before H can freeze. Exact-H dual production, independent G, and one formal local qualification remain later gates. The mandatory stop before all AWS effects remains unchanged.
