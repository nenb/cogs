# ADR 0370: Retire the ineligible approval and require a supervised production window

- Status: Accepted
- Date: 2026-09-25
- Decider: Nick Byrne
- Scope: terminal S planning/approval disposition and one governance-only successor

## Context

Protected S `2e17d61696fe8d4b3029227aab8baf54dc3ec4bc`, sole parent R `727636d61207903744aba52cb6a2325e92f13f8b`, passed its protected and exact-head checks. Under separately bounded read-only authority, sole planning run `36119445628`, attempt one, succeeded and published artifact `10856638176` (`sha256:f61b8f3622a4daab4df8f2e7f80abb2ed1b447ba5607c2f5d06182478f2bb281`). Independent archive and semantic review accepted its exact 69-member closure, seven saved plans, V6 package, V4 envelope, resolved AMI, provider package, strict ten-hour draft, and batch `40e4ad2a46bfd55ef7bdde2aaa26e99a599881453f08146c8443af75f66ed7ae`.

The transaction-owned planning role and repository variable were removed after exact-ownership and byte-identical zero-resource verification. Cleanup receipt SHA-256 is `19143c4bdd69a356e96d0b93f3e1e72e493d1d8cbe3e22f593ccd5f3f2ebc3d3`.

Sole plan-bound approval run `36123681852`, attempt one, succeeded and published artifact `10859216624` (`sha256:14d995bbb6fc2ddc9d299b38dd5fb6ba61d8e60ae6bacb7296017182808076e8`). The exact 73-member closure preserved all inherited planning bytes, produced V6 approval SHA-256 `9a331413297554b54830a8b91884596516b4e4ab5c9826f0bb417662526fb812`, and passed keyless signature, identity, issuer, package, principal, plan, deadline, and cost validation.

No exact `authorize-seven-stage2-production-cycles` token was supplied. No campaign was dispatched. The workflow's mandatory 32,400-second pre-consumption runway closed at `2026-09-25T10:37:00Z`; the controller's independent first-plan plus effect plus cleanup bound closed at `2026-09-25T10:53:00.873866Z`. Independent review therefore rejected campaign use despite the cryptographically valid approval. Executor and observer roles were never created. Exact inventory remained zero with SHA-256 `f6f11122417090d4edb52e756c470ce550296e8a07a7299db01704efbf8237b4`; terminal evidence SHA-256 is `3fb459e595a6cc0376c46eee4651ba43a1563a38bd1ecd7a7581f4af0b5f05e9`.

The incident is not a reason to weaken the ten-hour lifetime, nine-hour campaign gate, fifteen-minute first-plan reserve, eight-hour effect deadline, or thirty-minute cleanup reserve. Planning and approval consumed their intended finite window while destructive authorization remained absent.

## Decision

Retire S planning run `36119445628`, planning artifact `10856638176`, approval run `36123681852`, approval artifact `10859216624`, their batch, and their elapsed authorization window from all future production use. They are terminal and cannot be retried, reused, stitched, resumed, salvaged, or reinterpreted by a successor. Preserve them as successful read-only and cryptographic observations only; they grant no campaign, closure, or Stage 4 authority.

Permit one protected governance-only direct child of exact S. The successor changes only this decision, synchronized terminal history, prerequisite-map language, accounting assertions, and deterministic readiness evidence. It changes no H, G, Q, qualification, static package, planner, feasibility validator, approval issuer, signer, campaign, provider, Terraform graph, credential duration, deadline, cost, recovery, evidence, or destructive gate byte.

The successor grants no IAM, OIDC, planning, approval, apply, campaign, production, closure, promotion, publication, or Stage 4 authority. Before any fresh planning bootstrap, the operator must have the separately supplied exact `authorize-seven-stage2-production-cycles` token and a continuously supervised window sufficient to complete planning, independent review, approval, approval download, campaign admission, and controller consumption before both unchanged cutoffs. A fresh zero-resource baseline and separately reviewed exact-ownership IAM bootstrap remain mandatory. Only one new first-created attempt-one planning generation may run under the protected successor; it may consume no byte or authority from either S run or artifact.

Raise the tracked-file limit only from 1,569 to 1,570 for this literal ADR. Raise the governance line high from 8,800 to 8,950, product from 5,059 to 5,061, and readiness-ci from 289 to 291. Reallocate 250,000 prospective bytes from local-tofu-ssm (2,800,000 to 2,550,000) to readiness-ci (10,750,000 to 11,000,000) for the exact regenerated inventory; all other byte highs remain unchanged. The remaining tranche becomes 25,216 lines and 21,500,000 bytes and the global forecast becomes 43,216 lines and 29,500,000 bytes. Final-HGQ, serialized-inventory, aggregate byte, deletion-blind, and `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS=0` controls remain unchanged.

## Consequences

The S correction remains valid and protected, but its elapsed planning/approval generation cannot authorize production. No role or campaign resource remains. A later chain starts only from the protected successor and only when the exact destructive token and uninterrupted window already exist. Issue #42 stays open, and Stage 4 remains separate and non-authorized.
