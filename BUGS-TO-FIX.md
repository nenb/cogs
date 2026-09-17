# Bugs to Fix

Status: explicitly accepted and deferred by the owner for the single bounded Issue #42 Stage 2 campaign. These findings remain recorded work; this disposition does not claim that they are fixed, authorize a retry, close Issue #42, or grant Stage 4 authority.

Protected R was documentation/governance only. The later R3 and R4 corrections, R5 governance-only successor, R6 campaign-admission correction, and R7 governance successor authorized below are limited to the production approval and planning control plane, synchronized tests, additive retirement history, and deterministic readiness evidence. None changes H, G, Q, or the qualified implementation.

## 1. Create protected planning revision R

- R must differ from H, G, and Q.
- It should record your explicit risk overrides and contain no unintended campaign implementation changes.
- Pass protected CI and review the complete R tree.

Disposition: the protected commit containing this document is intended to establish R after CI and complete-tree review.

## 2. Resolve or explicitly accept the remaining P2 findings

- fixed/ungrounded pricing;
- budget-email artifact retention;
- non-reconstructable published inventory pages;
- stale campaign runbook.

The inventory finding is particularly relevant to closing #42: a successful campaign could still lack the independently reviewable zero-resource evidence required by the binding map.

Disposition: the owner explicitly accepts and defers all four findings for this single campaign.

## Additional accepted review findings

The owner also explicitly accepts and defers, for this single campaign:

- the absence of distinct human role holders;
- incomplete automated saved-plan semantic validation, with exact manual plan review used as the compensating control;
- the post-Q campaign revision's credentialed/root stager not being mechanically required to equal the qualified H copy, with complete-R review and unchanged executable bytes used as compensating controls.

The existing runner-loss policy remains unchanged: runner loss is failed or uncertain, grants no success or retry authority, and may require separately verified manual cleanup. The AWS planning and destructive campaign authorization phrases remain separate mandatory gates.

## 3. Retire the first protected planning generation unused

Protected R `73e4188ff306ead82cfa1b9c35729a7e25030c17` produced the sole successful attempt-one read-only planning run `35041075222` and artifact `10424913996` (`sha256:5b758ef52b8d042ca9c4de7e00dc3251dc6afe17b22663f97a56578e13db559c`). Independent readback and expanded review accepted all seven exact saved plans, but the operator intentionally did not issue approval or dispatch the campaign before their admission window closed. No campaign resource was created, and the read-only planning role was removed.

Disposition: that planning generation is historical, non-authorizing, expired, and must never be reused or retried at R. A protected documentation/governance-only direct successor R2 may support one separately authorized fresh planning observation only after the planning, executor, and inventory-observer roles are preconfigured and verified and a fully supervised campaign window is available. R2 does not change or repeat H/G/Q, alter campaign or workflow bytes, approve resource creation, authorize the destructive campaign, or close Issue #42.

## 4. Retire the failed R2 production-approval generation

Protected R2 `89b0a5b5843373ab92710ce92008fe1b4e6ca658` produced the sole successful attempt-one read-only planning run `35114827724` and artifact `10454702483` (`sha256:1159450680d732f03f398a04e19b442cf022436e05714defab66575a7683d379`). Independent readback and expanded semantic review accepted all seven plans. The sole attempt-one approval run `35118929555` then failed before signing or publication because the pinned non-root Cosign container could not traverse the runner-owned mode-`0700` approval directory. It produced no approval artifact. No campaign was dispatched, no billable campaign resource was created, and all three temporary IAM roles and ARN variables were removed.

Disposition: the R2 planning and failed-approval generation is terminal and permanently non-authorizing; neither workflow may be retried at R2 and its plans must never be used for a campaign. A protected R3 may bind both pinned Cosign invocations to the exact non-root numeric UID/GID that owns the private approval directory, add synchronized assertions, and refresh deterministic readiness evidence. R3 does not repeat H/G/Q or authorize planning, approval, resource creation, or campaign execution. Fresh planning at R3 still requires a new explicit read-only authorization and a new supervised window.

## 5. Retire the failed R3 production-approval generation

Protected R3 `cb30f534ce8801f605a5c021656d7569ff35306c` produced the sole successful attempt-one read-only planning run `35148506458` and artifact `10468186158` (`sha256:f84383926493be9e7f98592c38b9479a18c1a1676891ab11f5c682e6fe44c80b`). Independent exact-archive readback and expanded semantic review accepted all seven plans. The sole attempt-one approval run `35150577796` then failed before signing or publication because the exact runner UID had no writable container home and pinned Cosign attempted `mkdir /.sigstore` while initializing TUF. It produced no approval artifact. No campaign was dispatched, no billable campaign resource was created, and all three temporary IAM roles and ARN variables were removed.

Disposition: the R3 planning and failed-approval generation is terminal and permanently non-authorizing; neither workflow may be retried at R3 and its plans must never be used for a campaign. A protected R4 may centralize the pinned Cosign invocation in one bounded signer, provide separate private writable signing and verification homes, preserve the private approval directory, and add one singleton protected non-authorizing diagnostic that exercises live TUF initialization, GitHub OIDC, Fulcio/Rekor keyless signing, bundle custody, fresh-home network-disabled verification, exact certificate identity/issuer, pinned binary extraction, and artifact upload before any IAM setup or fresh planning. The diagnostic grants no planning, approval, campaign, retry, or AWS authority.

## 6. Retire the successful but unused R4 production generation

Protected R4 `1116692df81f40c9f3f60c0a7448bcb46167cc61` first passed singleton non-authorizing signing diagnostic run `35168491742` and artifact `10475417794` (`sha256:c43103ce7b93c62f3345bb93fe7ce8945ad6ae1f21a6889d123aba46a39a0b08`). It then produced sole successful attempt-one planning run `35170392903` and artifact `10476681104` (`sha256:a99eb16c3766a6021e177753d3be9d49279f30d598491c862e6df303d6f52182`). Exact archive readback and expanded semantic review accepted all seven plans under batch `447f6e4a73aab1911bb66f07e4b86f92501592dd58e9e341c4ddb1cbb337e4a8`. Sole attempt-one approval run `35172329037` succeeded and published artifact `10476784540` (`sha256:60680ae214d4ea43e4bf0c4214800a915ebe1f7d7a8e9cac9c3fbfe12ed24ffc`). Independent readback accepted the exact inherited plan bytes, approval bindings, provider and binary custody, Rekor inclusion proof, RFC3161 timestamp, and offline certificate identity and issuer verification.

No destructive authorization was issued before the approval expired at `2026-09-17T08:24:18Z`. No campaign was dispatched, no billable campaign resource was created, all three temporary IAM roles and ARN variables were removed, and independent inventory found zero campaign resources.

Disposition: the complete R4 planning and approval generation is expired unused, terminal, and permanently non-authorizing. Neither workflow may be retried at R4, and neither artifact may authorize a later campaign. A direct-child protected R5 may record this disposition, add synchronized assertions, and refresh deterministic readiness evidence without changing H/G/Q, the successful diagnostic, signer, approval, planning, campaign, provider, or executable bytes. R5 grants no IAM setup, planning, approval, campaign, retry, or AWS authority. Fresh temporary roles and a new exact read-only planning authorization remain mandatory.

## 7. Retire the R5 planning generation and correct its usable window

Protected R5 `87be0712de3889721b7c4ed3194c32646f823356` produced sole successful attempt-one planning run `35225324388` and artifact `10498263515` (`sha256:1df0a4f015d225464929b1dece0b4a2d24fe75bf3cddf5ecb8ea9c0360101350`). Independent readback accepted all seven distinct create-only plans under batch `5a29a9601d008640d7789adef3b0a7914b1bff5e71b520d5ea07a0eb0db4f931`. The draft began at `2026-09-17T13:09:43Z` and stated expiry at `2026-09-17T20:09:43Z`, but the campaign's unchanged 20,000-second minimum credential duration and 60-second margin closed admission at `2026-09-17T14:35:23Z`, only 5,140 seconds after planning began. Independent review was not complete before that hidden cutoff. The pre-dispatch guard therefore rejected later approval authorization without dispatching an approval or campaign workflow.

No approval or campaign run exists at R5. No campaign resource was created and campaign spend was zero. All three temporary IAM roles and ARN variables are absent, independent inventory reports zero campaign resources, and the inert GitHub OIDC provider remains.

Disposition: R5 planning is terminal and permanently non-authorizing; it cannot be retried or used by a successor. The owner explicitly authorizes one direct-child protected R6 correction that changes only the campaign's minimum derived credential duration from 20,000 to 16,500 seconds. The existing seven-hour approval lifetime and 60-second margin then provide a visible 8,640-second (`2h24m`) planning-to-admission interval. The new minimum still contains the complete 14,700-second effect-and-cleanup envelope plus 1,800 seconds for post-credential staging. The strict eight-hour maximum remains unchanged. R6 must preserve exact H/G/Q, the qualified runtime, planner, approval signer, campaign controller, provider, Terraform graph, effect deadline, cleanup reserve, cost bound, evidence formats, terminators, and every destructive authorization gate. After protected CI, fresh IAM setup and read-only planning still require their separate authorization; approval and `authorize-seven-stage2-production-cycles` remain later human gates.

## 8. Retire R6 after failed exact-head post-merge CI

PR #557 passed every required protected check and merged as R6 `2975deffaf20f518d6611f5757fc2778f7e53d50`, the sole child of R5, with reviewed tree `48c379d2027df7016f7aca5a1eca09b45cdb9cd3`. Exact-R6 Linux foundations run `35259074785`, attempt 1, passed. Exact-R6 CI run `35259074947`, attempt 1, failed only while downloading pinned packages for the unchanged insecure-container image: Debian Snapshot returned `TooManyRequests 503 No healthy backends` for seven package archives. Quality, secret scanning, the worker and sandbox image builds, and all completed jobs passed. This was an external snapshot-availability failure, not evidence against the R6 campaign-admission change, but a failed exact-head generation grants no production planning authority and cannot be retried into authority.

No R6 IAM setup, planning, approval, campaign, provider, OpenTofu, SSM, or resource operation occurred. Disposition: R6 is terminal as a production planning revision. The owner authorizes one direct-child protected R7 governance-only successor that records this failure and preserves the complete R6 tree except synchronized governance, accounting assertions, and deterministic readiness evidence. R7 must not change H/G/Q, the 16,500-second campaign guard, or any planner, signer, campaign controller, provider, Terraform, cost, cleanup, terminator, or evidence behavior. Only a clean first-created attempt-one protected R7 and successful exact-R7 post-merge CI/foundations may proceed to temporary IAM setup.
