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

## Amendment 1: terminal diagnostic convergence and bounded production remediation

- Date: 2026-09-27
- Decider: Nick Byrne
- Scope: terminal non-authoritative observations and one protected production-only successor

The authoritative campaign `36153546258` and every earlier or split diagnostic generation remain terminal. They cannot be retried, reused, stitched, resumed, salvaged, or granted authority. The successful replay `36263882996` remains non-authoritative. Fresh preparation `36284414224` approved only diagnostic revision `d5865c31fc451ea25627bd7942b8e2078b7749b7`; uninterrupted run `36284775744`, attempt one, then executed cycles 1–7. Job `108523330822` completed cycles 1–3, published signed continuation artifact `10923031991` (`sha256:060055bc95228b20468a5f89d3b58243b61cc86bf23df0e101c716c55da196cd`), and proved certain zero and credential retirement. Job `108547908195` admitted that exact continuation, completed cycles 4–7, retired credentials, and made the final account-wide zero observation.

Run `36284775744` failed only after those effects had ended. Root created the immutable evidence snapshot below private mode-`0700` `/var/lib/cogs`; the unprivileged artifact action could not traverse that parent. No canonical evidence artifact was uploaded. The run is a complete non-authoritative runtime observation but grants no production, evidence, closure, publication, or Stage 4 authority.

Authorize one protected direct successor of `610c28587596df50531ada8986a66024ca1ca23f` containing only the production-required corrections demonstrated by the terminal diagnostics, their tests, this amendment, and deterministic evidence synchronization. The successor:

1. securely creates absent root-private `/var/lib/cogs` and the issuance root without broadening private custody;
2. performs OIDC/STS exchange as root with only the exact token-request and `GITHUB_ENV` variables preserved;
3. strictly admits both observed GitHub-hosted OIDC endpoint families while retaining exact issuer, subject, audience, authority, query, and TLS checks;
4. commits the approval authentication JSON, bundle, pinned Cosign, and trusted-root identities together;
5. omits pagination flags for the two non-pageable EC2 inventory operations;
6. admits absent pre-mutation state during bounded cleanup, dynamically bounds segment-two sessions to remaining runway with an 18,000-second minimum, and reserves 960 seconds for STS response handling;
7. publishes only the root-owned immutable public evidence snapshot beneath `/var/lib/cogs-stage2-aws-evidence-v2`, leaving `/var/lib/cogs` mode `0700` and issuance and credential custody private; and
8. synchronizes the hostile-fetch caller-abort test to observed fetch entry after regeneration exposed its timer race, without changing any production timeout or runtime behavior.

The ADR 0370 task highs remain exactly `8,950 / 1,300,000`, `5,061 / 1,950,000`, `6,220 / 2,550,000`, `291 / 11,000,000`, and `4,694 / 4,700,000`; the remaining tranche remains `25,216 / 21,500,000`; and the historical global forecast remains `43,216 / 29,500,000`. Tracked files remain capped at `1,570`, serialized inventory at `262,144`, and `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS` remains zero.

Because those deletion-blind allocations were nearly exhausted before the newly observed production defects, establish a separate post-diagnostic remediation tranche anchored at exact protected revision `610c28587596df50531ada8986a66024ca1ca23f`. It permits at most 500 gross added lines and 1,000,000 gross added line-bytes across only the literal paths in `post_diagnostic_remediation`. It grants no deletion credit and does not modify, refill, or reinterpret any ADR 0370 allocation. It is also bounded by the unchanged older remediation and repository hard limits.

The initially drafted one-invocation readiness-regeneration control was exceeded during preparation: successful local readiness regenerations occurred both before and after the V4 synthetic-golden correction. Those intermediate uncommitted generations are terminal validation observations, are superseded by the final synchronized bytes, and grant no authority. Reconcile that deviation explicitly by defining `post_diagnostic_remediation.readiness_regenerations = 1` as the one accepted final sequential deterministic readiness generation retained in the protected successor, not as a false count of local tool invocations. The exact V4 synthetic-golden synchronization and readiness updates are compatibility evidence only; they do not authorize Stage 4, and Stage 4 remains blocked.

Independent pre-commit review then rejected that candidate because a shortened segment-two session did not necessarily cover the complete cleanup reserve, absent production state after a started segment-one campaign could be misclassified as clean, and the tranche checker admitted more than one descendant commit. That candidate and its readiness bytes are terminal and unaccepted. Authorize only the minimal corrections that bind each campaign timeout to the earlier executor/observer credential expiration minus a 1,860-second cleanup-and-transition reserve, accept absent state only on the separately proven pre-mutation staging-failure path, and require the protected successor to be exactly one direct child of the tranche base. A second independent review rejected the next candidate because role issuance, provider execution, recovery, and evidence snapshot commands still selected unchanged H paths. Preserve H itself, but root-copy its complete authenticated source into a separate private remediation root, replace only the five digest-pinned reviewed production files, freeze that root, and dispatch every affected production command through it; no diagnostic or earlier generation gains authority. A final rereview rejected the resulting local candidate because the copied tree omitted the `source` path component required by every overlay dispatch; those readiness bytes are terminal, and the overlay transaction must explicitly create its parent and copy H to `source` before installing replacements. The subsequent rereview rejected that local generation because issuance ran before overlay authentication and V4 validation retained H's stale signature helper; those readiness bytes are also terminal, so construct the overlay before issuance and bind validation to its helper. The next rereview rejected the local generation because H's adapter and command wrappers still routed effects, inventory, remote work, and recovery to H's provider; those readiness bytes are terminal, so the overlay must also replace and digest-bind that adapter and all four wrappers. Authorize one replacement final readiness generation after all of those corrections; it is the sole accepted generation represented by `readiness_regenerations = 1`. No further regeneration is authorized after the replacement bytes without new governance.

After this successor is protected and exact-head CI passes, permit one fresh first-created planning run, one plan-bound approval run, and exactly one attempt-one seven-cycle production campaign under the unchanged ten-hour lifetime, nine-hour admission gate, eight-hour effect deadline, thirty-minute cleanup reserve, maximum-cycle duration, cost bound, graph, H/G/Q, qualification, and evidence controls. The earlier planning, approvals, campaigns, diagnostics, continuations, and tokens supply no byte or authority to that chain. Canonical evidence upload, numeric-ID readback, byte equality, independent V4 validation, receipt readback, credential retirement, and final account-wide zero are all mandatory before closure.

## Amendment 2: close the authoritative ten-hour execution overlay

- Date: 2026-09-27
- Decider: Nick Byrne
- Scope: terminal attempt-one disposition and one narrowly bounded protected successor

Protected remediation successor `4d77f41a8c8b94ed48becf2073914bd2896a31ee` passed exact-head CI. Fresh planning run `36336824559` and artifact `10937119675` (`sha256:a48790502a3ad39e102f20c61d32d4d0f5d942c854dd26a680b2fe54a96590f6`) produced seven independently approved ten-hour plans. Plan-bound V6 approval run `36338143051` and artifact `10938086919` (`sha256:44a6adfa466fcf75174160a8c452ea819caab2437f0c0677ba6b7123c493e392`) then authorized attempt-one campaign `36339531720`.

The campaign authenticated the approval, installed the reviewed overlay, acquired bounded executor and observer sessions, and entered cycle 1, but failed before apply. The overlay omitted the ten-hour checker, and its provider still selected H's source root and therefore retained H's eight-hour `check-plan.py`, while the authenticated plan had approximately nine hours fourteen minutes remaining under the approved ten-hour contract. Exact reproduction returned `unsafe feasibility plan: expiry is not between 30 minutes and eight hours from now`. CloudTrail contains only identity and inventory reads, no AWS create or mutation event occurred, cleanup succeeded, and the independent final zero inventory retained SHA-256 `f6f11122417090d4edb52e756c470ce550296e8a07a7299db01704efbf8237b4`.

Retire those planning, approval, and campaign generations from future use. They remain useful failure observations but cannot be retried, reused, resumed, stitched, or credited. Preserve exact H `ba085947eaee321dfb724d94169d42bc36d397b0`, G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, Q `2d4b61a63cdb08a92d5fbde9095532fad2383e90`, their qualification, and the existing bounded IAM bootstrap.

Authorize exactly one protected direct child of `4d77f41a8c8b94ed48becf2073914bd2896a31ee`. It may add the already reviewed ten-hour `deploy/aws-feasibility/check-plan.py` and matching `deploy/aws-feasibility/main.tf` bytes to both immutable overlay manifests, bind `completion_campaign_aws_provider.py` to that exact immutable overlay root, update its manifest digest, add exact digest, routing, and staging regression assertions, record this decision, enforce its own direct-child accounting, and perform one final deterministic readiness regeneration. No other production behavior, graph, duration, cost, evidence, credential, cleanup, H/G/Q, or Stage 4 authority may change.

Establish a separate `post_authoritative_failure_remediation` tranche of at most 300 gross added lines and 1,000,000 gross added line-bytes rooted at that protected revision and limited to its exact sorted path allowlist. It grants no deletion credit and does not refill or reinterpret the completed 500-line post-diagnostic tranche. Stage 4 remains blocked and the historical ADR 0370 task allocations and repository limits remain unchanged.

After the successor is protected and exact-head CI passes, permit one fresh first-created planning run, one independent plan review, one plan-bound V6 approval, and one attempt-one seven-cycle campaign using the existing fresh workflow phrases. All upload/readback, byte-equality, V4 validation, receipt, credential-retirement, cleanup, and final-zero gates remain mandatory.

## Amendment 3: retire the partial campaign and preserve issuance runway

- Date: 2026-09-28
- Decider: Nick Byrne
- Scope: terminal partial-campaign disposition and one segment-two arithmetic successor

Protected successor `4916341c74cb55b8f3247bf5a3c8848672aac3ad` passed exact-head CI. Fresh planning run `36352983437` and artifact `10942428513`, independently accepted plan audit, plan-bound approval run `36354691379` and artifact `10943298492`, and attempt-one campaign `36355908374` formed one generation. Campaign job `cycles_1_3` completed ordinals 1–3, destroyed each cycle's resources, retired credentials, proved certain zero, and published byte-read-back continuation artifact `10947890127` (`sha256:d62c6e07d8c817e42ce55c7ec958179f1c084435a3428a8661d44f12a52cb2e1`). The second job authenticated that continuation but failed before OIDC or STS network exchange and before cycle 4.

The exact failure was a one-second shell-to-helper sampling drift. The workflow computed a runway-limited request of 19,141 seconds at `01:35:46Z`; the root helper sampled at `01:35:47Z` and correctly rejected that now-one-second-too-long request before reading the OIDC token. Failure-path cleanup and credential retirement passed. Independent account-wide inventory remained byte-identical zero with SHA-256 `f6f11122417090d4edb52e756c470ce550296e8a07a7299db01704efbf8237b4`.

Retire planning `36352983437`, approval `36354691379`, campaign `36355908374`, continuation `10947890127`, their batch, plans, approval, receipts, and partial cycles from all future production use. They cannot be rerun, retried, resumed, reused, stitched, or credited. Preserve exact H `ba085947eaee321dfb724d94169d42bc36d397b0`, G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, Q `2d4b61a63cdb08a92d5fbde9095532fad2383e90`, and qualification run `36036544983`; no H restart is required.

Authorize exactly one protected direct child of `4916341c74cb55b8f3247bf5a3c8848672aac3ad`. It may add a 180-second issuance slack before selecting each runway-limited segment-two session, require that slack at continuation admission, add the exact elapsed-sampling regression, record this disposition, enforce direct-child accounting, and perform one final deterministic readiness regeneration. Any pre-rereview uncommitted generation is terminal; the final post-format generation is the sole accepted regeneration. The unchanged helper still independently samples the authenticated approval and continuation, retains its 960-second runway reserve, and validates returned STS expiration. Segment two still requires at least 18,000 seconds and may request no more than 19,800 seconds. No other production, graph, credential, duration, cost, evidence, cleanup, H/G/Q, or Stage 4 behavior may change.

Establish `post_segment_two_failure_remediation` as a separate non-refilling tranche of at most 180 gross added lines and 1,000,000 gross added line-bytes across only its literal sorted paths. It does not alter the terminal 500/500 post-diagnostic or 271/300 post-authoritative-failure consumption, grants no deletion credit, and remains subject to all older repository limits.

After protected merge and exact-head CI, permit only a fresh zero baseline, one fresh first-created planning run, independent audit, one plan-bound approval, and one attempt-one campaign executing all seven cycles from ordinal 1. Canonical evidence upload and numeric-ID readback, byte equality, V4 validation, receipt readback, credential retirement, final account-wide zero, temporary IAM removal, and final independent audit remain mandatory. Stage 4 remains blocked and non-authorizing.

## Amendment 4: retire the elapsed admission window

- Date: 2026-09-28
- Decider: Nick Byrne
- Scope: terminal pre-credential generation disposition and one governance-only successor

Protected successor `24dbbab12323ed8e0f9a489411b4a6109ccfecaf` passed exact-head CI. Fresh planning `36380349043` / artifact `10952935360` (`sha256:417d7e8f8ea9b46d44e9fc49ec2334978d7145378b558b3861682f7b945f1ad2`) and plan-bound approval `36382995189` / artifact `10953661290` (`sha256:ad2e2a14c653f6884a35c644aeadb2ceb0418973866b90dd72a5631537637505`) passed independent review. Campaign `36386441695`, attempt one, then failed closed at the unchanged nine-hour admission gate. By verification time fewer than 32,400 seconds remained before approval expiry. The run failed before OIDC, STS, OpenTofu, SSM, or any AWS mutation; segment two never started. Independent account-wide inventory remained byte-identical zero with SHA-256 `f6f11122417090d4edb52e756c470ce550296e8a07a7299db01704efbf8237b4`.

Retire that planning, approval, and campaign generation, including every plan, batch, approval, token, and elapsed window. None may be rerun, retried, resumed, reused, stitched, or credited. Preserve exact H/G/Q and qualification `36036544983`; no H restart is required. The failure was an operational delay before the intentional admission boundary, not a defect in reviewed production behavior, so no workflow, helper, provider, graph, duration, cost, evidence, or cleanup behavior may change.

Authorize exactly one governance-only protected direct child of `24dbbab12323ed8e0f9a489411b4a6109ccfecaf` to record this disposition, freeze the completed segment-two tranche, establish deletion-blind direct-child accounting, and perform one deterministic readiness regeneration. Establish `post_admission_window_remediation` as a separate non-refilling tranche of at most 150 gross added lines and 1,000,000 gross added line-bytes across only its literal sorted paths. Pre-rereview generations are terminal; the final post-format generation is the sole accepted regeneration.

After protected merge and exact-head CI, require a fresh zero baseline, one fresh planning run, immediate independent audit, one fresh plan-bound approval, immediate independent audit, and one attempt-one campaign from cycle 1 while at least nine actual hours remain. Existing temporary IAM may remain until closure. All canonical publication/readback, V4 validation, receipt, retirement, cleanup, final-zero, independent-audit, and IAM-removal gates remain mandatory. Stage 4 remains separate, blocked, and non-authorizing.
