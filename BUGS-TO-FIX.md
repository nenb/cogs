# Bugs to Fix

Status: explicitly accepted and deferred by the owner for the single bounded Issue #42 Stage 2 campaign. These findings remain recorded work; this disposition does not claim that they are fixed, authorize a retry, close Issue #42, or grant Stage 4 authority.

Protected R was documentation/governance only. The later R3 and R4 corrections, R5 governance-only successor, R6 campaign-admission correction, R7 governance successor, and R8 executor-permission guard were limited to the production approval and planning control plane, synchronized tests, additive retirement history, and deterministic readiness evidence; none changed H, G, Q, or the qualified implementation. Section 10 separately permits an H-owned provider correction only in a non-authoritative diagnostic candidate before any fresh formal H/G/Q process.

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

## 9. Retire failed R7 campaign and close the missing executor permission before effects

Protected R7 `6a28492a70ee3b0eaffa57e8355070ee865492b9`, tree `e52a42a82456182d5a0e5cb618b2430d3550d74f`, passed exact-head attempt-one CI `35269083825` and Linux foundations `35269083795`. Sole read-only planning run `35275965649` produced artifact `10519889589` (`sha256:22948dfcc672cd9ec2c15457d205fde5f8a79e6784d9e295d2f63e3f50a9acb5`) and seven accepted plans under batch `1e6f37299df6bd92ced863afca4b5298b61311f1a43cd5a4da1f5a0905f31151`. Sole authenticated approval run `35278527916` produced verified artifact `10521084322` (`sha256:43e775acd96f7994612c6db70370d97e921fe42e2039586731647ad911ef9fe7`).

Sole attempt-one campaign run `35281016121` created the first cycle graph, then failed during OpenTofu apply before a provider apply receipt, SSM command, workload, or measurement. Its cleanup-only recovery also failed before any delete call. CloudTrail independently recorded `budgets:ListTagsForResource` `AccessDenied` during create readback, apply refresh, and recovery refresh. The temporary executor policy allowed Budget modification, tagging, untagging, and viewing but omitted the distinct provider-required tag-read action. Pinned provider v6.54.0 propagates this tag-read error from its Budget read, so apply could not settle and recovery could not reach destroy.

The instance was terminated and every exact batch-owned volume, network interface, VPC, subnet, gateway, route table, security group, launch template, two campaign roles, instance profile, termination schedule, and budget was independently identified and deleted. Repeated independent inventory returned total zero by `2026-09-17T22:23:06Z`. The three temporary GitHub OIDC roles and ARN variables were then removed. No evidence artifact exists, no cycle succeeded, and R7 planning, approval, and campaign bytes are terminal and permanently non-authorizing.

Disposition: permit one direct-child protected R8 correction. Before any resource effect, the campaign must use the acquired executor identity to call `budgets:ListTagsForResource` on an exact nonexistent `cogs-s2-permission-probe-<run>` budget ARN, require the authorized `NotFoundException`, and reject `AccessDenied`. Fresh IAM bootstrap must add and simulate `budgets:ListTagsForResource`. R8 must preserve exact H/G/Q, the 16,500-second guard, planner, approval issuer, controller, provider, Terraform graph, deadlines, costs, terminators, and evidence formats. R8 grants no same-byte retry or inherited authorization: protected CI, fresh IAM setup, fresh read-only planning authorization, authenticated approval authorization, and a fresh destructive phrase remain mandatory.

## 10. Retire failed R8 and require a complete non-authoritative R diagnostic before another H/G/Q chain

Protected R8 `fff2b20f89b1aae26158376104ada8425f8a0d19` passed exact-head CI `35289516189` and foundations `35289516201`. Sole planning `35293994076` produced artifact `10526314592` (`sha256:6d4c5deb521734dcde4ecbca203fdf1b94f7d945fe586a7e110ee9214c29130d`); sole approval `35295519831` produced artifact `10527701595` (`sha256:7b1ecc45c2818c884ae112d8ca28b7431585612bc909100d05a90f87ba163b5f`). The sole campaign `35297082154` passed the corrected Budget permission probe, created cycle 1, and sent SSM command `06a3f62c-20b4-4bfa-9f75-b45e2196bacc`. The command failed with exact diagnostic `immutable Stage 2 preparation failed at entry` before Kata, workload, measurement, or evidence.

The H-owned AWS provider directly invoked immutable preparation inside the AWS SSM ambient environment. The immutable preparer intentionally rejects every `AWS_*` and acquisition-authority variable. The provider must use fixed `/usr/bin/env -i` values before `/usr/bin/python3 -I -B`, with a hostile SSM-environment regression test.

The cycle-1 graph was destroyed. Repeated independent inventory returned exact zero, the terminated instance has no volume or ENI, all temporary roles and ARN variables were removed, and no static credential exists. R8 planning, approval, campaign, and destructive authorization are terminal and permanently non-authorizing.

Disposition: before another formal H/G/Q chain, permit one protected non-authoritative diagnostic candidate containing the clean-environment correction, executable regression coverage, separate diagnostic planning/signing/campaign workflows, synchronized governance, and deterministic readiness refresh. The diagnostic must use distinct phrases and `NON-AUTHORITATIVE` artifact names, set production and Issue 42 eligibility false, refuse formal workflow runs at its revision, execute the same seven-cycle AWS path, validate generated evidence privately, publish only a digest manifest, and retain all cost, deadline, recovery, independent observer, destruction, and zero-inventory controls. Preparation grants no AWS resource effect. A real diagnostic campaign requires `authorize-seven-stage2-non-authoritative-diagnostic-cycles`. Only a seven-cycle pass may allow the exact unchanged candidate bytes to enter a fresh formal H -> G -> Q process; the diagnostic itself grants no production or closure authority. Raise only the tracked-file high from 1,543 to 1,545 for the two literal diagnostic workflow files. Reallocate 300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making their active byte highs 5,000,000 and 6,700,000; all line highs, tranche totals, forecasts, serialized-inventory bounds, and global source-byte limits remain unchanged.

## 11. Retire the first diagnostic candidate after planning-export readback failure

Protected diagnostic candidate `8f1bf3032668c6f986fa31145911a42c0ece7925`, tree `a9d3635aa67be3d047f97dc57a9e2c7242d1b140`, passed exact-head CI `35354704622` and foundations `35354704494`. Fresh account-wide inventory found zero active resources in all 17 enabled regions. Sole attempt-one diagnostic preparation `35369019149` authenticated the exact fixture, used only read-only planning, produced seven plans, and uploaded non-authoritative artifact `10557980075` (`sha256:3cd400242d442cbb741d50a3e737c4e1cce87cbcf61dcf41612755c91c5fc862`). It failed before approval issuance because exact readback found that `actions/upload-artifact` omitted the planner's hidden, explicitly unstaged `plans/.provider-tf-data` bootstrap cache.

No signing, approval artifact, campaign dispatch, resource creation, OpenTofu apply, SSM, Kata, workload, or measurement occurred. Exact inventory remained zero, and all temporary roles and ARN variables were removed.

Disposition: the run, artifact, plans, window authorization, and candidate are terminal and permanently non-authorizing. Permit a direct-child correction that removes only the verified disposable provider-bootstrap tree after planning, rejects every remaining hidden planning path, and retains exact readback over the bytes that cross the artifact boundary. It must preserve all planner, provider, adapter, fixture, signer, campaign, graph, deadline, cost, recovery, and evidence behavior. The correction receives no IAM, workflow retry, planning, signing, approval, campaign, or AWS authority. A fresh `start-stage2-r-diagnostic-window` is required after protected merge; destructive authority remains separate. Reallocate 300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making their active byte highs 4,700,000 and 7,000,000 while keeping all line highs, totals, forecasts, source limits, and the global high unchanged.

## 12. Retire the replacement diagnostic after approval-issuer environment failure

Protected candidate `ce4b5895e16e882067cd01bc258394e25bc42048`, tree `bb324ac7763caca746e734353d7b60257f2c5ec7`, passed exact-head CI `35377483991` and foundations `35377483993`. Sole attempt-one preparation `35390352878` generated seven plans, normalized the export, passed exact readback, and uploaded non-authoritative planning artifact `10566006682` (`sha256:65ed5766f877e3302a2d3f0c96c685269827305bf54d1586b96971c94526ea18`). Approval issuance then failed before signing because the diagnostic workflow provided `CONTROL_HEAD` but not the issuer's required `COGS_STAGE2_CONTROL_REVISION` environment name.

No approval artifact, campaign dispatch, resource creation, OpenTofu apply, SSM, Kata, workload, or measurement occurred. Exact inventory remained zero, and all temporary roles and ARN variables were removed.

Disposition: the candidate, run, artifact, plans, and complete-run authorization are terminal and permanently non-authorizing. Permit only a direct-child correction mapping the already authenticated control input to the issuer's closed environment name, with a synchronized workflow assertion. Preserve all executable R-path bytes and require one fresh upfront complete diagnostic authorization after protected merge. Reallocate another 300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making active byte highs 4,400,000 and 7,300,000 without changing line highs, totals, forecasts, source limits, or the global high.

## 13. Retire cancelled post-merge checks and batch complete diagnostic audit assertions

Protected main `3be83879c87b552f7cdb07480ceda5e843add905`, tree `570b8f4c527d8156ca14d4db389a999f060be70a`, contains the approval-environment correction. Its identical-tree PR CI `35392818607` and foundations `35392818603` passed. At the owner's request to stop further CI before a complete local diagnostic audit, post-merge CI `35397053515` and foundations `35397053474` were explicitly cancelled. The cancelled exact-head generation is terminal and cannot borrow its PR checks or be retried into authority.

The no-cloud audit downloaded artifact `10566006682`, matched its digest, verified seven distinct plan binaries, validated every plan JSON and staged binding, and successfully ran the real approval issuer and authenticator over the exact bytes that had failed. Forty-one focused tests passed across every diagnostic workflow and R-path owner. Normal and recovery entries preserved the diagnostic selector under their exact clean environment. Every input, environment, artifact, signer identity, staging call, overlay, controller/provider entry, recovery path, evidence validator, and authority-negative publication handoff was reviewed. No additional diagnostic defect was found. No workflow or AWS operation occurred; exact inventory remained zero and temporary roles and ARN variables remained absent.

Disposition: permit one replacement candidate containing only durable entry/recovery and handoff assertions, this audit record, synchronized accounting, and deterministic readiness refresh. Preserve all R-path implementation bytes. Complete local validation must precede one protected PR and exact-main check sequence. No IAM or AWS workflow is authorized. After a clean candidate, one later `authorize-complete-stage2-r-non-authoritative-diagnostic` may cover the entire preparation-through-cleanup rehearsal without intermediate permission requests. Reallocate 300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making active byte highs 4,100,000 and 7,600,000 without changing line highs, totals, forecasts, source limits, or the global high.

## 14. Retire the failed timeout-corrected formal qualification generation

Formal qualification `35685410662`, attempt 1, ran all seven independent KVM cycles successfully at H `d98571b9f2be446ed478464d23df532d91b94e53`, G `431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33`, and Q `17380562a9fb9f7d08bea0269a9fdc5812b1faf7`. The aggregate then failed closed before package publication because cycles on distinct host boots legitimately reused host-local PID/device/inode mapping values. No planning, IAM setup, approval, campaign, provider, or AWS effect occurred.

Disposition: the complete generation, run, and seven cycle artifacts are terminal and permanently non-authorizing. They cannot be retried, stitched, resumed, or reinterpreted as accepted qualification. Apply the same host-boot scope to QEMU runtime, live-mapping, and process-fact observations in local aggregation, production reduction and issuance, and public evidence validation while retaining every global identity and independent-cycle gate. Additive retirement V4 and complete review must precede a wholly fresh H -> G -> Q chain and exactly one new qualification. IAM, planning, approval, and AWS remain denied until that fresh qualification passes independent audit.
