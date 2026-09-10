# ADR 0332: Retire premature rollout static generation

- Status: Accepted
- Date: 2026-09-10
- Deciders: Nick Byrne
- Scope: premature Stage2 static observation, complete generation retirement, and one replacement non-AWS chain

## Context

ADR 0331 froze implementation H `11c03441468d4c3130667321018e1cb6f626a303`, its sole attempt-one producer `34452651886` and artifact `10143009714`, then established direct-child control G `a9b54c1a823601c3e938e2a616abd0222c0a2846`. Trusted publisher `34467314193`, attempt 1, succeeded with artifact `10148066929`, archive SHA-256 `624326096066b8e1fd8978b6c0d12a61a3ac715a450dac4f2c9af5ea87b3b8ce`, and immutable OCI manifest `sha256:8188d9a1b20c61c36c37b65556616eaecc4eb3282efa0b4dab1819c44a3f6d7a`. Two independent audits accepted producer and publisher custody.

Ordinary non-authorizing runner observations progressed from mixed samples to three consecutive broad samples of 21/21 runners reporting `ImageOS=ubuntu24` and `ImageVersion=20260907.300.1`. Static observation `34486733842`, attempt 1, was then dispatched at G. Its only job succeeded, removed acquired state, and published artifact `10155984475`, archive SHA-256 `4229c9a8acd3f54992edb39a7ccdcda0c5c23a53691e93e16cbe956fc253a068`, containing exactly thirteen canonical members.

A required hostile audit found that sampled convergence did not satisfy the complete ADR 0330 prerequisite. Completion had not been positively established before dispatch. At the first hostile audit after dispatch, GitHub release `ubuntu24/20260907.300`, release ID `384601141`, still had `prerelease: true`; a fresh response at 2026-09-10T14:39:03Z confirmed the same state. GitHub therefore continued to mark deployment underway. ADR 0330 explicitly prohibited beginning the successor static observation while GitHub marked rollout incomplete. Structural success, exact cleanup, and an admitted runner image cannot retroactively authorize a prematurely started observation.

The retained private evidence bindings are:

- broad non-authorizing run `34457984042` attempts 5 and 6 at 2026-09-10T13:19Z and 13:53Z, each 21/21 target images; TSV SHA-256 values `29eb46089c9745b56d4c40a1d459032dcb6b133b2728b10c25ad7180e6dee89d` and `4a96f688f93e89cf8b1af155633ce2e109d47e7af9ef2da6ab10b8198bb93841`;
- final-confirmation attempt 7 at 2026-09-10T14:04Z, 21/21 target images, TSV SHA-256 `ff2e2b28fe31cef1731dcd51a9311d0b1fa40a3aba9605b9dfdb6203ff07cecf`;
- accepted producer audit SHA-256 values `b4c9071d3a318b1e84bd1fd4da3d2c0458cf05152a2432004dd80c2f4ce411b6` and `a334bf96a600a8d87a5744bb8ba7e177bef338abbe9c2284735208ed99557886`;
- publisher audits `05d16361894669f0b8db3d689930fb9e4886c557593b3974feb7bef305b59d42` and `c7e4690326453f6e94c097c0835f4457c3222168f31d9f1d345ed38ac09645bc`, with textual log SHA-256 `f840589de60c5d56c26ceba1959757404792ab2a6b7affdf3b281414b19cf5a0`;
- static audits `e23bf9f33f030759dafa0ce98e690f4fcf0a6ea6131f8d6db8f24f4afd158526` and `e0becb13f6efce42dfea8335b0c06ef1dbab84804f262c24e6226bd66b385013`, with textual log SHA-256 `c5afced562522786c90dce6e3c4fea624fedb1c24831e435fa8137e863e2ada7`;
- the bounded post-static HTTP response and headers, including GitHub Date and ETag, SHA-256 `1b48591e6fc4ec84c6014c41152e394e5f653dc970f63c762ee6995b3a84001a`.

These bindings preserve diagnosis and do not convert private files, expiring Actions artifacts, or mutable release metadata into authority. Exact downloaded producer, publisher, and static archives remain in private evidence custody; their public Actions copies currently expire on 2026-09-17.

The run performed no KVM/runtime launch and no AWS, provider, OpenTofu, SSM, inventory, deployment, campaign, or production operation. Its package is diagnostic historical evidence only and cannot become v7 or Q.

## Decision

Permanently retire the complete premature generation:

- revisions H `11c03441468d4c3130667321018e1cb6f626a303` and G `a9b54c1a823601c3e938e2a616abd0222c0a2846`;
- runs `34452651886`, `34467314193`, and `34486733842`;
- Actions artifacts `10143009714`, `10148066929`, and `10155984475`.

Preserve all bytes, logs, OCI content, signatures, and prior tombstones as immutable history. Do not retry, relabel, delete for credit, reuse custody, or blacklist the content-identical canonical rootfs layer. Retirement is an exact selection veto, never an ancestry veto or authorization grant. The central policy, closed Python copy, and all nineteen pre-effect workflow mirrors must agree on 29 revisions, 36 runs, and 26 artifacts.

Authorize one replacement implementation H whose substantive correction is an executable pre-effect release-completion gate in the static workflow. After exact retirement and hosted-image checks but before checkout, acquisition, fixed-root mutation, or singleton credit, it must fetch the exact public `actions/runner-images` release object and require:

- release ID `384601141` and node ID `RE_kwDOC1mGT84W7Iw1`;
- tag `ubuntu24/20260907.300` and target commit `fc63e1b4dbfacf7e2449bf0706226f9f6eea583e`;
- exact release name, `draft: false`, and `prerelease: false`.

It must emit only the bounded selected release fields to the log. Failure is before repository checkout or host mutation and grants no cleanup, retry, or observation authority. Human pre-dispatch review must still confirm the marker and broad fresh all-target observations; the executable gate is not permission to burn generations speculatively.

The replacement H must bind the exact corrected static-workflow SHA-256 `57aee5208eb2f8cc7b0f40fd6edcaabc7b226c5c83b6bbba56672cffd3f76b3b` in the static runtime boundary. After full local/Linux checks, deterministic readiness regeneration, accounting, broad review, and two exact-tree reviews, merge one protected H. Then require a fresh producer, sole-parent control G under ADR 0333, fresh publisher, and one static observation only after the public release is final and fresh broad samples remain all-target. ADR 0334 is reserved for exact v7 Q and qualification authority.

Raise only the remediation global gross high from 30,000 to 30,500 and integration owner high from 12,500 to 13,000. Add ADRs 0333–0334 to the prior single-ADR reservation, raising integration planned-new files from 81 to 83, total planned-new files from 89 to 91, and tracked-file high from 1,509 to 1,511. All other hard ceilings and no-deletion-credit rules remain unchanged.

## Consequences

The retired static artifact is non-authoritative and must not be copied into v7. No Q, mixed preflight, formal qualification, production, release, Stage3/Stage4 exit, OpenBao-production, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority exists. After a successful replacement non-AWS handoff, stop immediately before AWS.
