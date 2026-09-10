# ADR 0332: Establish image-bound Q and authorize qualification

- Status: Accepted
- Date: 2026-09-10
- Deciders: Nick Byrne
- Scope: exact H/G static package, explicit rollout-timing adjudication, mixed preflight, and seven-runner Stage2 qualification; no AWS

## Context

ADR 0331 froze implementation **H** `11c03441468d4c3130667321018e1cb6f626a303`, tree `d6a0d7f9189bcc37abcfb597a0220a7789f53d4c`, and its sole first-created attempt-one producer `34452651886`, artifact `10143009714`, archive SHA-256 `61e2a99a2ad651b954285a1310916ec22abca8300035f71a1544cfb942e25fe7`. Protected main established direct-child control **G** `a9b54c1a823601c3e938e2a616abd0222c0a2846`, tree `c3abc52d3a964d9236bfbd53bd5efd00a5c7edb6`. Two independent producer audits reconstructed the complete source and canonical 4,353-entry rootfs and accepted exact custody.

Trusted publisher `34467314193`, attempt 1, is the sole publisher dispatch at G. Artifact `10148066929` has Actions archive SHA-256 `624326096066b8e1fd8978b6c0d12a61a3ac715a450dac4f2c9af5ea87b3b8ce`. Publisher custody binds immutable OCI manifest `sha256:8188d9a1b20c61c36c37b65556616eaecc4eb3282efa0b4dab1819c44a3f6d7a`, descriptor `7e060278933ff79d0b9b40138afbf8bb9e799e6a2951b9c0c021f63069ebf71b`, publication receipt `98e4a07eea2247dbaac2d95ecf3e48ccdf21644f26ea5910faae223ef6b8ea2f`, and canonical rootfs `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`. Two independent audits accepted exact ORAS, Sigstore, archive, readback, and singleton custody.

Broad non-authorizing observations of run `34457984042`, attempts 5 and 6, and final confirmation attempt 7 each sampled 21/21 fresh runners on `ImageOS=ubuntu24`, `ImageVersion=20260907.300.1`. Their TSV SHA-256 values are `29eb46089c9745b56d4c40a1d459032dcb6b133b2728b10c25ad7180e6dee89d`, `4a96f688f93e89cf8b1af155633ce2e109d47e7af9ef2da6ab10b8198bb93841`, and `ff2e2b28fe31cef1731dcd51a9311d0b1fa40a3aba9605b9dfdb6203ff07cecf`.

The sole first-created no-KVM static observation `34486733842`, attempt 1, then succeeded at G on exact admitted image `ubuntu24` / `20260907.300.1`. It authenticated publisher custody, verified ambient executable/loader/library bytes, acquired only immutable fixtures, generated deterministic static data, read back artifact `10155984475` by exact numeric ID and archive digest, removed acquired state, and passed final static-boundary settlement. The artifact has Actions archive SHA-256 `4229c9a8acd3f54992edb39a7ccdcda0c5c23a53691e93e16cbe956fc253a068` and exactly thirteen canonical regular members.

The observed package binds H source manifest `e2e092bd14161425aacaead2abbe1eb41de50c2f78fdea3d6fffdcaf6711115f`, static control `b568b71d04002303edd77f5925e81ffb6c29f2259274ef544de1a4a478a8132d`, execution envelope `761fc8df09e3c821d40d57cd6cd6625f2287f93888777b60b7c9c25e1ae3c313`, runtime manifest `ef23ed3f27e818586e160cfecca52e30d3158f1aff521dade811c8818b11f942`, and ten exact executable contracts.

One initial audit accepted all technical custody. A second audit correctly observed that GitHub still marked release `ubuntu24/20260907.300` as `prerelease: true`; therefore the dispatch did not satisfy ADR 0330's separate timing instruction even though its actual runner and bytes were exact. The static workflow itself deliberately issued only non-authoritative comparison data. It did not mint Q, qualification, production, or AWS authority.

The rollout-completion wait was an availability safeguard against consuming an attempt-one downstream run on an old scheduler allocation. It was not the executable or byte-integrity authority: every preflight, formal-admission, seven cycle, and aggregate runner rejects any image other than exact `20260907.300.1`, and use-time closure verification rejects differing executable, loader, or library bytes. The owner explicitly chooses to accept the residual chance of a fail-closed old-image allocation rather than discard an otherwise successful exact-image static chain.

## Decision

For this exact generation only, supersede ADR 0330 and ADR 0331's requirement that GitHub first convert the public image release from prerelease to final. Do not claim that the marker had changed, forge it, or treat this as precedent for another image generation. Accept static run `34486733842` only as exact non-authoritative source data for Q because it was a sole attempt-one success on the required image, its actual closures matched, its exact artifact readback passed, and cleanup was certain. No failed or retried run receives credit.

Commit the exact thirteen independently read-back members without reserialization under `deploy/aws-feasibility/remote/stage2-completion-local-control-v7`. Fill only the previously blocked immutable H/G/static custody seals in `scripts/stage2-prebuilt-mixed-hg-preflight.sh` and `scripts/stage2-prebuilt-local-qualification-guard.py`, update their focused assertions, this decision and index, and deterministic non-authorizing readiness evidence. The qualification workflow and all H-owned runtime, rootfs, image-admission, grant, lifecycle, cleanup, contract, and retirement bytes remain unchanged.

Require the protected-main squash result to be one commit whose sole parent is exact G and whose tree equals the independently reviewed candidate. Freeze that result as qualification revision **Q** only after required protected checks pass.

After Q is established and independently checked, set the exact H/G/Q repository variables and authorize exactly one first-created attempt-one H/G/Q no-KVM mixed preflight. It must authenticate v7 and exact publisher/static custody, reject a non-target runner before mutation, verify host closures before acquisition and at use, normalize hosted `/opt`, complete immutable preparation without KVM, perform mandatory settlement twice, and succeed without artifact authority.

Only after two independent audits accept that exact preflight may one first-created attempt-one seven-runner formal qualification be dispatched with exact H, G, Q, and preflight run ID. Each ordinal must independently authenticate H/G/Q and v7, reject a non-target runner before mutation, execute exactly one ordinal-bound Kata/KVM lifecycle, publish exact cycle custody, and prove fail-closed cleanup. The aggregate must authenticate all seven numeric artifacts and issue only the pre-AWS qualification package.

## Consequences

The public runner-image release may remain a prerelease; this decision grants no assertion otherwise. Any mixed-preflight or qualification failure, cancellation, retry, wrong-image allocation, malformed dispatch, missing or mismatched artifact, cleanup uncertainty, persistence uncertainty, or residue grants no authority. Per the owner's instruction, stop immediately on such a failure and report it rather than rerun.

Q or successful qualification grants no production, release, Stage3/Stage4 exit, OpenBao production qualification, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority. After the seven-runner qualification and independent audit, write the final non-AWS handoff and stop immediately before AWS.
