# ADR 0350: Establish replacement Q and authorize qualification

- Status: Accepted
- Date: 2026-09-14
- Decider: Nick Byrne
- Scope: exact replacement H/G static package, mixed preflight, and seven-runner local qualification; no AWS

## Context

ADR 0349 established protected control **G** `fce64662b39b2a21e9b384eba8408ecd5311047a`, tree `2827ce3f558eebdd7f7e881df32380a09403eb12`, as the sole direct child of replacement implementation **H** `1ef6aae3506fded805d8277ec4bce02e585c0650`. Its reviewed candidate tree is equal to the protected result. Required PR checks passed, then exact-G protected-main CI `34871970289` and Linux foundations `34871970287` passed.

The sole first-created trusted publisher `34872020437`, attempt 1, passed both jobs at G and consumed frozen producer `34853517895`, artifact `10352673587`, and archive digest `sha256:e28f0687ade20140f8a25ce7e55b0be2aa2f81cd04f0a4a96672d1f271d8f56c`. Publisher artifact `10359751882` has Actions archive digest `sha256:dcb20858c575704aef914923ae4676630958df1213f783f56bcdfe43aa249616`. Its six members bind descriptor `757d1ddff8b58febc5686fd81ae14d03a0bbb6eb689549da5918c5acc924a17e`, publication receipt `a4c06948c90ea513010bc47f8440cf36de16cb0ef019c0955f709d4da462291d`, immutable OCI manifest `sha256:583fc354e9a53699859f9ff28c07d433aa32395fa00ade570498b50d83bb5470`, exact Sigstore verification, all-five-member registry readback, and the canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`. Two independent audits accepted the complete producer, publisher, signature, descriptor, readback and credential-cleanup chain.

GitHub's `ubuntu24/20260907.300` release is final. Twenty-three fresh exact-G foundations runners and both publisher runners independently reported `ImageOS=ubuntu24`, `ImageVersion=20260907.300.1`, establishing fresh broad convergence before static dispatch.

The sole first-created no-KVM static observation `34876857175`, attempt 1, then passed at G on exact image `20260907.300.1`. It authenticated exact publisher custody, materialized exact H, acquired and verified immutable fixtures, generated deterministic static data without KVM or runtime launch, read back the uploaded bytes by exact numeric identity, removed all acquired state, and passed final static-boundary settlement. Artifact `10361229317` is unexpired, contains exactly thirteen safe canonical regular JSON members, and has Actions archive digest `sha256:478275cdb16c9614a32854239d98d6f9d9ce6e5cffd466b5def69a1760108b5d`.

Two independent audits reconstructed all eighty selected H sources and all thirteen static members, accepted the exact publisher chain and zero residue, and recorded these bindings:

- source manifest `09cadffc28159e2f459d0da2003648934710baed9c6a5d29132b0f0ae2300314`;
- static control `4c2e0e0377ba80a3206f91489b2420bf61688fb757b0d9de1a8090b0cc851656`;
- execution envelope `2b77e9d24d009f5b4c509cc6a5f05bd852550f9ad14584bc05139dc45e081954`;
- runtime manifest `dfd088149455789a4e3992c5211892a0256c13558273f7a154d968d539498c67`;
- ten exact executable-closure contracts;
- qualification workflow `fcd78bff59c14c932a4357c6fda7a12f91b7a09814ce22da478436efd2560ee9` and retirement selector `cf7e4c8e889595d0d020eba11bdc821d0c7d019927a5c570350024d4d235705f` as the only exact G-owned selected-source bridge.

No AWS, provider, OpenTofu, SSM, inventory, deployment or campaign operation occurred.

## Decision

Replace the historical v7 package with the exact thirteen independently read-back members from artifact `10361229317`, byte for byte and without reserialization, under `deploy/aws-feasibility/remote/stage2-completion-local-control-v7`.

Fill only the replacement H/G/source/static/descriptor custody constants in `scripts/stage2-prebuilt-local-qualification-guard.py` and `scripts/stage2-prebuilt-mixed-hg-preflight.sh`. Add the final pre-effect repository-variable interlock to the mixed-preflight workflow and sanitized script admission: exact H/G/Q inputs must equal `STAGE2_LOCAL_IMPLEMENTATION_HEAD`, `STAGE2_LOCAL_CONTROL_HEAD`, and `STAGE2_LOCAL_QUALIFICATION_HEAD`, and both actors must equal `STAGE2_LOCAL_AUTHORIZED_ACTOR`, before API census or source acquisition. This is a final H/G/Q custody seal, not new runtime authority.

Preserve the narrow binding rule: the guard itself is Q's adapter, the qualification workflow and retirement selector must equal their exact G bytes, and every other selected source must equal H. Do not broaden that bridge, change the qualification workflow, retirement policy, H-owned runtime, rootfs, image, network, lifecycle, cleanup, provider or campaign behavior, or reserialize observed data.

Add focused assertions, this decision and index, and deterministic non-authorizing readiness refresh only. The protected-main squash result becomes qualification revision **Q** only if it is one commit whose sole parent is exact G, its tree equals the independently reviewed candidate tree, every required protected check passes, and exact static bytes remain unchanged.

After Q is established and independently checked, set `STAGE2_LOCAL_IMPLEMENTATION_HEAD` to H, `STAGE2_LOCAL_CONTROL_HEAD` to G, and `STAGE2_LOCAL_QUALIFICATION_HEAD` to Q, while confirming `STAGE2_LOCAL_AUTHORIZED_ACTOR=nenb`.

Then authorize exactly one first-created attempt-one exact H/G/Q mixed preflight. It must reject a non-target image before mutation, authenticate all custody, verify ambient and use-time closures, perform no KVM operation, settle twice, and prove zero residue. Only after independent audits accept that preflight may exactly one first-created attempt-one seven-runner qualification run. Its one full ordinal, six readiness ordinals, seven exact artifact readbacks, aggregate package readback, cleanup and zero-residue proof must all pass.

## Consequences

A failed, cancelled, retried, stale, malformed, wrong-image, artifact-mismatched or cleanup-uncertain Q check, preflight or qualification grants no authority and cannot be retried into authority with identical bytes.

Q, preflight and local qualification grant no production, release, Issue 42 closure, AWS, provider, OpenTofu, SSM, inventory, deployment or campaign authority. After the qualification package and independent audits are complete, write the immutable handoff and stop immediately before `.github/workflows/stage2-production-plan.yml`.
