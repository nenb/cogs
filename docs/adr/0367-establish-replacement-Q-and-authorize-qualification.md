# ADR 0367: Establish replacement Q and authorize qualification

- Status: Accepted
- Date: 2026-09-24
- Decider: Nick Byrne
- Scope: complete accepted static handoff, direct-child Q, mixed preflight, and seven-runner qualification; no AWS

## Context

ADR 0366 froze H `ba085947eaee321dfb724d94169d42bc36d397b0`, producer `35990583990`/artifact `10804234912`, and required G to be H's sole child. Reviewed candidate `5d38bc8950c3ec431a5e64df6b96be4a3f5ee2f6` passed PR CI `35995814304` and Linux foundations `35995814272`; its tree `25c2b7cb37e0d3d8214f3af52dd9ca7758d52b7f` merged as protected G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, whose sole parent is H. Exact-G runs `36000592000` and `36000592011` then passed attempt one.

The sole first-created attempt-one publisher `36006546962`, artifact `10810159633`, passed after those checks. Independent audit accepted archive `sha256:6d82101f82eb6689110e29851ac34af4bdb3b4576b59986b75e500ca4e9129ca`, OCI manifest `sha256:73c96853933b580ec0109c80642e07846653ad040255f7273349615fd69afda2`, descriptor `88b33740b2782240c894a8b1abf0988f5e65e0343cfda3cb1811affe1e8ca615`, publication receipt `abab23a3daa4dd50b8f7558479568cf50e7f27bb2a11dd20694ce9bdb658c5b2`, signature verification `6e6665423ebbfc698e46d7556ba0b0e637e8681c1d5be898703ec9425845f301`, workflow `ba0ee6460036de3ab923442227bcd9882573cad8b21fff1eb081b0641bada9af`, and audit record `68134ae3dda4cc7950ee372cb59ca7ddde415fe04dac8a62ed23600614433e54`.

Only afterwards the sole first-created attempt-one static run `36008194540`, artifact `10811168115`, passed on authenticated image `ubuntu24/20260920.314`. Independent schema and production validation accepted its exact thirteen members, archive `sha256:e2ac2d812d9695eaa79fa99e58271573188e58900db46697716a5efea24973f3`, control `28ea28ef436623f202f056638ad712ed885ed1d121ecf1eb314f7c41b1a76555`, envelope `57d3f080669614d4eb83e17577bed801087808c9b6af606adb8f3b5117ba01d6`, runtime manifest `e8d83c913c924fef5e45d4292fa0b53c1dd25f1917fbe403e000bc819e71682d`, source manifest `cf15e437888f7c1c2808e113576d3592bef40e39c9a88db199f0ca6a38986bb9`, static workflow `3ae5293bf3a94712df10d226ddcf900aa4cb057337fa31b45e0a1bddc089e024`, runtime boundary `8bbd5d19b569a8974b3d6691d68bf25b69b56926f7984173acda6cc43a60c6f0`, and audit record `52692aa87ed60252fafb8a9279f1103229f0b15ab4bb62e2e74c1463698172db`. No producer, publisher, or static AWS/provider/KVM effect occurred.

## Decision

Copy those thirteen accepted static members byte-for-byte into control V7. Bind H, G, producer, publisher, static custody, archive/control/source digests, descriptor, and H-reviewed qualification workflow `072a3fae20654df37aa532c42933bca18ecaa5e1fbe62ca68fe16bde0bb75cfa` in Q's fail-closed guard and mixed preflight.

Establish Q only as one reviewed protected commit whose sole parent is exact G, whose merge tree equals the reviewed candidate tree, and whose protected PR and fresh exact-main checks pass. Consume the last reserved deterministic readiness generation by changing `PRODUCT_TEST_PENDING_READINESS_REGENERATIONS` from 1 to 0; retain every ceiling, forecast, tranche, source/inventory bound, and deletion-blind charge.

After independent post-merge acceptance, authorize exactly one first-created attempt-one mixed H/G/Q no-KVM preflight. Only its independently accepted success may authorize exactly one first-created attempt-one seven-runner qualification at Q; each assigned runner image must be officially authenticated before source effects, and the existing terminal-generation and cleanup rules remain mandatory.

## Consequences

Any Q check, preflight, or qualification failure, retry, mismatch, image rejection, or uncertain cleanup is terminal and grants no continuation. This decision grants no IAM, AWS credential, planning, approval, provider, OpenTofu, SSM, production, Stage 4 execution, or Issue 42 closure authority.
