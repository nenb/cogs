# ADR 0305: Freeze final H and authorize G control observation

- Status: Accepted
- Date: 2026-09-06
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

ADR 0304 required diagnostic convergence before one clean authoritative chain. Protected-main implementation H is `8a1b56cfdaf013b27d8ef7a7e2753d3bb2582271`, whose sole parent is retired Q3 `06188f67a9a699924d645ce8aa0e91950b6341c7`. H protected CI runs `34001754058` and `34001754071` passed. No-mint diagnostic run `34003172790`, attempt 1, passed independent full and readiness lifecycles at exact H. The full route completed 21 measurements; both routes passed recovery, settlement, zero-residue, scaffold-restoration, and final-observation tails. It produced zero artifacts. Two independent audits passed.

Producer `34007531193`, attempt 1, is the sole producer at H. Admission, two byte-identical builds, and independent exact readback passed. Artifact `9981717931` has archive SHA-256 `0bc8ed4d5a93de47a4fe42d02b2c71a5eabfb9cb9f3ceecb3e9b43d92a28c491`; source manifest `80fd06033af09483730f15ecbda14aa342db4d3bc475fe55d1acc66ba52702f9`; receipt `3f92d64f814a69d45d356568a597c590a1cde899a3ea93aa4bb927626b045d34`; package `1692d24b909154e135a12477b000be2363349dfdd1143021a3bd72ce13130efb`; provenance `c670150c8127b3c0b16c2be4f774423ef915b8d99be909eecb016da79e7253ab`; and log `02eb9488ec941b3ec8c9f8c956181e490e1b6d51bc36a29530f16c9e189e1dd6`.

The canonical rootfs remains 4,353 entries with ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`, manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`, metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`, and sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`. Two independent producer audits passed.

## Decision

Freeze H. Establish this commit's protected-main squash result as G only if its sole parent is H and protected checks pass. G binds H and the exact producer observation and clears every retired H3/G3/Q3 authority.

After G protected checks pass, authorize exactly one first-created attempt-one publisher for producer `34007531193`, artifact `9981717931`, and archive digest `sha256:0bc8ed4d5a93de47a4fe42d02b2c71a5eabfb9cb9f3ceecb3e9b43d92a28c491`. Only after successful publisher audit authorize one first-created attempt-one no-KVM static observation at exact G. Independently audit both before committing exact read-back bytes as direct-child Q.

## Consequences

H and G grant no mixed preflight, formal qualification, AWS, provider, OpenTofu, SSM, inventory, or production authority by themselves. Failed, diagnostic, and retired generations remain non-authorizing.
