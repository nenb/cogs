# ADR 0307: Freeze bootstrap-corrected H and authorize G

- Status: Accepted
- Date: 2026-09-06
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

ADR 0306 retired the first final chain and corrected production bootstrap custody. Protected-main H is `8907eba3191d07573cd84573cb0b2adddff17bd6`, whose sole parent is retired G `69987e08cf9454fecf540a4de097f0877155b043`. H protected checks `34021524321` and `34021524322` passed. Exact-H no-mint diagnostic `34023790672`, attempt 1, passed independent full and readiness lifecycles, all cleanup tails, 21 full measurements, and produced zero artifacts. Two audits passed.

Producer `34028384783`, attempt 1, is the sole producer at H. Two byte-identical builds and exact readback passed. Artifact `9988125363` has archive SHA-256 `fb63a17959ad335bf0a53cb60b9548dd562f8b1a2ef5433bd27f25f1070900f3`; source manifest `f437ba77c1aac3b9abf96f5332c17edf74e258cdc9477b0bb1d2f47931cd22f3`; receipt `f7bd4257b5815144f98e5661686e4f31af965f5ae3a70ec27594c50e401c6f79`; package `5334c0aed21e5bab9f80ff7596d1c1cc7710d9d54ff8aae2b6bd99c839327307`; provenance `11523d82ff614009d33f7af55ed2f22ba3df761747ae5301f46df67f6ca0bab3`; and log `5d5331e99651a808ee1578e4ded373976b688fee7790fd37b1e842cb4e89bdc3`. Two audits passed.

## Decision

Freeze H. Re-anchor no-deletion-credit accounting at H's measured deploy/retained/workflow gross values `21,948/11,844/4,836`; G then measures 94,002 below the 94,100 hard stop. Establish this commit's protected-main squash result as G only if its sole parent is H and protected checks pass. G reserves additive v5 package custody and clears stale qualification constants.

Then authorize one first-created attempt-one publisher for producer `34028384783`, artifact `9988125363`, and archive digest `sha256:fb63a17959ad335bf0a53cb60b9548dd562f8b1a2ef5433bd27f25f1070900f3`. Only after publisher audit authorize one first-created attempt-one no-KVM static observation at exact G.

## Consequences

H and G grant no preflight, qualification, AWS, provider, OpenTofu, SSM, inventory, or production authority.
