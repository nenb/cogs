# ADR 0134: Preflight runtime extraction and bind the third KVM failure

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Correct the pre-KVM failure of run 32596053811

## Context

Exact H `a2c25f34c35d778965ab7b125fd3b8b4460b0617` and G `06a1d5124c68a34f80b932ed02173afa1bad365c` passed review and CI. Attempt-one run `32596053811` passed first-effect admission but failed during immutable preparation. The sole KVM/Kata entry was skipped, no report or receipt artifact existed, recovery and fixed-root cleanup steps completed, and the independent residue command returned a failure output. Cleanup certainty is therefore not claimed. Private failure-custody SHA-256 is `1cca92343d4bd038bf80b9349d1b93c206b9e1643f4861b9b55b75f4f1a2ca42`.

The immutable extractor previously delegated `.tar.zst` selection to GNU tar through `PATH`, did not preflight the exact extractor path or capacity before creating transaction state, and emitted only an undifferentiated failure. A pinned-container reproduction confirmed that a missing `zstd` makes extraction fail and leaves deliberately uncertain partial extraction state. The hosted run's exact internal stage was not observable, so no narrower success claim is made.

## Decision

Before creating immutable transaction state, require root-owned, non-group/world-writable executable `/usr/bin/tar` and `/usr/bin/zstd`, at least 12 GiB available extraction capacity, and at least 200,000 available inodes. Invoke zstd by absolute path using GNU tar's fixed `--use-compress-program=/usr/bin/zstd` form. Emit only one bounded allow-listed immutable-preparation stage on failure; do not expose exception text or unbounded diagnostics.

Add similarly bounded stage-only diagnostics to independent settlement without weakening any residue predicate. Bind run `32596053811` as the third exact completed/failure predecessor in first-effect admission. Missing, changed, retried, or extra history remains rejected.

Because immutable preparation belongs to implementation H, the correction requires a fresh reviewed H, one fresh no-KVM static observation, and a later directional G before any replacement KVM dispatch. The failed run and the prior static package grant no retry, KVM, cleanup, promotion, or release claim.

## Authority boundary

The correction, static observation, and one reviewed replacement local KVM dispatch remain within the owner's standing non-AWS instruction. No AWS/provider/OpenTofu/SSM/inventory/campaign operation, deployment, production, promotion, or release is authorized.
