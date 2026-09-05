# ADR 0300: Retire the first H/G/Q preflight and normalize hosted `/opt`

- Status: Accepted
- Date: 2026-09-05
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

The first exact H/G/Q preflight, run `33965298642`, attempt 1, executed on protected main at Q `728a77a87328e9cccd57547a930e84764964061f`. It authenticated H `d2fe08553d25d73fa276794c96b0f311e5406186`, G `a108f981dacad6978e2a37d16a143da5c3b51cf4`, and Q; completed immutable preparation without entering KVM; and failed during cleanup-only recovery.

The GitHub Ubuntu runner exposes `/opt` as the exact hosted scaffold `root:root:0777`. The mixed preflight omitted the normalization already required by the successful rehearsal and formal qualification paths. Static recovery correctly refused to retain `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml` through a world-writable ancestor and raised `untrusted admitted directory`. Both recovery attempts therefore failed before supervised fixed-root deletion, residue proof, or scaffold restoration. Ephemeral runner disposal is not evidence of cleanup. Full log SHA-256 is `a361a310545de37af60ecd24d14244a5dae8ba8214ea09954bbcdf6722f3a7d4`.

## Decision

Run `33965298642` and its H/G/Q tuple are permanently non-authorizing and must not be retried. Preserve the strict trusted-directory check.

The replacement mixed preflight must require `/opt` to be exactly `root:root:0777`, normalize it to `0755` before immutable preparation, and verify the result. An unconditional final step may restore `0777` only after settlement has run, `/opt/kata` is absent, and `/opt` is exactly `root:root:0755` or already restored; every other state fails closed. Tests bind ordering and exact modes.

Freeze the corrected append-only revision as H2. Re-establish an H2-bound producer, direct-child G2, publisher/static observation, and direct-child Q2 before one new attempt-one preflight. Historical rootfs and static bytes remain facts but cannot authorize the replacement tuple. No KVM qualification may start until that replacement preflight succeeds.

## Consequences

The correction does not weaken ancestry, first-attempt, cleanup, residue, or immutable-custody rules. It grants no AWS, provider, OpenTofu, SSM, inventory, or production authority.
