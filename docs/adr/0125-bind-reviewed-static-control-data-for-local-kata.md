# ADR 0125: Bind reviewed static-control data for local Kata

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Directional control revision G and one replacement local KVM qualification

## Context

Non-KVM static-control run `32577727971`, attempt 1, succeeded at implementation H `59d992b305cfd243f2d7b9c770fe24b0a36cc053` under workflow revision `c2540af5cb85e2845de1eebfad3475d28c0483e5`. Exact artifact ID `9477015379` was downloaded independently. The ZIP SHA-256 is `003a767ba419a9e5c566728731b7daf5826208d96e9b3e57376fb4c62c536259`; its control SHA-256 is `388618877fab7343e687db88dde5b47326a424810fb1493927381951c7c8c45e`. Private custody is `/Users/nenb/.pi/artifacts/cogs/issue42-static-control-32577727971`; custody-manifest SHA-256 is `5c62b47e5db9e63c61059252a22e6fd426bfbba5ff4b0d403d286e4b114041d6`.

Independent strict loaders validated the control, envelope, runtime manifest, ten executable closures, exact member hashes, directional H binding, package pin, rootfs identity, and canonical bytes. Draft 2020-12 schemas validated the three top-level members. The observation used no KVM/runtime/network/SSH or AWS/provider surface.

## Decision

Commit the exact 13 artifact members as `deploy/aws-feasibility/remote/stage2-completion-local-control-v2`. Fill the qualification guard only with the reviewed immutable values:

- implementation H: `59d992b305cfd243f2d7b9c770fe24b0a36cc053`;
- source manifest SHA-256: `09b566a522a3d97983227b679b15f80ead189271617dbcbc70e5e1639250294d`;
- control SHA-256: `388618877fab7343e687db88dde5b47326a424810fb1493927381951c7c8c45e`;
- unchanged qualification workflow SHA-256: `8cdfae74dc7913df8f75814c5e78d83d5e018cca3b9fd925cb04b87d35826c6b`;
- qualification-result schema SHA-256: `27d60133f202d9c32381d2b3dc8fe281334dc67d59dc8d72b402e6b7ca825375`.

The resulting revision G may authorize exactly one first-created attempt-one dispatch of the dedicated local Kata workflow after exact-head CI and review. Repository variables must equal reviewed H, exact G, and the authorized actor. Any failed, canceled, stale, retried, artifactless, or cleanup-uncertain observation grants no claim and no retry.

## Authority boundary

This authorizes only the previously approved distinct replacement Stage 2 hosted KVM/Kata qualification. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, or release authority. The process must stop before any AWS operation.
