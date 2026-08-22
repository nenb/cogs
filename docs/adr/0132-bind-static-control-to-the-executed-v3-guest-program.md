# ADR 0132: Bind static control to the executed V3 guest program

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Correct a pre-KVM cross-boundary identity mismatch

## Context

Hostile review of proposed control revision `84853f7817378739d7ebfe20e4d7593c4e1d42d7` found that static preparation used the SHA-256 of the complete historical V2 Python source file as `guest_program_sha256`. The actual SSH route executes the exact V3 guest stdin and terminal evidence correctly requires V3 `GUEST_PROGRAM_SHA256` `990f3a2cb57121a4aab2fb79b347bc3904082572ef8177f3c2d79c28d96e3db1`. The values cannot be equal, so dispatch would have consumed the sole generation before terminal evidence. No KVM dispatch occurred for the proposed revision.

Static run `32590966571` and artifact `9480330947` remain valid only as a non-KVM observation of the now-rejected H3 contract. They grant no KVM or promotion claim and cannot be reused for the corrected implementation.

## Decision

The V2 static envelope's additive `guest_program_sha256` field means the digest of the exact bytes issued as guest stdin, not a module source-file digest. Static preparation must obtain verified bytes from `completion_guest_workloads_v3.guest_program_bytes()`, independently hash them, and require equality with V3 `GUEST_PROGRAM_SHA256`. Admission must independently repeat the same exact-byte check.

Historical V1/V2 workload modules and schema shapes remain unchanged. The V3 route remains additive. A hostile cross-boundary test must feed the exact producer-generated result-binding base into the terminal evidence validator and prove acceptance only when its guest identity equals the executed V3 stdin digest.

Restore the rejected committed control package and KVM guard to the prior protected-main state. Treat the final implementation revision containing this correction as a new H. It requires a later one-shot no-KVM static observation and later directional G before any corrected KVM dispatch.

## Authority boundary

This correction and the required static observation are covered by the standing non-AWS instruction. It grants no retry/rerun of an existing observation, AWS/provider/OpenTofu/SSM/inventory/campaign operation, deployment, production, promotion, or release authority.
