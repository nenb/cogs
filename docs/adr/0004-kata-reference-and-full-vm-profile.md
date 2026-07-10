# ADR 0004: Use Kata as the reference runtime and preserve a full-VM profile

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Cogs requires a separate guest kernel and must support Kubernetes while remaining compatible with environments that cannot expose nested KVM.

## Decision

Use Kata Containers with QEMU/KVM and a Kubernetes `RuntimeClass` as the reference production profile. Trusted Cogs/proxy containers never share the Kata sandbox VM. Preserve the same SSH/proxy contract for a full external cloud VM profile where nested virtualization is unavailable. Plain containers, QEMU TCG/software emulation, and macOS VMs are development-only and carry no authoritative production or guest-root network claim. Any profile reporting `linux-kvm` must fail unless the hypervisor confirms KVM is present and actively enabled.

AWS virtual nested KVM versus bare metal remains pending the explicitly approved, single-instance Stage 2 campaign.

## Consequences

- Production installation requires cluster-scoped runtime administration and dedicated nodes.
- There is no silent `runc` fallback.
- Replacing Kata or silently falling back to a container crosses `IMPLEMENTATION.md` section 47.
