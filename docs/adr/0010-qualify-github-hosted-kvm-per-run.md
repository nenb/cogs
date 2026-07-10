# ADR 0010: Qualify GitHub-hosted KVM on every evidence run

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

`IMPLEMENTATION.md` section 7.1 asks for a self-hosted runner or CI offering that explicitly guarantees KVM. GitHub documents Linux Android hardware acceleration, but does not contractually guarantee general nested virtualization or `/dev/kvm`. Using a separate provider adds procurement and operational overhead.

## Decision

Use GitHub-hosted `ubuntu-24.04` as the initial Linux/KVM CI candidate, with capability treated as an assertion rather than an assumption. Every KVM evidence job must:

1. require an accessible `/dev/kvm`;
2. start QEMU with `-accel kvm`, which forbids TCG fallback;
3. query the running VM over QMP and require `query-kvm` to report both `present: true` and `enabled: true`;
4. boot a root guest and prove a boot identity distinct from the trusted runner host;
5. tear down reproducibly and upload an applicability-aware report.

Run qualification nightly, manually, and when a PR receives the `security` label. A failed preflight fails the job with no container/software-emulation fallback. Standard runners are used first; paid larger runners require Nick Byrne's approval. WarpBuild remains the documented fallback if GitHub availability or capacity is inadequate.

## Consequences

This is a recorded deviation from the provider-guarantee preference in section 7.1. Passing direct evidence supports the individual run; it does not promise future runner availability. Stage 0 qualification proves runner capability only and does not satisfy Stage 1 guest-root network-bypass claims.
