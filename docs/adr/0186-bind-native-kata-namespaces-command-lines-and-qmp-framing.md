# ADR 0186: Bind native Kata namespaces, command lines, and QMP framing

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H28 repeated certain launch and all post-launch link/address observations. It exposed additional exact Kata 3.32 and QEMU 11 representations. A focused native diagnostic against the still-live VM then achieved the first successful independent QMP/KVM observation.

Accept the native TAP state only as the coherent tuple `mq`, `UNKNOWN`, `eui64`; do not freely combine those fields with historical profiles. The nested virtiofsd launcher and worker share exact private mount and network namespaces distinct from both the host and operation network namespaces, while QEMU shares the shim mount namespace and the operation network namespace. Preserve the historical fixture profile, but accept the native profile only with the already required exact ancestry, executable, digest, command line, and worker relationship.

Kata supplies an empty shim argument only as the value immediately following `-publish-binary`; reject empty arguments anywhere else. Bind native QEMU and virtiofsd sandbox arguments by their exact role-specific forms rather than requiring the sandbox ID to be a standalone argument.

Read QEMU's Unix listener table through `/proc/<exact-qemu-pid>/net/unix`, because its QMP listeners live in QEMU's operation network namespace. Continue binding both exact listener inodes to distinct QEMU descriptors and the private inherited descriptor from argv. Accept only canonical CRLF-framed QMP input lines and the QEMU 11 status response with either the historical false `singlestep` member or its native omission. All IDs, message bounds, event grammar, version, KVM response, deadlines, socket generations, and before/after snapshots remain unchanged.

The focused diagnostic classified the exact shim/QEMU/virtiofsd roots and returned `kvm_present=true`, `kvm_enabled=true`, KVM API 12, and distinct private/observer QMP socket identities. It was explicitly non-authoritative and minted no qualification. Portable hostile tests cover each additive representation. H28 was independently cleaned to zero residue.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
