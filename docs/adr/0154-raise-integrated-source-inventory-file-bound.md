# ADR 0154: Raise the integrated source inventory file bound

- Status: Accepted under the owner's explicit integration and deterministic-regeneration instruction
- Date: 2026-08-24

The complete non-AWS integration closure contains 1,105 tracked files before this decision. ADR 0115's 1,100-file source-inventory bound therefore rejects the complete merged tree even though every file remains subject to exact path, mode, byte, per-file, aggregate, ordering, Git-identity, and generated-recursion controls.

Raise only the complete tracked-file cardinality bound to 1,200 in the producer and independent test. The additional reserve is bounded accounting room, not permission to omit source. Keep the 4 MiB per-file bound, 16 MiB aggregate bound, canonical complete inventory, no-symlink and single-link checks, exact pinned Git identity, and three explicit generated-evidence exclusions unchanged.

ADR 0153's no-deletion-credit line caps remain unchanged and independently enforced. This decision grants no AWS, provider, osito, KVM, network, promotion, production, or release authority.
