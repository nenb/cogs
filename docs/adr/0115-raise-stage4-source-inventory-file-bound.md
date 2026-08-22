# ADR 0115: Raise the Stage 4 complete-source inventory file bound

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Complete tracked-source inventory accounting only

## Context

The additive Issue 42 correction ADRs and isolated-import test bring the complete tracked repository to 1,026 regular files. The existing Stage 4 inventory bound of 1,024 now rejects the complete source before hashing, despite aggregate bytes and every per-file bound remaining satisfied.

## Decision

Raise only the complete tracked-file cardinality bound to 1,100 in the producer and independent test. Keep the 4 MiB per-file, 16 MiB aggregate, tracked mode, canonical ordering, no symlink/hardlink, exact Git identity, and generated-evidence recursion exclusions unchanged. The additional 74-entry reserve is bounded accounting room, not permission to omit or relocate source.

## Authority boundary

This is local evidence accounting only. It grants no static result, KVM, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority. The mandatory AWS stop remains.
