# ADR 0118: Normalize the exact runtime archive root entry

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Pinned Kata archive layout parsing

## Context

Static-control run `32566515932` passed guard, exact source, state creation, and immutable downloads/extraction, then failed while describing the pinned Kata archive because it contains one conventional `./` root directory entry. The strict parser already strips leading `./` from every descendant but rejected the root after normalization to an empty path. The run published no artifact and cleanup removed owned state. It did not open KVM/QMP, start runtime/task/network/SSH, or access AWS/provider APIs.

## Decision

Permit and omit exactly one leading archive root entry named `.` or `./` only when it is a root-owned mode-0755 empty directory with no link target. Reject duplicates and every other empty/dot component. Descendant path, object-kind, mode, ownership, link, byte, count, and aggregate checks remain unchanged. The extracted postwalk already omits its staging root, so this normalization makes archive and extracted manifests comparable without weakening descendant safety.

Bind run `32566515932` as the seventh exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
