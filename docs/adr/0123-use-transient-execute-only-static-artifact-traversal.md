# ADR 0123: Use transient execute-only static-artifact traversal

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Static-control artifact publication

## Context

Static-control run `32574273244` successfully generated and root-published the deterministic candidate, then the unprivileged pinned artifact action failed to traverse its root-owned `0700` ancestors. No artifact was uploaded. Final cleanup removed the candidate, source, fixtures, and Kata installation and passed the static-only runtime-boundary check. The run did not open KVM/QMP, start runtime/task/network/SSH, or access AWS/provider APIs.

The candidate directory and all descendants are already immutable root-owned `0555` directories and `0444` files. The fixed source remains a separate root-owned `0700` directory.

## Decision

After successful candidate production, verify the candidate and source ownership/modes, then transiently change only these three root-owned ancestor directories to execute-only `0711`:

- `/var/lib/cogs`;
- `/var/lib/cogs/stage2-completion-v1`;
- `/var/lib/cogs/stage2-completion-v1/control-observation-v1`.

Revalidate every changed ancestor as `root:root:711`, revalidate the source as `root:root:700`, and prove the intended immutable control member is readable before invoking the pinned artifact action. Do not grant directory listing or write permission. The unconditional cleanup removes the complete owned tree after upload success or failure.

Bind run `32574273244` as the eleventh exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
