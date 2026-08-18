# ADR 0102: Raise the local Kata owner integration line cap

- Status: Accepted under the owner's instruction to finish all non-AWS prerequisites
- Date: 2026-08-18
- Scope: ADR 0099 local implementation only

## Context

The reviewed process, network, runtime, SSH/input, workload, recovery, and result owners measure 44,810 conservative lines after genuine deduplication. The remaining exact rootfs-host-tool issuer, Kata artifact binding, executable coordinator, and non-AWS qualification wiring cannot fit readably below ADR 0099's 45,000 hard cap.

## Decision

Raise the retained preferred target to 47,000 and hard cap to 48,000 physical/no-deletion-credit lines. Deletions, test relocation, generated-code relocation, compressed security logic, and data-file code remain ineligible for credit. The centralized checker remains mandatory.

This grants no KVM attempt, retry, AWS/provider/controller action, issue closure, production claim, or release authority. ADR 0099's exact-head review, one non-AWS attempt, no-retry rule, and mandatory stop remain unchanged.
