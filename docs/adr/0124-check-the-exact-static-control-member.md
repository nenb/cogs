# ADR 0124: Check the exact static-control member

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Static-control artifact publication

## Context

Static-control run `32576106736` successfully generated and root-published the deterministic candidate, applied and verified execute-only ancestor traversal, then failed before upload because the workflow checked a nonexistent abbreviated filename. The producer's immutable member is `stage2-local-static-control-v1.json`. Final cleanup removed all owned state and passed. No artifact, KVM/runtime/network, or AWS/provider effect occurred.

## Decision

Check readability of the exact producer-declared immutable member `stage2-local-static-control-v1.json`. Keep the root ownership, `0700` fixed source, `0711` transient ancestors, immutable candidate modes, pinned upload action, and unconditional cleanup unchanged.

Bind run `32576106736` as the twelfth exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
