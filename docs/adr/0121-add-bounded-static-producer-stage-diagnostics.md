# ADR 0121: Add bounded static-producer stage diagnostics

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: No-KVM static candidate failure classification

## Context

Static-control run `32569177840` completed immutable preparation and reached the producer, which failed before publication but emitted only one undifferentiated message. The run uploaded no artifact; cleanup removed owned state. It did not open KVM/QMP, start runtime/task/network/SSH, or access AWS/provider APIs.

## Decision

Track one fixed allowlisted producer stage across source manifest, preparation receipt, runtime closure, launch assets, executable contracts, control bytes, and publication. Failure emits only `static no-KVM observation failed:<stage>`; it never emits exception text, paths, bytes, environment, archive data, or diagnostics from untrusted values.

Bind run `32569177840` as the ninth exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
