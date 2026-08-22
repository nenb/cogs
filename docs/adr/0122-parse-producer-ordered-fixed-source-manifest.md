# ADR 0122: Parse producer-ordered fixed-source manifest bytes

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Static-control source binding

## Context

Static-control run `32569932861` completed immutable preparation and failed at the allowlisted `source-manifest` producer stage. The historical fixed-source producer emits canonical UTF-8 JSON in the explicit key order `version`, `revision`, `entries`, while the new static producer incorrectly required generic lexicographically sorted JSON. The run uploaded no artifact and cleanup removed owned state. It did not open KVM/QMP, start runtime/task/network/SSH, or access AWS/provider APIs.

## Decision

Add a dedicated decoder for the immutable historical fixed-source manifest. It rejects duplicate keys, non-finite constants, invalid UTF-8, NUL, bounds violations, unknown/missing keys, and any bytes not exactly reproduced in the historical explicit key order with compact separators and terminal newline. Existing row, revision, ordering, mode, size, and digest checks remain unchanged. Generic static-control JSON remains sorted canonical and is not reinterpreted.

Bind run `32569932861` as the tenth exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
