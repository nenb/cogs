# ADR 0116: Create fixed immutable-preparation state parents

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Fresh hosted static-control preparation state

## Context

Static-control run `32565389560` passed its guard, exact checkout, static census, and fixed-source materialization, then failed before acquisition because source archives intentionally omit `deploy/aws-feasibility/.state`, while immutable preparation attempted to create a child below that absent private state parent. The run produced no artifact and cleanup removed the fixed source. It did not open KVM/QMP, start containerd/task/network/SSH, or access AWS/provider APIs.

## Decision

Before creating transaction state, immutable preparation creates only the fixed `.state` and `completion-v1` directory pair with mode `0700`, then verifies directory type, exact effective owner, and no group/other write bits. It accepts no caller path or fallback. Add fresh-root tests.

Bind run `32565389560` as the sixth exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain within the standing non-AWS authority. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
