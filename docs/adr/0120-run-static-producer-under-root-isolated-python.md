# ADR 0120: Run the static producer under root isolated Python

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Hosted static-control producer entry

## Context

Static-control run `32568536415` completed exact immutable preparation, then failed before candidate production because the workflow's unprivileged shell could not traverse the root-owned mode-0700 fixed source to `cd`, and isolated Python would also omit sibling owner imports. The run uploaded no artifact; cleanup removed all owned state. It did not open KVM/QMP, start runtime/task/network/SSH, or access AWS/provider APIs.

## Decision

Invoke the producer as root by its fixed absolute path without a shell `cd`. The producer resolves its own authenticated script directory and prepends only that exact directory under `python3 -I` before importing sibling owner modules. It accepts no caller path, current directory, environment selector, or fallback. Add isolated-import tests.

Bind run `32568536415` as the eighth exact attempt-one completed-failure predecessor. The replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event remain non-AWS prerequisites. No KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority is granted.
