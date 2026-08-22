# ADR 0114: Run immutable preparation under isolated Python

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Hosted static-control immutable-preparation import correction

## Context

Replacement static-control run `32564546902` passed its authenticated guard, exact H checkout, static boundary census, and fixed-source materialization, then failed before acquisition because `python3 -I` intentionally omitted the script directory and `completion_kata_immutable_preparation.py` could not import its reviewed sibling owner module. The run produced no artifact and cleanup removed the fixed source/preparation roots. It did not open KVM, QMP, containerd, a task, guest networking, AWS, or a provider.

## Decision

The immutable-preparation entry resolves its own authenticated script directory and prepends only that exact directory to isolated Python's module search path before importing fixed sibling owner modules. It accepts no caller path, environment selector, current directory, package installation, or fallback. Add a test that loads the entry through `python3 -I` from an unrelated working directory.

Bind run `32564546902`, attempt one, exact workflow head/input/title and completed failure as the fifth closed-world predecessor. A replacement generation remains singular and earliest.

## Authority boundary

This correction and one replacement static event are authorized by the standing instruction to complete all non-AWS prerequisites. It grants no KVM qualification result, retry of an existing run, AWS/provider/OpenTofu/SSM/inventory/campaign action, production, or release authority. Work still stops before AWS execution.
