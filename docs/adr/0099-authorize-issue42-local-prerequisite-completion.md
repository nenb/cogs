# ADR 0099: Complete issue #42 local prerequisites before AWS

- Status: Accepted by explicit owner instruction
- Date: 2026-08-17
- Scope: Local implementation and non-AWS Linux/KVM qualification only

## Context

Issue #42 still requires seven fresh AWS cycles with authenticated Kata SSH readiness and representative in-Kata Git, package-build, and package-install measurements. The current tree contains the deterministic rootfs, fixtures, Kata lifecycle foundations, and Outcome Two trusted runtime closure, but it deliberately lacks production Kata owners, final workload-output pins, and the authoritative local seven-sample workload result. ADRs 0045 and 0065 therefore correctly stop before the seven-cycle AWS controller.

The retained Stage 2 count is about 32,669 physical lines and its conservative no-deletion reserve is at least 33,912. The previous 34,000 hard cap cannot hold readable prerequisite corrections. The owner asked to prioritize implementation over extensive process documentation while retaining the no-AWS boundary.

## Decision

Authorize only the local work needed to reach the existing step-5 stop:

1. Replace the deliberately unavailable Kata network, process, runtime, SSH, coordinator, and qualification owners with fixed production-owned APIs that preserve the accepted `/30`, no-default-route, authenticated-SSH, no-fallback, exact ownership, bounded deadline, and reverse-cleanup contracts.
2. Add a strict runtime/workload contract, deterministic package candidate transaction, manual final output pin, post-pin reproduction, and one-lifecycle seven-sample Git/build/install qualification.
3. Add portable hostile and failure-path tests. After clean exact-head review, permit one non-AWS Linux/amd64 KVM qualification through a reviewed same-repository workflow with no persisted credentials and no provider access.
4. Preserve historical schemas and evidence. New candidate/final qualification data must use new versions and cannot become AWS, production, or release evidence.

The Stage 2 preferred target becomes 42,000 physical lines and the hard cap becomes 45,000 for the retained counted set. No deletion credit, test relocation, generated-code relocation, compressed security logic, or Outcome Two allowance may be used to evade that cap.

## Mandatory stop

Stop again after exact local Kata and workload qualification. This ADR does **not** authorize:

- the seven-cycle controller, completion evidence publisher, or readiness promotion;
- AWS credentials, STS, provider APIs, OpenTofu planning/apply/destroy, SSM, inventory, or any cloud resource;
- workflow retries, replacement qualification attempts, fallback, broader networking, additional packages, or changed immutable inputs;
- issue closure, Stage 4 blocker removal, production, or release claims.

A later explicit decision must review the exact local result and separately authorize controller implementation. A still later exact authority is required for one AWS batch.

## Consequences

Implementation may now proceed in readable slices and use one reviewed non-AWS KVM qualification attempt. Any failed, uncertain, residue-producing, source-mismatched, or cap-exceeding result stops for review and grants no retry.
