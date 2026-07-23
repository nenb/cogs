# ADR 0039: Raise Stage 2 completion cap after artifact closure

- Status: Accepted
- Date: 2026-07-23
- Decision owner: Nick Byrne
- Acceptance: Nick Byrne approved resuming the stated issue #42 plan with a cap-only ADR before rootfs implementation; accepted by the delegated project lead under Nick Byrne's standing delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0038 authorizes local-only implementation of the bounded issue #42 Stage 2 completion capability. It fixes the immutable Debian OCI and snapshot inputs, exact ten-package candidate set, standalone Kata authenticated-SSH semantics, representative synthetic workloads, seven sequential cycle shape, cleanup and evidence requirements, and separate future cloud-execution gate. It set a preferred cumulative Stage 2 target of 4,600 lines and a hard cap of 5,100 lines.

Artifact closure is now implemented at clean merged `main` commit `27230008eff0ab4dfd5efc2b4e2f51e8e933667f` after PR #201. The exact 16-artifact contract and cache, OCI and snapshot metadata, package index, and all ten fixed package archives pass the read-only verification boundary. The implementation includes strict stable-file checks, fail-closed acquisition and redirect handling, and bounded ar, compression, tar-framing, semantic, path, link, type, metadata, and resource preflight. This closes the fixed-input acquisition slice, but it does not compose a rootfs or establish any later qualification gate.

The current conservative Stage 2 production count is already 4,589 lines. Only 11 preferred lines and 511 hard-cap lines remain under ADR 0038. That cannot safely accommodate the measured remaining rootfs, fixture, runtime-closure, Kata networking and SSH lifecycle, workload, seven-cycle controller, evidence, and readiness work.

### Frozen conservative count set

This decision removes ambiguity between ADR 0038's literal count and the broader count consistently reported during artifact closure. Physical lines in the following set count toward the cumulative Stage 2 cap:

| Current counted set | Lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 3,998 |
| `schemas/aws-stage2-measurement-evidence-v1alpha1.json`, `scripts/validate-aws-stage2-measurement-report.ts`, and `scripts/render-aws-stage2-measurement-report.ts` | 466 |
| `schemas/aws-feasibility-report-v1alpha1.json` and `scripts/validate-aws-feasibility-report.ts` | 125 |
| **Current conservative total** | **4,589** |

The accepted measurement schema, validator, and renderer account for ADR 0038's literal evidence category. The legacy feasibility schema and validator remain counted conservatively even though they were omitted from that literal subtotal. Any new Stage 2 completion evidence schema, validator, or renderer required by ADR 0038 also enters this count set. Retained counted files do not stop counting merely because a replacement or shared implementation is added.

Tests, documentation, reports, generated evidence, and fixed artifact or pin contracts remain excluded. They remain mandatory and must stay readable. Moving production behavior into an excluded file category to evade the cap is forbidden.

### Measured remaining implementation

The remaining estimate uses net production lines after modest safe reuse and assumes no risky deletion credit:

| Remaining slice | Net lines |
| --- | ---: |
| Acquisition closure and stable local entry point | 20-100 |
| Deterministic rootfs composition, postwalk, normalization, and two-build pinning | 650-950 |
| Deterministic fixtures and exact-package runtime closure qualification | 300-500 |
| Kata SSH/network lifecycle and complete identity-bound cleanup | 750-1,050 |
| Full-cycle guest Git and package workloads | 250-400 |
| Seven-cycle controller and fake state-machine behavior | 450-700 |
| Separate strict completion evidence, validation, and rendering | 650-900 |
| Local readiness aggregation and AWS stop | 100-200 |
| **Total remaining** | **3,170-4,800** |

The projected conservative cumulative range is therefore **7,759-9,389 lines**. The existing hard cap cannot contain even the low case.

Security-sensitive ownership, timeout, SSH, networking, evidence, and cleanup code must remain explicit and reviewable. Compressing it into dense shell, combining unknown and absent states, removing independent observations, weakening redaction, or introducing generic command, path, package, or cleanup seams to preserve the obsolete cap is not acceptable.

## Decision

Amend only ADR 0038's numeric cumulative Stage 2 line targets:

- preferred cumulative target: **8,500 lines**;
- hard cumulative cap: **9,500 lines**.

The current 4,589-line baseline leaves 3,911 preferred lines and 4,911 hard-cap lines. The preferred target lies within the measured projection and encourages safe reuse without making reuse a prerequisite. The 1,000-line preferred-to-hard contingency is 25.6% of the preferred incremental allowance and permits review-driven hardening and readable security code. The hard cap remains only 111 lines above the measured high case; implementation must stop and produce another measured decision rather than exceed it.

Where ADR 0038 qualification gate 8 and its stop gates refer to 5,100 lines, the amended value is 9,500 lines. Where ADR 0038's line-budget section refers to the 4,600-line preferred target, the amended value is 8,500 lines. ADR 0038 itself remains historical and unchanged.

This decision grants line budget, not scope. It does not authorize implementation beyond the remaining ADR 0038 capability, and it creates no cloud or execution authority.

## Required implementation discipline

The added budget is limited to normal readable implementation of the measured slices:

- reuse the existing archive records, stable-file checks, bounds, task-state normalization, bounded execution, QEMU baseline, percentile, validation, and redaction patterns where their existing contracts remain exact;
- keep rootfs composition and package overlay fixed to the pinned base and exact ten-package set, with no package scripts and no silent dependency expansion;
- build rootfs and fixtures twice in clean temporary roots and pin identical outputs before cloud consideration;
- retain exact authenticated SSH, network namespace, veth, tcfilter, no-default-route, firewall, key, and no-host-network semantics;
- retain identity-bound normal, failed, timed-out, and interrupted cleanup with independent absence observations and no force fallback;
- keep one full and six readiness cycles ordered, non-overlapping, source/artifact/expiry bound, and unable to publish partial evidence; and
- implement a separate strict completion evidence version without changing accepted historical v1alpha1 evidence.

Safe consolidation is encouraged only after equivalent hostile tests exist. No cap credit is assumed for deleting historical runtime or controller behavior.

## Boundaries retained from ADR 0038

Every non-numeric ADR 0038 requirement remains binding, including:

- local-only implementation of exactly seven fresh sequential create/measure/destroy cycles, one full and six readiness, with at most one instance and the unchanged exact 16-resource shape;
- the fixed region, instance type and capacity, encrypted disposable disk, nested virtualization, IMDSv2, no-ingress security group, SSM controller, Scheduler termination, and guest-local termination fallback;
- one absolute expiry no greater than four hours, a 90-minute normal batch deadline, expected aggregate cost below USD 0.25, and publishable estimated cost below USD 0.50;
- immediate state-bound destroy and independent zero inventory after every cycle, final independent zero inventory, and abort of later cycles and evidence on any uncertainty;
- the exact pinned Debian OCI base, snapshot, ten-package candidate set, package identities, no maintainer-script execution, and stop-and-replan requirement for any insufficiency or drift;
- the exact `/30` netns/veth/tcfilter topology, no guest default route, no host networking, CNI, bridge, NAT, public SSH, ingress, EC2 key pair, TOFU, keyscan, forwarding, password, PAM, or authentication fallback;
- fresh fixed-purpose keys, preconstructed host trust, restricted client authorization, strict authenticated marker timing, and publishable-evidence redaction;
- deterministic synthetic Git and package workloads without Cogs or user source, a compiler, remote helper, guest fetch, or guest network;
- separate strict completion evidence with exactly seven ordered cycles, recomputed summaries, cleanup and inventory proof, additional-property rejection, sensitive-content rejection, and no failed, partial, duplicate, mixed-source, mixed-artifact, cross-batch, or cleanup-uncertain publication;
- all nine local qualification gates, with only the numeric line threshold amended by this decision; and
- the distinct outer gate and separate future human approval binding the exact clean revision, account, region and type, plan and digests, AMI, rootfs and fixtures, price and quota, expiry and deadline, costs, recovery path, and one named batch.

The exact outer phrase remains only a fail-closed mechanism and supplies no standing cloud approval.

## Stop gates and non-claims

Implementation must stop for another ADR or explicit human decision before:

- exceeding the **9,500-line** hard cap;
- changing the cloud graph, concurrency, region, instance type, disk, cost, time, expiry, package set, immutable inputs, SSH daemon or authentication mode, network boundary, cleanup semantics, evidence boundary, or accepted historical evidence;
- adding an eleventh package, compiler, general OCI/package tooling, guest fetch, arbitrary path, URL, package, command, Cogs/user source, credential, or prompt;
- changing `src`, `dev/launcher`, workflows, package dependencies, lockfile, ADR 0012, ADR 0037, or production/release/deploy scope;
- using retry or rerun substitution, stop/start samples, forced deletion, timeout relaxation, cross-batch samples, or partial evidence; or
- executing AWS for debugging or proceeding after any qualification or cleanup uncertainty.

This ADR does not create resources, authorize AWS plan, inventory, apply, or execution, approve a workflow, provide measurement evidence, or close issue #42. It does not establish EKS, Kubernetes, `RuntimeClass`, CNI/NetworkPolicy, Stage 4 latency gates, p99 behavior, EBS workspace behavior, warm pools, autoscaling, real Cogs/Pi/model/OpenBao/proxy/WAL/telemetry integration, multi-session isolation, Stage 5 resilience/load, release, production, compliance, general availability, or regional capacity. ADR 0012 and its mandatory EKS reruns remain unchanged.

## Consequences

Local ADR 0038 implementation may resume without compressing security-critical rootfs, SSH, networking, timeout, cleanup, orchestration, validation, or redaction code under the obsolete 5,100-line cap. Future implementation changes must report the frozen conservative count and stop below 9,500 lines.

All authority remains exactly where ADR 0038 placed it: local capability and deterministic output implementation may proceed, but cloud execution remains closed until every qualification gate passes and Nick Byrne separately approves one exact named batch.
