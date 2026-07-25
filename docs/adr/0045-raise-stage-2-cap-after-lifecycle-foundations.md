# ADR 0045: Raise Stage 2 completion cap after lifecycle foundations

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's repeated explicit instruction, “ok back to work, keep going orchestrating until you get to step 5,” while retaining the separate prohibition on AWS deployment, provider, OpenTofu, workflow-dispatch, and campaign activity. In the accepted staged plan, step 5 is the seven-cycle controller boundary; this decision permits local work through steps 2–4 and requires another stop before controller implementation.

## Context

ADR 0044 set a preferred cumulative target of 20,000 physical lines and a hard cumulative cap of 22,000. It did not change the issue #42 capability or cloud-approval boundary.

At clean issue-branch head `a20d4653f0e0c3fc4d0030a30b1c7b9c0dbf6004`, the frozen cumulative count is **17,442 physical lines**:

| Frozen counted set | Lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 16,851 |
| Frozen historical schema/validator/renderer files named by ADR 0039 | 591 |
| **Current cumulative total** | **17,442** |

The increase since ADR 0044 is the reviewed fixed operation journal, fd-bound process supervisor, exact input owner, network/firewall model, Kata runtime ownership model, SSH/lifecycle composition, and fail-closed qualification gate. Those foundations remain deliberately unavailable to production: committed host-tool, runtime, network, SSH, source, and KVM attestations do not yet exist, so the coordinator fails before opening an owner or invoking an external mutation.

The current host is macOS arm64 and cannot establish Linux-amd64, EUID-0, KVM, Kata 3.32.0, containerd 2.2.1, stored-spec, virtio-fs, authenticated SSH, teardown, or residue authority. Passing generic GitHub `linux-kvm` checks covers existing Stage 3 conformance only and is not issue #42 standalone Kata authority.

The accepted staged plan defines step 5 as the production seven-cycle controller, not the tests' internal `S5` label. Step 1 is complete and step 2 has reviewed foundations but not authoritative wiring or qualification. Steps 3–7 remain absent. A corrected conservative remaining estimate is:

| Remaining named work | Low–high |
| --- | ---: |
| Finish step 2: exact fixture/tool attestations, owner wiring, authoritative normal/failure/timeout/interrupt cleanup | 1,500–2,500 |
| Steps 3–7 retained from the prior measured plan: closure/candidate, qualification/workloads, controller, evidence, readiness | 2,370–3,640 |
| **Total remaining** | **3,870–6,140** |
| **Projected cumulative from 17,442** | **21,312–23,582** |

The projected high exceeds ADR 0044's 22,000 hard cap by 1,582 lines. ADR 0044 therefore requires a stop before more counted production implementation. The estimate is not permission to implement later stages out of order or to bypass the exact-host qualification gate.

## Decision

Amend only ADR 0044's numeric cumulative Stage 2 limits:

- preferred cumulative target: **24,000 lines**;
- hard cumulative cap: **25,500 lines**.

The preferred target is 418 lines above the corrected projected high. It is a target, not a requirement to consume the margin or compress security code.

The hard cap leaves 8,058 lines from the measured 17,442 baseline and 1,918 lines above the 23,582 projected high. That review margin is 31.2% of the 6,140-line remaining high estimate. It is reserved for readable qualification-driven corrections and grants no additional scope.

Every 20,000 preferred-target and 22,000 hard-cap reference, projection, and numeric stop threshold in ADR 0044 is superseded by 24,000 and 25,500. The frozen counted set, retained-file accounting, physical-line method, exclusions, anti-evasion rule, and no-deletion-credit planning method remain unchanged.

## Staged authority and mandatory stops

This decision permits no immediate production slice on the current macOS host. The next allowed activity is exact-head, no-code qualification/replanning on a Linux-amd64 EUID-0 host with active KVM, the fixed source location, exact private artifact cache, Kata 3.32.0, and containerd 2.2.1.

After that environment exists, implementation may add only qualification-driven step-2 wiring and corrections needed to open the fixed owners and prove normal, failed, timed-out, and interrupted cleanup with zero exact-owned residue. Stop before step 3 unless every step-2 authority gate passes. Continue the accepted staged order through steps 3 and 4 only after each preceding gate passes.

**Stop on arrival at step 5.** This ADR does not authorize implementation or execution of the seven-cycle controller. A fresh review must remeasure the branch and confirm exact qualification, package/workload pins, remaining scope, and the continued cloud prohibition before controller work.

After each counted production slice, remeasure the complete frozen set and revise every remaining named range. Stop before further implementation whenever `actual frozen count + revised remaining high >= 25,500`, or whenever implementation itself would reach 25,500. Reaching 24,000 is not permission to weaken behavior, move code into excluded files, or skip review.

## Retained requirements

All non-numeric requirements and stop gates in ADRs 0038–0044 remain binding, including:

- the immutable Debian inputs, exact ten-package set, deterministic direct rootfs writer, rootfs pin, fixture pins, runtime closure, and canonical eleven-entry OCI mount list;
- no package scripts, eleventh package, compiler, guest fetch, host `chroot`, host tar, second writer, fallback, arbitrary command/path seam, or host writable guest-work mount;
- strict standalone Kata authenticated SSH over the fixed `/30`, no default route, exact process/share/mount identities, and the accepted teardown order;
- unknown, replaced, malformed, timed-out, over-bound, unreapable, or contradictory state is preserved and never converted to absence;
- no project force/lazy/recursive mount cleanup, broad kill, broad firewall deletion, recursive discovery cleanup, TOFU, keyscan, host-network fallback, retry substitution, or partial evidence;
- deterministic package candidate and fixed guest workloads with immediate per-sample deletion before any controller work;
- exactly seven fresh sequential campaign cycles, independent destruction and zero proofs, strict completion evidence, expiry, cost, and resource limits remain future required scope rather than present authority; and
- Docker and generic KVM workflows remain non-authoritative for the standalone issue #42 Kata gate.

No workflow change is authorized by this ADR. The issue branch must retain the repository's accepted workflow surface unless a separate decision explicitly changes it.

## Non-authority

This is a cap-only and stage-boundary decision. It grants no AWS CLI, provider, OpenTofu, plan, inventory, apply, SSM, workflow dispatch, deployment, resource, campaign, evidence-publication, release, or production authority. It does not close issue #42.

The strongest result allowed before the step-5 stop remains authoritative local qualification and pinned workload readiness. AWS remains closed until Nick Byrne separately approves one exact named batch with its clean revision, account, region/type, checked plan, immutable identities and pins, current price/quota, expiry/deadline, cost limits, and exact destroy/recovery path.
