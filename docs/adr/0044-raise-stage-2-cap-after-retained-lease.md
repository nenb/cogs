# ADR 0044: Raise Stage 2 completion cap after retained-rootfs lease review

- Status: Accepted
- Date: 2026-07-24
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead on 2026-07-24 under Nick Byrne's explicit instruction, “ok back to work, keep going orchestrating until you get to step 5,” while retaining his separate prohibition on AWS deployment/provider/OpenTofu activity.

## Context

ADR 0042 set a preferred cumulative target of 17,500 physical lines and a hard cumulative cap of 19,000. ADR 0043 then replaced the planned host-mounted writable tmpfs with a Kata guest tmpfs and exact read-only input binds. Neither decision changed the accepted Stage 2 capability, security requirements, or separate cloud-approval boundary.

At clean local issue branch head `87acb8bd921e7186b324e1bb8e07c498ee4e677b`, the frozen cumulative count is now **11,759 physical lines**:

| Frozen counted set | Lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 11,168 |
| Frozen historical schema/validator/renderer files named by ADR 0039 | 591 |
| **Current cumulative total** | **11,759** |

This is 904 lines above ADR 0042's 10,855-line baseline. The increase consists of the reviewed 117-line canonical Kata mount-contract foundation and 787 net production lines for the durable retained-rootfs lease foundation. The lease work preserved the existing direct materializer, but hostile review established that a retained root could not remain an ordinary active build: generic recovery could delete it after the lease-owning process died while Kata still referenced the path.

The measured lease implementation includes a durable `leased` state, release ancestry, ownership replay, and stable ledger/path/lock verification. Its authoritative Linux real-cache qualification and full filesystem fault suite remain separate gates and are not claimed by this ADR.

For cap estimation only, the latest conservative lifecycle plan accounts for a fixed operation journal, bounded command execution, conservative named-create crash handling, exact network/firewall contracts, complete external-state recovery branches, and host-tool qualification. This accounting is non-authoritative: ADR 0044 does not accept those mechanisms. Any lifecycle or host-tool contract not already fixed by ADRs 0038–0043 requires separate review and, where it changes an accepted mechanism or scope, a separate accepted ADR before implementation.

The resulting whole-roadmap ranges are:

| Remaining named work | Low–high |
| --- | ---: |
| Fixed operation journal and capabilities | 330–400 |
| Fixed fd-exec process owner and tool-closure preflight | 400–600 |
| Fixed inputs, fresh keys, fixtures, manifest, cleanup | 700–1,050 |
| Fixed `/30` network and firewall owner | 350–550 |
| Kata runtime/spec/process/share owner | 550–850 |
| SSH, operation completion, rootfs release, entry, qualification | 650–950 |
| **Remaining minimal lifecycle** | **2,980–4,400** |
| Executed closure/contracts/package candidate | 700–1,100 |
| Fixed guest workloads | 300–480 |
| Seven-cycle controller/state | 500–780 |
| Completion schema/validator/renderer | 690–980 |
| Readiness/expiry/integration | 180–300 |
| **Deferred named work** | **2,370–3,640** |
| **Total remaining** | **5,350–8,040** |
| **Projected cumulative from 11,759** | **17,109–19,799** |

The previous 19,000 hard cap is therefore insufficient in the reviewed high case by 799 lines. Implementation stopped before the operation-journal slice. The ranges conservatively reserve readable implementation space for already required security behavior and the non-authoritative planning allowances above; they must not be lowered merely to force the current plan under the old cap. A separately reviewed compliant mechanism may revise them.

## Decision

Amend only ADR 0042's numeric cumulative Stage 2 limits:

- preferred cumulative target: **20,000 lines**;
- hard cumulative cap: **22,000 lines**.

The preferred target is 201 lines above the corrected 19,799 high projection. It is a target, not a requirement to compress code or consume the margin.

The hard cap leaves 10,241 lines from the measured 11,759 baseline and 2,201 lines above the corrected remaining high. That margin is reserved for readable review-driven corrections. It grants no additional module, package, artifact, mount, runtime, network, workload, controller, evidence, deployment, or campaign scope.

Every 17,500 preferred-target and 19,000 hard-cap reference, projection, and remeasurement or stop-gate threshold in ADRs 0042–0043 is superseded by 20,000 and 22,000 respectively. The frozen counted set, retained-file accounting, physical-line method, exclusions, anti-evasion rule, non-numeric stop discipline, and no-deletion-credit planning method remain unchanged.

## Retained requirements and stop discipline

Every non-numeric requirement and the non-numeric discipline of every stop gate in ADRs 0038–0043 remains binding. In particular:

- immutable Debian/rootfs inputs and the exact ordered ten-package set remain unchanged;
- no package scripts, package drift, eleventh package, compiler, guest fetch, host `chroot`, external or staged extractor, host tar, fallback, alternate rootfs writer, or caller-selected rootfs behavior is authorized; ADR 0040's one direct fixed materializer remains the sole composition route;
- deterministic fixtures, complete closure, package-output pinning, fixed workloads, and immediate per-sample cleanup remain required;
- the canonical eleven-entry OCI mount list and guest tmpfs/read-only input design remain fixed;
- standalone Kata requires strict authenticated SSH, fixed `/30` networking, exact process/share/mount observation, and the accepted teardown order;
- unknown, replaced, malformed, over-bound, timed-out, unreapable, or contradictory state is preserved and never converted to absence;
- project code may not use force/lazy/recursive mount cleanup, broad kill, broad firewall deletion, recursive discovery cleanup, TOFU, keyscan, host-network fallback, or a weaker runtime path;
- exact input/control removal and post-runtime rootfs verification precede rootfs release authorization;
- exactly seven fresh sequential cycles, independent destruction/zero proofs, expiry, cost, and strict completion evidence remain unchanged; and
- local Docker remains functional-only and cannot establish Linux/KVM/Kata or campaign authority.

After each production slice, remeasure the complete frozen set and revise every remaining named range. **Stop before further production implementation whenever `actual frozen count + revised remaining high >= 22,000`, or whenever implementation itself would reach 22,000.** Reaching 20,000 is not permission to weaken behavior, relocate code into excluded files, or skip review and qualification.

## Non-authority

This is a cap-only decision. It grants no AWS CLI, provider, OpenTofu, workflow-dispatch, deployment, SSM, resource, campaign, release, or production authority. No cloud activity is needed or permitted for the local implementation slices.

The strongest allowed local result remains readiness to request review for one exact named batch. AWS remains closed until Nick Byrne separately approves that batch with its clean revision, account, region/type, checked plan, immutable identities and pins, current price/quota, expiry/deadline, costs, and exact destroy/recovery path.
