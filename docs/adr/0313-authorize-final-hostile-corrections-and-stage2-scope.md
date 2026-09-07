# ADR 0313: Authorize final hostile corrections and Stage2 scope

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval to complete every required non-AWS prerequisite and stop before the authoritative chain
- Inputs: independent reports `/tmp/cogs42-posth-review-{holistic,lifecycle,network,authority}.md` at candidate `8df10d33f2a7359f6dccd576ebb4ce02706dcd6a`

## Context

The integrated correction candidate removed zero-traffic S3 success, added generation-bound guest proxy trust, retired the OpenBao bootstrap root before readiness, supported an eight-hour certificate plus margin, separated close observation from actual retirement, bounded Envoy resources, denied x32 syscall encodings, discarded long-lived KVM UART output, and added final WAL/completion observation. Local full tests had one expected stale-source-inventory failure and no code-test failure.

Independent hostile review nevertheless reproduced final ownership defects: detached OpenBao metadata/data cancellation and identity callback work; an incompletely published revocation-action frontier; a reentrant late egress factory; ordinary production shutdown misclassified as dependency loss; ambiguous Envoy extraction custody; invalid Envoy HTTP/2 header-field configuration; format-string interpretation of credential values; an unproved fixed-root cgroup monitor; and local-driver network/smoke ownership races. These are not permitted to become authority through scope narrowing.

A qualified OpenBao runtime artifact is unavailable. A signed upstream 2.6.2 image remains scan-failing. The bounded first-party derivative research found a supported recognition mechanism and exact source/dependency closure, but current compiler/tool source gates remain blocked. OpenBao is not in the Stage2 rootfs/Kata/custody execution graph, although ADR 0308 previously made its real fixture a global pre-H gate.

## Decision

### Final source corrections

Authorize narrow regression-first correction of every reproduced shared-source defect above. Preserve one actual work owner, fresh caller observations, sticky uncertainty, exact resource identities, fail-closed authorization, no secret/error reflection, and historical evidence. Specific requirements:

1. join exactly one OpenBao response cancellation and identity callback promise on every exit;
2. publish the complete watcher transition/action frontier before callbacks can reenter;
3. publish egress factory startup ownership before invoking the factory;
4. distinguish owner-requested shutdown from spontaneous dependency loss without suppressing genuine revocation;
5. persist Envoy extraction acquisition intent before Docker effects and retain it on ambiguous cleanup;
6. render only valid pinned-Envoy fields, encode credentials as literal header bytes or reject unsupported values, and remove the fixed-root cgroup monitor unless exact mount identity is externally proved;
7. bind local smoke cleanup to its own successful generation, retire helper processes without numeric-PID reuse, and prevent name-based network inverse success across a foreign replacement or state an enforceable exclusive-domain prerequisite;
8. correct current-source S3 documentation while retaining historical result bytes and the narrower observed-traffic claim.

No test may treat timeout, ENOSYS, missing traffic, listener refusal, path absence, or a successful command status as actual retirement.

### Stage2-only replacement-H scope

Supersede ADR 0308's real OpenBao/S3/production-Envoy fixture requirement **only for the forthcoming Stage2-only H decision**. The selected Stage2 graph is fixed rootfs inputs and authenticated source → deterministic producer/publisher custody → immutable import/lease → Kata/QMP/network/SSH/workloads → exact teardown/recovery/evidence. It does not start the Stage3 Node launcher, OpenBao, S3-09, model/integration credentials, or production worker composition.

A later ADR may freeze complete repository source bytes as H solely for that Stage2 graph after all shared-source defects and applicable Stage2 Linux/root/KVM checks pass. Such an H proves source identity, not qualification of every source file. It must retain these explicit unresolved blockers:

- OpenBao image admission and real ACL/KV/PKI/storage/root-retirement evidence;
- production credential and workload-identity qualification;
- full S3-09/Envoy/KVM development-launcher runtime observations and universal all-attempt traffic coverage;
- Stage3/Stage4 exit, release, cloud and production authority.

Synthetic OpenBao/Envoy tests remain `synthetic-contract-only`. Retired OpenBao entry points must be excluded or blocked before effects in the admitted Stage2 graph; they cannot be fallback. No production credentials may be used. Shared source with a confirmed P0–P2 defect must still be fixed or explicitly excluded from executable Stage2 reachability and documented; scope cannot relabel a source defect as a pass.

All applicable Stage2 supply-chain, x32 policy, descriptor/provenance, no-fallback, H/G/Q separation, first-created attempt-one, process/network custody, final residue, recovery and evidence requirements remain mandatory. Final source/readiness evidence must preserve OpenBao/production/cloud fields as false and v5 as absent before Q.

This scope decision does not freeze H or authorize producer. Future freeze/control and Q/qualification decisions are ADR 0314 and ADR 0315.

### Accounting

Reallocate the unchanged 16,000 global gross ceiling after measured integrated accounting:

| Owner | Ceiling |
|---|---:|
| route | 1,700 |
| revocation | 3,000 |
| relay | 1,700 |
| lifecycle | 6,300 |
| completion | 1,900 |
| integration | 3,300 |
| **Total** | **16,000** |

Release the unused absent `test/history-fragments.test.ts` reservation, transfer its new-file slot from completion to integration, and use it for this ADR. Retain all other exact path, line, source, Stage2 and future-v5 limits. Enforce or explicitly report ADR 0309's tighter post-H deploy/retained/workflow reserves in final accounting.

## Validation

Before a Stage2-only H freeze:

1. all reproduced P1/P2 code defects have permanent hostile regressions;
2. focused and full tests, format/type/schema/preset/descriptor/image/lock/license/audit and exact accounting pass;
3. final source/readiness evidence is deterministically regenerated after the last tracked change;
4. current protected Linux/root and applicable KVM checks pass on exact source;
5. x32 denial is observed as filter enforcement on an admitted modern kernel, not inferred from ENOSYS;
6. selected Stage2 reachability excludes retired OpenBao and production credential paths;
7. at least two independent final reviews report no P0–P2 blocker in the Stage2 graph or shared source boundary;
8. final control v5 remains absent and all authority fields remain false.

Real Stage3/4 runtime observations are recorded as deferred blockers, not successful gates.

## Authority boundary

This ADR authorizes local correction, integration, static evidence regeneration and ordinary protected Linux/root/KVM CI. It grants no producer, publisher, preflight, qualification, image publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release, Stage4 exit or Issue #42 closure authority. Work stops before the authoritative chain.
