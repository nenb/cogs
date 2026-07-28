# Capability Wave 3 architecture challenge — safe observation shape

## Scope and reviewed authority

This challenge read the five first reviews, the five exact-head rereviews, both holistic reports, the implementation gate, `.pi/outcome-two/capability.md`, `OUTCOME-TWO-PLAN.md`, accepted ADR 0087, accepted ADR 0088, and all five capability implementation surfaces at current head `cfc512d`. The implementation surfaces are byte-identical to reviewed implementation head `ab578313c50f52768003fa3416c514627ba1946d`.

This document changes no production or capability implementation and authorizes no workflow event.

## Decision

**There is no safe, contract-valid attempt at the current head. Do not apply the label, dispatch, or rerun the workflow.**

A useful **unprivileged-only** observation is architecturally possible, but only after a new decision amends the fixed case matrix and schema to expose an honest root-transition-safety prerequisite. It cannot be encoded honestly by the current schema. It would retain no sudo policy or host-root `map_files` observation; those cases would be categorically blocked.

That amended observation would still be non-authoritative. It is not needed by the production closure architecture, which ADR 0087 deliberately makes independent of a favorable capability report. If the project is unwilling to narrow the probe and schema, the correct outcome is to abandon the capability observation rather than execute sudo.

## Why the sudo transition is not exactly supervisable

ADR 0088 requires all of these simultaneously:

1. the outer recovery supervisor remains unprivileged;
2. it retains exact stop/reap authority over every sudo process and root helper;
3. every child sets `PR_SET_PDEATHSIG=SIGKILL` before release;
4. a sudo/root boundary that clears parent-death state rearms it before case work; and
5. crash, timeout, or worker loss cannot strand a privileged process.

Those conditions do not close the credential-transition interval.

A credential-changing set-user-ID transition may clear the child's parent-death signal. After sudo changes the command's real/effective/saved IDs to root, the unprivileged outer process is not categorically entitled to signal it. A pidfd preserves process identity but does not bypass signal permission checks. The root Python helper can rearm `PDEATHSIG` only after its credential-changing exec, dynamic-loader startup, and enough interpreter startup to execute helper code. Therefore an interval exists in which:

- the parent-death contract has been cleared;
- the eventual root helper has not rearmed it; and
- the unprivileged outer supervisor may no longer have stop authority.

A readiness message sent after rearming proves only that the interval ended successfully. It does not let the outer recover a hang, crash, or parent loss *during* the interval. Trusting sudo, root, and the GitHub host under T0/T1 does not solve this lifecycle fact.

No primitive authorized by ADR 0087/0088 closes the gap. In particular:

- `pidfd_send_signal` retains normal credential checks;
- `no_new_privs` would prevent the privilege gain being measured;
- a helper that drops back to the runner UID still has an all-root startup interval;
- a user/PID namespace rooted in the runner's host UID does not measure host-root sudo behavior;
- relying on sudo's internal monitor is not the specified retained identity/readiness/recovery protocol; and
- a delegated cgroup, privileged external supervisor, system service, VM, or workflow-level root guard is not an authorized prerequisite or implementation surface.

Consequently, the requirement that an unprivileged outer supervisor categorically recover every host-root transition is impossible with the listed primitives. Executing the transition and hoping the fixed helper reaches its rearm code is not a safe attempt.

## What the exact implementation does

The implementation does not provide the required topology:

- `main()` directly enters effectful `probe_linux()` (`scripts/runner-capability-probe.py:1461-1479`).
- `probe_linux()` makes itself the subreaper and is also the sole ledger, case runner, cleanup owner, and report producer (`:1185-1263`). There is no outer process.
- `Ledger.run()` starts `subprocess.Popen()` before child registration (`:293-303`). Executed work has no parent release gate.
- `ChildIdentity` retains PID, start time, session, and pidfd, but not expected executable or process-group identity (`:193-197`). Signaling is by process group, not through retained exact signal authority.
- The `preexec_fn=child_boundary` call does not preserve the subprocess stdin/stdout pipe descriptors. It redirects fd 0/1/2 to `/dev/null` and closes the other descriptors, so the root-helper input and categorical output channels are destroyed before exec.
- Sudo map and close-from cases are attempted whenever the sudo file identity is `ok` (`:1216`, `:1233-1234`). No supervision-safety prerequisite exists.
- Baselines are only an fd snapshot, cwd generation, and rlimit pair (`:1187`, `:1245-1246`), not the ADR 0088 baseline set.

The second reviews also demonstrated that the production validator accepts impossible complete reports, the schema numeric domains disagree with ADR 0088, credential admission remains incomplete, internal records are not strict/canonical, and the scripted fault model is detached from production control flow. Blocking sudo alone would not make this implementation runnable.

## Can all sudo/root cases be represented as blocked?

### Current schema: no

The report requires:

- `sudo.noninteractive`;
- both close-from invocations; and
- `procfs.host_sudo_root`, including `setup` and `maps_read`.

ADR 0088 permits `blocked` only when it names a fixed, non-`ok` prerequisite and the operation was not attempted. On a normal hosted runner, the unprivileged authentication of `/usr/bin/sudo` is expected to be `ok`. The current report has no `sudo.root_transition_readiness` or equivalent check. Therefore:

- `sudo.noninteractive` cannot honestly be blocked by `sudo.executable.observation` when that observation is `ok`;
- using an unrelated denied case as its prerequisite is forbidden;
- `unsupported` with null errno is reserved for a proved absent fixed object;
- `denied` requires an attempted operation returning `EPERM`/`EACCES`;
- `mismatch` requires a successful operation with an exact false postcondition; and
- inventing `ECANCELED`, `ETIMEDOUT`, or another errno for an unattempted operation would be fabricated state.

Once `sudo.noninteractive` has no honest state, its close-from dependents and the host-root proc case also have no honest complete encoding. Omitting them is schema-invalid. A schema-shaped incomplete report does not relax ProbeStatus semantics. The only honest result under the current schema is **no report and job failure**.

That would be safe if no effects had started, but it would not be a useful observation because the workflow retains only the final canonical line and permits no partial output or artifact.

### Minimal schema amendment for an unprivileged-only observation

A new decision could add a closed prerequisite under `sudo`, for example:

```text
sudo.root_transition_readiness = {
  status: mismatch,
  unprivileged_recovery_authority_retained: false
}
```

The status would describe a successful local readiness evaluation whose exact postcondition is false; it would not claim a failed sudo syscall. The fixed dependency graph would then be:

```text
sudo.root_transition_readiness.status = mismatch
sudo.noninteractive = blocked by sudo.root_transition_readiness.status
sudo.close_from_3.invocation = blocked by sudo.noninteractive
sudo.close_from_4.invocation = blocked by sudo.noninteractive
procfs.host_sudo_root.setup = blocked by sudo.noninteractive
procfs.host_sudo_root.maps_read = blocked by procfs.host_sudo_root.setup
```

All unobserved sudo fd/exit fields would be null. The blocked map case would have selected/opened counts zero, null first-open failure, and vacuous descriptor-closure truth only if the semantic contract explicitly permits that value for an unattempted case.

The schema, producer validator, genuinely independent validator, fixtures, and every exact prerequisite mutation must change together. The readiness status must not be hidden by marking the authenticated sudo executable `mismatch`; setuid mode does not make its file identity unauthenticated. It must not be represented by a fabricated errno.

This change lets a complete report mean “all cases classified,” not “all cases attempted.” It does **not** characterize effective sudo policy. The plan and ADR must explicitly accept that narrower deliverable.

## Minimal outer-supervisor state machine

Use ADR 0087's existing exact owner states rather than adding recovery aliases:

```text
NEW -> BASELINED -> RUNNING -> CLEANING -> COMPLETE
                    |            |
                    +----------> POISONED -> FAILED
```

State meaning and transition guards are exact:

| State | Permitted behavior | Exit guard |
| --- | --- | --- |
| `NEW` | Validate fixed invocation and public controls. Capture no case fact and perform no probe effect. | Every baseline below is captured twice where stability is required. Otherwise fail with no effect and no report. |
| `BASELINED` | Hold private baseline authority and prove every owner registry empty. Capture the original subreaper state before changing it. | Transition only when the deadline/cleanup reserve is established and no root transition is in the fixed case plan. |
| `RUNNING` | Set the outer as subreaper; create fixed pipes/gates; fork a blocked worker; obtain pidfd/start/executable/session/process-group identity; register it; receive closed readiness; revalidate; then release. Spawn every case child through the same outer-owned gate. The worker never directly releases an unregistered descendant. | A valid worker result is accepted only after all case children are exactly reaped and all result channels close canonically. At second 100, close release gates and start cleanup; no new effect starts. |
| `CLEANING` | Close gates, terminate only retained matching same-UID identities, reap, close every tracked fd, undo exact owned effects in their owning namespace, restore process-local state, and compare every baseline. No case effect is permitted. | All comparisons equal, all registries empty, no close/reap/restore error, and no uncertainty. |
| `COMPLETE` | Encode one report only after semantic validation and a second canonical encoding agree. Repeated cleanup is a no-op. | Terminal. |
| `POISONED` | Sticky failure entered from `RUNNING` or `CLEANING` on any timeout, malformed record, identity loss, worker failure, cleanup error, or uncertainty. Attempt every independently safe cleanup action without discarding the primary failure. | Transition to `FAILED`; cleanup retry cannot turn the result into success. |
| `FAILED` | Emit no report when cleanup/codec safety is uncertain; otherwise at most one safe incomplete line if every represented fact is honest. | Terminal nonzero exit. |

The outer supervisor performs no capability case. A minimal implementation should make all case processes direct, gated children of the outer and forward their validated categorical records to the effect worker. This avoids relying on an effect worker to report descendants that already started. If the worker is allowed to fork, it must pass pidfds and complete identities to the outer and receive outer acknowledgement **before** releasing each child; that is strictly more complex.

No sudo process or root helper appears in this state machine.

## Exact private baselines

All baseline details remain private and only aggregate booleans cross into the report.

1. **Invocation/source:** exact PR head, checkout HEAD, the three admitted blob digests, and byte-for-byte empty checkout porcelain before effects. Retain the checkout dirfd generation and repeat HEAD/porcelain at cleanup.
2. **Credentials:** real/effective/saved UID and GID, supplementary groups, all capability sets, securebits, `no_new_privs`, and dumpability. Prove the outer and every executable unprivileged case retain the runner's host identity. Before executing Python or unshare, privately reject setuid/setgid or file-capability privilege gain. Sudo is authenticated but never executed.
3. **Descriptors:** every inherited fd number with stable object generation, descriptor flags, and status flags; the snapshot's own fd is excluded. Every later fd is registered immediately and final comparison is exact, including fd reuse detection.
4. **Processes:** the exact initial direct-child set, no owned descendants, original child-subreaper state, signal dispositions used by the owner, and empty child registry. Process scans may compare a baseline but never grant signal authority.
5. **Namespaces and mounts:** retained identities for current user, PID, mount, and network namespaces plus two stable bounded reads of the current mount table. Record empty mount/namespace registries. Final reads and identities must match exactly.
6. **Limits:** original soft and hard `RLIMIT_NOFILE` and any other limit the driver changes. Restore the exact original pair before comparison.
7. **Private names:** retained no-follow authority for `/tmp`, its stable generation/policy, and exact absent/pre-existing state for every fixed private name. A pre-existing name blocks the related case; it is never adopted.
8. **Checkout:** admitted HEAD, index/worktree/untracked/ignored cleanliness, and the fixed implementation blob digests. Cwd inode equality alone is insufficient.
9. **Registries:** descriptor, child, result-channel, private-name, mount, namespace-handle, and limit-change registries all start empty and must end empty.
10. **Time:** one monotonic absolute second-120 deadline and second-100 no-new-effect boundary captured before `RUNNING`; every loop and fallible effect checks the applicable absolute bound.

Failure to capture or compare any baseline permits no complete report. A private baseline may contain IDs needed for authority but must not add them to public JSON.

## Case disposition

“Safe” below means safe only after the outer state machine, exact baselines, strict records, semantic matrix, and production-driven fault tests exist. It does not describe the current implementation.

| Fixed case | Disposition | Reason/required guard |
| --- | --- | --- |
| Source/envelope, runner metadata, `uname`, rlimit read | Safe unprivileged | Read-only and no child privilege transition. |
| Python/gzip/zstd/unshare/sudo file identity | Safe unprivileged | Descriptor-held bounded read and generation revalidation. Sudo is read, never executed. Executed tools additionally require a private no-setuid/no-setgid/no-file-capability gate. |
| Exec/CLOEXEC and low/high `close_range` | Safe unprivileged | Dedicated gated child; sparse high fd only after hard-limit prerequisite; child-local limit restoration; death closes fds. |
| Host-runner proc/maps | Safe unprivileged | Fixed Python child, no root transition, bounded reads, exact descriptor closure. |
| Network, mount, and PID namespace creation attempts | Safe unprivileged | Dedicated same-UID child. Denial is categorical; a created namespace is process-lifetime-bound and all descendants must be registered/reaped. |
| Direct user namespace and combined user/mount/PID/proc cases | Safe unprivileged with qualification | Host real UID remains the runner UID even when the child has namespaced capabilities. Require fixed unshare/Python identities, outer-owned descendants, no host-root mapping, and exact namespace/mount teardown. |
| Seccomp/NNP case | Safe unprivileged | Dedicated child; irreversible only to that child; exact prerequisite/status coupling. |
| KVM presence/open/two read-only ioctls | Safe unprivileged | No VM creation; descriptor is outer-accounted and closes on child death. Success remains non-authoritative and per-run only. |
| Runner-temp `O_TMPFILE` publication and private-name setup | **Blocked until exact recovery is implemented and fault-qualified** | Host-visible named effects can survive a worker crash. Current post-create registration and pathname cleanup are insufficient. |
| Private tmpfs, O_PATH bind, and proc-mount cases | **Blocked until exact owning-namespace recovery is implemented and fault-qualified** | Current batched/pathname cleanup and absent mount/namespace baselines are unsafe. Each must be a dedicated child with retained authority. |
| `sudo.noninteractive` | **Always blocked in the safe shape** | Starting sudo crosses the unsupervisable setuid interval. |
| `sudo.close_from_3` and `sudo.close_from_4` | **Always blocked in the safe shape** | Depend on blocked sudo admission. |
| `procfs.host_sudo_root` setup/maps | **Always blocked in the safe shape** | Depend on blocked sudo admission; no root helper is started. |

The temporary/mount rows expose a second strict edge: a last outer supervisor killed by `SIGKILL` cannot clean a host-visible name after its death, and runner disposal is not cleanup evidence. A categorical no-residue claim therefore requires either process-lifetime-only kernel objects, a separately retained durable cleanup owner, or blocking all host-visible named effects. ADR 0088 currently names no such durable owner. This must be resolved, not hidden behind “no report on outer loss.”

## Does ADR 0088 already permit the safe shape?

**It permits the fail-closed principle, but it does not fully authorize this shape.**

ADR 0088 already says:

- a failed preparation/readiness step permits no case effect;
- an unattempted dependent case is `blocked` by an exact non-`ok` prerequisite;
- correctly blocked cases may coexist with `outcome="complete"`; and
- the outer supervisor must remain unprivileged.

Those rules require blocking a transition that cannot be supervised. They do not supply a reportable root-transition-readiness check. The current closed schema and accepted fixed matrix have no such prerequisite, while ADR 0087 C5 and ADR 0088 section 4 are written around actual sudo/root-helper execution. Permanently replacing the planned sudo characterization with an architectural block changes a primitive claim and report dependency graph. Under ADR 0087's stop rule, that needs a new ADR (or explicit amendment), even though it stays within the same five implementation surfaces and strengthens safety.

The amendment must also state whether the plan's “effective sudo policy” field is satisfied by “not observed: blocked for lifecycle safety.” If actual sudo behavior remains mandatory, the requirements are incompatible and the probe must be abandoned.

## Capability is not an Outcome 2 completion requirement

`OUTCOME-TWO-PLAN.md` section 10 does not include a capability-probe run or capability report in the Outcome 2 completion gate. The gate requires trusted closure repeatability, exact object accounting, mapped-closure equality, sealed generation binding, portable hostile tests, native Jobs A–E, thin integration, restored baselines, exact-head hostile review, and no cloud authority consumption. It does **not** require sudo characterization or any capability observation.

ADR 0087 is equally explicit that the capability log has authority `none`, production does not depend on a favorable value, and required primitives are asserted and qualified by their production/native owners. Therefore no-run does not block Outcome 2 and is not a missing evidence exception. It is the normal fail-closed disposition for an optional observation whose safe execution cannot be proved.

## Required stop/abandon decision

1. **Current exact head: NO-RUN / ABANDON.** This is the recommended final disposition, not merely a pause for another correction. The implementation has unresolved P1–P3 findings, no separate attempt approval, no outer supervisor, broken subprocess channels, incomplete baselines, and no honest schema encoding for a deliberate sudo block. The observation is absent from the Outcome 2 completion gate, so it has no offsetting delivery necessity.
2. **Proceed with Outcome 2 without a capability result.** Production already fails closed and qualifies required primitives in their own native owners. Record capability as intentionally not run; do not create a placeholder, waiver, or inferred value.
3. **Only if a newly identified non-authoritative research need justifies more work:** accept a new ADR/schema amendment, narrow the probe to unprivileged observations, block every root transition through a new exact readiness prerequisite, resolve the named/mount recovery edge, implement the real outer topology, and obtain clean hostile rereview plus separate exact-event approval. This is optional future research, not an Outcome 2 prerequisite.
4. **If sudo descriptor policy or host-root maps remain mandatory for that future research:** abandon that probe design as impossible under an unprivileged outer supervisor. Do not spend more line budget trying to make unprivileged Python own an all-root transition.
5. **Never interpret no report, incomplete output, blocked sudo fields, or a complete unprivileged report as sudo denial, sudo policy characterization, native qualification, runtime authority, or security evidence.**

**Final architecture disposition: do not run the current capability workflow; abandon it for Outcome 2 and continue the completion plan without capability evidence.**
