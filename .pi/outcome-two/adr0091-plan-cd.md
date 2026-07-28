# ADR 0091 C/D corrective architecture plan

Status: planning input only. This is not an accepted ADR and grants no implementation or execution authority.

- Reviewed implementation: `ea6e74fe709e02061e13be78922da13a8cf6f748`.
- Review record: `.pi/outcome-two/native-final-review-cd.md`.
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Scope: the six C/D findings, including the common report defect on which C/D artifact cleanup depends.
- This plan performs no implementation, native selector, workflow run, sudo, namespace, mount, cloud, provider, AWS, production, or release action.

## Decision shape

ADR 0091 should replace the C/D substitute implementations with two thin callers of fixed, admitted production facades:

1. `completion_trusted_runtime_closure.qualify_fixed_descriptor_primitives()` for C; and
2. `completion_trusted_runtime_launcher.qualify_fixed_process_lifecycle()` for D.

The names above are fixed proposed interfaces, not implemented interfaces. Each no-argument workflow facade constructs the real production `_Ops` and owner. A private `_with_ops` form is available only to portable tests. It is not reachable through CLI arguments, environment values, an admission packet, or a workflow selector.

The existing authenticated held-byte bootstrap receives a closed job-to-mode mapping. C can select only `cogs.runtime-descriptor-qualification/v1`; D can select only `cogs.runtime-lifecycle-qualification/v1`. The bootstrap authenticates the exact closure/launcher source blobs from the admitted head before loading them. These modes are admitted by ADR 0091 specifically because they enter the shared owners below; they may not select another coordinator or accept a caller-supplied path, operation list, limits, PID, descriptor, signal, deadline, or policy.

C/D drivers retain only workflow context construction, the fixed bootstrap call, strict decoding of one typed result, check mapping, and common finalization. They contain no raw syscall number, `fork`, `pidfd_open`, `setsid`, signal, wait, `/proc` parser, fd enumeration, subreaper, or cleanup implementation.

## Finding disposition

| Final C/D finding | Required closure |
| --- | --- |
| P1-1: preregistered D identity contradicts its later `setsid()` | Register immutable identity plus a one-use planned session transition. Advance to the exact post-`setsid` identity before descendant creation or case release. |
| P1-2: raw-PID descendant handoff and instantaneous adoption check | Transfer the creator-held pidfd with one exact `SCM_RIGHTS`/`SCM_CREDENTIALS` packet while the descendant is blocked; install it in the surviving owner before acknowledgement; use bounded recursive and stable adoption censuses. |
| P1-3: `listdir(fd)` creates an untracked duplicate | One admitted production `getdents64` snapshot implementation reads through the exact enumerator fd under fixed byte/entry/call bounds. Common, C, and D use that implementation. |
| P1-4: driver-local close-range/lifecycle substitutes and completed portable observations | C enters the closure descriptor owner and its real `_Ops.close_range`; D enters the launcher's real `_ProcessOwner`. Portable adapters cut syscall boundaries inside those state machines rather than replacing a whole case. |
| P1-5: report close uncertainty permits fd reuse and cleanup deletes unproved names | Common owns one-shot fd leases and a preregistered report transaction capability. No open follows uncertain close in that process; cleanup compares exact retained generations and preserves replacements. |
| P2-1: `cleanup.paths` observes an unused flat `.json` name | Common captures and recomputes the actual fixed directory `/tmp/cogs-native-qualification-{job}` and `report.json` lease. C/D do not manufacture `paths` booleans. |

This also closes the C/D portion of holistic P1-2, P1-4, and P2-1. It does not claim to close unrelated A/B/E/integration findings.

## Shared ownership boundary

### Common owner

`scripts/native-qualification/common.py` owns:

- workflow/head admission and the closed C/D production-mode map;
- capture and final comparison of descriptor, direct-child/owned-descendant, path, mount, namespace, limit, and checkout baselines;
- the pre-effect `CommonBaselineLease` and its one-use post-cleanup observation receipt;
- the report transaction, durable cleanup capability, canonical validation, publication, upload cleanup, and report-path restoration; and
- aggregation of primary, production-cleanup, baseline, and report-cleanup failures.

`finalize_report` must consume a `CommonObservationReceipt`; it must not accept seven caller-provided booleans. The receipt is bound to one context, one captured baseline, one production result, and one final observation. Unknown, repeated, mismatched, or partially observed domains are false.

The `paths` observation is split truthfully:

- the in-report value proves all job-owned paths and the actual report root were at their pre-publication baseline immediately before report staging; and
- the separate mandatory post-upload cleanup result proves removal of the exact published report generation and restoration of that same root.

A report cannot claim that its own later publication has already been removed.

### Closure descriptor owner

`deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` is the sole owner of:

- the Linux `getdents64` adapter and dirent parser;
- fd lease states and exact descriptor snapshots;
- `RLIMIT_NOFILE` normalization/restoration;
- `F_DUPFD_CLOEXEC`, `F_DUPFD`, `dup3`, and the fixed fd 198/4096 construction;
- the same `_Ops.close_range` and close-complement implementation used by production helpers;
- atomically created pidfd authority, the blocked exec child, release/status gates, and exact child outcome; and
- a typed `DescriptorQualificationResult` containing categorical observations only.

The runtime helper path and C facade call the same snapshot, close-complement, fd lease, and child owner code. A qualification-only copy, raw C syscall wrapper, or driver-local cleanup is forbidden.

### Launcher process owner

`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` is the sole owner of:

- `_ProcessOwner`, `_ProcessLease`, immutable and transitional identities;
- atomic leader creation, pidfds, release gates, and subreaper state;
- descendant pidfd transfer and credential validation;
- recursive descendant/adoption census;
- pidfd signaling, waitid observation, exact reap, and cleanup deadlines; and
- a typed `LifecycleQualificationResult` whose individual facts cannot substitute for one another.

Production launcher recovery and D use the same transition, transfer, census, stop, and reap methods. D may map typed facts to fixed report checks but may not infer a fact from another fact or from registry emptiness alone.

## Exact common fd baseline

There is one implementation, owned with the closure primitives and consumed by common and launcher owners after authenticated loading:

1. Read and retain the original soft/hard `RLIMIT_NOFILE` before opening the enumerator.
2. Open exactly `/proc/self/fd` with `O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`; immediately place the number in an `OWNED` one-shot lease.
3. Call the production `_Ops.getdents` on that exact fd with a 32,768-byte buffer. Permit at most 32 nonempty chunks plus one EOF call, at most 1,048,576 bytes in total, and at most 16,384 numeric entries. Reaching a bound before EOF is failure, never a truncated snapshot.
4. Strictly parse each `linux_dirent64`: complete 19-byte header, aligned record length of at least 24, record wholly in the returned chunk, one NUL-terminated name, canonical decimal spelling, value at most `INT_MAX`, and no duplicate numeric name. `.` and `..` are ignored only after valid parsing.
5. Require the enumerator number to occur exactly once. Exclude only that number. There is no `listdir`, `scandir`, `fdopendir`, glob, range scan, or second proc-directory open.
6. While the process is single-threaded and every owned child is blocked, apply `F_GETFD`, `F_GETFL`, and `fstat` to every listed number. Record the sorted tuple `(fd, FD_CLOEXEC, access/status flags, file type, dev, ino, rdev, mode)`. `EBADF`, entry drift, an unknown flag, or duplicate identity is terminal.
7. Close the enumerator exactly once. A before-effect close error leaves it `OWNED` for one cleanup attempt; an after-effect/unknown close error marks `CLOSE_UNCERTAIN`. No later open may occur in that process after uncertainty, so the number can never be reused and accidentally closed.
8. Repeat the same bounded operation after production cleanup. Exact tuple equality is the only source of `cleanup.descriptors=true`.

C's mechanism-specific baseline additionally preregisters the original limit and every created descriptor lease before the next fallible operation. Limit restoration is reread exactly; hard limit mutation is always failure. D uses the same descriptor snapshot and has no second parser.

## C: blocked registration and genuine descriptor primitives

The fixed C production transaction is:

1. Common captures its baseline. The closure owner captures the original limit and fd tuple and creates an empty write-ahead lease registry.
2. Normalize only the soft limit to exactly 8,193 after proving the hard limit is infinity or at least 8,193. Reread both values.
3. Create the source pipe and register both ends before duplication. Create exactly fd 198 with `F_DUPFD_CLOEXEC` and fd 4,096 with `F_DUPFD`; register each returned fd before another effect and reject any alternate number.
4. Before child creation, create and register release/status descriptors and a placeholder process lease. Use the production atomic `clone3(CLONE_PIDFD|SIGCHLD)` adapter, so the parent receives PID and pidfd together. The child can only block on its release read; it cannot duplicate, close, exec, or report success yet.
5. Fill the placeholder with pidfd, start time, fixed Python executable generation, parent/session/group identity, and all gates. If any fill step fails, close/abort the gate and boundedly observe/reap the still-effectless child through creation authority. Reap is attempted even after readiness, EOF, status, or close failure.
6. Release only after registration. In the child, call the shared production `dup3` and close-complement, which in turn calls the genuine `_Ops.close_range`. Exec the fixed held Python generation and report only the exact inherited set `{0,1,2,197,4096}`. There is no iteration-based closure substitute.
7. Require exact `waitid(P_PIDFD, ..., WEXITED|WNOHANG|WNOWAIT)` `CLD_EXITED/0`, then exact nonblocking `waitpid` reap and matching status. A zombie is identified by the retained pidfd and preregistered immutable identity; `/proc/<pid>/exe` is not required after death.
8. Close fd 4,096 through the same `close_range` primitive and prove `EBADF`; close all remaining leases in reverse order; restore and reread the original limit; compare the production and common baselines.

Cleanup signals a live C child only through its retained pidfd after pre-death invariant revalidation. It always closes/aborts gates first, then uses the shared bounded TERM/KILL/reap owner. It never signals a raw PID or treats an unavailable identity as permission to kill.

## D: planned identity transition

A process identity has immutable and stateful parts:

- immutable: PID, pidfd lease, start time, fixed executable generation, creator role, case ID, and protocol sequence;
- initial: parent PID, session ID, and process-group ID observed while blocked; and
- planned transition: exactly one `setsid`, with target session ID and process-group ID both equal to the leader PID.

The owner writes `BLOCKED/PRE_SETSID` plus the exact target before release. Release permits only `setsid` and a transition-status write. The owner independently rereads start time, executable, session, and group; it advances the lease to `BLOCKED/POST_SETSID` only when immutable fields are unchanged and `(sid, pgid) == (pid, pid)`. It then acknowledges transition completion. Descendant creation and every case effect remain blocked until that acknowledgement.

A status EOF or an error after a possibly effective `setsid` does not restore the stale tuple. The lease enters `TRANSITION_UNCERTAIN`, where cleanup accepts only the two preregistered session/group states for invariant checking, signals only by retained pidfd, and can never support a passing observation. Once `POST_SETSID` is established, later TERM/KILL checks require only that exact state.

## D: exact pidfd and credentials protocol

Each registered post-`setsid` leader creates its one descendant with `clone3(CLONE_PIDFD|SIGCHLD)`. The descendant blocks before PDEATH arming, signal-handler changes, case readiness, or any other assigned effect. The creator retains its atomic pidfd until transfer is acknowledged.

Leader and outer owner use a preregistered `AF_UNIX|SOCK_SEQPACKET|SOCK_CLOEXEC` pair with `SO_PASSCRED=1`. One registration datagram contains:

- fixed protocol version, case ID, role, nonce, and monotonic sequence;
- descendant PID, start time, parent PID, session, process group, and fixed executable generation; and
- exactly one ancillary `SCM_RIGHTS` item containing exactly one creator-held pidfd.

The kernel-supplied ancillary data must contain exactly one `SCM_CREDENTIALS` record equal to the registered leader `(pid,euid,egid)`. Receive uses `MSG_CMSG_CLOEXEC|MSG_DONTWAIT` with exact payload/control bounds and rejects `MSG_TRUNC`, `MSG_CTRUNC`, unknown levels/types, missing/duplicate credentials, missing/extra/misaligned rights, extra packets, replayed sequence/nonce, or trailing fields.

All kernel-installed rights are wrapped in leases before semantic validation, so malformed packets cannot leak fds. The outer owner independently rereads the descendant identity, requires a live nonready pidfd, and registers the transferred pidfd and preregistered release gate. Only then does it return an exact credentialed acknowledgement. After acknowledgement the creator closes its duplicate pidfd and loses release authority; the surviving outer owner is authoritative. Send failure, lost acknowledgement, malformed transfer, or creator death routes the leader through its retained creator pidfd cleanup while the outer owner cleans the registered leader. No side assumes the other acquired authority without the acknowledgement state.

## D: descendant and adoption census

The outer process captures the original subreaper value, sets it to one, and rereads one before creating a leader. Restoration sets the original value and rereads it after every process is reaped.

Census is observation and reconciliation, not raw-PID signal authority:

- Parse `/proc/self/task/self/children` and each registered live process's task-children file with the production bounded parser: at most 65,536 bytes per record, 16 total descendants, canonical unique positive PIDs, and a 16-node recursion bound.
- Bind every row to a registered pidfd/start-time/executable/session/group record. An unexpected row is immediately quarantined only after `pidfd_open` plus before/after start-time and parent-chain validation; it can never contribute to a pass. Failure to acquire retained authority is cleanup uncertainty, not permission to signal by PID.
- A stable census means two consecutive identical identity-and-edge graphs under one monotonic deadline, with no unregistered node. Merely observing `pid in children` once is insufficient.
- After a leader exits and is exactly reaped, poll to a stable graph in which its still-unreaped descendant is a direct child of the subreaper. Mark the descendant `ADOPTED/WAITABLE` only then. A transferred pidfd before adoption supplies liveness/signal authority but does not falsely imply wait authority.
- After final reap, require the exact original direct-child graph, an empty owner registry, and two equal final censuses.

A spawn-after-transfer, disappearing edge, new recursive node, census overflow, identity drift, or adoption timeout fails the case and exercises quarantine cleanup.

## D: exact outcome, TERM/KILL, and reap sequence

Each PDEATH case is independent:

1. Register and transition the intermediate parent; transfer/register the blocked descendant.
2. Release the descendant only to arm `PR_SET_PDEATHSIG(SIGKILL)`, reread the parent identity around `prctl`, and report `ARMED`. The before-release case remains behind its case gate; the after-release case consumes that gate and reports `RELEASED`.
3. Command the parent to exit normally. Observe exact parent `waitid` `CLD_EXITED/0`, perform exact `waitpid(WNOHANG)` reap, and compare statuses.
4. Establish stable adoption of the descendant. Observe its exact `CLD_KILLED/SIGKILL`, then exactly reap and compare status.

The TERM/KILL case proceeds as follows:

1. Establish a post-`setsid` leader and one registered blocked descendant inheriting the exact leader session/group. Release both only to install fixed TERM-ignore behavior and report readiness.
2. Revalidate each live post-transition identity and send TERM separately through each pidfd. Wait the full fixed TERM interval under the shared monotonic deadline and require both pidfds to remain nonready.
3. Revalidate and KILL the leader through its pidfd. Require `waitid` `CLD_KILLED/SIGKILL`, exact reap, and stable descendant adoption.
4. Revalidate and KILL the adopted descendant through its pidfd. Require the same exact siginfo and reap status.
5. Prove the final census and common baseline. No `killpg`, raw PID signal, blocking wait, leader-only absence, or one outcome standing for another is accepted.

Production and recovery always attempt gate closure, liveness observation, TERM, bounded wait, KILL, `waitid`, and reap in that order where applicable. Each operation has its own result; failures are aggregated rather than short-circuiting later reap. After `waitid` establishes death, pidfd identity and recorded pre-signal invariants replace unavailable zombie `/proc/exe` checks.

## Common report correction required by C/D

ADR 0091 should make report cleanup a preregistered transaction rather than pathname recovery:

1. A fixed common prepare call, before the driver effect, creates an opaque 256-bit transaction nonce and a mode-0600, no-follow, exclusive journal beneath the fixed runner-private common root. Workflow YAML only passes the opaque capability to the fixed driver/upload-cleanup calls; it implements no file policy and never prints the capability.
2. The fsynced write-ahead journal records state transitions and exact parent-directory, report-directory, staged-file, and published-file generations. Journal records are canonical and nonce-authenticated. The report is still the only uploaded object; generations and nonce are never report metadata.
3. Every fd is a one-shot lease with `OWNED`, `CLOSED`, or `CLOSE_UNCERTAIN`. A close is attempted once. After an uncertain close, the process opens nothing else; it uses only already-held directory/journal authority for exact-name comparison and cleanup, then fails terminally. Thus an uncertain retired number cannot be reused.
4. Before unlink, compare the current no-follow name to the journaled retained generation. Unlink only equality. A missing expected name, replacement, extra name, directory replacement, or unverifiable journal is preserved and fails; cleanup never deletes it to manufacture an absent baseline.
5. Pre-publication failure and upload failure use the same state machine. The fixed `always()` cleanup can authenticate and remove an exact staged-only, published, or already-removed transaction. It rejects impossible state transitions and proves journal and report-root baseline restoration.
6. `cleanup.paths` is derived from the actual `/tmp/cogs-native-qualification-{job}` baseline, not `/tmp/cogs-native-qualification-{job}.json`.

The portable report matrix must include short/zero/interrupted write and read; fstat/fsync; before- and after-effect close; fd reuse attempts; staged reopen; canonical/schema/semantic divergence; no-replace collision; directory fsync; prepare/driver crash states; staged unlink; published replacement; report-directory replacement; upload failure; cleanup replay; and journal corruption/replacement. Every cut ends in one exact publication followed by exact removal, or terminal failure without deleting an unproved object.

## Portable fault adapters and acceptance

Portable tests call only private `_with_ops` state machines. The workflow facades always construct real system ops and expose no injection parameter. Adapters model state and cut immediately before or after each primitive effect; they do not return completed `pdeath_case`, `terminate_tree`, inheritance, close-range, or restoration booleans.

C adapters cover getdents chunks/EOF/bounds, enumerator close uncertainty, limit set/read/restore, fd allocation and reuse, clone3/pidfd result, registration fill, gate writes/EOF, `dup3`, each close-range interval, exec status, identity drift, waitid siginfo, waitpid reap, and every descriptor close.

D adapters cover leader clone/registration, setsid before/after/status loss, descendant clone, sendmsg/recvmsg before/after, all credential/right cardinality and truncation cases, acknowledgement/release loss, spawn-after, recursive census changes, adoption delay, subreaper set/read/restore, identity drift, TERM/KILL before/after, waitid none/wrong code/wrong signal, waitpid mismatch, deadlines, and pidfd/control close uncertainty.

The fake kernel maintains fd tables, lease states, process identities, parent edges, sessions/groups, liveness, waitability, siginfo, and reap state. Tests assert the event trace and final owner state at every cut. Branch-removal sentinels must fail if registration, transition acknowledgement, rights leasing, credentials checks, census reconciliation, TERM, KILL, waitid comparison, reap, limit restoration, or baseline comparison is removed.

Cross-file static acceptance additionally requires:

- C/D driver call only their fixed admitted facade and common APIs;
- no forbidden driver-local primitive token or syscall number;
- production runtime and qualification facades reference the same descriptor/process owner symbols;
- `listdir`, `scandir`, `fdopendir`, blocking wait, raw PID signaling, and group-wide signaling are absent from the authority paths; and
- the complete common report fault matrix and exact path names are exercised without a workflow/native selector.

No portable test may call the no-argument system facade, `--workflow-bound`, sudo, a real namespace/mount/seccomp operation, or a real process/fd qualification case.

## Measured readable highs proposed for ADR 0091

The reviewed head currently measures `3811/4000` native lines. Relevant exact measurements are common `400/400`, C `250/250`, D `350/350`, common test `197/200`, C test `91/120`, D test `112/150`, closure `2098/2100`, launcher `1897/1900`, runtime-closure portable `350/350`, and lifecycle portable `550/550`.

The correction was estimated by enumerating the state transitions and fault cuts above, then adding approximately 10% readable integration margin. The “correction allowance” is gross newly introduced physical lines after `ea6e74f`; deletion of substitutes does not replenish it. The hard high remains gross physical additions from `bec0a19b...`. Both limits bind.

| Exact existing surface | Current gross | Correction allowance | Proposed hard high |
| --- | ---: | ---: | ---: |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | 2,098 | 190 | 2,300 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | 1,897 | 430 | 2,350 |
| `test/outcome-two-runtime-closure-portable.py` | 350 | 200 | 550 |
| `test/outcome-two-lifecycle-portable.py` | 550 | 450 | 1,000 |
| `.github/workflows/ci.yml` Outcome 2 addition | 250 | 24, within existing margin | 300 |
| `scripts/native-qualification/common.py` | 400 | 380 | 800 |
| `scripts/native-qualification/job-c-descriptors.py` | 250 | 45 | 300 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 350 | 50 | 400 |
| `test/native-qualification-common.test.ts` | 197 | 270 | 480 |
| `test/native-qualification-c.test.ts` | 91 | 159 | 250 |
| `test/native-qualification-d.test.ts` | 112 | 288 | 400 |

The trusted/portable individual highs become **10,230**; this is the revised trusted/portable subtotal high. Unlisted trusted highs remain exactly ADR 0090's highs.

With all unlisted native highs unchanged, native individual ceilings sum to **5,250**. Set the independently binding native subtotal high to **5,100**, so at least 150 lines of individual ceiling remain unused. The projected native total is 5,027, leaving 73 lines below that subtotal; that margin is not transferable.

The binding trusted/portable and native subtotals total **15,330**. Set the Outcome 2 aggregate high to **15,400**, retaining ADR 0090's 70-line aggregate margin. These C/D planning numbers overlap the common/report correction and must be merged once with the common ADR 0091 plan, not added to it a second time. Other ADR 0091 slices may require a separate integrated remeasurement before acceptance.

Blank/comment lines count. Generated data, compression, renames, deletions, and moving behavior into YAML/tests provide no credit. No new file, dependency, package, action, service, cache, secret, job, retry, or fallback is included.

## Gates and stops

Before any implementation authority, the integrated ADR 0091 must reconcile this plan with common, A/B, E/integration, schema, and holistic plans; state one exact closed file set; and publish non-overlapping highs. This planning commit itself authorizes none of that work.

After a later implementation authorization, portable/static gates must pass and a fresh exact-head C/D review must independently verify every disposition above, exact gross counts, genuine production symbol ownership, all fault traces, and common report cleanup. Resolve every P0–P3 finding before seeking a separate native-execution ADR.

Stop and replan before any native selector or workflow run; any new surface/dependency; any exceeded file/subtotal/aggregate high; any caller-selected primitive/policy; any unregistered effectful child; any raw-PID or broad-scan signaling authority; any uncertain cleanup represented as pass; or any cloud/AWS/provider/production action.
