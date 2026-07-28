# Outcome 2 parser/closure lifecycle correction map

- Design ID: `O2-CLOSUREFIX-DESIGN`
- Design head read: `2023e650e88767e0bd7574f0c302e780743eab5a`
- Exact implementation: unchanged from `64c055762e260b8fc2eed96741bdb30c89183f3c`
- Authorities read: accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, and all five `closure-review-*.md` reports present at the design head.
- Scope: parser correctness, closure descriptor/process lifecycle, component resolution, and crash recovery only.
- Disposition: correction design only. No production/test/schema edit and no production, portable, native, workflow, cloud, or deployment execution is authorized by this document.

## 1. Binding and stop conditions

The exact relevant blobs are:

| Surface | Blob |
| --- | --- |
| `completion_elf.py` | `5e3ba497a5862eb039b4b3a984e877c3dc470c9f` |
| `completion_trusted_runtime_closure.py` | `508378c42810729b43c300aea58d3ae3f1eda292` |
| `completion_trusted_runtime_launcher.py` | `0b00f02e0f45b5fc4850c85df56dfd4c819e2d1d` |
| trusted-closure schema | `cdd8abf68df367b4839511d34e0ffd8c0de1201a` |
| lifecycle portable suite | `f8f5cef518c8b0518a0c659f095ac1473bf67321` |
| recovery portable suite | `590a6635ef6ed72ddb01e60c333f46ce6a72bdad` |
| closure portable suite | `debba331e3f5c60f7fdafbd7f8d7c372699584ee` |
| mapped-closure portable suite | `73581e0be05eca93726d61567e34425b30677284` |

The parser and closure owner are already at their ADR 0087 non-transferable highs (240/240 and 1,220/1,220). The launcher is at 599/600. Implementation must therefore stop for a new accepted ADR that grants readable per-file growth and any private process-protocol surface. Deletion, compressed control flow, moving production behavior into tests, or unused aggregate margin is not authority.

This map does **not** close the reviews' separate pre-effect source-admission, forgeable handoff, executable/report binding, execution-time loader/library binding, real T2 launcher, independent runtime schema validation, or Job E findings. Those remain blockers after this lifecycle work.

## 2. Corrected internal ownership model

Keep ADR 0087's public API unchanged. Replace the current raw integer/list bookkeeping internally with three explicit leases:

```text
_FdLease(fd, purpose, state=OWNED)
  OWNED -> CLOSED
  OWNED -> TRANSFERRED
  OWNED -> CLOSE_UNCERTAIN       (terminal; the integer is never used again)

_HelperLease(
  pid, pidfd, start_time, session, process_group,
  phase, expected_executable_identity,
  input_gate, status_gate, descendants, reaped
)
  ALLOCATED -> SPAWNED -> PREEXEC_IDENTIFIED -> EXEC_IDENTIFIED
            -> STOPPING -> REAPED
            \-> UNCERTAIN

_PreparationLease
  fd_baseline, child_baseline, fd_registry, helper_registry,
  primary_error, cleanup_errors, uncertainty
```

Every acquired fd is put in the registry immediately after the acquiring syscall returns and before the next fallible operation. Every helper gets a lease immediately after an atomic PID+pidfd spawn result and before polling, proc access, or another syscall. Gates are fields of that registered lease, never untracked return values.

A close is attempted at most once for each `_FdLease`. A close error means ownership is uncertain; it does not mean either open or closed. The fd number must not be retried, transferred, inspected, or allowed to identify a later object. `POISONED` stores one immutable aggregate error and repeats that same object on every `close()`.

There is no fallible action after publishing `CLOSED`. In particular, move/remove the current `cleanup.after` checkpoint after `self._state = CLOSED` (`completion_trusted_runtime_closure.py:1091-1092`). All checkpoints and baseline proofs happen first; only then may state become `CLOSED`.

## 3. Exact correction map

### C1 — fd baseline enumeration

**Current defect:** `_Ops.list_fds()` uses pathname `os.listdir("/proc/self/fd")` and returns its transient enumeration descriptor (`closure.py:241-245`). `_prove_ready_baseline()` then compares that stale number with a later transient number (`:1105-1110`).

**Production correction:**

1. Reserve and validate fds 0, 1, and 2 before the first source/proc open. Closed stdio is filled with fixed `O_CLOEXEC` `/dev/null` descriptors and registered until duplicated into 0-2; no source fd may ever occupy 0-2.
2. `_SystemOps.snapshot_fds()` opens `/proc/self/fd` once with `O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`, immediately registers that exact directory fd, and enumerates it with bounded `getdents64` on that fd. Do not use pathname `listdir`, `scandir`, or any library call that opens/duplicates an unobservable directory stream.
3. Parse only unique decimal names in `0..INT_MAX`; reject malformed, duplicate, truncated, over-bound, or non-EOF enumeration. Require the enumeration fd itself to appear exactly once and exclude exactly that fd from the returned immutable snapshot.
4. Close the enumeration lease once, aggregating read/parse and close errors. A close error makes the snapshot uncertain and unusable.
5. Use this same function for initial, READY, failure, close, handoff, and launcher snapshots. A baseline is captured before effects; READY must equal `baseline | exactly-three-output-fds`; failure/close must equal baseline.

**Portable proof:** scripted dirent chunks drive empty/multi-chunk/EOF, malformed name, duplicate, count bound, hidden extra fd, changing enumerator number, primary-plus-close, and close-uncertain cases through production `snapshot_fds()` logic. A Linux native adapter test separately challenges the actual `getdents64` implementation; fake `{0,1,2}|live` snapshots are not accepted as lifecycle evidence.

### C2 — helper gate and child registration

**Current defect:** `_spawn_helper()` returns `(child, gate)` only after exec handshake, pidfd open, and proc identity reads; `_prepare()` registers the child later (`closure.py:587-669,1140-1143`). Startup cleanup uses raw PID kill and blocking wait. The gate is never owner-registered.

**Production correction:**

1. Allocate input gate, status channel, and `/dev/null` under the preparation fd registry; register each end immediately.
2. Spawn with fixed Linux `clone3(CLONE_PIDFD, exit_signal=SIGCHLD)` so PID and pidfd are acquired atomically. No fork-plus-later-`pidfd_open` gap is accepted for this fixed profile.
3. Immediately create and register `_HelperLease(pid, pidfd, gates...)` before clock reads, polling, proc reads, or status I/O.
4. The child creates its fixed session, installs PDEATHSIG, verifies its parent, reserves stdio, closes all fds except the exact allowlist, and emits a fixed pre-exec readiness record. It remains blocked until the parent has recorded its pre-exec identity.
5. After parent acknowledgement, the child execs the held executable. CLOEXEC closure of the status end is the success signal. The ordinary input gate remains blocked throughout mapping capture.
6. `_stop_helper()` accepts only the registered lease; there is no separate raw `gate_write` argument. Closing the input gate changes that lease's fd state before TERM/KILL handling.
7. A startup failure closes gates and performs bounded identity-aware recovery. Raw `kill(pid, ...)` and `waitpid(pid, 0)` are forbidden.

**Portable proof:** drive the real allocation/spawn/registration state machine with model PID and fd tables. Inject every effect before and after lease registration. Assert the process remains independently live until production cleanup reaps it; an empty fake fd dictionary is insufficient.

### C3 — pidfd, start-time, session, process-group, and executable identity

**Current defect:** the settled helper has useful identity fields, but startup lacks them; the emergency KILL does not re-run `_matching_child()`; pidfd is closed even when reap failed (`closure.py:671-733`). Launcher children retain only a numeric PID (`launcher.py:396-484`).

**Production correction:**

- Identity is the conjunction of the retained pidfd, expected numeric PID, strict `/proc/<pid>/stat` start time, SID, PGID, and phase-specific executable `(dev,inode)`.
- Pre-exec identity uses the authenticated fixed preparation executable; post-exec identity uses the resolved tool executable. A phase transition requires a complete second observation, not inferred status-pipe EOF.
- Before **every** TERM or KILL, revalidate the complete identity and pidfd liveness. Revalidate again after TERM timeout and immediately before KILL. A mismatch is terminal uncertainty and grants no signaling authority.
- Keep the pidfd and lease registered until exact `waitid(P_PIDFD, ..., WEXITED|WNOHANG)`/`waitpid(WNOHANG)` confirmation and descendant cleanup complete. Never discard the pidfd merely because cleanup is returning an error.
- Apply the same lease and functions to launcher tool children. Direct raw-PID signaling, identity-free waits, and launcher-specific weaker cleanup are removed.

**Portable proof:** model PID reuse, start-time drift, SID drift, PGID drift, executable replacement, pidfd death, process exit before proc read, identity drift between TERM and KILL, and reap failure. Assert no signal appears in the model log unless the immediately preceding complete identity record matched.

### C4 — descendants

**Current defect:** helper cleanup reads only one direct `children` file and rejects nonempty bytes; launcher never checks descendants. Neither path can recover/reap a grandchild (`closure.py:697-733`; `launcher.py:401-482`).

**Production correction:**

1. The outer supervisor records the exact pre-effect child baseline and enables/restores the fixed child-subreaper state around preparation.
2. Each helper owns a new SID/PGID. The child installs the fixed no-process-creation filter before exec where compatible with the three fixed helpers; any clone/fork/vfork denial failure is terminal.
3. Build a bounded recursive descendant census from strict `children` records. For every observed PID, open a pidfd and capture start time, SID, PGID, parent relation, and executable identity. Repeat the census byte-for-byte to establish a stable set before acting.
4. Normal mapping requires the set to be empty. An unexpected descendant fails preparation.
5. Recovery acts only on registered, still-matching identities in the owned session/process group. TERM/KILL is per pidfd, not an unbounded process scan or raw process-group broadcast. As subreaper, the supervisor boundedly reaps adopted descendants as well as the direct helper.
6. Success requires the recursive set empty, every registered process `reaped=true`, the helper registry empty, and the original child baseline restored.

If a process can fork faster than a stable bounded census can be established, cleanup is uncertain and no report/handoff is issued.

**Portable proof:** model one child, child+grandchild, disappearing descendant, foreign SID/PGID, PID reuse, unstable census, clone-denial failure, adopted reap, and descendant reap timeout. The model process table is independent of fd/pidfd tables.

### C5 — bounded waits and escalation

**Current defect:** helper startup failure and launcher success/failure use `waitpid(pid, 0)`. Launcher performs blocking wait after pipe EOF, outside the ten-second I/O deadline.

**Production correction:**

- One monotonic absolute deadline covers each start/status phase. Separate fixed absolute deadlines cover TERM and KILL phases.
- All waits are `WNOHANG`/`waitid(...WNOHANG)` loops. Each loop checks the deadline before and after EINTR, sleeps no longer than the remaining interval, and has a fixed iteration/sleep floor bound.
- EOF on output/status pipes does not disable the execution deadline. The launcher must still boundedly observe exact child exit.
- Escalation is: close release/input gates; validate; TERM; bounded wait; validate; KILL; bounded wait; exact reap; descendants; baseline. No unbounded final wait exists, including exception paths.
- Timeout keeps the lease `UNCERTAIN` with signaling identity retained for outer recovery. It never becomes `reaped=true` because a pipe closed or `ProcessLookupError` was seen.

**Portable proof:** frozen/advancing clocks, EOF-while-live, EINTR, TERM exit, TERM timeout/KILL exit, KILL timeout, unexpected wait result, lost reap ownership, and deadline rollover all run through one production wait/escalation function used by closure and launcher.

### C6 — proc/map descriptor close aggregation

**Current defect:** `_read_proc()` and map-file reads use bare `finally: close(fd)`, so a close error replaces the primary parse/read/authentication error (`closure.py:581-586,765-789`).

**Production correction:**

- Every proc, maps, map_files, exe, status, and fd-directory open returns an `_FdLease` registered in the current operation scope.
- A single `_finish_fd(lease, primary)` attempts close once. If both exist, raise `RuntimeClosureCleanupError((primary, close_error))` in that order. If several independently owned descriptors remain, attempt each reverse close and append every failure in deterministic reverse-acquisition order.
- `_read_proc`, `_maps_snapshot`, `_matching_child`, and each mapped-object read use this operation scope; no bare `finally: ops.close(...)` remains.
- After any close uncertainty, perform no new acquisition or authority-expanding operation. Run only independently safe cleanup/baseline comparisons and poison the owner.

**Portable proof:** for every proc/map open site, inject open/read/parse/fstat/generation/ELF failures independently and paired with close failure. Assert exact aggregate order and exactly one close attempt per lease.

### C7 — sealed-report close uncertainty

**Current defect:** `_seal_report()` closes the writable fd and, if close reports failure, passes the same fd to `_close_local()`, risking a second close after number reuse (`closure.py:836-868`).

**Production correction:**

1. Register writable memfd and read-only reopened fd as separate leases.
2. Complete write, fsync, readback, seals, read-only reopen, generation equality, and read-only/seal checks while both are owned.
3. Attempt writable close exactly once. On success mark it `CLOSED`; only then may the read-only lease be returned/transferred.
4. On writable close error mark it `CLOSE_UNCERTAIN`, never mention that integer to an fd operation again, close the distinct read-only lease once, poison, and issue no report.
5. A read-only close failure is treated identically. Baseline mismatch may add evidence but cannot convert uncertainty to a known-open descriptor or authorize retry.

Apply this once-only rule to all fds, not only reports.

**Portable proof:** direct `_seal_report` success and every write/fsync/readback/add/get-seal/reopen/fstat/close cut, including “close had effect then raised and number was reused.” The oracle requires no operation on the reused number and repeated owner close returns the same poison.

### C8 — strict kernel and supervisor records

**Current defect:** proc stat accepts an under-specified suffix; children is tested with `strip()` only; maps ignores device/offset strictness and accepts loose rows; helper status accepts any nonempty failure bytes.

**Production correction:** all parsers are pure byte-input functions with typed immutable outputs and fixed byte/record bounds.

- **`/proc/<pid>/stat`:** exactly one complete bounded record; decimal PID must equal the requested PID; command parentheses are delimited using the last valid `") "`; state is one accepted kernel state byte; every field through field 22 is present and lexically valid; start time is a nonnegative bounded integer. Trailing NUL, extra line, malformed separators, or truncation rejects.
- **`children`:** accept only empty or a bounded sequence of positive decimal PIDs separated by one ASCII space, with at most one trailing space and one terminal LF; reject duplicate/zero/out-of-range PIDs and all other whitespace/bytes.
- **`maps`:** require one LF per row and terminal LF; exact address `hex-hex`, four permission bytes, page-aligned hex offset, hex `major:minor`, decimal inode, and at most one path remainder. Extents are positive, ordered, non-overlapping, and bounded. For nonzero inode mappings, parsed device and inode must agree with `fstat(map_files)`; paths are never authority. For inode zero, executable rows are only the fixed synthetic allowlist.
- **status/control:** fixed message enum, exact field count/length, exact sequence number, no duplicate/out-of-order record, and no trailing bytes. EOF is success only at the one state where CLOEXEC EOF is specified.
- **report:** existing strict UTF-8/canonical JSON remains separate; runtime tracked-schema independence is still an open non-lifecycle finding.

**Portable proof:** table-driven accepted and one-byte hostile records call these production parsers directly and also pass through full helper/mapping/recovery flows. No adapter returns a pre-parsed successful identity or map row.

### C9 — page-correct `PT_LOAD` model

**Current defect:** `completion_elf.py:117-152` permits `p_align` 0/1 for `PT_LOAD`, compares unrounded byte spans, and resolves virtual bytes without Linux page remap/BSS semantics.

**Production correction for the fixed Linux x86-64 profile:**

1. Fix page size at 4096 for this parser profile. Every `PT_LOAD` has power-of-two `p_align >= 4096`; require both `p_offset % p_align == p_vaddr % p_align` and 4096-byte congruence. Reject `p_align` 0/1.
2. Require LOAD headers in strictly increasing virtual-page order and nondecreasing file-page order. Keep all overflow/file/memory bounds.
3. For each LOAD, derive page-rounded virtual/file extents and the affine file-byte mapping. Build a bounded interval model in program-header load order, including file-backed bytes and the zero-fill interval `[p_vaddr+p_filesz, p_vaddr+p_memsz)`.
4. Rounded virtual overlap is accepted only where overlapping file-backed intervals have the same virtual-to-file-page delta and therefore name the same bytes. Different-file-page aliasing is rejected. Apply later permission remaps without changing byte identity.
5. `PT_INTERP`, `PT_DYNAMIC`, the dynamic string table, and every decoded name must resolve wholly to one final file-backed interval. Any portion supplied by BSS/zero fill, overwritten by an incompatible later LOAD, or selected by more than one incompatible mapping rejects.
6. Reject pure-BSS LOADs in this fixed metadata profile unless a later compatibility review proves a required fixed host object needs them; ordinary file-backed LOADs may have BSS tails under the model above.

**Portable proof:** port the complete prior parser matrix to `parse_elf64`, then add `p_align=0`, `p_align=1`, page incongruence, different-page alias, compatible same-page overlap, rounded overlap, reversed LOAD, BSS-over-dynamic, BSS-over-string, and overflow fixtures. Each fixture reaches the public `parse_elf64(data)` call.

### C10 — component symlink and alias policy

**Current defect:** the production walker is substantial, but its portable `FsOps` has no symlinks/races; launcher source admission uses `Path.resolve()` and final-component-only open. The same-inode fixture is not bound to the real provider and has the wrong oracle.

**Production component policy:**

- Fixed logical paths themselves are absolute and contain no empty, `.`, or `..` component.
- Resolution starts from a retained, authenticated root directory fd. Every directory uses `lstatat(no-follow) -> openat(O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) -> fstat`, requiring exact generation equality, directory type, UID 0, and no group/world write.
- A symlink is allowed only when its containing directory already passed that policy and the symlink is UID 0. Use `lstatat -> readlinkat -> lstatat`; generation and target bytes must be identical. Symlink mode bits are not used as authority.
- Relative and absolute targets are allowed because the fixed host paths commonly use them. Absolute targets reset to retained root. `..` is allowed only in a symlink target and may not pop above root. Empty/`.` target components, NUL, non-UTF-8, overlong targets, more than 40 links, or more than 256 expanded components reject.
- The final object uses `lstatat -> openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC) -> fstat` with exact generation and source policy. After complete read/authentication, repeat resolution and require byte-identical component transcript (parent identity, component bytes, object kind/generation, and symlink target) plus the same final generation.
- `realpath`, `Path.resolve`, `PATH`, cwd-relative authorization, and final-component-only authorization are forbidden in closure and launcher source admission. Both use this one descriptor-relative policy.

**Production alias policy:**

- Two candidate logical paths resolving to the same `(device,inode)` and the same complete generation/hash/ELF are one provider. Close the duplicate held fd and accept; public metadata contains no chosen path.
- Two distinct identities are ambiguous even if bytes and SONAME are equal. Reject both and close both.
- Within and across tools, one authenticated identity may have only one role. Reuse as loader across tools or library across tools is allowed; executable/loader/library role aliasing is rejected. The three fixed executable identities must be pairwise distinct.
- Every SONAME still has exactly one identity provider per tool. Global same-role reuse affects aggregate deduplication only; it does not remove per-tool provider checks.

**Portable proof:** exact transcripts cover relative/absolute links, `..`, root escape, loop, depth/component bounds, mutable link target, ancestor replacement, stat/open race, second-pass rename, and no-realpath/PATH sentinels. Bind same-identity alias fixtures to the actual existing provider and require success; require distinct-identity same-byte candidates, cross-role identity, and aliased fixed executables to fail.

### C11 — fixed outer recovery

**Current defect:** `test/outcome-two-recovery-portable.py` crashes an in-memory worker and then runs an unrelated fresh success. Production has no outer owner capable of recovering the crashed process or its helpers.

**Production topology, internal to the unchanged public constructor:**

```text
caller / fixed outer supervisor (subreaper; owns baselines and all helper leases)
  |
  +-- preparation worker (PDEATHSIG; source/proc/map/report logic)
  |
  +-- helper for fixed tool (direct child spawned by outer on worker request)
```

1. `prepare_fixed_runtime_closure()` starts a fixed preparation worker through the private supervisor. The outer registers the worker's atomic pidfd identity before releasing it.
2. The worker requests helper creation over a bounded `SOCK_SEQPACKET` socketpair using strict fixed records and passes the already-authenticated executable fd with `SCM_RIGHTS`. The outer verifies the descriptor/generation request, creates and registers the helper as its **direct** child, retains all gates/pidfd authority, and acknowledges before helper release. The worker itself never owns an unregistered child.
3. The worker may read the helper's proc/maps data, but every helper lifecycle effect remains outer-owned. It reports MAP_DONE/STOP through the fixed protocol.
4. On success the worker passes exactly the two sealed executable fds and read-only sealed report fd to the outer. The outer independently checks descriptor count, roles, seals, CLOEXEC, report bytes, and worker status; boundedly reaps the worker; proves helper and baseline restoration; then constructs the `PreparedRuntimeClosure` around those received leases.
5. On worker crash, malformed record, control EOF, timeout, or parent-death cut, anonymous worker fds close by process death. The outer closes received fds, closes helper gates, revalidates every retained helper/descendant identity, performs bounded TERM/KILL/reap, reaps the worker, restores subreaper state, and proves baselines. There is no retry and no new preparation in that call.
6. If exact recovery cannot be proved, return one terminal cleanup error and no owner/report/handoff. No pathname, mount, or named state is introduced by closure preparation; any future named state requires retained parent-fd authority and a new protocol/ADR.
7. If the outer itself dies, worker PDEATHSIG and helper parent-death chains close anonymous resources; no success can be reported. Runner disposal is still not evidence, and this case cannot be reclassified as proved cleanup.

**Portable proof:** a real fresh supervisor process runs the production supervisor state machine against model host-object operations and a harmless real blocked process. Crash the preparation worker at every registered cut. The surviving outer must recover the exact worker/helper, report `reaped=true`, prove OS fd/child baselines, and emit one terminal result. A subsequent independent success is tested only as module-state isolation, never called recovery.

## 4. Production `_Ops` seam that portable tests must drive

The present `_Ops` mixes a concrete system implementation with overridable defaults, while suites patch complete production routines. Replace it with a total private protocol and two explicit implementations:

```python
class _Ops(Protocol):
    # fd/filesystem primitives
    def openat(...) -> int: ...
    def close(...) -> None: ...
    def fstat(...) -> StatRecord: ...
    def lstatat(...) -> StatRecord: ...
    def readlinkat(...) -> bytes: ...
    def getdents(...) -> bytes: ...
    def pread(...); def pwrite(...); def read(...); def write(...): ...
    def memfd_create(...); def fchmod(...); def fsync(...); def fcntl(...): ...

    # process primitives
    def clone3_pidfd(...) -> SpawnResult: ...
    def pidfd_send_signal(...); def waitid_pidfd_nohang(...): ...
    def getsid(...); def getpgid(...): ...
    def set_child_subreaper(...); def get_child_subreaper(...): ...

    # time/control transport
    def monotonic(...) -> float: ...
    def sleep(...) -> None: ...
    def poll(...) -> tuple[PollEvent, ...]: ...
    def socketpair_seqpacket(...); def send_record_fds(...); def recv_record_fds(...): ...

class _SystemOps(_Ops): ...       # the only class containing os/fcntl/ctypes/select/time
class _ModelOps(_Ops): ...        # test-only, complete deterministic kernel model
```

Exact seam rules:

1. Production orchestration contains no direct `os`, `fcntl`, `signal`, `select`, `time`, `subprocess`, `Path.resolve`, or `ctypes` effect outside `_SystemOps`. Pure hashing, canonical encoding, and pure byte-record parsers remain outside.
2. `_SystemOps` has no fault selectors. `prepare_fixed_runtime_closure()` always constructs it with no argument. `_ModelOps` is reachable only through the existing private test constructor and is absent from `__all__`.
3. `_ModelOps` implements separate fd-object, process, pidfd, filesystem-generation, clock, proc-byte, and control-packet tables. Closing a pidfd does not reap a process; removing an fd does not kill a child; process exit does not imply reap. This prevents the current false residue oracles.
4. Fault scripts attach to primitive operations as `before`, `success`, or `after-effect error`. The latter is mandatory for open/clone/write/seal/close/send-fd operations. Every script entry must be consumed exactly once; dead fixture rows and unconsumed operations fail the suite.
5. Tests inject only through `_Ops`. They may not patch `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, `_stop_helper`, `_seal_source`, `_seal_report`, `_prepare`, wait/escalation, or recovery. Those exact production functions must run.
6. Unit tests may call pure parsers and narrow production functions, but at least one success and every lifecycle cut must run end-to-end through `_prepare_with_adapter_for_tests(_ModelOps(...))` and the outer supervisor path.
7. Child setup is a production `_helper_child_main(ops, fixed_spec)` function. Portable child-mode tests drive it with `_ModelOps`; native Job D separately qualifies real clone3/pidfd/PDEATHSIG/session behavior.
8. System-only primitives are qualified narrowly in native Jobs A/C/D. Native tests do not duplicate parser, model fault, close uncertainty, or recovery matrices.

## 5. Required portable correction matrix

All fixture manifests are executable truth: the suite asserts exact equality between declared case IDs and observed case IDs.

| Matrix | Required cases |
| --- | --- |
| fd baseline | changing enumerator fd, multi-chunk EOF, malformed/duplicate dirent, hidden fd, open/read/close faults, ready/failure/close comparisons |
| helper allocation | every gate/status/devnull/clone registration cut, closed-stdio permutations, inherited ambient fd, parent-change, child setup/exec/status faults |
| identity/wait | PID reuse; pidfd/starttime/SID/PGID/exe drift; EOF-live child; EINTR; TERM/KILL exits/timeouts; wait/reap loss |
| descendants | none; direct; grandchild; unstable census; foreign group/session; adopted reap; descendant timeout; baseline restoration |
| proc/maps | strict stat/children/maps records; all map bounds; ambiguous identity; every proc/map open/read/parse/fstat/close and primary+close pair |
| report fd | complete `_seal_report` matrix, read-only reopen identity, after-effect close/reuse, owner poison repeat |
| ELF | prior complete parser matrix plus all page alignment/alias/rounded-overlap/reversed/BSS cases |
| components | relative/absolute symlink, `..`, escape, loop, replacement phases, transcript drift, same/distinct alias, role alias, no PATH/realpath |
| outer recovery | every preparation/publication/handoff/cleanup cut with a surviving outer, real blocked child, exact revalidation/reap, no unrelated retry |
| integrated residue | exact fd/child/subreaper/path baseline, empty registries, no uncertain lease, no report/handoff on any fault |

The current `hostile[:10]` slice, uniterated maps `hostile` rows, unused lifecycle `cleanup` rows, patched recovery harness, fabricated launcher results, and adapter-local `live == {}` assertions must be removed as evidence patterns.

## 6. Implementation order and acceptance

1. Accept a corrective ADR with readable highs and the private outer-supervisor protocol.
2. Introduce pure strict-record and page-LOAD parsing with hostile fixtures.
3. Introduce lease registries and the total `_Ops`/`_SystemOps` seam.
4. Correct fd snapshots, component resolution, and once-only close handling.
5. Unify helper/launcher identity, descendants, and bounded wait/escalation.
6. Add the fixed outer supervisor and replace fresh-retry tests with recovery tests.
7. Run the complete portable matrix; then run only the applicable native primitive jobs.
8. Obtain fresh exact-head parser/authentication, mapping/cleanup, launcher/schema, portable-test, and holistic hostile reviews with no unresolved P0-P3.

No READY state, report, handoff, pass result, or cleanup success may be published if any lease is `CLOSE_UNCERTAIN`, any helper/descendant is not exactly reaped, any baseline cannot be compared, a deadline expires, a record is malformed, or outer recovery is incomplete.
