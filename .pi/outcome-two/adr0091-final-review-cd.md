# ADR 0091 final hostile review — production Jobs C/D

## Verdict

**BLOCKED** — implementation head `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08` has unresolved P1 findings. It is not eligible for native execution or a later execution ADR.

**SIGNOFF: BLOCKED**

## Scope and boundary

Reviewed the exact C/D production owners, fixed-operation admission, C/D drivers, common baseline/report custodian, and their portable/focused tests at `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08` against accepted ADR 0091 and its frozen API.

This was static/portable only. I invoked no `--workflow-bound` selector, sudo, native qualification case, workflow dispatch, namespace/mount/seccomp operation, provider, cloud, or AWS route.

## Severity summary

- **P0:** none found.
- **P1:** six unresolved findings.
- **P2:** none separate from the P1 acceptance failures.
- **P3:** none found.

## Findings

### P1-1 — D aliases one PDEATH path into four distinct lifecycle claims and never performs the required TERM/KILL case

`_qualify_admitted_fixed_process_lifecycle` creates only one leader and one descendant (`completion_trusted_runtime_launcher.py:2443-2504`). It sends TERM only to the descendant (`:2505`), asks the leader to exit normally (`:2508-2511`), then observes the descendant's PDEATHSIG death (`:2512-2519`). There is no independent before-release PDEATH case, after-release PDEATH case, or TERM-then-pidfd-KILL leader/descendant case.

The result then assigns the same `siginfo` value to both `before_release_death` and `after_release_death`, and derives `term_kill_bounded` from `survived_term and siginfo` even though that SIGKILL came from PDEATHSIG rather than an owner-issued KILL (`:2526`). `pdeathsig_armed`, `parent_handshake_exact`, and `starttime_revalidated` are also emitted as unconditional `True` values rather than their own observations.

This can publish claims for mechanisms that did not run. It fails ADR 0091 `AT91-PROC-01` for independent identities, signals, siginfo, wait, reap, and outcome derivation.

### P1-2 — D's planned `setsid` gate and transfer/census/adoption protocol are incomplete and the production receive is racy

The child writes `S` after `setsid` and immediately creates its descendant (`completion_trusted_runtime_launcher.py:2461-2464`). It never waits for the outer owner to confirm immutable identity and exact `(sid, pgid) == (pid, pid)`. The parent confirms only later (`:2498-2502`), so descendant creation is not held behind the mandatory second gate.

The leader writes transition status before it sends the pidfd packet. The parent immediately calls `receive_descendant`, whose first action is nonblocking `recvmsg(... MSG_DONTWAIT)` without a readiness/deadline wait (`:757-760`, `:2498-2502`). A valid native schedule can therefore fail with `EAGAIN`.

The positive transfer does carry one kernel credential record and one `SCM_RIGHTS` pidfd, and registers it before sending `A`. However, the packet omits the required role/case identity, no extra-packet/replay check follows, and the acknowledgement is an uncredentialed one-byte receive in the leader (`:2481-2486`). Census is only two sorted PID tuples with a 4,096-node bound (`:780-785`, `:1479-1489`), not the required bounded identity-and-edge graph, reconciliation/quarantine, or adoption state. Adoption is one instantaneous direct-child membership check (`:2512`).

Thus credentialed pidfd transfer exists in part, but the exact preregistration, second gate, complete transfer, stable recursive census, spawn-after ownership, and stable adoption contract does not.

### P1-3 — D has no production failure settlement state machine

After changing subreaper state (`completion_trusted_runtime_launcher.py:2447-2449`), the transaction performs socket/pipe allocation, process creation, transition, transfer, signals, waits, closes, and restoration as one unguarded straight-line block through `:2527`. There is no `try/finally`, aggregate cleanup, gate-abort path, `owner.cleanup(primary)`, or guaranteed subreaper readback on any cut.

Any failure in `setsid` status, nonblocking transfer receive, credentials/identity validation, census, acknowledgement, signal, deadline, waitid/waitpid, or close bypasses lines `2520-2525`. The function can leave gates, endpoints, registered processes, descendants, pidfds, and changed subreaper state unsettled in the production bootstrap. Process exit or runner disposal is not the required owner-driven wait/reap/restoration evidence.

### P1-4 — C reaches real `getdents64`/`close_range`, but its advertised exact descriptor transaction is not the required transaction

Positive: C enters the closure production facade, `_snapshot_fds` calls the real `_Ops.getdents`, child close-complement calls the real `_Ops.close_range`, and the parent directly closes fd 4096 through that same primitive (`completion_trusted_runtime_closure.py:2106-2111`, `:2152-2155`, `:2177-2182`). The driver no longer contains a local syscall substitute.

The remaining production behavior is not exact:

- `_snapshot_fds` bounds only accumulated entry count. It has no 32-call or 1,048,576-byte bound (`:789-806`), and its dirent parser accepts unaligned records as small as 20 bytes and does not reject nonzero bytes after the first NUL (`:769-786`). A stream of empty-name/non-numeric-free chunks can run without the ADR bound.
- The child never execs the fixed held Python generation. It closes the complement, snapshots its own pre-exec fd table, writes `exact`, and exits (`:2145-2158`). Therefore `inheritance_exact` is not an exec inheritance observation.
- `wait_pidfd_nohang` uses reaping `waitid` but C inspects neither `si_code` nor status and performs no matching exact wait/reap comparison; a child can write `exact` and subsequently die abnormally while `inheritance_exact` remains true (`:2168-2176`; `_Ops.wait_pidfd_nohang` at `:411-413`).

This fails `AT91-FD-01` despite using the intended syscall symbols.

### P1-5 — The portable/focused tests replace the missing C/D mechanisms instead of making their branches and faults reachable

The only direct C owner exercise is one happy scripted call plus replay (`test/outcome-two-runtime-closure-portable.py:428-445`). It has no open/pipe/dup/clone/release/exec/getdents-call-bound/close-range-before-or-after/reuse/limit/wait/siginfo/reap cut.

The D owner fixture has only six rows: planned-setsid happy/session drift, transfer happy/wrong credentials, and census happy/spawn-after (`test/fixtures/outcome-two/lifecycle/owner-cases.jsonl`; `test/outcome-two-lifecycle-portable.py:508-610`). It never invokes `_qualify_admitted_fixed_process_lifecycle`, so it cannot expose the missing second gate, `EAGAIN` race, aliased PDEATH cases, absent TERM/KILL case, adoption, wait/reap, subreaper, or transaction cleanup.

The cross-file bootstrap test explicitly replaces held execution with an all-true completed result (`test/outcome-two-trusted-launcher-portable.py:783-791`). The focused C/D tests only decode preassembled dictionaries and regex-check that the thin drivers contain no mechanisms (`test/native-qualification-{c,d}.test.ts`). The older lifecycle/recovery matrices primarily exercise closure helper cleanup and isolated `_ProcessOwner` fragments, not the D production transaction.

Accordingly, declared/selected/consumed/oracle equality is not established for the ADR 0091 case sets, and branch removal in the actual C/D owners would remain green.

### P1-6 — Common's report custodian is neither safely preregistered nor retained/reaped under an authenticated cleanup capability

`_start_custodian` uses `fork()` followed by `pidfd_open()` (`scripts/native-qualification/common.py:507-520`). The child can bind/listen on its abstract cleanup socket before it waits for `START` (`:534-540`), so a named effect can precede parent pidfd registration. If `pidfd_open`, child-fd close, readiness send/read, or validation fails, there is no process-owner cleanup/reap path.

After publication, the client closes both its control lease and pidfd (`:500-506`) while the child remains blocked in `accept()` (`:593-600`). The later workflow cleanup is a different process and cannot wait/reap that child. It connects to a predictable run/job socket and sends only `CLEANUP`; the child checks same uid/gid but not the receipt nonce, head, run, or another opaque capability (`:638-665`). Any same-credential process can trigger report deletion before upload completes.

The common companion never runs this custodian transaction. It substitutes a `Cust` object, exercises one happy in-memory publication, a lease poison, parser snippets, and `_name_matches` tokens (`test/native-qualification-common.test.ts:151-208`). It does not cover fork/pidfd cuts, worker crash, upload failure, custodian loss, unauthorized cleanup, close uncertainty, replacement at every phase, or child reap. This fails `AT91-OUTER-01` and `AT91-REPORT-01`, so C/D report ownership is not signable even independently of the owner defects above.

## Verification performed

Portable/static passes:

- C/D focused Node tests: **6/6 passed**.
- `test/outcome-two-runtime-closure-portable.py`: passed.
- `test/outcome-two-lifecycle-portable.py`: passed.
- `test/outcome-two-recovery-portable.py`: passed.
- `test/outcome-two-trusted-launcher-portable.py`: passed.
- Python AST parsing for the nine reviewed production/portable Python files: passed.
- `git diff --check a3f529a^..a3f529a`: passed.

The common TypeScript companion could not start because locked dependencies are not provisioned in this checkout (`ajv/dist/2020.js` missing). This is recorded as an unexecuted gate, not native evidence and not the basis of the findings.

Gross additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa` remain numerically within ADR 0091: trusted/portable listed text `9308/10790`, native `3329/5400`, aggregate `12637/16250`. Relevant exact files include launcher `2600/2600`, closure `2327/2350`, common `750/750`, runtime-closure portable `449/450`, and lifecycle portable `688/720`. The exhausted launcher/common highs do not waive the defects; correction must delete/restructure within the accepted accounting rules or stop for another measured ADR.

## Required before rereview

1. Implement independent before-release PDEATH, after-release PDEATH, and TERM/KILL transactions; derive every D field from its own exact signal/siginfo/wait/reap observation.
2. Hold descendant creation behind an outer-confirmed post-`setsid` gate; make transfer receive deadline-driven, complete and replay/extra-packet closed; reconcile bounded identity-and-edge censuses and stable adoption.
3. Give D one aggregate failure-settlement path that always closes gates, retains pidfd authority, signals only after invariant checks, waits/reaps, restores/rereads subreaper, and proves final census/fd baselines.
4. Make C's enumerator exactly call/byte/entry bounded and strictly parsed; execute the admitted fixed Python generation and compare exact waitid/waitpid outcome rather than pre-exec fd state.
5. Replace completed observations with primitive before/after fault matrices that invoke both complete production owners and prove declared = selected = consumed = oracle with branch-removal sentinels.
6. Atomically preregister and retain the report custodian, authenticate post-upload cleanup with the opaque transaction capability, and prove exact child retirement/reap and the complete publication/recovery fault matrix.
7. Rerun all ordinary portable/static gates at one new clean exact head and obtain a fresh hostile C/D review. Native execution remains forbidden pending five clean reviews and a later accepted execution ADR.
