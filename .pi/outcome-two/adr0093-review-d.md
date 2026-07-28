# ADR 0093 exact-head hostile review — Job D lifecycle

## Verdict

**BLOCKED** — exact implementation head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` retains unresolved P1 defects in transfer identity, creator/outer failure settlement, and the causal portable corpus. Job D is not eligible for ADR 0093 signoff or native execution.

**SIGNOFF: BLOCKED**

## Scope and boundary

Reviewed Job D's three independent before-release, after-release, and TERM/KILL transactions; descendant preregistration and the post-`setsid` second gate; credentialed pidfd/role/case/identity transfer; recursive census and adoption; exact siginfo/wait/reap; aggregate cleanup and subreaper restoration; the thin D client; and the D portable/focused corpus at exact head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`.

This was static/portable review only. I invoked no `--workflow-bound` route, native qualification, sudo/native primitive, workflow, provider, cloud, or AWS operation. No production source was edited.

## P0–P3 summary

- **P0:** none found.
- **P1:** three unresolved findings.
- **P2:** none separate from the P1 authority/acceptance defects.
- **P3:** none found.

## Findings

### P1-1 — A received pidfd is not bound to the asserted PID before TERM/KILL effects

`_ProcessOwner.receive_descendant` transfers the one received right and passes it to `register(value["pid"], pidfd_fd=pidfd)` (`completion_trusted_runtime_launcher.py:885-886`). `register` associates that descriptor with the packet PID, but all of its start/session/group/executable observations are opened by the packet PID (`:770-786`); it never verifies that the received pidfd itself names that PID. The recursive census likewise proves that the packet PID is the leader's child, not that the transferred descriptor targets it (`:919-930`).

The TERM/KILL case then calls `_process_matches(descendant)`, which again inspects the numeric packet PID, and sends both signals through the unbound received pidfd (`:3297-3307`). Only the later `waitid(P_PIDFD)` record compares `si_pid` with the packet PID (`:3224-3237`), after the signal effects. A wrong pidfd accompanied by an otherwise exact packet and same credentialed sender can therefore direct TERM/KILL to a different process before Job D rejects it. This fails ADR 0093's requirement that exact pidfd/identity authority be transferred before descendant effects.

Bind the pidfd target to the asserted PID, in the common namespace, before acknowledgement/release or any signal. Add wrong-target and fd-reuse mutants that prove no effect occurs on mismatch.

### P1-2 — Pre-registration transfer rejection can kill the creator before it settles its gated descendant

The local leader correctly creates the descendant with `_ProcessOwner.spawn`, leaving it blocked on the registration gate, and keeps local pidfd authority while sending the transfer (`:3136-3168`). But outer rejection before `receive_descendant` calls `register`—including missing/extra rights, wrong credentials, malformed JSON, or nonce/case/role binding failure—leaves the outer owner with only the leader. `_run_lifecycle_case` immediately enters `owner.cleanup(primary)` on that rejection (`:3337-3348`). Cleanup can TERM/KILL and reap the leader while the leader is waiting for the acknowledgement.

That asynchronous leader death does not run `_lifecycle_leader`'s Python cleanup block (`:3191-3213`). Closing the inherited registration writer makes the gated descendant reject EOF and `_exit(125)` (`:3044-3080`), but the descendant is then adopted by the subreaper without any outer lease/pidfd and is not reaped. The final children baseline can diagnose the zombie; it cannot settle it. The race where the leader times out first and performs local cleanup does not make the opposite cut safe.

The leader's best-effort `Z:` packet is also not an aggregate handoff, and the outer path that already failed `receive_descendant` does not await it. Thus failure and cleanup authority are not transferred to one surviving aggregate owner for every transfer cut, contrary to ADR 0093.

Provide a creator-owned abort/settlement handshake that the outer owner waits through before retiring the leader, or transfer enough independently authenticated descendant authority for the outer owner to adopt and reap every rejection path. Preserve and aggregate both primary and cleanup failures.

### P1-3 — The declared D ledger does not execute the creator/descendant production state machines and omits required cuts

The new matrix does call `_qualify_admitted_fixed_process_lifecycle` and the parent half of `_run_lifecycle_case`, and its success row observes three case completions. It does not execute `_lifecycle_leader` or `_lifecycle_descendant`. The modeled `clone_pidfd` always returns a positive parent PID (`test/outcome-two-lifecycle-portable.py:940-952`), while `ScriptedSocket.recvmsg` fabricates the descendant and SCM packet (`:730-770`). For malformed pre-registration transfers it explicitly calls `creator_abort_descendant()` (`:768-769`, `:977-981`), manufacturing exactly the creator settlement that production does not guarantee.

Consequently the rows named `before-secondary-pidfd` and `after-secondary-pidfd` inject at `leader-clone`, not at descendant creation (`qualification-cases.jsonl:7,18`). No row executes or faults descendant preregistration, the child-side gate read, local identity acquisition, sendmsg/shutdown/acknowledgement, local-authority retirement, PDEATH arming/readback, or the leader cleanup/failure packet. The exact siginfo corpus mutates only `si_status` (`qualification-cases.jsonl:25`), not PID, UID, or code; there are also no exact waitpid identity/status, adoption identity, child-baseline, subreaper readback, or socket/pipe close-uncertainty cuts.

`declared == selected == consumed == oracle` (`test/outcome-two-lifecycle-portable.py:1164-1199`) therefore proves bookkeeping over an incomplete scripted parent model, not causal coverage of the complete D production state machines. Completed-result fabrication was removed from the thin client, but this substitute child protocol remains non-accepting under ADR 0093.

Run the actual leader and descendant production functions above mocked native primitives, give each fallible before/after-effect transition an independently selected row, and require exact sentinel/oracle consumption for all three transactions and all settlement branches.

## Positive observations

The source now constructs three separate case transactions (`completion_trusted_runtime_launcher.py:3376-3379`). The leader is confirmed in its planned post-`setsid` identity before the second gate allows descendant creation (`:3273-3277`). The descendant is locally preregistered behind a gate before PDEATH/TERM behavior (`:3136-3155`), and the outer transfer checks credentials, closed packet fields, nonce/case/role/sequence, repeated identity census, replay, and EOF before acknowledgement (`:838-907`, `:3277-3289`). `_exact_signal_reap` now checks exact PID, UID, `CLD_KILLED`, `SIGKILL`, waitpid PID, signaled state, and terminating signal (`:3224-3239`). The thin D client is receipt-only and preserves `SystemExit(0)` success.

These corrections resolve important parts of the ADR 0092 findings but do not close the P1 defects above.

## Verification performed

Portable/static only:

- Exact reviewed head: `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`; worktree was clean before this report.
- `/usr/bin/python3 -I -B test/outcome-two-lifecycle-portable.py`: passed.
- `git diff --check ce1f6f8..0db8c26`: passed.
- Focused TypeScript D test was not run because the locked `tsx` executable is not provisioned. This is an unexecuted portable gate, not native evidence and not the basis of the findings.

## Required before rereview

1. Prove the transferred pidfd targets the asserted descendant before acknowledgement, release, TERM, or KILL.
2. Make every pre-registration transfer rejection converge on a surviving owner that has exact descendant authority and performs bounded signal/wait/reap with aggregate failure retention.
3. Replace the scripted child fabrication with causal execution of `_lifecycle_leader` and `_lifecycle_descendant`, and cover every preregistration, second-gate, transfer, census/adoption, PDEATH, TERM/KILL, exact siginfo/wait/reap, subreaper, descriptor, and cleanup cut.
4. Rerun all ordinary static/portable gates at one exact clean implementation head and obtain a fresh hostile D review. Native/cloud execution remains forbidden.
