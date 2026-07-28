# ADR 0093b fresh exact-head hostile review — Job D lifecycle

## Verdict

**BLOCKED** — exact implementation head `0d934c9e03aae17a5f219f302cf5c09058d45c59` retains P1 defects in transferred-descendant settlement, rejected-transfer fallback settlement, and the required complete causal D corpus.

**SIGNOFF: BLOCKED**

## Scope and execution boundary

Reviewed ADR 0093 section 7 and the current corrected Job D production owner, transfer identity binding, before-release/after-release/TERM-KILL transactions, aggregate cleanup, thin client, lifecycle fixtures, and complete portable corpus. The worktree was clean at the reviewed head.

This was static/portable review only. I did not invoke `--workflow-bound`, native qualification, sudo, native primitives, workflow dispatch/rerun, network, provider, cloud, AWS, OpenTofu, deployment, campaign, production, or release activity. No production source was edited.

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 3 | unresolved; blocking |
| P2 | 0 | none separate from the P1 authority/acceptance defects |
| P3 | 0 | none found |

## Findings

### P1-1 — Generic failure cleanup can observe descendant death and falsely mark it reaped without `waitpid`

A received descendant is registered with `waitable=False` (`completion_trusted_runtime_launcher.py:905-912`). Only the happy path changes it to `waitable=True`, after the leader has exited and `_stable_adoption` has passed (`:3546-3553`). Every earlier failure instead reaches `owner.cleanup(primary)` (`:3573-3577`). Owner iteration preserves registration order, so it settles the leader before the later registered descendant (`:965-968`). Killing/reaping the leader makes the subreaper the descendant's surviving parent.

The descendant still has `waitable=False`. `_wait_bounded` treats pidfd readability for such a lease as if reap occurred: it sets `lease.reaped = True` and returns without calling `waitpid` (`:1134-1142`). `_stop_process` has the same ready-at-entry shortcut (`:1164-1169`). If the descendant is alive when cleanup begins, `_stop_process` sends TERM/KILL and then takes the non-waitable shortcut when the pidfd becomes readable. If it is already a zombie, `_stable_direct_child` can reject because it requires `/proc/<pid>/exe` identity (`:1880-1889`), after which the shortcut again marks it reaped. The pidfd is then closed although the now-direct child was never waited.

This affects failures after transfer acknowledgement but before the explicit adoption/reap path, including child arming/status, release/readback, leader exit, and adoption cuts. The final child baseline can reject the zombie; it does not settle it. ADR 0093 requires aggregate failure settlement, not diagnosis after cleanup authority was discarded.

### P1-2 — Rejected-transfer fallback still has a creator-timeout branch with no post-kill adoption

`_settle_rejected_transfer` asks the creator to abort, waits for its settlement packet, and then calls `_wait_bounded(leader)` (`completion_trusted_runtime_launcher.py:3219-3242`). If that wait reaches its deadline, the function records `creator-settlement` but leaves the leader alive (`:3242-3247`). It immediately runs `_adopt_unregistered_children` while the still-live leader remains the descendant's parent (`:3248-3255`) and raises the aggregate.

The enclosing `_run_lifecycle_case` then reaches ordinary `owner.cleanup(primary)` (`:3573-3577`), which may TERM/KILL and reap the leader. Any creator-owned, not-yet-transferred descendant is adopted only at that later point, after the sole adoption scan has already run. There is no second adoption-and-reap pass after generic cleanup. This recreates the original pre-registration leak on creator timeout, control-send failure, creator cleanup hang/failure, or a boundary race at the shared deadline.

A rejected transfer must converge on a surviving owner that kills and waits the creator, then adopts and reaps every newly exposed child before returning the aggregate. The current ordering does not provide that guarantee.

### P1-3 — The portable ledger still does not execute either child-side production state machine and omits most required cuts

The production matrix remains a parent-only scripted model. `ProductionLifecycleKernel.clone_pidfd()` always returns a positive parent PID (`test/outcome-two-lifecycle-portable.py:952-966`); `ScriptedSocket.recvmsg()` fabricates the descendant packet and SCM rights (`:738-772`); and `reject_transfer()` directly marks the descendant reaped and exits the leader (`:990-995`). The suite replaces the production socket type with `ScriptedSocket` (`:1127`) but never calls `_lifecycle_leader` or `_lifecycle_descendant`. An AST probe over the exact suite found zero direct calls, and no qualification fixture row names either function.

The rejection oracle therefore manufactures the creator settlement that P1-2 fails to guarantee. The model also keeps executable identity available for dead modeled processes, allowing `_stable_direct_child` to make a modeled adopted zombie waitable and hiding P1-1.

The 30-row qualification corpus has no independently selected cuts for descendant clone/preregistration, child registration-gate read/EOF, parent-before/after checks, PDEATHSIG set, TERM-ignore installation, child status writes, release read, leader pipe allocation, transfer `sendmsg`/shutdown/ack, local pidfd retirement, creator cleanup/failure-packet send, waitpid PID/status mutations, adoption identity, child-baseline drift, or most socket/pipe close uncertainties. The standalone owner fixture no longer contains its former wrong-target/fd-reuse rows; the qualification fixture has one wrong-target row but no fd-number-reuse/drift mutant (`qualification-cases.jsonl:29`).

`declared == selected == consumed == oracle` consequently proves bookkeeping over an incomplete substitute protocol. It does not satisfy ADR 0093 sections 7 and 10 or the prior rereview requirement to run the actual leader and descendant production functions above mocked native primitives at every fallible transition.

## Positive observations

The production transfer identity defect itself is substantially corrected. `receive_descendant` transfers the received right into an owned lease and production calls `register(..., bind_received_pidfd=True)` (`completion_trusted_runtime_launcher.py:905-912`). Registration reads `/proc/self/fdinfo/<fd>` three times and requires the retained pidfd target to equal the packet PID before packet identity checks, acknowledgement, release, or signal effects (`:784-786`, `:1048-1065`). The qualification fixture now rejects a wrong-target pidfd and mutates all four exact waitid fields (PID, UID, code, and status).

The positive clone/negative secondary-pidfd result is also retained and settled through the creator's numeric direct-child authority rather than being discarded. These fixes close important portions of the prior transfer-identity finding, but they do not close aggregate settlement or corpus completeness.

## Verification performed

Portable/static only:

- Exact implementation head: `0d934c9e03aae17a5f219f302cf5c09058d45c59`.
- All seven `/usr/bin/python3 -I -B test/outcome-two-*-portable.py` suites: **PASS**.
- All seven corresponding `-O -I -B` runs: **PASS** by rejecting optimized mode.
- AST parse of the production launcher, Job D client, and lifecycle portable suite: **PASS**.
- Static corpus probe: 30 qualification rows; zero calls to `_lifecycle_leader` or `_lifecycle_descendant`; zero fixture production methods naming them.
- `git diff --check 0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a..0d934c9e03aae17a5f219f302cf5c09058d45c59`: **PASS**.
- The focused TypeScript D test was not run because this checkout has no `node_modules`/locked `tsx`; no install or network access was attempted.
- The broader accounting-predecessor `git diff --check` reports pre-existing trailing whitespace in historical `.pi/outcome-two/*.md` review files; the corrected implementation range above is clean.

## Required before rereview

1. Never equate pidfd death readiness with reap for a descendant that has become a direct child; retain authority until exact `waitid`/`waitpid` settlement is proved on every failure branch.
2. Reorder rejected-transfer fallback so creator termination/reap is followed by a stable adoption-and-reap pass even when the settlement packet or bounded creator wait fails.
3. Execute the actual `_lifecycle_leader` and `_lifecycle_descendant` functions above mocked primitives, rather than fabricating their packet, descendant, creator cleanup, and reap effects.
4. Add independently selected and oracle-consumed rows for every before/after fallible child, creator, transfer, acknowledgement, PDEATH, TERM/KILL, exact wait, adoption, descriptor, baseline, and cleanup transition, including pidfd reuse/drift.
5. Obtain another clean exact-head static/portable hostile review. Native/cloud execution remains forbidden.

# SIGNOFF: BLOCKED

Do not authorize Job D native execution or rely on its lifecycle evidence at `0d934c9e03aae17a5f219f302cf5c09058d45c59`.
