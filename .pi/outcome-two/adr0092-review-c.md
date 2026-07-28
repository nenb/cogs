# ADR 0092 hostile review — production Job C

## Verdict

**BLOCKED** — exact implementation head `3846383f0d88c190226356ca9aeeeda402943aaa` has an unresolved P1 acceptance failure and a P2 exact-bound defect. It is not eligible for native execution or a later execution ADR.

**SIGNOFF: BLOCKED**

## Scope and boundary

Reviewed the production C descriptor owner, its fixed-operation/common handoff, thin C driver, descriptor fixture, and focused portable tests against ADR 0092's exact bounded-dirent, held-Python exec inheritance, wait/siginfo/reap, limit/fd settlement, close-reuse, and production-path fault-matrix requirements.

The reviewed tree was clean at the exact head before this report. This review was static/portable only: no `--workflow-bound` selector, native qualification, sudo, workflow dispatch, namespace/mount/seccomp operation, provider, cloud, or AWS route was invoked.

## P0–P3 summary

| Severity | Verdict |
| --- | --- |
| P0 | None found. |
| P1 | **1 unresolved.** The declared C corpus is not a real causal production fault/settlement matrix. |
| P2 | **1 unresolved.** The production getdents call bound rejects the authorized boundary. |
| P3 | None found. |

## Findings

### P1-1 — The C corpus neither drives the required primitive cuts nor proves cleanup or exec causality

The fixture declares only 28 cases (`test/fixtures/outcome-two/lifecycle/descriptor-cases.jsonl:2-29`). It omits substantial required cuts: directory/proc/tool opens; getdents syscall/read/EOF failures; post-effect limit changes; malformed clone/pidfd registration; start-time/executable/session/group drift; child gate closes and `dup2`; each child close-complement interval; readiness timeout; trailing status; completion write; siginfo PID/UID; wait-status disagreement; before/after reap; pidfd close; cleanup signal; and final baseline-observation failures.

More importantly, the harness does not prove the fields it declares. `descriptor_cut_corpus()` ignores each row's `production_method`, `cleanup_domains`, and `sentinel`; it adds every iterated ID to selected/consumed/oracle unconditionally (`test/outcome-two-runtime-closure-portable.py:635-693`). A rejecting row need only make the adapter's top-level `fired` bit true and return any rejection. Except for one reused-number assertion, the harness never requires restored limits, the original fd table, an empty child registry, exact reap, or a complete expected event trace after failure (`:677-689`). Removing settlement branches can therefore leave this equality check green.

The exec proof is also split into noncausal substitutes. The child adapter discards the executable fd, argv, and environment and raises `ChildExec` merely because `execve` was called (`:585-595`). The separate parent adapter fabricates `R`, the admitted executable identity, and `{0,1,2,197,4096}` independently of the child execution (`:367-420`). A wrong executable fd/argv or removal/change of `_close_complement()` can still satisfy these oracles. This does not establish ADR 0092 section 9's complete production state machine above a mocked syscall boundary or its branch-removal requirement.

Two nominal bound cases demonstrate the same issue. The fixture's byte-bound stream reaches the production call-bound rejection rather than the byte-bound branch, while its entry-bound stream returns a single chunk larger than 32,768 bytes and is rejected by the chunk-size guard before the aggregate entry check (`test/outcome-two-runtime-closure-portable.py:523-537`; production at `completion_trusted_runtime_closure.py:793-856`). Green execution therefore does not prove the named byte and entry oracles.

This is acceptance-blocking even though the production happy path now visibly uses strict parsing, held-fd `execve`, post-exec identity/fd observations, `waitid(...WNOWAIT)` plus `waitpid`, close-uncertain state, exact limit readback, and final baselines (`completion_trusted_runtime_closure.py:2295-2535`). Those branches remain insufficiently fault-proved.

### P2-1 — Production permits only 31 nonempty getdents chunks plus EOF, not the frozen 32 plus EOF

`_snapshot_fd_directory()` loops while `calls < 32` and consumes the EOF inside those 32 total calls (`completion_trusted_runtime_closure.py:831-862`). Consequently 31 nonempty chunks followed by EOF pass, but 32 nonempty chunks followed by the separately permitted EOF are rejected as `descriptor enumeration call bound before EOF` without issuing that EOF call.

That contradicts the frozen exact contract of at most 32 nonempty chunks **plus one EOF call** and differs from common's corresponding 33-iteration implementation (`scripts/native-qualification/common.py:185-200`). The fixture has only an over-bound rejection and no exact 32-chunk boundary acceptance case, so it does not catch the off-by-one. A portable direct adapter probe at the reviewed head reproduced `31 + EOF = ACCEPT` and `32 + EOF = REJECT`.

This is fail-closed rather than a false pass, so it is P2, but it still violates the exact bounded production transaction and blocks clean P0–P3 signoff.

## Positive observations

- C remains a thin caller and strictly rejects false/missing production observations.
- Production executes the resolved held Python fd, verifies its post-exec identity, and observes the post-exec descriptor set twice.
- Parent outcome handling compares exact `CLD_EXITED/0` siginfo with nonblocking `waitpid` status and marks the child reaped.
- The exact-head close-range change marks fd 4096 `CLOSE_UNCERTAIN` before the syscall and avoids later baseline opens under uncertainty.
- Limit restoration rereads the exact original soft/hard pair, and common independently compares stable full descriptor rows before publication.

These positives do not cure P1-1 or P2-1.

## Verification performed

Portable/static only:

- `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -B test/outcome-two-runtime-closure-portable.py` — **passed**.
- `node --test test/native-qualification-c.test.ts` — **4/4 passed**.
- Python AST parsing of production C, common, driver, and portable C files — **passed**.
- `git diff --check 3846383^..3846383` and `git diff --check 5367cdf..3846383` — **passed**.
- Pure adapter boundary probe — **31 nonempty + EOF accepted; 32 nonempty + EOF rejected**.

The green retained tests are recorded as test outcomes, not as acceptance evidence for the missing matrix obligations.

## Required before rereview

1. Replace the row-loop oracle with a stateful fake-kernel matrix that drives every required primitive before/after cut through `_qualify_fixed_descriptor_primitives_with_ops`, validates exact error/trace and final owner state, and makes declared = selected = consumed = oracle substantive.
2. Causally link the child close-complement and exact held-fd exec to the parent's executable/fd/status observations; add branch-removal sentinels for registration, fixed exec, close intervals, wait comparison, reap, restoration, and baselines.
3. Add genuine byte/entry/call boundary oracles and all omitted identity, deadline, signal, wait/reap, close, and restoration cuts.
4. Permit exactly 32 nonempty getdents chunks plus one EOF call, then prove both the accepted boundary and first rejected over-bound case.
5. Rerun the ordinary portable/static gates on one new clean exact head and obtain a fresh hostile C review. Native execution remains forbidden.
