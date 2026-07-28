# ADR 0093 hostile review — production Job C

## Verdict

**BLOCKED** — exact implementation head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` retains one acceptance-blocking P1. The production happy path now visibly implements the strict 32-nonempty-plus-EOF bound, held-Python exec, exact wait/siginfo/reap, and limit/fd settlement, but the mandatory portable corpus still does not causally prove those mechanisms or failure settlement.

**SIGNOFF: BLOCKED**

## Scope and boundary

Reviewed the production C descriptor owner, bounded dirent parser/enumerator, child exec-inheritance transaction, wait/siginfo/reap path, failure cleanup, limit/fd restoration, common receipt handoff, thin C driver, descriptor ledger, and focused portable tests against ADR 0093 section 6 and the carried ADR 0092 C rereview requirements.

The tree was clean at the exact reviewed head before this report. Review and probes were static/portable only. No native qualification, `--workflow-bound` operation, sudo, workflow dispatch/rerun, namespace/mount/seccomp operation, network/provider, cloud, or AWS action was invoked. No implementation file was edited.

## P0–P3 summary

| Severity | Verdict |
| --- | --- |
| P0 | None found. |
| P1 | **1 unresolved.** The declared C corpus remains noncausal and does not prove failure-path settlement or all real primitive cuts. |
| P2 | None found. |
| P3 | None found. |

## Finding

### P1-1 — The C ledger can stay green after deleting required exec-inheritance and failure-reap behavior

The revised harness reaches the production facade, but its fake child and parent do not share one causal fd/process state. On release, `_execute_released_child()` starts a separate recursive qualification with a new `DescriptorCutOps` (`test/outcome-two-runtime-closure-portable.py:604-624`). Its `execve` oracle checks only executable fd identity, argv, and environment (`:640-656`); it never verifies the child's actual fd table, either `dup2`, or any close-complement interval. The parent then returns a hard-coded `/proc/123/fd` set after the independent `child_exec_proved` bit is set (`:564-566` and `DescriptorOps.getdents`). Consequently the alleged causal link does not derive the parent's inherited descriptors from the child effects.

A portable in-memory branch-removal probe confirmed the defect: replacing production `_close_complement` with a no-op and rerunning `descriptor_cut_corpus()` still passed. Making both modeled child `dup2` effects no-ops also left the corpus green. These are required causal inheritance branches at production lines `2515-2520`, not optional implementation details.

Failure settlement is likewise not an oracle. For rows declaring the `children` cleanup domain, `child_reaped` is required only for an accepted result (`test/outcome-two-runtime-closure-portable.py:774-777`), never for rejection. Descriptor settlement checks only that the adapter did not record the same numeric close twice (`:787-790`), not restoration of the original fd table, closure of every owned lease, or explicit terminal uncertainty. `consumed` and `oracle` are then added after the generic outcome check (`:773,793`), so ledger equality does not make those claims substantive. A second in-memory mutation that removed every failure-path `_wait_descriptor_child(..., expected=None)` wait/reap left the entire declared corpus green, despite production cleanup lines `2601-2647` then losing its required child retirement evidence.

The matrix is also still incomplete and permits wrong-cause rejection. It has no primitive fault for production opens, proc reads/fstats, `getsid`/`getpgid`, either child `dup2`, each `_close_complement` range, readiness polling, completion write, trailing status, identity revalidation, cleanup KILL, or final baseline observation. The generic close fault fires on the first close rather than proving a named late cleanup close. The byte-bound adapter emits 33 full chunks and reaches `descriptor enumeration call bound before EOF`; the entry-bound adapter emits a single chunk larger than 32,768 bytes and reaches the per-chunk `descriptor baseline bound` before aggregate entry counting (`test/outcome-two-runtime-closure-portable.py:556-563`; production `completion_trusted_runtime_closure.py:877-902`). Because the harness requires only the broad result `reject` (`:733-765`), both rows are marked oracle-proved without reaching their declared predicate.

ADR 0093 requires portable cases to drive every real production cut, prove exec causality and cleanup, and make declared/selected/consumed/oracle equality causal. Surviving removal of child descriptor settlement and failure reap is a direct branch-removal failure, so green retained tests cannot authorize native execution or later execution ADR signoff.

## Positive observations

- `_snapshot_fd_directory()` now permits 32 nonempty bounded calls and performs a distinct 33rd EOF probe (`completion_trusted_runtime_closure.py:875-902`); the exact boundary and first over-bound portable cases pass.
- The production exec child uses the held admitted Python fd, fixed argv, empty environment, an in-exec fd witness, post-exec executable identity, and two post-exec fd snapshots (`:2515-2564`).
- `_wait_descriptor_child()` validates exact PID/UID, `CLD_EXITED/0` on success, `WNOWAIT`, exact nonblocking `waitpid` reap, and status agreement (`:2102-2180`).
- Cleanup retains close uncertainty, restores and rereads the original limit, and refuses a passing result when final descriptor/child baselines differ (`:2578-2699`).
- Job C is receipt-only and does not fabricate checks or reread operation metadata.

These production improvements do not cure P1-1's mandatory acceptance-evidence failure.

## Verification performed

Portable/static only:

- `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -B test/outcome-two-runtime-closure-portable.py` — **passed**.
- `node --test test/native-qualification-c.test.ts` — **1/1 passed**.
- Python AST parsing of production closure, common, C driver, and portable closure test — **passed**.
- `git diff --check ce1f6f8^..HEAD` and `git diff --check 0db8c26^..0db8c26` — **passed**.
- In-memory mutation probe removing production `_close_complement` — **corpus still passed**.
- In-memory mutation probe making child `dup2` effects no-ops — **corpus still passed**.
- In-memory mutation probe deleting failure-path wait/reap — **corpus still passed**.
- Named-bound probe — `byte-bound` rejected at the call-bound diagnostic; `entry-bound` rejected before aggregate entry counting.

Mutation probes changed no repository file and invoked no native primitive.

## Required before rereview

1. Use one stateful fake kernel for the parent and released child so `dup2`, CLOEXEC, every close-complement interval, held-fd exec, the child's readiness witness, and the parent's `/proc/<pid>/fd` observations all derive from the same fd table and process transition.
2. For every rejecting child case, require exact wait/siginfo/reap or an explicitly asserted terminal-uncertainty state; require the exact final fd/lease table and limit state rather than only no duplicate closes.
3. Add before/after-effect cuts for every real C primitive, including opens/proc observations, child closes and dups, polling/reads/writes, identity checks, signal, wait/reap, pidfd/ordinary closes, limit operations, and final baseline observations.
4. Bind each row to its exact expected production diagnostic/event trace and genuine boundary stream so an unrelated earlier rejection cannot satisfy the ledger.
5. Rerun portable/static gates on one new clean exact head and obtain a fresh hostile C review. Native execution remains forbidden.
