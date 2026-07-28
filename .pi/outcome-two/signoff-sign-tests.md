# Outcome 2 exact-head signoff — sign tests

- Reviewed implementation head: `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`
- Scope: only findings from the five `closure-final-review-*.md` reports and the corrections through `aa45a04`; no broad re-audit
- Decision: **BLOCKED — native Jobs A–E implementation is not ready to begin**

## Unresolved findings

### P1-1 — Launcher and recovery fixtures still manufacture their predicate result instead of faulting the selected production predicate

`test/outcome-two-trusted-launcher-portable.py:204-211` implements `PrimitiveModel.trip()` by recording the row's own `sentinel` and raising `RuntimeLauncherError` with the row's own `intended_code`. The adapters enter a named production method, but most rows then fail at one common early primitive independent of `primitive_fault`. A focused trace of every row found, among other collapses:

- all 12 `_enter_boundary` rows fail at `ops.chroot`;
- all 14 `_run_tool_with_ops` rows fail at `ops.socketpair`;
- all 25 `_coordinate_with_ops` rows fail at the first `ops.open`;
- all 10 `_recv_status` rows fail at the same `endpoint.recv`; and
- `recvmsg-duplicate-rights` for `_WorkerIssuer._accept_runtime_closure` fails at `endpoint.sendmsg`, before the declared receive predicate.

Consequently faults such as capability readback, seccomp route/errno, exec EOF/order, final maps, observed facts, strict proc/control records, issuance ancillary variants, root cuts, and cleanup states are credited without reaching their selected production decision. Removing those downstream predicates would leave the corresponding rows green.

Recovery retains the same defect in `test/outcome-two-recovery-portable.py:138-149,214-222`: every row registers the same three modeled process leases, then `crash()` records or throws the fixture-selected label. It never crashes `_worker_main`, closure/helper issuance, `_materialize_root`, mount setup, or the namespace transaction at the declared write-ahead cut. Calling the real `_recover_transaction_with_ops` over this fabricated inventory proves only generic owner cleanup, not recovery of each production authority-bearing cut.

This leaves the final-review `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, and production-predicate portion of `AT-FIXTURE-01` finding unresolved.

### P2-1 — Fixture sentinels are still labels or method reachability, not branch-removal oracles

The launcher model self-records the fixture sentinel in `PrimitiveModel.trip()`, and recovery does likewise around its synthetic crash. The other corrected ledgers do not supply the required independent branch sentinel:

- runtime-closure, mapped-closure, and sealing require `sentinel == production_method` (`test/outcome-two-runtime-closure-portable.py:34-36`, `test/outcome-two-mapped-closure-portable.py:36-38`, `test/outcome-two-sealing-portable.py:47-49`);
- lifecycle checks only that compound method/sentinel labels are nonempty (`test/outcome-two-lifecycle-portable.py:535-536`); and
- report tests likewise check only nonempty method/sentinel lists (`test/outcome-two-runtime-report-portable.py:247-248`).

Invoking a method and checking an exception type is useful execution evidence, but the method name itself does not prove that removal of the fixture's named predicate makes that row fail. The final-review branch-removal-sentinel finding remains unresolved.

### P2-2 — The corrected launcher is cap-packed and cannot satisfy its hard high after ordinary readable formatting

The static gross counts pass only in the current compressed representation. `completion_trusted_runtime_launcher.py` is `1,899/1,900` lines but contains 58 same-line compound statements and 149 lines over 120 characters. Examples include packed imports and policy rows at lines 4-7 and 51-59, one-line fallible `_SystemOps` methods/decisions at lines 431-509, and one-line cleanup `try`/effect decisions around lines 774-905 and 1600-1723. Splitting only two such one-line method bodies already takes the file beyond 1,900; fully ordinary formatting requires substantially more.

The same retained cap pressure exists in `test/outcome-two-runtime-closure-portable.py` (`350/350`, 24 same-line compound statements) and `test/outcome-two-lifecycle-portable.py` (`547/550`, 9 same-line compound statements). ADR 0089 makes ordinary readable formatting part of acceptance and makes file highs non-transferable, so the numeric unformatted check does not close the final readability/high finding.

## Focused verification

- Exact initial head and clean worktree: **PASS** — `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`.
- Seven isolated direct portable suites: **PASS**; all seven optimized runs rejected `-O`. These passes are non-accepting for P1-1/P2-1.
- Every tracked `*.jsonl` fixture: **PASS true JSONL** — every nonempty physical line independently decodes as one JSON value. Fixture aggregate is `680/900` LF lines.
- Static gross counts: **PASS numerically** — trusted/portable subtotal `8,114/8,930`; launcher `1,899/1,900`, closure `2,098/2,100`, runtime-closure test `350/350`, lifecycle test `547/550`, report test `400/400`.
- `npm run format:check`: **environment blocked** — locked `biome` executable is absent. Human formatting inspection establishes P2-2 independently.

## Native implementation readiness

**NOT READY.** ADR 0089 requires no unresolved P0-P3 at a fresh exact head. This head retains one P1 and two P2 findings in the reviewed correction scope. Native execution cannot repair self-authored fixture outcomes, absent branch-removal sentinels, or noncompliant readable-line accounting.

SIGNOFF COMPLETE
