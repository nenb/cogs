# ADR 0093b final hostile review — production Job C

- **Exact reviewed head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Branch:** `review/o2-93b-c`
- **Scope:** ADR 0093 sections 3, 6, and 10; the production C descriptor owner, exact 32-nonempty-plus-EOF bound, held-Python exec inheritance, exact wait/siginfo/reap and settlement, descriptor case ledger, portable C fake kernel/corpus, common receipt boundary, thin C client, and focused static test.
- **Method:** fresh static and portable-only review. The tree was clean at the reviewed head. No native primitive, `--workflow-bound` operation, sudo, workflow dispatch/rerun, namespace/mount/seccomp action, network/provider, cloud, AWS, OpenTofu, deployment, campaign, production, or release action was run. No implementation file was edited.

## Verdict

**BLOCKED.** The corrected corpus now shares parent/child fd state and catches deletion of the child `dup2` and close-complement effects, but it still fabricates child termination during failure cleanup and does not enumerate repeated production identity cuts. Required production cleanup and post-exec identity branches can be deleted while the complete declared C corpus remains green.

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | None found. |
| P1 | 1 | Unresolved; acceptance-blocking causal-corpus defect. |
| P2 | 0 | None found. |
| P3 | 0 | None found. |

## Finding

### P1-1 — The C corpus still fabricates failure reaps and collapses repeated production cuts

The modeled kernel records `child_exited`, but the cut adapter's `waitid_pidfd_nohang()` never requires it. Except for the special cleanup-KILL row, any retained pidfd immediately yields `CLD_EXITED` (`test/outcome-two-runtime-closure-portable.py:741-756`), and `reap_pid_nohang()` then unconditionally marks the child reaped (`:757-769`). Closing a release or completion gate only deletes an fd (`:380-384`, `:797-806`); it does not make the gated child consume EOF and exit. Thus failures such as `release-short` are reported as exactly reaped while the shared kernel still says the child never exited.

This bypasses the real cleanup transaction. Production closes the retained release/completion gates before its first cleanup wait, then uses identity-bound KILL and a second exact wait if the child remains live (`deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:2601-2647`). An in-memory branch-removal probe deleted the production gate-close loop at `:2602-2609`; all 80 declared C rows still passed. A second portable probe made waitid return `None` while `child_exited` was false; the corpus then failed at `AT92-C-01:release-short` with the retained pidfd. The green corpus therefore depends on a fabricated exit rather than proving the required gate/exit/wait/reap causal chain.

The new edge rows are also operation-name tokens, not complete cut identities. `edge()` consumes the first matching name (`test/outcome-two-runtime-closure-portable.py:541-545`), while a successful production transaction invokes the modeled proc-stat open three times, proc-exe open/fstat four times, `getsid`/`getpgid` three times, and held-Python `pread` three times. The fixture has only one broad row for each name (`test/fixtures/outcome-two/lifecycle/descriptor-cases.jsonl:67-72`). It cannot distinguish registration, pre-release revalidation, post-exec revalidation, and cleanup authorization. An in-memory branch-removal probe deleted both post-exec identity checks at production `:2554-2557`; the entire corpus still passed. Only the four dirent-bound rows assert an exact production diagnostic (`test/outcome-two-runtime-closure-portable.py:900-911`); other rows require a broad rejection after the adapter has emitted its own sentinel.

ADR 0093 requires every real production cut, exact failure settlement, and substantive declared = selected = consumed = oracle equality. A corpus that remains green after deleting creator-gate cleanup and both post-exec identity checks is non-accepting even though its ordinary run passes.

## Exact production observations

No separate P0–P3 production defect was found in the statically reviewed C owner:

- `_snapshot_fd_directory()` permits 32 nonempty calls and issues a separately bounded EOF probe; exact-boundary and first-over-bound rows pass (`completion_trusted_runtime_closure.py:875-902`).
- The child performs both `dup2` operations, closes the complement, executes the held admitted Python fd with fixed argv and empty environment, and the parent performs repeated post-exec fd observations (`:2515-2564`).
- `_wait_descriptor_child()` checks exact PID/UID/code/status, preserves the `WNOWAIT` observation, performs exact nonblocking reap, and compares wait status (`:2102-2180`).
- The owner tracks close uncertainty, rereads the restored limit, and requires final descriptor/child baselines (`:2578-2699`).
- The C client remains receipt-only and does not fabricate checks or reread common cleanup.

These static positives do not substitute for ADR 0093's mandatory complete causal portable evidence.

## Verification performed

Portable/static only:

- `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -B test/outcome-two-runtime-closure-portable.py` — **PASS**.
- `node --test test/native-qualification-c.test.ts` — **PASS (1/1)**.
- Optimized portable invocation (`/usr/bin/python3 -O -I -B ...`) — **rejected as required** with `optimized mode is forbidden`.
- Python AST parsing of production closure, common, C client, and portable closure suite — **PASS**.
- `git diff --check 0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a..0d934c9e03aae17a5f219f302cf5c09058d45c59` on the focused C surfaces — **PASS**.
- In-memory production mutation removing creator-gate cleanup — **corpus still PASS**.
- In-memory production mutation removing both post-exec identity checks — **corpus still PASS**.
- In-memory causal-exit probe requiring `child_exited` before waitid — **corpus FAIL** at `release-short`, exposing the fabricated reap.
- Happy-path operation-count probe — proc-stat open **3**, proc-exe open/fstat **4**, `getsid`/`getpgid` **3**, held-Python `pread` **3**; the ledger declares one broad row for each.

Mutation probes modified only in-memory source strings, changed no repository file, and invoked no native primitive.

## Required before rereview

1. Model child liveness causally: release-gate EOF, completion-gate EOF, successful completion, exec failure, and pidfd signal must each drive an exact terminal status before waitid/reap can succeed.
2. Require every created child to end in exact reap or explicit retained-pidfd terminal uncertainty, with the exact exit/signal status and final fd/limit/lease state for every rejecting row.
3. Give every repeated production primitive an occurrence/phase-specific case and oracle, especially registration, pre-release and post-exec identity observations, cleanup identity authorization, both readiness phases, every child/parent close, signal, wait, reap, and final baselines.
4. Bind each row to its exact production diagnostic and ordered effect/settlement trace; rerun branch-removal probes for creator gates and post-exec identity checks.
5. Obtain a new clean exact-head hostile C review. Native execution remains forbidden.

# SIGNOFF: BLOCKED

`0d934c9e03aae17a5f219f302cf5c09058d45c59` has one unresolved P1. It is not eligible for ADR 0093 C signoff or native qualification authority.
