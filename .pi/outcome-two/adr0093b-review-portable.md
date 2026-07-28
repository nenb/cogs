# ADR 0093b fresh exact-head hostile portable review

- **Reviewed head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Branch:** `review/o2-93b-portable`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** complete production owners above portable syscall/process models, causal case ledgers, readability enforcement, and ADR 0093 gross-addition highs
- **Execution boundary:** static analysis and portable Python only. No native selector, sudo, namespace/mount/seccomp qualification, workflow dispatch/rerun, provider, network, cloud, AWS, OpenTofu, deployment, campaign, production, release, or source edit was performed.
- **Verdict:** **BLOCKED**

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 4 | blocking |
| P2 | 1 | blocking |
| P3 | 0 | none found |

## Findings

### P1-1 — The common/custodian ledger still substitutes test owners for the production issuer and child loops

The corrected production API now has `SystemCommonOps.run_fixed_operation()` and the sole fixed CLI issuer (`scripts/native-qualification/common.py:531-550`), but the portable common matrix does not execute it. `CommonOps.run_fixed_operation()` returns a precomputed dictionary (`test/outcome-two-recovery-portable.py:700-723`); that dictionary is produced by a separate launcher model before the matrix. Therefore held-root walking, Git admission, capsule construction, sealed fd 3/fd 4 issuance, child gating, output collection, and exact production decode are not one causal common transaction.

The matrix also still does not execute production `_custodian_main()` or `_custodian_worker()` (`scripts/native-qualification/common.py:1423-1513`). `CommonKernel.fork()` only returns a parent PID, while `CommonSocket.send()` and `CommonKernel.server_cleanup()` directly call publication and cleanup helpers (`test/outcome-two-recovery-portable.py:608-613,647-669`). Listener creation, child release, production worker registration, accept/peer handling, and the real loop can regress without falsifying a row.

Portable line tracing of the passing recovery suite recorded `_issue_cli=0`, `_custodian_main=0`, and `_custodian_worker=0`. Callable names in `production_method` do not establish reachability. This remains contrary to ADR 0093 section 10's complete common/custodian production-state-machine requirement.

### P1-2 — D still fabricates both production child protocols

`production_lifecycle_case()` reaches the production qualifier and parent owner, but `ScriptedSocket` fabricates transition, transfer, release, and failure packets (`test/outcome-two-lifecycle-portable.py:693-779`), and `ProductionLifecycleKernel.clone_pidfd()` creates only modeled process records (`:952-968`). Neither production `_lifecycle_leader()` nor `_lifecycle_descendant()` (`completion_trusted_runtime_launcher.py:3260-3430`) runs.

Portable line tracing of the passing lifecycle suite recorded `_lifecycle_leader=0` and `_lifecycle_descendant=0`. Consequently child-side preregistration gates, transfer issuance, PDEATHSIG ordering, release behavior, and creator-owned failure settlement remain outside the causal matrix. ADR 0093 sections 7 and 10 require the complete D state machine, not only the parent parser and cleanup owner.

### P1-3 — B/integration run split success demonstrations, not the complete causal child state machines or cuts

The new split models materially call `_worker_main()` and `_namespace_owner()` (`test/outcome-two-trusted-launcher-portable.py:1949-2050`), but they are invoked only after the independently modeled parent launcher has already succeeded (`:2145-2149`). The worker uses a substituted closure constructor and completed issuance receipt. The namespace model's `child_clone()` always returns a parent result and injects a ready-made boundary packet (`:1996-2003`), so the production child branch and `_child_fd_install()` never run.

Portable tracing confirmed `_worker_main=2`, `_namespace_owner=4`, but `_child_fd_install=0`. The tool ledger has only four rows: B and integration success plus two B secondary-pidfd failures. It has no worker, namespace-owner, tool-child, exec-boundary, transfer, mount, exit, or reap fault cuts, and integration has no rejecting row at all (`test/fixtures/outcome-two/launcher/tool-process-cases.jsonl`). Declared/selected/consumed/oracle equality over that truncated set is not complete causal coverage under ADR 0093 sections 5 and 10.

### P1-4 — Crash rows prove preservation, not the required recoverability

The common ledger classifies most publication, upload, and custodian-loss cuts as `disposition:"preserved"` and treats the retained active directory as a completed oracle (`test/fixtures/outcome-two/launcher/common-custodian-cases.jsonl:10-35,39-41`). It does not perform a later recovery transaction from any of those crash states.

Production has no such recovery route. If the custodian dies while the active directory remains, cleanup has no retained private capability with which to continue. If the active directory has already become the retained quarantine, a later `cleanup_report()` explicitly rejects that state (`scripts/native-qualification/common.py:1524-1529`: `retained quarantine requires live authority`). The quarantine-after-effect row calls this `restored` merely because the active name disappeared; it does not demonstrate a subsequent authenticated recovery.

Fail-closed preservation is safer than deleting unauthenticated bytes, but it does not satisfy ADR 0093 section 4's requirement that every crash cut be classified **and recoverable**, nor section 10's complete custodian ledger.

### P2-1 — The readability gate still misses positional authority, generation, and ownership claims

The AST gate defines security claims only by the suffixes `Result`, `Observation`, `Receipt`, and `Evidence` (`test/outcome-two-portable.test.ts:121,179`). The gate therefore passes while production still contains unlabeled positional security-bearing constructions, including:

- twelve positional fields in `_SourceAdmission(...)` (`completion_trusted_runtime_launcher.py:3723`);
- ten positional generation fields in `_GenerationRow(...)` (`:549,565`);
- positional process authority in `_ProcessLease(...)` (`:780,804,1858`);
- positional `_PrivateGenerationRow(...)` and `HelperLease(...)` (`completion_trusted_runtime_closure.py:2314,1194`).

The embedded gate was executed and passed, reproducing the false negative. ADR 0093 section 11 requires labels for security claims, not only dataclass names with four selected suffixes.

## High accounting

No numeric high is exceeded. Gross physical additions from `bec0a19` are:

| Surface | Added / high |
| --- | ---: |
| closure | 2,811 / 3,100 |
| launcher | 3,757 / 4,700 |
| native common | 1,778 / 1,900 |
| native schema / schema registration / workflow | 340 / 700; 264 / 300; 318 / 400 |
| trusted-runtime closure schema (subtotal-accounted) | 134 added |
| runtime-closure / mapped / lifecycle / recovery portable | 921 / 1,000; 625 / 700; 1,249 / 1,800; 1,000 / 1,500 |
| trusted-launcher portable | 2,300 / 2,300 |
| runtime-report / sealing / wrapper portable | 430 / 550; 333 / 450; 275 / 400 |
| fixtures aggregate | 534 / 1,700 newline-counted lines |
| common focused test | 491 / 1,500 |
| A/B/C/D/E/integration clients | 94 / 420; 94 / 500; 94 / 380; 94 / 520; 95 / 620; 95 / 500 |
| A/B/C/D/E/integration focused tests | 88 / 350; 85 / 350; 80 / 450; 80 / 600; 87 / 500; 88 / 400 |

The trusted/portable subtotal is **14,369 / 19,000**, the native subtotal is **4,265 / 10,000**, and the listed aggregate is **18,634 / 29,000**. The trusted-launcher portable file has no remaining line headroom. Numeric compliance does not cure incomplete owners or nominal crash oracles.

## Portable/static verification

- Seven isolated `/usr/bin/python3 -I -B` Outcome Two portable suites: **PASS**.
- Seven optimized `/usr/bin/python3 -O -I -B` runs: **PASS** (all rejected optimized mode).
- Python compilation of closure, launcher, common, and all six clients: **PASS**.
- Embedded AST readability gate: **PASS**, with the P2-1 false negatives above reproduced statically.
- Portable line tracing, including spawned threads: **PASS as an analysis mechanism** and reproduced the unreachable production bodies listed above.
- Correction-range source/test `git diff --check 3846383..0d934c9`: **PASS**.
- TypeScript/AJV wrapper: **not run** because this clean worktree has no `node_modules`; no installation or network access was attempted.
- Native, sudo, workflow, provider, network, cloud, and production actions: **not run**.

# SIGNOFF: BLOCKED

`0d934c9e03aae17a5f219f302cf5c09058d45c59` has four P1 findings and one P2 finding. ADR 0093 portable signoff is denied. This review grants no native, sudo, workflow dispatch/rerun, artifact, provider/cloud/AWS/OpenTofu/deployment, production, release, issue-closure, or later execution-ADR authority.
