# ADR 0091 final holistic hostile review

- **Reviewed implementation head:** `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`
- **Correction range:** `964dffe2664a9b05b9a53173574f82bf071e7dcd..a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`
- **Gross-accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Method:** fresh static/portable hostile review of all 27 changed production, native, workflow, schema, fixture, and test surfaces; no prior report was treated as authority.
- **Execution boundary:** no `--workflow-bound`, sudo, namespace, mount, seccomp, `map_files`, compression executable, pidfd/process qualification, native workflow, provider, network, cloud, OpenTofu, deployment, campaign, or AWS operation was run.
- **Disposition:** **BLOCKED**

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 7 |
| P2 | 2 |
| P3 | 0 |

Any one finding blocks ADR 0091 signoff. The green portable/static suite does not override the concrete production-path failures below.

## Findings

### P1-1 — Every workflow control executable and all six job clients convert success into exit 1

`raise SystemExit(success_code)` is inside a `try` whose `except BaseException` catches that same `SystemExit`, then raises `SystemExit(1)`:

- `scripts/native-qualification/common.py:745-750`
- `scripts/native-qualification/job-a-runtime-mappings.py:182-187`
- `scripts/native-qualification/job-b-compression.py:223-228`
- `scripts/native-qualification/job-c-descriptors.py:88-92`
- `scripts/native-qualification/job-d-process-lifecycle.py:90-94`
- `scripts/native-qualification/job-e-sandbox.py:162-167`
- `scripts/native-qualification/thin-integration.py:159-164`

The first real workflow path already stops at `.github/workflows/ci.yml:167-187`: valid eligibility runs `common.py --eligibility`, `_main()` returns 0, and the wrapper changes it to 1. If that were repaired, A–E and integration would still change a successful driver return to 1. Their upload steps would be skipped, each `always()` cleanup invocation would also return 1 after running, integration would not become eligible, and the required final invocation at `.github/workflows/ci.yml:417-456` would also force failure.

Portable direct-CLI confirmation, with no native selector or effect, produced:

```text
native-common-failed
eligibility_exit=1
native-common-failed
final_exit=1
```

The focused tests call `_dispatch`, `_workflow_bound`, `evaluate_eligibility`, or `require_final_results` after loading modules; none executes the real `__main__` success path. This is why all 32 focused tests remain green.

**Acceptance impact:** `AT91-BOOT-01`, `AT91-MODE-01`, `AT91-WF-01`, all six operation IDs, upload/cleanup ordering, and definition-of-complete six-path reachability.

### P1-2 — Common can publish a passing report without a successful production operation

`NativeSession.run_fixed_operation()` records `_operation_used` before invoking the owner (`common.py:684-690`), but `settle_native_phase()` and `publish()` never require either `_operation_used` or a successfully returned operation token (`common.py:698-718`). A caller can begin a C or D session, skip the owner entirely, supply all-pass `production_checks`, settle an unchanged scripted baseline, and publish `result: pass`. A/B/E/integration can do the same with fabricated schema-valid metadata.

A portable scripted adapter confirmed `skip_operation_pass= pass` without calling `run_fixed_operation()`.

This is a complete substitute-owner acceptance route in the common authority, not merely missing wrapper coverage.

**Acceptance impact:** `AT91-BOOT-01`, `AT91-MODE-01`, `AT91-REPORT-01`, `AT91-NOSUB-01`, and A–E/integration owner authenticity.

### P1-3 — Caller-mutable cleanup evidence can turn an observed baseline failure into pass

`CleanupEvidence` is frozen only at the dataclass attribute level; `values` is the mutable dictionary created at `common.py:705-708`. `publish()` later copies its current contents at lines 714-718. A driver can receive a false observation, mutate `evidence.values[domain]` to true, and have common derive `cleanup_restored: pass`.

Portable confirmation observed `restored=False`, changed only `values["checkout"]`, and then produced `mutated_cleanup_pass= pass`.

ADR 0091 requires common alone to derive all seven booleans and forbids caller cleanup claims. The nonce authenticates the object identity, not the contents.

**Acceptance impact:** `AT91-BASE-01`, `AT91-REPORT-01`, `AT91-OUTER-01`, and all six cleanup paths.

### P1-4 — D reports the required pre-release PDEATH observation from the post-release death

The descendant blocks at `launcher.py:2469`. After transfer acknowledgement, the leader releases it at lines 2484-2487. The outer owner then sends TERM and only later tells the leader to exit at lines 2504-2508. There is one resulting SIGKILL/siginfo observation at lines 2513-2517.

Nevertheless, line 2526 places the same `siginfo` value in both `before_release_death` and `after_release_death`. No parent-death-before-release case occurred. A passing D result therefore asserts a security fact that production did not observe.

The portable D tests decode fabricated booleans and exercise selected `_ProcessOwner` methods; they do not execute or oracle this production sequence.

**Acceptance impact:** `AT91-PROC-01`, deterministic D metadata, and `AT91-NOSUB-01`.

### P1-5 — D has no failure recovery after changing subreaper state and creating process/fd authority

`_qualify_admitted_fixed_process_lifecycle()` changes `PR_SET_CHILD_SUBREAPER` at `launcher.py:2447-2449`, then opens sockets/pipes and spawns the leader at lines 2450-2454. Restoration and closure exist only on the successful tail at lines 2520-2525. There is no outer `try/finally`, no `owner.cleanup(primary)`, and no aggregate cleanup-error path.

Any malformed transfer, identity/census drift, timeout, failed signal, failed read/write, or close cut after line 2449 bypasses subreaper restoration and bounded owner cleanup. Process exit is not the required production recovery state machine and cannot prove the baseline or preserve primary plus cleanup failures.

**Acceptance impact:** `AT91-PROC-01`, `AT91-OUTER-01`, `AT91-BASE-01`, and `AT91-READABLE-01` fallible-effect ownership.

### P1-6 — E checks the host root as if it were the sandbox root

In the inner sandbox process, the tmpfs at `root` is remounted read-only/noexec at `launcher.py:2368`, but `_final_mount_check(os.getpid(), ops)` runs at line 2369 before `_enter_boundary()` performs `chroot(root)` at line 2370. `_final_mount_check()` explicitly inspects the process root mount and `/proc/<pid>/root/...` (`launcher.py:1391-1404`). At that point those are still the host root and host paths, not the prepared tmpfs.

On the intended Ubuntu host this must reject the ordinary host `/` for missing the exact root flags, containing proc, and exposing `/usr/bin/python3`. Job E cannot produce its required sandbox result. The focused E tests use a completed result dictionary and lexical sentinels; they do not drive this production transaction.

**Acceptance impact:** `AT91-E-01`, `AT91-MODE-01`, `AT91-OUTER-01`, and six-path reachability.

### P1-7 — Post-upload cleanup can authenticate a substitute custodian

`cleanup_report()` reads `.owner.json` by pathname and accepts its `socket` after checking only shape, job, and digest syntax (`common.py:638-652`). It does not recompute the socket from the actual workflow run/attempt, compare receipt run/head/size/digest to the environment and uploaded generation, authenticate the nonce, or otherwise bind the endpoint to the surviving custodian. It then trusts any same-UID endpoint at that receipt-selected abstract socket that answers `CLEAN` (`common.py:660-666`).

A same-UID surviving process can replace the report directory/receipt, point cleanup at its own socket, remove the replacement, and return `CLEAN`; the real custodian and its retained generations are bypassed. This defeats the exact generation comparison that is supposed to protect upload and preserve mismatch/replacement evidence.

**Acceptance impact:** `AT91-REPORT-01`, `AT91-OUTER-01`, and exact upload-then-cleanup authority.

### P2-1 — Eligibility and required-final authority execute merge-ref bytes, not the exact reviewed head

The six native jobs explicitly check out `github.event.pull_request.head.sha`, but the eligibility checkout at `.github/workflows/ci.yml:172-173` and required-final checkout at lines 425-426 omit `ref`. On `pull_request`, those steps use the synthetic merge ref. They execute `common.py` from different bytes than the six exact-head jobs while accepting head/merge workflow identity interchangeably.

A base-branch change can therefore alter eligibility or final-result interpretation without changing the reviewed head or the common blob recorded by the six reports. The static workflow test checks token presence and result strings, not checkout identity.

**Acceptance impact:** `AT91-BOOT-01`, `AT91-WF-01`, deterministic source/workflow metadata, and the exact-head gate.

### P2-2 — The mandatory readable-security gate is not met

The two security-critical files are at their exact individual highs, but retain packed control/data flow that the tests do not reject:

- `scripts/native-qualification/common.py` is exactly **750/750** and repeatedly combines fallible effects/state transitions on one physical line, including lines 47, 113-114, 169, 268, 674, 692-693, 700, and 726.
- `completion_trusted_runtime_launcher.py` is exactly **2600/2600**; line 2427 packs the complete sandbox result derivation into one physical line, and line 2526 packs all lifecycle claims—including the duplicated false claim from P1-4—into an unlabelled positional tuple.

The changed `test/outcome-two-portable.test.ts` readability scan does not cover `common.py` or the six native clients, and its launcher scan does not reject these packed expressions. This is the exact failure mode `AT91-READABLE-01` says static/AST review must prevent: security claims and cleanup decisions are hidden rather than immediately attributable to observations and leases.

**Acceptance impact:** `AT91-READABLE-01`; cap/style signoff.

## Real six-path trace

| Path | Intended authority chain at `a3f529a` | Review result |
| --- | --- | --- |
| A | exact-head driver → common session → held source root/client/launcher → mapping admission → `PreparedRuntimeClosure._for_fixed_mapping` → independently recomputed A metadata → common baseline/custodian | **Blocked:** P1-1 and P1-2/P1-3 bypasses |
| B | exact-head driver → held compression admission → production closure/launcher runtime owner → exact mask 63 and marker digests → common report | **Blocked:** P1-1 and common bypasses; metadata checks themselves are present |
| C | exact-head driver → zero-argument common adapter → held descriptor admission → closure production `getdents64`/`close_range` owner → common report | **Blocked:** P1-1 and trivial no-operation passing route P1-2 |
| D | exact-head driver → zero-argument common adapter → held lifecycle admission → launcher `_ProcessOwner` → common report | **Blocked:** P1-1, false PDEATH fact P1-4, and absent recovery P1-5 |
| E | exact-head unprivileged driver → held sandbox admission/root capsule → sandbox-only owner, without closure load → common report | **Blocked:** P1-1 and wrong-root observation P1-6 |
| integration | waits for A–E → exact-head driver → held ordinary runtime admission → complete production owner → exact ordinary result → common report | **Blocked:** eligibility/A–E failure prevents scheduling; its own P1-1 remains |

The held-source operation table, result-type separation, E closure exclusion, and thin integration delegation are statically present. They cannot support signoff while common can publish without using them and the executable workflow cannot reach a successful result.

## AT91 acceptance catalog

| Acceptance | Disposition | Reason |
| --- | --- | --- |
| `AT91-BOOT-01` | **BLOCKED** | P1-1 and P1-2; P2-1 exact-head split |
| `AT91-A-01` | **BLOCKED (dependent)** | Real mapping-owner route is present, but no successful executable path and common permits substitution |
| `AT91-A-META-01` | **PASS static/focused only** | Ordering, bounds, providers, mapped sequence, and recomputation checks passed focused/schema tests |
| `AT91-B-01` | **PASS static/focused only** | Mask 63 and exact marker/source/sealed/mapping checks are present and focused mutations passed |
| `AT91-FD-01` | **PASS static/portable only** | Closure owner and portable getdents/close-range matrices passed; no native effect run |
| `AT91-PROC-01` | **BLOCKED** | P1-4 and P1-5 |
| `AT91-OUTER-01` | **BLOCKED** | P1-3, P1-5, and P1-7 |
| `AT91-BASE-01` | **BLOCKED** | Caller can rewrite derived cleanup evidence (P1-3) |
| `AT91-REPORT-01` | **BLOCKED** | No-operation pass, mutable cleanup, substitute custodian, and forced cleanup exit failure |
| `AT91-SCHEMA-01` | **PASS static/focused only** | Six schema goldens/mutations and `npm run schemas` passed; semantic authority remains blocked elsewhere |
| `AT91-E-01` | **BLOCKED** | P1-6 |
| `AT91-I-01` | **BLOCKED (dependent)** | Thin ordinary-owner route is present, but P1-1 prevents execution and A–E prevent scheduling |
| `AT91-MODE-01` | **BLOCKED** | Held profile separation exists, but common can publish without any fixed mode and CLI paths fail |
| `AT91-WF-01` | **BLOCKED** | P1-1 and P2-1 |
| `AT91-NOSUB-01` | **BLOCKED** | P1-2, P1-3, and P1-7 are live substitution routes |
| `AT91-READABLE-01` | **BLOCKED** | P2-2 |

“PASS static/focused only” is not overall acceptance and grants no execution authority.

## Surface and cap audit

All 27 files changed from accepted ADR commit `964dffe` were reviewed: workflow/config/API freeze; closure and launcher production owners; native report schema/common/A–E/integration; schema validator; lifecycle fixture; seven focused native tests; and five changed portable tests.

Gross additions from `bec0a19` remain numerically inside the ADR highs:

- trusted/portable listed files: **8,972** lines;
- Outcome Two fixtures: **343** lines;
- trusted/portable subtotal: **9,315 / 10,790**;
- native listed subtotal: **3,329 / 5,400**;
- listed aggregate: **12,644 / 16,250**;
- exact individual highs reached: launcher **2,600 / 2,600**, common **750 / 750**;
- correction-range `git diff --check`: pass.

Numeric cap compliance does not satisfy readable-style acceptance. No implementation-cap credit or authority is inferred from deletion or remaining subtotal margin.

## Portable/static verification

Passed:

- Python AST parse: 16 reviewed production/native/portable Python files.
- `npm run format:check`: 243 files checked.
- `npm run typecheck`.
- `npm run schemas`: 16 schemas plus examples, negative cases, and report semantics.
- focused changed TypeScript tests: **32/32 passed**, including all seven native companions and the aggregate Outcome Two portable suite.
- all seven Outcome Two Python portable suites through `test/outcome-two-portable.test.ts`.
- correction-range `git diff --check`.

Additional portable hostile probes exposed P1-1 through P1-3. No native or cloud operation was used.

## Native/AWS boundary

This review grants **no** native execution, workflow dispatch/rerun, sudo, artifact acceptance, AWS, provider, OpenTofu, deployment, campaign, production, release, issue-closure, or execution-ADR authority. The existing ADR 0091 native/AWS blocks remain mandatory. Because the reviewed head has unresolved P1/P2 findings, it is not eligible to be named by a later native-execution ADR.

# Final outcome: BLOCKED

`a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08` has unresolved P1 and P2 findings. ADR 0091 holistic signoff is denied.
