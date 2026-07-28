# ADR 0093b final exact-head holistic hostile review

- **Exact reviewed implementation head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Branch:** `review/o2-93b-holistic`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Authority reviewed:** accepted ADR 0093 together with the carried ADR 0092 requirements; Outcome Two workflow, closure/launcher/common/schema, all six real clients (A–E and thin integration), focused/portable tests, and tracked fixtures
- **Method:** hostile static review and portable Python only. No `--workflow-bound` selector, native primitive, sudo, workflow dispatch/rerun, network, provider, cloud, AWS, OpenTofu, deployment, campaign, production, release, or implementation edit was run.
- **Verdict:** **BLOCKED — no ADR 0093 signoff**

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 3 | unresolved; blocking |
| P2 | 1 | unresolved; blocking |
| P3 | 0 | none found |

## Findings

### P1-1 — The new CLI bridge executes the tracked client/common before admission and still lets the run-selected PR head authorize itself

The deleted ambient launcher API is now wired to the fixed CLI, so the prior dead-symbol failure is corrected. The replacement still does not implement ADR 0093 section 1 or the launcher API note's independently authenticated pre-execution issuer.

Every real client first executes checkout bytes and imports checkout `common.py` (`scripts/native-qualification/job-*-*.py:24-29`, `thin-integration.py:24-29`). `WorkflowContext.from_environ()` then reads/hashes the already executing workflow, client, common, and schema (`common.py:121-146`). Only later does `SystemCommonOps._admit_sources()` ask Git for the tree selected by `context.head_sha` (`:377-390`). That head is the dynamic pull-request head supplied by the same workflow envelope; there is no separately fixed reviewed-head authority in common, the workflow, or the launcher issuer. Common packages that same value into both admission and capsule (`:429-441`) and starts the held launcher (`:531-543`).

The launcher validates the resulting capsule's internal OIDs/digests and mode, but those OIDs and revision came from this already running common transaction. It has no independent Git/head pin. Thus a different self-consistent checkout/head supplies both the bytes and the pin against which those bytes are accepted. More fundamentally, the selected client and common have already run before their pathname generations are compared to Git, so later hashing cannot authenticate the generations that Python executed.

This affects A, B, C, D, E, and integration equally. The bridge is fail-closed on malformed input, but it is not the required authority boundary “before tracked execution.” E's separate root-owned bootstrap/pin shape is statically sound and does not cure the unprivileged issuer gap before sudo.

### P1-2 — Cleanup now avoids name-racy deletion by never deleting the transaction, falsely succeeds with a retained report, and cannot recover custodian-loss/crash states

The correction removed the check-then-unlink/rmdir operations, but replaced cleanup with permanent quarantine rather than baseline restoration:

1. Publication links `.report.stage` and renames it to `report.json` at `common.py:1302-1305`; only afterward does it create/link the generation-bearing receipt at `:1306-1311`. ADR 0092 section 4's carried rule requires the complete durable intent before the first staged named effect. The earlier `.authority.json` has digest/size but no staged/published generation.
2. `_cleanup_owned()` verifies current bytes and then `_retain_quarantine()` merely renames the whole active directory to `/tmp/.cogs-native-qualification-<job>.retired` (`:1387-1423`). No owned file or directory is removed.
3. `cleanup_report()` declares success only when the active name is absent **and the retired directory is still present** (`:1577`). A subsequent cleanup rejects that retained directory (`:1525-1529`), and a future publication rejects it as a non-baseline (`:1285-1289`). The report, receipt, and authority remain named on disk.
4. If the in-memory custodian or endpoint is lost, there is deliberately no authenticated recovery path. The fixture classifies custodian loss and publication crash cuts as preserved failures, not recoverable transactions. They are permanently stranded without the private capability.

This violates ADR 0093 section 4's authenticated exact cleanup, crash recoverability, custodian retirement transaction, and baseline restoration requirements. It also contradicts the workflow step name and final-gate meaning “Restore fixed report-path baseline”: the final job accepts `cleanup=success` while a path explicitly included in common's own `paths` baseline remains present.

### P1-3 — Mandatory evidence gates accept P1-1/P1-2 and still do not causally execute complete B/D/integration/common state machines

The green portable gates are not accepting evidence under ADR 0093 sections 9–11:

- The common oracle defines `disposition == "restored"` as only “active path absent”; it does not require the retired path absent (`test/outcome-two-recovery-portable.py:681-693`). The happy fixture therefore labels permanent quarantine `cleanup:restored` (`common-custodian-cases.jsonl:2`). Its modeled fork does not run production `_custodian_main()`/`_custodian_worker()`; `server_cleanup()` directly calls receipt/cleanup helpers.
- The sole-issuer tests separately decode a capsule and run `_issue_cli()` with a trivial synthetic Python source. They do not execute any exact real client → `SystemCommonOps.run_fixed_operation()` → held real `_bootstrap_main()` path, and they do not reject the post-execution/self-selected-head authority in P1-1.
- D's production matrix replaces sockets with `ScriptedSocket`, whose receives create and report a modeled descendant (`test/outcome-two-lifecycle-portable.py:693-770,979-991`). It does not execute production `_lifecycle_leader()` or `_lifecycle_descendant()` at all.
- B/integration's parent launcher model likewise does not call its observed production children (`owner_calls` is required to remain empty). Only after the parent result is complete does the test separately call `_modeled_worker_execution()` and two `_modeled_namespace_execution()` functions (`test/outcome-two-trusted-launcher-portable.py:2119-2176`). Split executions with a fabricated parent protocol are not one causal complete state machine.
- `tool-process-cases.jsonl` has only happy B/integration and two secondary-pidfd rows. It does not enumerate every worker/namespace/tool transfer, credential, rights, identity, acknowledgement, EOF, wait/reap, close, restoration, and cleanup cut. E's 24-case corpus similarly omits explicit transfer send/credentials/rights/identity/EOF/ack/release and many per-descriptor/namespace/mount/readback cleanup cuts required by ADR 0093 section 8.

A and C are materially improved: A now recurses through its production child branch, and C's expanded corpus covers the exact 32-nonempty-plus-EOF bound, exact wait fields, exec causality, and many allocation/cleanup cuts. E also executes its leader and inner bodies in the threaded model. Those improvements do not satisfy the all-six/common complete-state-machine gate.

### P2-1 — The readability gate still permits positional authority/generation/process claims

ADR 0093 section 11 requires rejection of unlabelled positional security claims across closure, launcher, common, and all six clients. The AST gate recognizes only names ending in `Result`, `Observation`, `Receipt`, or `Evidence` (`test/outcome-two-portable.test.ts:121,179-180`). It therefore accepts security-bearing constructors with other names.

Current production examples include ten positional generation fields in `_GenerationRow(...)` (`completion_trusted_runtime_launcher.py:549,565`), positional process authority in `_ProcessLease(...)` (`:780,804,1858`), and all twelve authority fields in `_SourceAdmission(...)` (`:3723`). The old narrow predicate remains unchanged and does not enforce the decision.

## Six real production paths

The prior deleted-API reachability defect is fixed: all six paths can now statically reach the held CLI bootstrap. None is signable because all inherit P1-1, P1-2, and the common evidence defect.

| Path | Current exact-head route | Disposition |
| --- | --- | --- |
| **A** | workflow A → tracked client/common → held CLI mapping mode → closure `_qualify_admitted_fixed_python_mapping` → immutable receipt/report | **Route present; blocked by source authority and report cleanup.** A's portable child branch is materially causal. |
| **B** | workflow B → held CLI compression mode → closure issuance → worker/namespace/tool transactions → receipt/report | **Route present; blocked.** Parent and child portable executions remain disconnected and the tool cut ledger is incomplete. |
| **C** | workflow C → held CLI descriptor mode → closure descriptor owner → 32 non-empty `getdents64` calls plus separate EOF → exec/wait/reap/restore → receipt/report | **Route present; blocked by global authority/cleanup.** C's focused portable model is materially improved. |
| **D** | workflow D → held CLI lifecycle mode → three `_run_lifecycle_case` transactions → receipt/report | **Route present; blocked.** Portable parent receives a fabricated leader/descendant protocol and never runs the two production child bodies. |
| **E** | workflow E → held CLI sandbox mode → fixed sudo/root bootstrap → root-pinned launcher sandbox owner → receipt/report | **Static route present; blocked.** Root pin/command shape is independent, but provisioning/sudo remain intentionally absent and the E cut corpus is incomplete. |
| **Integration** | workflow integration after A–E → held CLI runtime mode → closure issuance and two tools → thin receipt/report | **Route present; blocked.** It shares B's split parent/child evidence and all global defects. |

## Authority and cleanup disposition

| Boundary | Result |
| --- | --- |
| Workflow eligibility/dependencies | Exact PR-head checkout expressions, always-executed failed eligibility gate, A–E dependencies, integration A–E needs, upload-before-cleanup, and final result inventory are statically present. |
| Held launcher/source/client bytes | Common opens and generation-checks five objects and compares them with the Git tree selected by `context.head_sha`. **Too late for the already executing client/common and not a separately fixed head.** |
| Sole launcher CLI | Sealed fd 3/fd 4 ABI and isolated `/usr/bin/python3 -I -B -` are present; the dead ambient API remains absent. **Its issuer authority is P1-1.** |
| E root source | Fixed sudo command and root-owned bootstrap/authority paths remain statically present; the root bootstrap authenticates its own bytes and exact source rows before compile. No provisioning or sudo authority is granted. |
| Operation/report source | One recursively frozen operation receipt is rederived before publication; clients supply only failure diagnostics. This portion is structurally sound. |
| Upload interval | A retained inotify watch and final byte/generation checks reject observed mutation. Complete intent is still published too late, and no upload acknowledgement independently identifies artifact-consumed bytes. |
| Terminal cleanup | Exact active directory is renamed to retained quarantine and custodian exit is observed. **Report-path baseline is not restored, retained bytes are never removed, and loss/crash states are not recoverable.** |

## ADR 0093 matrix

| Requirement | Result |
| --- | --- |
| 1. Independent sole bootstrap issuer | **FAIL — P1-1.** CLI bridge exists, independent pre-execution authority does not. |
| 2. Immutable operation receipt/report source | **PASS static.** |
| 3. Exact descriptor/child generations | **PASS static/portable for reviewed owners.** |
| 4. Digest/capability cleanup and crash recovery | **FAIL — P1-2/P1-3.** |
| 5. Preregister fds/children | **PASS static for the corrected creator-owned secondary-pidfd paths; complete evidence still fails P1-3.** |
| 6. C exact bound/cuts | **PASS static/portable.** |
| 7. D preregistration/three cases/aggregate settlement | **PASS static shape; FAIL mandatory complete portable execution under P1-3.** |
| 8. E inner authority/root pin/every cut | **PASS static transfer/root-pin shape; FAIL complete cut evidence under P1-3.** |
| 9. Parsed causal workflow acceptance | **PASS static/portable workflow shape.** |
| 10. Causal complete portable ledgers | **FAIL — P1-3.** |
| 11. Readable transitions | **FAIL — P2-1.** |
| 12. CLI success remains success | **PASS static.** Launcher/common/clients leave `SystemExit(0)` outside `except Exception`. |

## Accounting

No ADR high breach was found from `bec0a19`:

- trusted/portable subtotal: **14,362 / 19,000**
- native subtotal: **4,265 / 10,000**
- listed aggregate: **18,627 / 29,000**
- closure **2,811 / 3,100**; launcher **3,757 / 4,700**; common **1,778 / 1,900**; workflow **318 / 400**; native schema **340 / 700**; schema registration **264 / 300**; fixtures **527 / 1,700**; trusted-launcher portable **2,300 / 2,300**. All other listed individual files are below their highs.

## Exact identities

- launcher SHA-256: `058093d35f1d5f1f3c5dc55becd534202746751b1fa78cd467c38767ab7668bd`
- launcher Git-blob SHA-1: `8699f0b2f2bb457062c732e16847bb23aa10e62b`
- four-source framed SHA-256: `b397d91ea2b8d8f48625b720ce78df3a9dbc9ef32864136bbd9dfceb3226905d`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

These identify reviewed bytes only; they grant no execution or provisioning authority.

## Verification

- Seven isolated `/usr/bin/python3 -I -B` Outcome Two portable suites: **PASS**.
- Seven `/usr/bin/python3 -O -I -B` optimized-mode runs: **PASS** (all rejected optimized mode).
- AST parse/compile for closure, launcher, common, all six clients, and seven portable suites: **PASS** (16 files).
- `git diff --check 0db8c26..0d934c9`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Full predecessor-range `git diff --check bec0a19..0d934c9`: **not clean only because older tracked `.pi/outcome-two/*.md` files contain pre-existing trailing spaces; no corrected implementation-path whitespace finding was identified.**
- Focused TypeScript/AJV/npm gates: **not run** because this clean review worktree has no `node_modules`; no installation or network access was attempted.
- Native, sudo, workflow, provider, cloud, AWS, deployment, and production actions: **not run**.

## Outcome boundary

This review grants no native authority. Jobs A–E and thin integration have not run at this head. Native process/descriptor/namespace/mount/seccomp facts, root provisioning, artifact bytes, report cleanup, same-run integration, Phase B, cloud/AWS/provider/OpenTofu/deployment, production, release, issue closure, and Outcome Two completion remain unproved and unauthorized.

# SIGNOFF: BLOCKED

`0d934c9e03aae17a5f219f302cf5c09058d45c59` retains three P1 findings and one P2 finding. Do not name it in a native-execution ADR, invoke `--workflow-bound`, provision/run sudo, dispatch/rerun the workflow, rely on artifacts, or authorize production/release/issue-closure/cloud activity.
