# ADR 0093 fresh exact-head holistic hostile review

- **Exact reviewed head:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Branch:** `review/o2-93-holistic`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Authority reviewed:** accepted ADR 0093; Outcome 2 production closure and launcher; native common; workflow; native report schema and registration; A–E and thin-integration clients; all portable/focused tests and tracked Outcome 2 fixtures
- **Method:** static and portable only. No `--workflow-bound` production selector, native primitive, sudo, workflow dispatch/rerun, network, provider, cloud, AWS, OpenTofu, deployment, campaign, production, or release action was run.
- **Verdict:** **BLOCKED — no ADR 0093 signoff**

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 3 | unresolved; blocking |
| P2 | 0 | none separate from the P1 findings |
| P3 | 0 | none separate from the P1 findings |

## Findings

### P1-1 — All six workflow paths call an API ADR 0093 deleted, so no production operation can reach the sole bootstrap issuer

ADR 0093 section 1 and the launcher API note require the fixed launcher bootstrap CLI to be the sole issuer and require source/client authentication before tracked launcher/client execution. The launcher correctly no longer defines `invoke_fixed_admitted_operation`; its only complete dispatcher is `_bootstrap_with_ops()` / `_bootstrap_main()` at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:3450-3514`.

Common was not moved to that contract. `SystemCommonOps.run_fixed_operation()` authenticates held bytes and compiles the held launcher, then does:

```python
invoke = getattr(module, "invoke_fixed_admitted_operation")
result = invoke(operation, context.head_sha, admitted_bytes, held[client_path].raw, digest)
```

at `scripts/native-qualification/common.py:436-441`. Static compilation of the exact launcher at this head proves `hasattr(module, "invoke_fixed_admitted_operation") is False`; the call therefore raises `AttributeError` for A, B, C, D, E, and integration before fd 3/fd 4 admission, `_bootstrap_with_ops()`, or any production owner.

There is also no independent issuer above this gap. The workflow directly executes each tracked client, each client imports tracked `common.py`, and common starts the custodian and takes baselines before source admission. The launcher helper `_prepare_client_from_admitted_bytes()` (`:2246-2276`) can construct bootstrap input, but nothing in production calls it or creates the required sealed fd 3/fd 4 bootstrap process. Calling that ambient helper would not by itself meet section 1 in any event.

This is fail-closed rather than evidence forgery, but it makes every Outcome 2 production path nonfunctional and leaves the required independently authenticated source/client bootstrap authority unimplemented.

### P1-2 — Cleanup still has check-then-unlink/rmdir races and loses generation authority at terminal crash cuts

ADR 0093 section 4 explicitly requires retained directory/generation authority and recovery without a check-then-unlink/rmdir race.

`_quarantine_verified()` verifies the generation currently at a quarantine name and then unlinks that **name** in a later syscall (`scripts/native-qualification/common.py:1284-1302`). A replacement between the final `_identity_at()` and `os.unlink()` is not bound to the retained file generation.

The directory path has the same defect. `_remove_report_directory()` stats the retired name, compares it with the open directory, closes the retained directory fd, and then calls `rmdir(target)` (`:1305-1317`). A replacement between `:1314` and `:1316` can be removed instead. More importantly, after a crash following the active-to-retired rename, all report/receipt/capability generations may already have been unlinked. Recovery opens the fixed retired name and removes any empty directory without a persisted expected generation (`_open_retired_directory()` and `cleanup_report()` at `:1474-1500`). The analogous active-empty recovery at `:1501-1505` likewise no longer authenticates the directory to the operation receipt.

The report intent does positively bind report digest, size, generation, run/head/attempt/job, cached source identities, and an HMAC. The cleanup capability is kept out of `.owner.json` and retained separately. Those properties do not bind the final unlink/rmdir syscalls or preserve exact authority after the named directory becomes empty.

### P1-3 — The mandatory portable gate accepts both the dead six-path integration and the omitted cleanup races

ADR 0093 sections 9–11 require causal production-path acceptance and equality of declared, selected, consumed, and oracle-proved cuts.

The launcher portable suite explicitly observes the removed API, but its condition only rejects an inconsistent launcher **if the API exists** (`test/outcome-two-trusted-launcher-portable.py:2183-2191`). It never checks that common stopped calling the deleted symbol. `invoke_bootstrap()` directly fabricates fd 3/fd 4 and calls `_bootstrap_with_ops()`; the common focused and recovery tests replace `Ops.run_fixed_operation()` with completed dictionaries (`test/native-qualification-common.test.ts:239-269`, `test/outcome-two-recovery-portable.py:666-681,813-819`). Thus green tests do not execute the real common → sole bootstrap boundary that every workflow path uses.

The custodian fixture declares publication cuts only through `receipt-link`, plus connection/pidfd retirement cuts. It has no cut after report/receipt/capability quarantine rename, before/after each unlink, after directory retirement, before retained-fd close, or before rmdir. Its virtual `rename`, `unlink`, and `rmdir` operations are atomic dictionary updates and cannot inject a same-name generation replacement (`test/outcome-two-recovery-portable.py:518-555`). Consequently the declared ledger cannot prove ADR 0093 section 4's exact cleanup transaction and remains green with P1-2.

## Six real production paths traced

The common prefix in the checked-in workflow is: exact PR-head checkout → clean/credential-free checkout checks → tracked client `--workflow-bound` → `NativeSession.begin()` → custodian startup and common baseline → `SystemCommonOps._admit_sources()` against `context.head_sha` → compile held launcher → lookup of deleted `invoke_fixed_admitted_operation` → abort. No path reaches the fixed bootstrap dispatcher at this head.

| Path | Intended owner after the sole bootstrap | Exact-head disposition |
| --- | --- | --- |
| **A** | workflow A → bootstrap mapping mode → held closure `_qualify_admitted_fixed_python_mapping` → resolver/helper/maps transaction → immutable common receipt/report | **Blocked at common `getattr`.** The mapped-closure owner and portable corpus are present, but production never invokes them. |
| **B** | workflow B → bootstrap compression mode → `_coordinate_with_ops` → private closure issuance → gzip/zstd `_run_tool_with_ops` → common receipt/report | **Blocked at common `getattr`.** The tool-child pidfd transfer is statically present; it is unreachable from the workflow path. |
| **C** | workflow C → bootstrap descriptor mode → `_qualify_admitted_fixed_descriptor_primitives` → bounded getdents/exec/wait/reap/limit settlement → common receipt/report | **Blocked at common `getattr`.** The 32 non-empty calls plus separately bounded EOF owner is present but unreachable. |
| **D** | workflow D → bootstrap lifecycle mode → three `_run_lifecycle_case` transactions → transferred descendant authority → exact siginfo/wait/reap → common receipt/report | **Blocked at common `getattr`.** The preregistration and three-case owner are present but unreachable. |
| **E** | workflow E → bootstrap sandbox mode → fixed sudo command → independently provisioned root bootstrap/pin → `_root_capsule_entry` → complete sandbox owner → common receipt/report | **Blocked before launcher bootstrap and therefore before sudo.** Root bootstrap bytes and independent-pin comparisons are statically present; provisioning and sudo remain intentionally unauthorized and unproved. |
| **Integration** | workflow integration after A–E → bootstrap runtime mode → same closure issuance and two real tool transactions → thin receipt/report | **Blocked at common `getattr`.** Dependency wiring is correct, but the production composition cannot start. |

## Exact source authority

| Boundary | Static result |
| --- | --- |
| Workflow exact head | Checkout refs, same-repository/attempt-one eligibility, A–E needs edges, integration needs A–E, upload-before-cleanup, and final `always()` outcome inventory are structurally present. |
| Common held generations | Four fixed sources plus the selected client are opened beneath a retained root, generation-checked, and matched to Git blob IDs from `context.head_sha` before held-launcher compilation. |
| Sole launcher bootstrap | Bootstrap validates the closed admission, sealed held-source/client capsule, source order, Git object IDs, aggregate digest, exact result profile, and dispatches one operation. **No production issuer launches it.** |
| Root E source | Fixed command and fixed root-owned bootstrap/authority paths are present. The root bootstrap checks its own digest and exact source rows before compiling launcher bytes. No provisioning or sudo authority is supplied here. |
| Report source | Common freezes one typed operation result and derives checks/metadata from the private receipt. Clients are receipt-only. This is structurally sound but cannot be reached through the broken production boundary. |
| Recovery source | Receipt HMAC covers cached workflow/schema/common/client identities and run/head/attempt/job. Current cleanup also recomputes workflow/common/client bytes. Terminal empty-directory recovery no longer has a retained operation generation, as described in P1-2. |

Exact recomputation at reviewed head:

- launcher SHA-256: `987d6080aad83c18783898df9338bd84febe165cf46912847d027c8eeb24852e`
- launcher Git-blob SHA-1: `e5d27b13a4a514f80e6e0b20c6ce3e12d36b32fe`
- four-source framed SHA-256: `dde990d2e7adde92be4ef63b1e72042cfdb64232a73a4361863c7ceae68935bc`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

Hashes identify bytes only; they grant no execution or provisioning authority.

## Exact cleanup transaction traced

1. Custodian startup now preregisters supervisor/worker behind gates and retains pidfds.
2. Publication creates a private fixed directory, links separate cleanup authority, links and renames exact report bytes, then links an HMAC-authenticated intent binding report digest/size/generation and cached source identities.
3. Workflow upload names only `report.json`; cleanup receives expected run/head/attempt and either authenticates the live custodian peer or falls back to local recovery.
4. Recovery verifies authority, receipt HMAC, report bytes, and report generation when an intent exists; it quarantines report, receipt, and capability in that order.
5. **Authority breaks at terminal name removal:** generation is checked before later name-based unlink; the open directory is checked before later name-based rmdir; after a terminal crash, empty active/retired names are removed without persisted operation generation.

## ADR 0093 matrix

| Requirement | Result |
| --- | --- |
| 1. Independent sole bootstrap issuer | **FAIL — P1-1.** |
| 2. Immutable operation receipt/report source | **PASS static, unreachable in production.** |
| 3. Exact descriptor/child generations | **PASS static/portable for reviewed owners.** |
| 4. Digest/capability cleanup and race-free crash recovery | **FAIL — P1-2/P1-3.** |
| 5. Preregister all fds/children | **PASS static for reviewed closure/launcher/custodian owners.** |
| 6. C exact bound and production cuts | **PASS owner/static/portable; workflow reachability fails under P1-1.** |
| 7. D preregistration and three cases | **PASS owner/static/portable; workflow reachability fails under P1-1.** |
| 8. E inner authority and root pin | **PASS static/portable; workflow reachability fails and root provisioning remains outside authority.** |
| 9. Parsed causal workflow acceptance | **PASS workflow structure; cross-file real CLI production boundary fails P1-3.** |
| 10. Causal portable ledgers | **FAIL — P1-3.** |
| 11. Readable transitions | **PASS checked AST/static surfaces.** |
| 12. CLI success remains success | **PASS static.** Common/clients catch `Exception`; launcher does not catch `SystemExit(0)`. |

## Accounting

Gross additions from `bec0a19` remain within every ADR 0093 high:

- trusted/portable subtotal: **13,712 / 19,000**
- native subtotal: **4,102 / 10,000**
- listed aggregate: **17,814 / 29,000**
- closure **2,811 / 3,100**; launcher **3,523 / 4,700**; common **1,771 / 1,900**; workflow **318 / 400**; native schema **340 / 700**; fixtures **495 / 1,700**; all other listed files are within their individual highs.

## Verification

- Seven isolated `/usr/bin/python3 -I -B` Outcome 2 portable suites: **PASS**.
- Seven optimized `-O -I -B` rejection runs: **PASS** (all rejected optimized mode).
- Python AST parse for production closure, launcher, common, A–E, integration, and portable suites: **PASS**.
- Exact static probe: common calls `invoke_fixed_admitted_operation`; exact held launcher does not define it; `_bootstrap_main` is present: **production boundary mismatch reproduced**.
- `git diff --check ce1f6f8^..0db8c26`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Focused TypeScript/AJV/full npm gates: **not run** because this checkout has no `node_modules`; no dependency installation or network access was attempted.
- Native, sudo, workflow, provider, cloud, and AWS actions: **not run**.

## Outcome 2 boundary

This review grants no native authority. Jobs A–E and thin integration have not run on this head, and this head cannot reach their production owners through common. Native runtime objects, namespaces/seccomp/mount behavior, report artifacts, same-run integration, root provisioning, Phase B, AWS, provider, OpenTofu, deployment, production, release, issue closure, and Outcome 2 completion remain unproved and unauthorized.

# SIGNOFF: BLOCKED

`0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` has three unresolved P1 findings. Do not authorize `--workflow-bound`, sudo/native execution, workflow dispatch/rerun, artifact reliance, production, release, issue closure, provider/cloud/AWS/OpenTofu/deployment activity, or an Outcome 2 completion claim.
