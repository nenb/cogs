# ADR 0093 provenance/authority exact-head review

- **Reviewed implementation head:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Reviewed tree:** `b861aec6605837f669fc91d7c4aa1b31e596aafa`
- **Scope:** fixed Git-held source identity, independent root bootstrap identity, rejection of internally consistent unauthorized input, and profile/replay authority
- **Method:** static, portable Git/object inspection only; no tracked source, native, sudo, workflow, provider, cloud, or constructed-payload execution
- **Verdict:** **BLOCKED — NO SIGNOFF**

## P0–P3 verdict

| Severity | Count | Verdict |
|---|---:|---|
| P0 | 0 | None found in this scope. |
| P1 | 2 | Blocking issuer/integration defects. |
| P2 | 1 | Portable acceptance masks the broken production bridge. |
| P3 | 0 | None recorded. |

## Findings

### P1 — The independently authenticated fixed-bootstrap issuer does not exist on the production path

ADR 0093 and `.pi/outcome-two/adr0092-launcher-api.md` require an issuer to fix the Git head/profile, compare held source and client generations with that exact Git tree, and only then start held launcher/client code. The implemented pieces do not form that transaction:

- The workflow starts the checkout's tracked client directly (`.github/workflows/ci.yml:201`, `243`, `285`, `327`, `369`, `411`). Each client imports and executes tracked `common.py` before source admission.
- `NativeSession.begin()` starts the custodian and performs baseline observation (`scripts/native-qualification/common.py:1590`, `1598–1602`) before `SystemCommonOps._admit_sources()` is reached.
- Common does perform a strong held-byte/Git-tree comparison at `scripts/native-qualification/common.py:369–390`, but its expected revision is the workflow/environment context and the check occurs only after the tracked client/common path is already running.
- The launcher bootstrap has no Git-tree lookup or independently fixed expected head. `_bootstrap_with_ops()` selects `mode` from caller-supplied admission bytes (`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:3450–3477`); capsule blob OIDs are also capsule-supplied and only checked for internal hash consistency.

Consequently, the fixed Git-held comparison is not the pre-execution authority required by the decision. A direct bootstrap envelope can select its profile/revision through internally consistent admission/capsule fields, while the only component that consults Git is not a functioning bootstrap issuer. Profile authority is therefore not closed end to end.

### P1 — Common calls an API removed from the exact-head launcher, so all six real operation paths fail before bootstrap

After held-source admission, common compiles/executes the held launcher and unconditionally resolves `invoke_fixed_admitted_operation` (`scripts/native-qualification/common.py:395–401`, `436–441`). Exact-head launcher exports no such function. Static symbol inventory finds `_prepare_client_from_admitted_bytes()` at launcher line 2246 and `_bootstrap_with_ops()` at line 3450, but no `invoke_fixed_admitted_operation` definition.

Thus `getattr()` raises before A/B/C/D/E/integration can enter the fixed bootstrap CLI. This is not merely an unavailable native prerequisite: the sole-issuer redesign removed the old bridge without wiring common to the replacement. Exact-head provenance validation cannot sign off a production path that has no callable issuer.

### P2 — Portable acceptance conditionally skips the removed bridge and substitutes the production operation owner

`test/outcome-two-trusted-launcher-portable.py:2183–2196` only checks the legacy invocation and held-Python path **if those attributes exist**. It does not require or drive a common-to-`_bootstrap_main()` issuer bridge. `test/native-qualification-common.test.ts:244–269` supplies a fake `Ops.run_fixed_operation`, and the recovery matrix likewise uses `CommonOps.run_fixed_operation`; neither reaches `SystemCommonOps.run_fixed_operation()` against the exact launcher.

The suite can therefore report portable success while the real common path deterministically fails at the missing symbol and while the pre-execution issuer requirement remains unproved.

## Verified properties

- **Exact Git identity:** clean worktree initially resolved to the requested head and tree; `git fsck --no-dangling HEAD` and both ADR-range/exact-head `git diff --check` completed without findings.
- **Held source comparison primitive:** `_admit_sources()` opens and generation-checks the fixed source/client paths, obtains exact `100644` blob IDs with `git ls-tree`, and compares held bytes to Git blob framing before compiling the held launcher. The defect is its placement/lack of a functioning independent issuer, not its blob calculation.
- **Independent root comparison shape:** the fixed root bootstrap reads root-owned fixed names, checks the bootstrap bytes against `root_bootstrap_sha256`, compares revision/launcher/source-set/source rows before `exec(compile(...))`, and rejects a capsule that differs from the supplied independent authority (`launcher.py:2423–2472`). The repository intentionally does not provision those files, so this is static design evidence only and grants no sudo/native authority.
- **Unauthorized root capsule case:** the portable hostile matrix mutates each source, recomputes an internally consistent capsule, retains the independent baseline authority, and expects rejection before sandbox effects (`test/outcome-two-trusted-launcher-portable.py:693–749`).
- **Internal replay guards:** closure capabilities and launcher admissions contain one-shot state checks. They do not repair the absent independently authenticated outer issuer/profile binding.

Representative exact-head Git blob IDs were fixed by `git ls-tree HEAD`: launcher `e5d27b13a4a514f80e6e0b20c6ce3e12d36b32fe`, closure `f76088b48114a20cc8b929e9ae72cf4cf2917b52`, common `3adc4da396eeb3e31144c1c6b1742a9551828aae`, workflow `d47b656d4d21c54d6e462e213b96417447bf2276`, and native report schema `1e892705fa261701b3d6e388ec11ede2f6214f7e`.

## Signoff

**Denied at `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`.** Do not authorize native/sudo execution, workflow dispatch or rerun, artifact reliance, provider/cloud/AWS activity, production, release, issue closure, or a later execution ADR from this review. A correction must provide one independently authenticated pre-execution Git/profile issuer, wire common to the fixed bootstrap CLI without restoring ambient caller authority, and add portable production-path coverage that fails if that bridge is absent.
