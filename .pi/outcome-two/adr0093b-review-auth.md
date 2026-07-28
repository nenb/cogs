# ADR 0093b final exact-head provenance/authority hostile review

- **Reviewed implementation head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Reviewed tree:** `9e29cfd781074721a9cb858c9878ab4661c12822`
- **Scope:** source/client Git provenance, sole-bootstrap authority, independent E root provenance, and rejection ordering for unauthorized input
- **Method:** static Git/object, AST, and source-order inspection only. No payload was constructed. No native selector, sudo, workflow dispatch/rerun, network, provider, cloud, AWS, OpenTofu, deployment, or production action was run.
- **Verdict:** **BLOCKED — NO SIGNOFF**

## P0–P3 verdict

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | None found in this scope. |
| P1 | 1 | Blocking source-issuer authority defect. |
| P2 | 1 | Acceptance does not detect the P1 ordering defect. |
| P3 | 0 | None found in this scope. |

## Findings

### P1 — Source/client authentication still occurs inside already-running tracked client/common code, not before it

ADR 0093 section 1 and `.pi/outcome-two/adr0092-launcher-api.md` require the independently authenticated issuer to hold and authenticate the exact source/client generations against a separately fixed Git head **before starting tracked launcher or client code**. The corrected CLI bridge is internally coherent, but it remains below that boundary:

- All six workflow jobs start the checkout's tracked client directly (`.github/workflows/ci.yml:216,258,300,342,384,426`).
- The tracked client imports tracked `common.py` and calls `NativeSession.begin()`. Common reads caller/environment context, starts the custodian, and takes process/filesystem baselines before source admission (`scripts/native-qualification/common.py:121-147`, `1588-1602`).
- Only later does `SystemCommonOps.run_fixed_operation()` reopen the selected client and four launcher sources, query the Git tree named by `context.head_sha`, and launch the held bootstrap (`common.py:531-545`). The selected held client is authenticated but never executed; the already-executing client generation is not bound to that retained descriptor. Common itself is not in the held source/client capsule and is not authenticated by a pre-execution issuer.
- The launcher bootstrap performs no independent Git lookup. It accepts revision, mode, blob IDs, and source bytes from fd 3/fd 4 and checks their internal consistency (`completion_trusted_runtime_launcher.py:2270-2395`, `3684-3739`). Therefore the fixed CLI is a validator for issuer-supplied material, not the separately pinned issuer. Moving material construction from the removed ambient Python API into tracked common does not make the authority independent.

This leaves a concrete generation gap: bytes already interpreted as the client/common can differ from the later reopened Git-matching generations. It also leaves A/B/C/D/integration bootstrap admission dependent on the already-running caller path. E has an additional independent root pin and rejects before root sandbox effects, but that later boundary does not repair the outer source issuer for all six jobs.

A valid correction needs an issuer above tracked client/common execution (or an equivalently fixed, independently provisioned wrapper) that fixes the reviewed head/profile, holds and authenticates the exact executable client/common/launcher generations, and only then executes held code.

### P2 — Current acceptance proves capsule compatibility, not pre-client issuer authority

The corrected tests establish useful lower-boundary properties but cannot fail on the P1 defect:

- `test/outcome-two-trusted-launcher-portable.py:2251-2273` checks only textual ordering inside `SystemCommonOps.run_fixed_operation()` and the presence of `_issue_cli`/`_bootstrap_main`; it does not establish an issuer before workflow client execution.
- `test/native-qualification-common.test.ts:306-328` constructs a common capsule and feeds it directly to the launcher decoder. Lines `330-347` drive `_issue_cli` with arbitrary test source rather than the real authenticated common-to-bootstrap transaction.
- The root hostile contract constructs self-consistent unauthorized capsules and invokes `_root_capsule_entry()` directly (`test/outcome-two-trusted-launcher-portable.py:686-779`). That is useful decoder evidence, but the actual root bootstrap remains static source-order evidence, and these cases do not cover the outer source/client generation gap.

Thus portable acceptance can stay green while workflow clients/common execute before the claimed sole issuer authenticates them.

## Verified properties

- Exact-head tracked bytes for the four fixed sources and all six clients match their `100644` Git blob IDs.
- Common's held-source walk retains file descriptors, checks complete generations, obtains object IDs from `git ls-tree` at `context.head_sha`, and compares Git blob framing before `_issue_cli` (`common.py:377-399`, `531-541`).
- The removed `invoke_fixed_admitted_operation` API remains absent. `_issue_cli` seals launcher/admission/capsule bytes, gates the child until pidfd adoption, and executes fixed `/usr/bin/python3 -I -B -` with an empty environment and fd ABI 0–4 (`common.py:403-519`).
- The E sudo command is fixed and contains no rendered authority (`launcher.py:2674-2685`). The root bootstrap opens fixed root-owned, non-group/world-writable bootstrap and authority names with `O_NOFOLLOW`, generation-checks both, verifies its own pinned digest, and compares revision, launcher digest, source-set digest, and exact source rows before compiling capsule launcher bytes (`launcher.py:2514-2623`). `_root_capsule_entry()` authenticates before `_sandbox_only_transaction()` (`launcher.py:3163-3167`).
- Missing or mismatched root provisioning therefore fails closed by static control flow. The repository intentionally does not provision either root-owned file; this review grants no root or sudo authority.

## Static verification

All executed checks passed:

- exact HEAD/tree assertion;
- Git `100644` blob recomputation for the four fixed sources and six clients;
- Python AST parsing and non-executing compilation for launcher, common, and all six clients;
- root authority/self-hash/revision/source-row comparisons ordered before `exec(compile(...))`;
- `git diff --check 3846383..HEAD` and `HEAD^..HEAD`;
- `git fsck --no-progress --no-dangling HEAD`.

Exact identities at the reviewed head:

- launcher SHA-256: `058093d35f1d5f1f3c5dc55becd534202746751b1fa78cd467c38767ab7668bd`
- launcher Git blob SHA-1: `8699f0b2f2bb457062c732e16847bb23aa10e62b`
- four-source framed SHA-256: `b397d91ea2b8d8f48625b720ce78df3a9dbc9ef32864136bbd9dfceb3226905d`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

The payload-building hostile suite was not executed, per the review constraint. TypeScript/AJV gates were not run because `node_modules` is absent and no dependency installation/network access was authorized.

## Signoff

# BLOCKED — NO SIGNOFF

Do not authorize native/sudo execution, workflow dispatch or rerun, artifact reliance, a later execution ADR, production, release, issue closure, provider/cloud/AWS/OpenTofu/deployment activity, or an Outcome Two completion claim from this review. The independent source/client issuer must exist above tracked client/common execution, and portable acceptance must prove that exact boundary.
