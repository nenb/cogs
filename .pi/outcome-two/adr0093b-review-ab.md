# ADR 0093B fresh exact-head hostile review — Jobs A/B

- **Reviewed implementation head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Scope:** A/B fixed CLI issuer, exact process/descriptor ownership, immutable receipt derivation, and exact A/B metadata
- **Method:** fresh static review and portable mocked tests only
- **Native/cloud execution:** **not performed**. No `--workflow-bound` client, native primitive qualification, sudo, namespace/mount/seccomp action, workflow dispatch/rerun, provider, network acquisition, cloud, AWS, OpenTofu, deployment, production, or release action was invoked.
- **Verdict:** **BLOCKED**

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 2 | unresolved; blocking |
| P2 | 0 | none additional |
| P3 | 0 | none additional |

## P1 findings

### P1-1 — The required portable A/B path still does not compose common's fixed CLI issuer with the real bootstrap owners

The production correction is present: `SystemCommonOps.run_fixed_operation()` now admits held source/client generations, builds the admission and sealed capsule, and calls `_issue_cli()` (`scripts/native-qualification/common.py:531-545`). `_issue_cli()` creates the gated `/usr/bin/python3 -I -B -` process with descriptors 0–4 and exact reap handling (`:444-519`), and the launcher authenticates fd 3/fd 4 before dispatching mapping or compression (`completion_trusted_runtime_launcher.py:3684-3746`). The deleted ambient `invoke_fixed_admitted_operation` bridge is absent.

The portable acceptance does not traverse that corrected boundary. `invoke_bootstrap()` hand-builds admission/capsule bytes and directly calls `_bootstrap_with_ops()` (`test/outcome-two-trusted-launcher-portable.py:430-500`); the suite's common-side check is source-token/order inspection only (`:2249-2273`). The common focused test separately feeds `_capsule()` to `_decode_held_source_capsule()` (`test/native-qualification-common.test.ts:306-328`). Its only `_issue_cli()` execution is Linux-gated, uses a synthetic script rather than the real bootstrap, and does not call `SystemCommonOps.run_fixed_operation()` (`:330-347`). A's owner corpus begins directly at `_qualify_fixed_python_mapping_with_ops()` (`test/outcome-two-mapped-closure-portable.py:539-571`).

Accordingly, no portable case composes **held Git admission → common `_issue_cli` → real `_bootstrap_with_ops` authentication/mode selection → A or B owner → common decode/immutable receipt**. A mismatch in fd wiring, admission mode, real result framing, or common-to-bootstrap ownership can remain green. ADR 0093 sections 1 and 10 require the fixed bootstrap to be the sole causally tested issuer and require complete A/B production state machines above mocked native primitives; static string presence and separately completed owners are non-accepting.

### P1-2 — B's accepting corpus still disconnects worker/namespace ownership from the result and metadata it approves

The new B test executes the parent `_coordinate_with_ops()` with a model whose `clone_pidfd()` returns only the parent result. It explicitly requires the patched real `_worker_main` and `_namespace_owner` wrappers to have **no calls** (`test/outcome-two-trusted-launcher-portable.py:2119-2144,2170-2175`). After the parent has already consumed a preconstructed issuance packet and produced its result, the test invokes three separate child models (`:2145-2149`):

- `_modeled_worker_execution()` replaces the closure constructor with a stub owner that returns a fabricated `_IssuanceReceipt`; it does not produce the packet consumed by the parent (`:1949-1979`).
- Each `_modeled_namespace_execution()` creates a new kernel/process graph and scripted status/transfer commands, disconnected from the namespace processes owned and settled by the parent (`:1982-2058`).

The complete-process fixture contains only B success, integration success, and worker/namespace secondary-pidfd rejection (`test/fixtures/outcome-two/launcher/tool-process-cases.jsonl:2-5`). It has no causal complete-owner rows for issuance producer/consumer acknowledgement and EOF, helper registration/retirement, namespace transfer send/receive/credentials/rights/EOF/ack, or the two tool-child failure settlements. Component tests do not reconnect those cuts to the B result.

This matters to exact metadata ownership: the accepted B result and `_runtime_metadata()` are derived from the parent's preconstructed report/rows, while the separately executed worker returns an unrelated receipt. The green oracle therefore does not prove that the exact worker-owned sealed generations and process transactions caused the parser/tool/top-closure metadata later frozen by common. This remains contrary to ADR 0093 sections 2, 5, and 10.

## P2

No P2 finding additional to the blocking causal-acceptance defects.

## P3

No P3 finding.

## Verified positive properties

- Production common no longer references `invoke_fixed_admitted_operation`; it issues an isolated, gated fixed CLI from sealed held launcher/admission/capsule bytes and checks the returned head/source-set identity.
- The launcher authenticates the exact fixed source set and selected client before loading private closure code or choosing mapping/compression production entries.
- Positive-PID/invalid-secondary-pidfd handling now retains the creator's numeric direct-child authority, closes both gate ends, bounded-waits, and if necessary signals/reaps that unrecycled direct child (`completion_trusted_runtime_launcher.py:430-437,800-827,1090-1142`).
- A's direct owner executes the mapping helper child branch in the portable model, enforces registration before release, proves exact mapped order/digests, and restores descriptors/children.
- B production metadata binds gzip/zstd object rows, closure/mapping/execution-mapping digests, source/sealed executable digest and size, seal mask 63, exact fixed output, parser closure, and the parser/zstd/gzip aggregate (`completion_trusted_runtime_launcher.py:624-647`; `scripts/native-qualification/common.py:834-865,903-924`).
- Common freezes the exact returned result before returning it to the client, re-derives checks/metadata from the private receipt, and excludes caller-supplied pass checks or metadata (`scripts/native-qualification/common.py:1622-1655,1692-1705`).
- A and B clients are failure-only adapters and do not construct report metadata.

## Portable/static verification

- Exact clean pre-report head: **PASS** — `0d934c9e03aae17a5f219f302cf5c09058d45c59`.
- Seven `/usr/bin/python3 -I -B` Outcome Two portable suites: **PASS**.
- Seven optimized `-O -I -B` refusal runs: **PASS** (all rejected optimized mode).
- Python AST parsing for ELF, closure, launcher, common, A, and B: **PASS**.
- Focused Node tests for A, B, and thin integration using `--experimental-strip-types`: **PASS**.
- `test/outcome-two-portable.test.ts`: **not runnable** because `ajv/dist/2020.js` is absent; no dependency installation or network acquisition was attempted.
- Static fixed-CLI/dead-API/admission-order probes: **PASS**.
- `git diff --check 0db8c26..HEAD` and clean-worktree `git diff --check`: **PASS**.
- Relevant gross additions remain within ADR 0093 highs: closure `2811/3100`, launcher `3757/4700`, common `1778/1900`, mapped portable `625/700`, trusted-launcher portable `2300/2300`, A client/test `94/420` and `88/350`, B client/test `94/500` and `85/350`.
- Exact review identities: launcher SHA-256 `058093d35f1d5f1f3c5dc55becd534202746751b1fa78cd467c38767ab7668bd`; four-source framed SHA-256 `b397d91ea2b8d8f48625b720ce78df3a9dbc9ef32864136bbd9dfceb3226905d`.

# BLOCKED

Exact implementation head `0d934c9e03aae17a5f219f302cf5c09058d45c59` has two unresolved P1 findings. ADR 0093B A/B signoff is denied. This report grants no native execution, `--workflow-bound` use, workflow dispatch/rerun, artifact reliance, production/release/issue closure, provider, cloud, AWS, OpenTofu, or deployment authority.
