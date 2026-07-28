# ADR 0093 final exact-head hostile review — integration / CLI issuer / custodian / exact result

**Disposition: BLOCKED — NO SIGNOFF**

- **Exact implementation head reviewed:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Exact tree:** `9e29cfd781074721a9cb858c9878ab4661c12822`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** thin integration; fixed launcher CLI issuer; immutable operation result/report derivation; report custodian publication, cleanup authority, retirement, and reap; causal portable acceptance.
- **Method:** fresh hostile static and portable review of the corrected exact tree. No `--workflow-bound` selector, native qualification primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, AWS, OpenTofu, deployment, production, or release operation was invoked. No implementation file was edited.

## P0–P3 summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 8 | unresolved; blocking |
| P2 | 2 | unresolved; blocking under ADR 0093 |
| P3 | 1 | unresolved; blocking under ADR 0093 |

ADR 0093 requires ten exact-head reviews with no unresolved P0–P3. This head is not eligible for signoff or a later native-execution ADR.

## Findings

### P1-1 — The fixed issuer authenticates too late: tracked client and common code execute first

The launcher CLI bridge now exists, and `SystemCommonOps.run_fixed_operation()` does authenticate held launcher/source/client generations before `_issue_cli()` (`scripts/native-qualification/common.py:531-545`). That fixes the deleted-symbol failure at the prior reviewed head.

It does not satisfy the sole-issuer order required by ADR 0093 and `.pi/outcome-two/adr0092-launcher-api.md`. The workflow directly starts the checkout's tracked client (`.github/workflows/ci.yml:411-426`); that client imports tracked `common.py`, constructs `WorkflowContext`, starts the report custodian, and takes native baselines (`common.py:1596-1602`) before `_admit_sources()` is reached. The component performing admission is therefore itself caller-head tracked code already in execution. The launcher API note expressly requires an independently authenticated issuer to hold and compare the exact head generations **before starting tracked launcher or client code**.

A self-consistent changed client/common generation can execute before the supposed trust gate. The new child CLI is a downstream dispatcher, not the required pre-execution issuer.

### P1-2 — A caller can still fabricate the private receipt and publish a passing integration report without an operation

`NativeSession` protects the receipt only with Python name mangling and stores the session nonce in another caller-readable attribute (`common.py:1578-1594`). Settlement checks only that `__receipt` is present (`:1668-1691`); publication rederives claims from whatever internally consistent receipt occupies that attribute (`:1692-1710`). It never proves that `run_fixed_operation()` created the receipt or even ran.

A portable hostile probe instantiated a session, did **not** call `run_fixed_operation`, built an all-true `RuntimeQualificationResult` dictionary with arbitrary source/closure digests, read `session._nonce`, assigned a matching `OperationReceipt` to `session._NativeSession__receipt`, settled, and published. Exact output:

```text
fabricated_receipt_without_operation=PASS_REPORT bd2684d7d4c947cd4edcd535444c8e1e170ff634dab95c90d89ca45634fea637
```

The report result and every integration check were `pass`. This directly violates ADR 0093 sections 2 and 10: caller-fabricated/skipped operations remain accepting. Recursive freezing and rederivation protect a legitimate receipt from mutation but do not establish its issuer.

### P1-3 — Successful cleanup proves custodian exit, not exact reap

The client creates the custodian as its child (`common.py:1177-1201`), publishes, closes the control channel, and exits. The later workflow cleanup is a separate process and is not the custodian's waitable parent. Nevertheless cleanup calls `_retire_child(..., waitable=False)` (`:1566-1569`). `_bounded_reap()` then only polls pidfd readiness and performs no `waitpid` (`:1099-1105`). Pidfd readiness proves exit, not reap.

There is no surviving supervisor that remains the waitable parent through upload and cleanup. Thus the successful path cannot establish ADR 0093's exact custodian retirement/reap requirement.

### P1-4 — The portable custodian oracle turns pidfd readiness into a fictitious reap

`CommonPoll.poll()` sets `process.reaped = True` and emits `custodian:reaped` whenever the modeled process is merely not live (`test/outcome-two-recovery-portable.py:396-410`). `CommonKernel.audit()` then treats that bit as exact reap (`:681-693`). This masks P1-3 and makes fixture sentinels such as `custodian:reaped` pass without a production wait operation.

The dedicated `retire-exact-waitable-reap` row tests a different `waitable=True` helper path; it does not prove the real successful `cleanup_report()` path, which is explicitly non-waitable.

### P1-5 — Cleanup does not receive or prove possession of the retained private capability

The raw capability correctly no longer appears in durable plaintext. However, `cleanup_report()` never receives it over private authority. The listener name is derived from public run/job/head data (`common.py:1070-1072`), and the worker accepts any same-UID/GID peer that supplies those public fields plus its own syntactically valid nonce (`:1484-1496`). The capability is used only by the custodian to authenticate its own disk receipt.

Any same-UID process can consume the one-shot listener and trigger premature quarantine or denial of the legitimate cleanup. This is not ADR 0093 section 4's retained private cleanup grant.

### P1-6 — Custodian acquisition has a PID-reuse retirement race

Cleanup authenticates `SO_PEERCRED` and reads `/proc/<pid>/stat` before acquiring the secondary pidfd (`common.py:1544-1555`). If the custodian exits and the PID is reused between those operations, `pidfd_open(peer_pid)` may bind an unrelated same-UID process. A failed/invalid reply then passes that pidfd to `_retire_child(..., terminate=True)`, allowing SIGKILL of the replacement process.

Process identity must be validated through already-acquired stable process authority; a pathname start-time check before pidfd acquisition does not close reuse.

### P1-7 — Publication crash cuts are preserved but not recoverable or baseline-restoring

`_publish_transaction()` has no rollback owner around directory creation, anonymous allocation, writes, fsyncs, links, readback, and rename (`common.py:1284-1316`). If the custodian dies before a complete live receipt/listener transaction, the creator can only retire the process. `cleanup_report()` requires a live active directory with `.authority.json` and then a connection to the live custodian (`:1524-1544`); it deliberately has no authenticated lost-custodian recovery.

The fixture labels early cuts `crash:classified` and `preserved`, but an empty or partial fixed directory has no usable cleanup grant and permanently blocks the next baseline. That is neither recoverable exact retained authority nor baseline restoration, contrary to ADR 0093 sections 4 and 10.

### P1-8 — Portable integration remains disconnected and completed-result based

The corrected trusted-launcher suite first lets the modeled parent launcher produce `value` (`test/outcome-two-trusted-launcher-portable.py:2141-2144`). Only after that result exists does it independently call `_modeled_worker_execution()` and two `_modeled_namespace_execution()` bodies (`:2145-2149`). The parent protocol still fabricates the child traffic/result; the subsequently executed child bodies cannot causally affect that already-completed result.

The common/custodian matrix compounds this: `CommonOps.run_fixed_operation()` returns a copied precompleted result dictionary (`test/outcome-two-recovery-portable.py:700-721`), `CommonKernel.fork()` never runs `_custodian_main`/`_custodian_worker`, and fake socket methods directly call `_publish_transaction()` and `server_cleanup()` (`:345-365`). The fixed CLI is checked by source tokens and a harmless fake script, not by one accepting common → exact bootstrap → ordinary owner → immutable receipt → custodian transaction above a coherent model.

This is precisely the detached completed-result fabrication ADR 0093 section 10 declares non-accepting.

### P2-1 — Fixed descriptor installation can overwrite a not-yet-installed source

The child sequentially `dup2()`s source descriptors to 0–4 without first relocating sources away from the target range (`common.py:467-475`). If any standard descriptor is initially closed, one of the launcher/admission/capsule/pipe allocations may occupy 0–4; an earlier `dup2` can overwrite a source needed by a later mapping. The fixed ABI then depends on ambient descriptor layout and fails closed with the wrong fd 3/4 bytes.

### P2-2 — The long-lived custodian inherits undeclared ambient descriptors

After `fork()`, the custodian child closes only the parent socket endpoint (`common.py:1183-1189`). It does not close all descriptors except its control authority, and it never execs, so `CLOEXEC` does not help. It can retain workflow pipes, locks, or other resources throughout upload while those descriptors are absent from its declared ownership/cleanup model.

### P3-1 — Any pidfd poll event is treated as process exit

`_bounded_reap()` accepts any nonempty `poll()` result (`common.py:1099-1105`) rather than requiring the expected `POLLIN` event and rejecting `POLLERR`/`POLLNVAL`. This can convert an invalid pidfd observation into successful retirement evidence.

## Confirmed corrected properties

- The deleted ambient `invoke_fixed_admitted_operation` route remains absent.
- Common now creates sealed admission/capsule descriptors and executes `/usr/bin/python3 -I -B -` with an empty environment; the bootstrap requires descriptors 0–4 and canonical fd 3/fd 4 input.
- Held source/client bytes are matched to exact Git tree blob IDs before the child CLI is released.
- `SystemExit(0)` is not converted to failure in thin integration, common, or launcher: each top-level handler catches `Exception`, not `BaseException`/`SystemExit`.
- The checked-in thin integration client remains thin and does not independently read the returned result or construct checks/metadata.
- Legitimate returned results and nested metadata are recursively frozen, and publication rederives checks/metadata from the stored receipt. P1-2 concerns receipt provenance, not mutation of a legitimately issued receipt.
- The raw cleanup capability is absent from `.authority.json` and `.owner.json`; P1-5 concerns missing private delegation to the cleanup caller.
- Gross additions remain within the reviewed individual highs for this scope: common `1778/1900`, trusted-launcher portable `2300/2300`, thin integration `95/500`, and focused integration test `88/400`.

## Exact deterministic identities

Recomputed from exact HEAD:

- launcher SHA-256: `058093d35f1d5f1f3c5dc55becd534202746751b1fa78cd467c38767ab7668bd`
- launcher Git-blob SHA-1: `8699f0b2f2bb457062c732e16847bb23aa10e62b`
- four-source framed SHA-256: `b397d91ea2b8d8f48625b720ce78df3a9dbc9ef32864136bbd9dfceb3226905d`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

These are review identities only and grant no execution authority.

## Verification

Passed:

- exact-head check: `HEAD == 0d934c9e03aae17a5f219f302cf5c09058d45c59`
- `git diff --check HEAD^..HEAD`
- `git diff --check 0db8c26..HEAD`
- Python AST parsing of common, thin integration, trusted launcher, and trusted-launcher portable suite
- JSONL parsing of all launcher fixtures
- seven isolated `/usr/bin/python3 -I -B` Outcome Two portable suites
- optimized-mode refusal for all seven portable suites
- `node --test --experimental-strip-types test/native-qualification-integration.test.ts` — 1/1
- hostile skipped-operation/fabricated-receipt probe — reproduced P1-2

Unavailable:

- `test/native-qualification-common.test.ts` could not load `ajv/dist/2020.js`; no dependency installation or network acquisition was attempted.

Not run:

- No native selector/qualification, sudo, workflow, network, provider, cloud, AWS, OpenTofu, deployment, production, or release operation.

# SIGNOFF: BLOCKED

Exact head `0d934c9e03aae17a5f219f302cf5c09058d45c59` retains eight P1, two P2, and one P3 defects in the requested integration/CLI issuer/custodian/exact-result scope. Do not authorize native execution, sudo, workflow dispatch/rerun, artifact reliance, a later execution ADR, provider/cloud/AWS activity, production, release, or issue closure from this review.
