# ADR 0093 final exact-head hostile review — common/custodian/source receipt

**Disposition: BLOCKED — NO SIGNOFF**

**Exact implementation head reviewed:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Method:** fresh static and portable-only hostile review of corrected common source admission, immutable operation receipt/report derivation, descriptor authority, custodian ownership, publication/upload receipt, cleanup authorization, quarantine, crash recovery, retirement/reap, and the focused portable/static acceptance. No native primitive qualification, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, AWS, OpenTofu, deployment, campaign, production, release, or implementation edit was performed.

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 7 |
| P2 | 3 |
| P3 | 0 |

ADR 0093 requires no unresolved P0–P3. The findings below block common signoff.

## Findings

### P1-1 — Cleanup never proves private capability possession, so same-UID disk/socket substitution can produce false success

The durable `.authority.json` publishes every selector needed to reconstruct the abstract socket name and expected request, including run/head/job and custodian PID/start (`scripts/native-qualification/common.py:1070-1072`, `1224-1238`). `cleanup_report()` trusts that disk record, connects to the predictable name, and authenticates only the peer identity named by the same disk record (`:1530-1549`). Its request contains only public record fields plus a caller-generated nonce (`:1551-1560`). The worker accepts any same-UID/GID requester with those public fields; the retained capability authenticates the worker's own receipt, not the cleanup requester (`:1486-1497`).

A same-UID admitted process can move the real active directory aside, create a mode-0700 replacement with an authority naming its own PID/start, bind the predictable socket, move the replacement to the retired name, echo `CLEAN:<nonce>`, and exit. The client then sees the disk-selected peer, matching retired generation, and absent active pathname and returns success (`:1566-1577`), while the real report generation remains elsewhere. The private capability is no longer durable plaintext, but cleanup does not receive or prove it over retained private authority as ADR 0093 requires.

### P1-2 — The publication receipt still does not bind the bytes consumed by `actions/upload-artifact`

`_receipt()` is created locally before upload and calls itself a `stable-upload-window` (`common.py:1241-1267`, `1285-1315`). Neither the upload action nor cleanup supplies an uploader-issued digest, size, source generation, artifact/session identity, or completion acknowledgement to the custodian. The workflow merely orders a generic pathname upload before cleanup (`.github/workflows/ci.yml:217-230`), while cleanup can be requested by any same-UID peer and carries no upload receipt (`common.py:1557-1560`).

The inotify watch and later pathname digest prove at most that selected local state looked unchanged at sampled times. They cannot prove which bytes/generation the uploader opened and consumed, or that upload completed before an unauthorized cleanup request. Thus the required causal chain from exact publication generation to exact uploaded bytes is absent.

### P1-3 — Quarantine remains pathname-racy, and verification is not atomic with the namespace transition

`_cleanup_owned()` closes each retained named file after checking it, then `_retain_quarantine()` renames the active pathname (`common.py:1382-1422`). `_retain_quarantine()` records the retained directory identity but never proves that the source pathname still denotes it before the rename; it only checks the target absence, performs `renameat2`, and diagnoses the moved generation afterward (`:1387-1396`). A same-UID exchange can therefore make it move a foreign directory and discover the mismatch only after mutating the namespace.

There is also a mutation window after `_watch_clean()` and after report/receipt checks but before rename (`:1497-1507`), plus another exchange window after the terminal retired-name stat and before the final existence-only assertion (`:1573-1577`). Inotify is sampled once and does not make those checks atomic. The implementation removed check-then-unlink/rmdir, but it did not meet ADR 0093's retained-directory/generation, race-free quarantine requirement.

### P1-4 — Publication and quarantine crash states are preserved but not recoverable or idempotent

Publication has durable effects after directory creation and each link/rename/fsync (`common.py:1274-1315`) but no rollback or independent recovery state machine. The only HMAC capability lives in the custodian. If publication acknowledgement is lost, `NativeSession.publish()` aborts and kills/reaps that sole authority holder (`:1079-1096`, `1758-1763`), leaving any already-created named state unrecoverable. Custodian timeout/death has the same result.

Cleanup explicitly rejects an already-retired state (`:1527-1529`), so a crash after quarantine but before an authenticated reply cannot be retried. Fixture rows 10–29 merely classify partial states as `preserved`; row 40 likewise calls custodian loss preserved. None proves a fresh process can recover to a terminal state. ADR 0093 requires every crash cut to be classified **and recoverable**.

### P1-5 — Successful cleanup proves custodian exit, not exact reap

On the workflow cleanup path the custodian is no longer a child of the cleanup process. Success calls `_retire_child(..., waitable=False)` (`common.py:1566-1569`), for which `_bounded_reap()` only polls pidfd readability and never performs a wait (`:1099-1105`). Pidfd readability establishes exit, not that the exact process was reaped.

The portable model hides the distinction by setting `process.reaped = True` whenever its fake poll sees a dead process (`test/outcome-two-recovery-portable.py:396-409`). Therefore both production and acceptance fail ADR 0093's exact custodian retirement/reap requirement.

### P1-6 — Workflow/common/driver/schema source receipts remain susceptible to pathname ABA

`_sha256()` performs `lstat`, `Path.read_bytes()`, `lstat` (`common.py:90-95`), and schema admission repeats that path-based shape (`:138-146`). A same-UID replacement B can be read between two observations of restored object A, causing B's digest/bytes to be accepted as A's generation. Cleanup again re-resolves workflow/common/driver pathnames instead of checking retained source handles (`:1377-1380`).

The launcher source set itself is held by descriptors and Git-blob checked, which is a material improvement, but the report's common/driver/workflow/schema identities are not exact retained generations. The executed client is also admitted separately while `source_set_sha256` is computed only over `SOURCE_PATHS`, not the client (`:377-399`, `429-443`), so the operation receipt does not carry one canonical manifest identity covering every executed component.

### P1-7 — The green common/custodian corpus does not execute the real custodian or prove crash/private-authority causality

The portable `fork()` only returns a modeled parent PID (`test/outcome-two-recovery-portable.py:608-612`). `CommonSocket.send()` directly calls production `_publish_transaction()` in the driver process (`:345-365`), and a connector directly calls `server_cleanup()` (`:351-355`); `_custodian_main()`/`_custodian_worker()` child IPC is never run. Capability, VNodes, transaction handles, and process state remain in one `CommonKernel` across `crash_close()` (`:413-437`, `675-680`). Fake poll equates exit with reap, and successful-path upload/authentication sentinels are appended by the harness (`:647-664`, `899-914`) rather than observed from an uploader receipt.

The fixture's publication crash rows accept permanent `cleanup:preserved` states, and its string sentinels do not carry generations/digests or independently enumerate required cuts (`test/fixtures/outcome-two/launcher/common-custodian-cases.jsonl:10-29`). The TypeScript focused cleanup test replaces `_file_digest_at` and `_retain_quarantine`, while key receipt/descriptor claims are lexical AST assertions (`test/native-qualification-common.test.ts:239-304`, `349-400`). Declared/selected/consumed equality is therefore equality over a non-causal and incomplete model, not the complete common/custodian production state machine required by ADR 0093.

### P2-1 — “Cleanup” leaves a permanent retired report directory and is not repeatable

The terminal path only renames the complete report directory to `/tmp/.cogs-native-qualification-<job>.retired`; no authenticated file retirement/removal follows (`common.py:1387-1422`, `1573-1577`). A second cleanup rejects the retained state (`:1527-1529`), and future publication rejects it (`:1287-1289`). This leaves report and authority metadata indefinitely and does not restore the complete named-path baseline.

### P2-2 — The inotify allocation can leak before registry adoption

`_mutation_watch()` calls `inotify_init1()` and then `registry.adopt()` without closing the returned descriptor if adoption fails (`common.py:1431-1440`). In contrast to `FdRegistry.open()` and `_adopt_socketpair()`, registry uncertainty/allocation failure leaves this newly allocated descriptor unowned, violating immediate visible adoption/recovery.

### P2-3 — The pidfd is not causally bound to the authenticated socket peer

`cleanup_report()` reads `SO_PEERCRED`, checks `/proc/<pid>/stat`, and only afterward opens a pidfd, with no post-open start-time/peer revalidation (`common.py:1544-1556`). Peer exit and PID reuse in that interval can bind retirement to a different process; on an invalid reply the code may signal that pidfd (`:1566-1569`). Exact transferred process authority therefore remains unproved.

## Corrected properties observed

- `OperationReceipt` now recursively freezes the result and derived nested metadata, re-derives checks/metadata at publication, and rejects post-return mutation (`common.py:1622-1655`, `1692-1705`).
- Held launcher/source/client bytes are opened beneath a retained root, generation checked, and Git-blob authenticated before isolated CLI execution (`:377-443`).
- Descriptor anchors use duplicated open-file descriptions plus `kcmp` equality, flags, stat generation, and stable repeated censuses (`:584-623`).
- Custodian socketpair and startup pidfd ownership are visibly adopted before release; secondary cleanup pidfd failure now fails closed.
- Raw cleanup capability bytes are no longer written to a named receipt.
- Gross additions remain within the reviewed highs for focused surfaces: common `1778/1900`, common focused test `491/1500`, recovery portable `1000/1500`, workflow `318/400`, schema `340/700`, and schema registration `264/300`.

These corrections do not resolve the findings above.

## Portable/static evidence

Passed:

- `PYTHONDONTWRITEBYTECODE=1 python3 -I -B test/outcome-two-recovery-portable.py`
- `PYTHONDONTWRITEBYTECODE=1 python3 -I -B test/outcome-two-trusted-launcher-portable.py`
- Focused Python AST and JSONL parsing for common/recovery/trusted-launcher and common/sandbox fixtures
- Focused `git diff --check 0db8c26..0d934c9` and common readability/line-width check

Not run:

- `test/native-qualification-common.test.ts` and the TypeScript portable wrapper, because `node_modules` is absent. No dependency installation or network acquisition was attempted.
- Any native or cloud action, per ADR 0093 and review instructions.

The green portable results are non-accepting because of P1-7.

## Requirement disposition

| Area | Result | Reason |
| --- | --- | --- |
| Immutable operation-derived report | **PASS static** | Recursive freeze and re-derivation corrected. |
| Exact source receipt | **FAIL** | P1-6 path ABA and split client/source-set identity. |
| Exact descriptor baseline | **PASS static** | Anchored OFD identity and stable census present. |
| Custodian preregistration | **PASS static** | Startup gate and creator cleanup improved. |
| Private cleanup authority | **FAIL** | P1-1 requester never proves private capability. |
| Uploaded-byte receipt | **FAIL** | P1-2 has no uploader-issued causal receipt. |
| Race-free cleanup/quarantine | **FAIL** | P1-3 retains pathname exchange windows. |
| Crash recovery/idempotency | **FAIL** | P1-4 preserves irrecoverable states. |
| Exact custodian retirement/reap | **FAIL** | P1-5 proves exit only; P2-3 leaves identity race. |
| Complete causal portable corpus | **FAIL** | P1-7 bypasses the custodian and fabricates key oracles. |
| Terminal path cleanup | **FAIL** | P2-1 permanently retains and rejects quarantine. |

# Final decision: BLOCKED

**NO SIGNOFF** for exact implementation head `0d934c9e03aae17a5f219f302cf5c09058d45c59`.

This report grants no native execution, sudo, workflow dispatch/rerun, artifact reliance, cloud/AWS/provider/OpenTofu/deployment action, production, release, issue closure, or later execution-ADR authority.
