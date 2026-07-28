# ADR 0092 hostile signoff review — common operation/report/baselines

**Disposition: BLOCKED — NO SIGNOFF**

**Exact implementation head reviewed:** `3846383f0d88c190226356ca9aeeeda402943aaa`

**Accepted ADR commit:** `c18b7f5`

**Method:** fresh portable/static hostile review of common operation receipt, immutable cleanup evidence, stable common baselines, and durable report custodian/crash/upload/replacement/capability/reap behavior. No `--workflow-bound` invocation, native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS action was run. No implementation file was edited.

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 6 |
| P2 | 1 |
| P3 | 0 |

ADR 0092 requires no unresolved P0–P3. The findings below block common signoff.

## Findings

### P1-1 — A caller-controlled second metadata read can publish a pass that diverges from the immutable operation receipt

`NativeSession._bind_candidate()` snapshots and checks `candidate.metadata` once at `scripts/native-qualification/common.py:1181-1197`, but `publish()` iterates the caller object again at line 1223. `ReportCandidate` is frozen only around a mutable/caller-defined `metadata` object. Common does not retain the checked snapshot or derive the published metadata directly from `OperationReceipt`.

A portable hostile iterable returned the exact integration metadata on the binding read and a different, independently schema-valid `source_set` digest on the publication read. Common published `result: pass`; the published source-set digest was `9…9` while the receipt-bound production source-set digest remained `1…1`:

```text
PASS report metadata diverged from immutable operation receipt
```

The same double-read pattern exists for `production_checks` at lines 1178 and 1209. This is the caller-fabricated/cross-result publication route ADR 0092 section 3 forbids.

### P1-2 — Common descriptor baselines do not identify descriptor generations

`_descriptor_snapshot_once()` records fd number, `F_GETFD`, `F_GETFL`, and underlying-file stat fields (`common.py:404-433`). Its before/after `_generation()` checks authenticate the underlying inode during one observation, not the open descriptor/file-description generation across the operation. Closing a baseline fd and reopening the same object at the same number with the same flags produces the same row and can satisfy the repeated census at lines 435-438.

Thus close/reopen replacement of (for example) a `/dev/null` stdio fd can compare equal to the original baseline. Repeated equal snapshots do not recover the lost generation. This fails the required stable descriptor generation/identity proof.

### P1-3 — Cleanup never authenticates the uploaded report bytes against the durable receipt

The receipt records `report_sha256` and `report_size` at `common.py:846-847`, but those fields are never consumed after receipt parsing. Cleanup compares only `_identity()` (`common.py:752-754`, 955-984), which omits ctime, mtime, inode version, link count, and content digest. A same-inode, same-size rewrite after publication therefore passes cleanup classification. The upload action reads the pathname, so substituted bytes can be uploaded while cleanup and the required-final job still succeed.

The receipt generation is also not part of the receipt: `_read_receipt()` stabilizes whichever `.owner.json` it opens, while `_finish_owner()` accepts that current pathname identity at lines 936-939. A copied replacement receipt is not distinguished from the transaction's receipt generation. This fails exact retained bytes/generation authority across upload.

### P1-4 — Legal cleanup crash cuts are unrecoverable, and verified exchanges retain unlink/rmdir races

`_finish_owner()` exchanges `.owner.json` with the slot name and only then unlinks/fsyncs (`common.py:936-943`). A crash after line 939 leaves capability-slot bytes named `.owner.json` and the real receipt under `report.json`, `.report.stage`, or `.cleanup.slot`. The next `cleanup_report()` begins by decoding `.owner.json` as the receipt at line 1046, so this legal cut cannot be classified or restored. A crash after the first unlink has the same problem.

Replacement safety is also incomplete:

- `_exchange_verified()` stats both names and returns (`common.py:921-935`), after which callers unlink by name at lines 940, 962, and 969. Replacement between verification and unlink is deleted.
- `_remove_report_directory()` closes the held directory and removes the fixed pathname without proving that pathname still denotes the held directory generation (`common.py:944-950`). A rename/replacement can therefore preserve the owned directory elsewhere and delete a foreign empty replacement.

The implementation consequently proves neither every crash suffix nor “foreign/replaced state is never deleted.”

### P1-5 — The cleanup capability is disclosed, and custodian startup/retirement is not bounded on all paths

The opaque capability is written in plaintext to both the durable receipt (`common.py:843`) and `.cleanup.slot` (`878-879`). `cleanup_report()` recovers it from that receipt (`1053`), and the worker authenticates only the disclosed value plus same UID/GID (`1028-1032`). A same-UID process can read the transaction directory, reproduce the request/socket identity, race early cleanup, or impersonate a lost custodian. Recording the capability itself contradicts the required nonce/capability-digest receipt and does not close the prior substitute-custodian threat.

Custodian bounds are also partial. Startup waits on `recv()` without a timeout (`823`), `_retire_child()` uses blocking `waitpid(pid, 0)` (`795`), startup fallback blocks at `833`, and the supervisor blocks at `1013`/`1015`. Validation failures after `_ops.run_fixed_operation()` (`1139-1145`) and publication/binding failures do not call `abort()`, so no bounded aggregate retirement owner is invoked on those paths. The 10-second poll in `cleanup_report()` does not repair these earlier unbounded waits.

### P1-6 — Mandatory portable acceptance is helper/token coverage, not the required state-machine fault corpus

`test/native-qualification-common.test.ts:195-286` scripts `Ops.observe()` with completed dictionaries instead of driving `SystemCommonOps._descriptor_snapshot()` and `_children()` through generation/race cases. The durable test at lines 288-336 patches `_exchange_verified`, `_anonymous`, link, unlink, fsync, and directory removal; it invokes `_cleanup_owned()` only to completion. It therefore cannot expose P1-3/P1-4.

There is no declared/selected/consumed/oracle-equal corpus for common baselines or report startup, write, fsync, close, rename, readback, upload failure, custodian loss, intermediate crash, capability substitution, pidfd retirement, or bounded reap. Neither `_custodian_main()` nor `_custodian_worker()` is driven. This fails ADR 0092 section 9's mandatory production-path acceptance even independently of the live defects above.

### P2-1 — The readable-transition gate does not cover the required common/client control flow

The only common readability check (`test/native-qualification-common.test.ts:393-407`) enforces 160-character width and rejects one-line `try`/`with` nodes only at line 800 or later. It does not inspect earlier security transitions and does not inspect any of the six clients. Existing packed effects include `common.py:66`, `77`, `116`, `129`, and `195`. `test/outcome-two-portable.test.ts` applies its semicolon ban to closure/launcher and portable suites, not common or the six native clients.

This is not the AST/static common-and-all-six-clients transition gate required by ADR 0092 section 8.

## Positive observations

- The exact reviewed tree was clean before this report was created.
- A private frozen `OperationReceipt` is created only after the operation returns; replay/profile/settlement checks are present.
- `CleanupEvidence.values` returns a `MappingProxyType`, and publication checks the session nonce.
- Descriptor and process observers now use bounded repeated censuses and per-observation stat checks; these improvements do not close P1-2.
- Receipt-first named publication, anonymous report/slot/receipt objects, exact-head/code fields, worker preregistration, pidfds, and upload-before-cleanup workflow ordering are present.
- Eligibility and final jobs check out the exact PR head.
- Static Python AST/compile and `git diff --check c18b7f5..3846383` passed.
- Gross additions remain within ADR 0092 numeric highs: common `1250/1250`; trusted/portable listed subtotal plus fixtures `11167/14500`; native listed subtotal `4308/7500`; listed aggregate `15475/22000`.
- The focused TypeScript companion could not be rerun because `node_modules`/`tsx` is absent. No dependency or network acquisition was attempted. The portable hostile operation-binding probe above ran without native effects.

## Requirement disposition

| Area | Result | Reason |
| --- | --- | --- |
| Common operation receipt | **FAIL** | P1-1 permits receipt-divergent passing metadata. |
| Immutable cleanup evidence | **PASS static only** | Mapping proxy and nonce checks are present; overall authority remains blocked. |
| Stable baselines | **FAIL** | P1-2 does not identify close/reopen descriptor generations; mandatory race corpus is absent. |
| Durable report/upload | **FAIL** | P1-3 does not authenticate uploaded bytes or receipt generation. |
| Crash/replacement cleanup | **FAIL** | P1-4 has unrecoverable legal cuts and check-then-unlink/rmdir races. |
| Capability/custodian/reap | **FAIL** | P1-5 discloses the capability and leaves unbounded/unowned paths. |
| Portable acceptance/readability | **FAIL** | P1-6 and P2-1. |

# Final decision: BLOCKED

**NO SIGNOFF** for exact implementation head `3846383f0d88c190226356ca9aeeeda402943aaa`.

This review grants no native execution, workflow dispatch/rerun, artifact reliance, cloud/AWS action, production, release, issue closure, or later execution-ADR authority.
