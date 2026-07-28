# ADR 0093 fresh exact-head hostile signoff — common

**Disposition: BLOCKED — NO SIGNOFF**

**Exact implementation head reviewed:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`

**Accepted ADR commit:** `ce1f6f8`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Method:** fresh static/portable hostile review of common's immutable operation-derived reports, pre-effect source/schema caching, exact descriptor/process baselines, and custodian startup, durable publication/upload, capability, exchange, crash recovery, retirement, and reap behavior. No native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, AWS, OpenTofu, deployment, production, or release action was run. No implementation file was edited.

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 6 |
| P2 | 1 |
| P3 | 0 |

ADR 0093 requires no unresolved P0–P3. The findings below block common signoff.

## Findings

### P1-1 — The cleanup capability is still durable plaintext, and the disk authority can select its own authenticator

ADR 0093 requires cleanup to receive the capability over retained private authority and forbids placing it in recoverable receipt plaintext. `_authority()` instead serializes `"capability": capability.hex()` (`scripts/native-qualification/common.py:1113-1128`), and `_publish_transaction()` links those bytes under the durable name `.cleanup.capability` before publishing the report (`:1183-1187`). Independent cleanup recovers the capability by opening that file (`:1222-1244`) and sends the disclosed value back to the worker (`:1541-1548`).

Moving the raw value out of `.owner.json` did not make it private. The report directory and file are mode 0700/0600 for the same UID that runs the admitted client. After `NativeSession.publish()` returns, that caller can read the value. The authority file itself is not authenticated by any separately retained secret: it supplies the capability, capability digest, report digest/size, and custodian identity against which the HMAC receipt is checked. A same-UID caller can therefore replace the authority with a new capability, HMAC a matching receipt, and bind replacement report bytes/generation. If the new socket identity does not resolve, `cleanup_report()` takes its direct fallback and accepts this disk-selected authority.

This is the same substitute/self-authenticating authority class ADR 0093 section 4 expressly required the correction to remove.

### P1-2 — Cleanup authenticates post-upload pathname state, not the bytes and generation consumed by the upload

The `uploaded-report-intent` receipt is created before the workflow's upload action (`common.py:1131-1157`, `1175-1205`). The action receives only `/tmp/cogs-native-qualification-<job>/report.json`; no artifact digest, size, generation, or upload acknowledgement is returned to the custodian or supplied to `--cleanup`. Cleanup later reopens the pathname and compares its then-current bytes/generation to the pre-upload receipt (`:1273-1275`, `1341-1349`).

Consequently, temporarily exchanging `report.json` while `actions/upload-artifact` reads it and restoring the original generation before cleanup is not observable by common. The original inode can be renamed away and restored without changing the receipt's recorded file generation. Cleanup can pass while the artifact contains different bytes. Calling a pre-upload intent an uploaded receipt does not bind the upload effect required by ADR 0093 section 4.

### P1-3 — Descriptor baselines still cannot distinguish close/reopen replacement

`_descriptor_snapshot_once()` records descriptor number, underlying object stat fields, `st_rdev`, `F_GETFD`, and `F_GETFL` (`common.py:473-492`). Those are not an open-descriptor/open-file-description generation. Closing a baseline descriptor and reopening the same object at the same number with the same flags—for example `/dev/null`—produces the same row. Three equal censuses (`:468-472`, `495-498`) repeat the ambiguity rather than detect replacement.

The focused test only AST-checks that `_generation(after)` and the two flag names occur (`test/native-qualification-common.test.ts:279-283`); it has no production observer close/reopen oracle. ADR 0093 section 3's exact descriptor generation remains unproved and bypassable.

### P1-4 — Quarantine unlink and final directory removal retain the prohibited generation races

`_quarantine_verified()` verifies the quarantine name at `common.py:1300` and then unlinks that name at `:1301`. A same-UID exchange/replacement between those operations deletes the replacement rather than the verified generation. `_remove_report_directory()` similarly stats the retired name at `:1313-1314`, closes the retained directory descriptor at `:1315`, and then removes the pathname at `:1316`; a rename plus foreign empty replacement in that interval is deleted.

The initial `RENAME_NOREPLACE` quarantine/retirement steps improve crash classification, but they do not make the later name-based deletion generation-atomic. These are direct check-then-unlink/check-then-rmdir races, contrary to ADR 0093 section 4's retained-directory/generation requirement and its rule that foreign or replaced state must not be deleted.

### P1-5 — Secondary cleanup pidfd failure can report success without retiring or proving exit of the live custodian

After connecting to and authenticating the worker PID, `cleanup_report()` opens a secondary pidfd (`common.py:1532-1540`). Any `OSError` from that open is swallowed at `:1550-1551`. Because `pidfd` remains `None`, the fallback skips retirement at `:1555-1560`, deletes the transaction, and returns success at `:1561-1571`. Closing the connected endpoint may eventually make the worker fail and its supervisor reap it, but cleanup neither retains authority nor waits for/proves that outcome before success.

The portable oracle masks this defect: its secondary-pidfd fault explicitly sets the process to dead and reaped before raising `OSError` (`test/outcome-two-recovery-portable.py:583-591`). A real `pidfd_open()` failure does not imply either fact.

End-to-end authority is incomplete more generally. Startup retains the first-fork supervisor (`common.py:1066-1090`), while durable authority records only the second-fork worker (`:1126-1127`). On successful publication the client closes control but never explicitly retires/reaps the retained supervisor (`:977-985`); later cleanup can observe only the worker. This does not establish exact retirement/reap of the complete custodian tree.

### P1-6 — The mandatory common/custodian corpus omits most real cuts and does not model adversarial exchanges

The 20-row fixture covers a happy path, a few startup faults, five publication boundaries, two static substitutions, and selected retirement cases. It does not cut the complete production state machine at anonymous allocations, capability/report/receipt writes, every fsync, report readback/lseek, inventory verification, descriptor closes, worker socket allocation/bind/listen/accept/receive/send, authority/receipt reads, every quarantine rename/fsync/unlink, directory retirement/fsync/rmdir, or the success/failure supervisor-worker handoff and reap suffixes.

The modeled kernel's `fsync`, write/read, unlink, and rmdir paths have no fault injection, and only publication's report rename has a rename crash cut. The focused durable test replaces `_remove_report_directory` entirely and performs each cleanup only to completion (`test/native-qualification-common.test.ts:295-336`). It cannot expose P1-2/P1-4. The descriptor acceptance is token/AST coverage rather than a complete common observer state machine. The secondary-pidfd row's false death/reap premise additionally makes a real failing cut green.

Thus declared/selected/consumed/oracle equality is only equality over an incomplete and partly incorrect declaration, not ADR 0093 section 10's complete common/custodian production-path acceptance.

### P2-1 — Receipt-derived metadata is only shallowly immutable and is trusted separately from the frozen result

The operation result is recursively frozen, but `_derive_operation()` returns metadata rows wrapped only with `MappingProxyType(dict(row))`. A/B metadata still contains mutable nested lists and dictionaries. `_receipt_claims()` verifies the digest of `_result`, then independently thaws and trusts `_metadata` without rederiving it from `_result` or checking equality (`common.py:1646-1655`, `1687-1698`). Python name mangling is not an authority boundary; an admitted caller holding the session can reach and mutate those nested objects.

Most arbitrary mutations are rejected later by semantic validation, so this is not rated as a separate pass-forgery route. It nevertheless violates ADR 0093 section 2's exact immutable operation-derived report source and leaves caller mutation able to derail publication/custodian completion.

## Positive observations

- The exact reviewed tree was clean before this report was created.
- `WorkflowContext` now caches workflow/common/driver digests and stable schema bytes/digest before custodian effects; publication validation uses the cached schema bytes.
- Common recursively freezes the typed operation result, derives production checks internally, removes caller-supplied pass checks/metadata, and binds the result/source-set digests into reports.
- Process observations include PID, parent/group/session edges, start time, executable generation, and repeated recursive censuses.
- Custodian socketpair descriptors are adopted before later effects, both forked children are gated until pidfd ownership exists, and startup waits/reaps are bounded.
- Publication uses anonymous files, fsyncs, no-replace renames, report digest/size/generation, and an HMAC receipt. These improvements do not close P1-1/P1-2/P1-4.
- The portable recovery suite passed, and Python AST plus JSON/JSONL static parsing passed. Its green result is non-accepting for the reasons in P1-5/P1-6.
- `git diff --check ce1f6f8..0db8c26` passed. `node_modules` is absent, so focused TypeScript/AJV tests were not run; no dependency installation or network acquisition was attempted.
- Gross additions remain within the reviewed ADR 0093 highs: common `1771/1900`, workflow `318/400`, native schema `340/700`, schema registration `162/300`, common focused test `437/1500`, and recovery portable `947/1500`.

## Requirement disposition

| Area | Result | Reason |
| --- | --- | --- |
| Immutable operation-derived reports | **FAIL** | P2-1 leaves separately trusted shallow-mutable metadata. |
| Admitted source/schema caching | **PASS static** | Pre-effect digests and schema bytes are cached and used for publication. |
| Exact common baselines | **FAIL** | P1-3 cannot identify close/reopen descriptor replacement. |
| Custodian startup/preregistration | **PASS static, acceptance incomplete** | Gating/adoption improved; P1-6 omits mandatory cuts. |
| Durable upload binding | **FAIL** | P1-2 never authenticates the upload action's consumed bytes/generation. |
| Cleanup capability | **FAIL** | P1-1 persists the raw capability and lets disk state select its authenticator. |
| Exchange/crash recovery | **FAIL** | P1-4 retains deletion races; P1-6 omits cleanup crash suffixes. |
| Custodian retirement/reap | **FAIL** | P1-5 permits success without retained authority or proved retirement. |
| Complete portable common/custodian ledger | **FAIL** | P1-6's declaration is incomplete and one oracle assumes the desired result. |

# Final decision: BLOCKED

**NO SIGNOFF** for exact implementation head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`.

This review grants no native execution, sudo, workflow dispatch/rerun, artifact reliance, cloud/AWS/provider/OpenTofu/deployment action, production, release, issue closure, or later execution-ADR authority.
