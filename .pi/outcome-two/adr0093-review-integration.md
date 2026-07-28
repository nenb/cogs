# ADR 0093 hostile signoff — thin integration and common/custodian

**Disposition: BLOCKED**

- **Exact implementation head reviewed:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Exact tree:** `b861aec6605837f669fc91d7c4aa1b31e596aafa`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** thin integration; exact ordinary owner/result/digests; duplicate-authority removal; common immutable receipt/report derivation; report custodian publication, recovery, and retirement; deterministic identities.
- **Method:** fresh hostile static and portable review at exact HEAD. No native selector/primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS operation was invoked. No production source was edited.

## P0–P3 verdict

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 3 | **blocking** |
| P2 | 0 | none additional |
| P3 | 0 | none additional |

ADR 0093 requires ten exact-head reviews with no unresolved P0–P3. This head is not eligible for signoff or later native-execution authority.

## Findings

### P1-1 — Common calls the ambient launcher API that ADR 0093 removed, so no real operation can reach the fixed bootstrap

**Requirements:** ADR 0093 sections 1, 2, and 10: the fixed trusted bootstrap is the sole operation issuer; common must retain its exact typed result; complete production state machines, rather than fabricated completed results, must be accepted.

`SystemCommonOps.run_fixed_operation()` authenticates held source/client bytes and compiles the held launcher, but then performs:

```python
invoke = getattr(module, "invoke_fixed_admitted_operation")
result = invoke(operation, context.head_sha, admitted_bytes, held[client_path].raw, digest)
```

at `scripts/native-qualification/common.py:438-441`. The exact launcher deliberately has no `invoke_fixed_admitted_operation` definition; its only production entry is `_bootstrap_main()` / `_bootstrap_with_ops()` at `completion_trusted_runtime_launcher.py:3461-3515`. The checked-in API note also states that the ambient function no longer exists.

A static exact-byte probe using common's own `_launcher()` produced:

```text
ambient_entry= False
fixed_cli= True
AttributeError ... has no attribute 'invoke_fixed_admitted_operation'
```

Consequently integration—and A through E—fails after source admission but before the ordinary owner, result, receipt, or report. The focused integration test does not detect this: its real-common seam intentionally raises from a fake `Ops.run_fixed_operation()`, while the common receipt test returns prebuilt result dictionaries and the launcher portable test exercises bootstrap owners separately. There is no accepting cross-file common-to-fixed-bootstrap production path.

**Required correction:** make common's separately authenticated source/client generations drive the fixed isolated launcher bootstrap ABI and retain its exact decoded typed result. Do not restore the removed ambient bytes/revision API or add a second operation owner. Add a portable accepting test that traverses `SystemCommonOps.run_fixed_operation()` through the real fixed bootstrap dispatcher and ordinary runtime owner above mocked primitives.

### P1-2 — The durable cleanup transaction writes its HMAC capability in recoverable plaintext and remains self-authorizing

**Requirements:** ADR 0093 section 4: the cleanup capability is never written in recoverable receipt plaintext; cleanup receives it over retained private authority and authenticates exact run/head/attempt/job, uploaded bytes, and custodian identity.

`_authority()` writes `"capability": capability.hex()` (`common.py:1113-1128`), and `_publish_transaction()` durably links those bytes as `.cleanup.capability` in the same report directory (`:1183-1187`). Recovery reopens that named file and returns the raw key (`:1222-1244`). The adjacent publication receipt's HMAC is keyed by that same recoverable value (`:1131-1157`, `:1247-1261`). Mode `0700` does not make the key private from another same-UID process, which is the relevant substitution boundary.

This is not cured by live peer checking. On connection failure, `cleanup_report()` uses the file-selected authority and key to authenticate the file-selected receipt, then directly calls `_cleanup_owned()` (`:1506-1520`, `:1532-1570`). A same-UID process can therefore choose a fresh capability, current directory/report generations, digest/size, run/head values, and a matching HMAC, force the endpoint fallback, and make the recovery path accept its self-consistent replacement state. The custodian fixture tests only corrupt report/receipt bytes without recomputing authority; the static assertion merely proves the raw key is absent from `_receipt()`, not that it is absent from recoverable storage.

**Required correction:** keep the raw cleanup capability solely in retained private process/descriptor authority. Durable public state may contain only a non-secret binding. Recovery after custodian loss must use an independently retained/authenticated grant rather than an adjacent plaintext key; otherwise it must preserve state and fail closed. Add capability disclosure, fully re-signed same-UID replacement, endpoint substitution/loss, and whole-directory replacement cases to the causal corpus.

### P1-3 — Cleanup still uses explicit check-then-unlink/rmdir name races and can delete a replacement generation

**Requirements:** ADR 0093 section 4: quarantine/exchange operations use retained directory and generation authority, preserve foreign/replaced state, and contain no check-then-unlink/rmdir race.

`_quarantine_verified()` checks the quarantine name's identity and then unlinks that name in a separate syscall (`common.py:1295-1302`). A same-UID process can exchange `.retired-report`, `.retired-owner`, or `.retired-capability` after the final `_identity_at()` and before `unlink()`, causing cleanup to remove a foreign generation. `_remove_report_directory()` repeats the defect at directory scope: it stats the retired name, closes the retained directory, and then calls `rmdir()` by name (`:1305-1319`), leaving a replacement window after generation validation.

The portable kernel serializes each modeled operation and has no exchange between the identity check and removal, so its crash-cut matrix cannot prove this race absent.

**Required correction:** remove by retained generation authority or use an atomic exchange/quarantine protocol whose final destructive operation cannot retarget a name after validation. Apply the same rule to directory retirement. Add adversarial exchanges at every final file unlink and directory rmdir cut, with a preservation oracle for the foreign generation.

## Confirmed properties

- `thin-integration.py` is genuinely thin: it calls only `session.run_fixed_operation("integration")`, does not inspect the returned ordinary result, and supplies only failure phase/diagnostic/error to common.
- The thin client contains no second source bootstrap, result decoder, digest constructor, native owner, sudo path, process supervisor, or report metadata authority.
- Once given a valid result dictionary, common freezes it, computes its canonical result digest, validates the exact ordered ordinary inventory/version/marker/head/source-set, requires every ordinary observation true, fixes both output digests, and deterministically derives metadata in `closure`, `gzip_output`, `source_set`, `zstd_output` order.
- Caller mutation of the dictionary returned by `run_fixed_operation()` does not mutate the frozen receipt. Report checks, metadata, operation result digest, and source-set digest come from the receipt rather than the thin client.
- Source, workflow, driver, common, and admitted schema bytes are cached before operation effects for report validation. Canonical JSON encoding is sorted and newline-terminated.
- No duplicate ordinary production owner was found. The blocking integration defect is that common never reaches the sole fixed bootstrap owner.

## Exact deterministic identities

Recomputed from exact HEAD:

- launcher SHA-256: `987d6080aad83c18783898df9338bd84febe165cf46912847d027c8eeb24852e`
- launcher Git-blob SHA-1: `e5d27b13a4a514f80e6e0b20c6ce3e12d36b32fe`
- four-source framed SHA-256: `dde990d2e7adde92be4ef63b1e72042cfdb64232a73a4361863c7ceae68935bc`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

These are review identities only and grant no execution authority.

## Verification

Passed:

- `git diff --check HEAD^..HEAD`
- `git diff --check 3846383..HEAD`
- Python AST parsing for common, thin integration, and trusted launcher
- `node --test --experimental-strip-types test/native-qualification-integration.test.ts` — 1/1
- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py`
- `/usr/bin/python3 -I -B test/outcome-two-recovery-portable.py`
- exact-byte missing-entry probe — reproduced P1-1

Unavailable:

- `test/native-qualification-common.test.ts` could not load `ajv/dist/2020.js` in the clean workspace. No dependency or network acquisition was attempted. In the combined invocation, the independent integration test still passed.

Not run:

- No native, sudo, workflow, provider, cloud, or AWS operation.

# Final verdict: BLOCKED

Exact head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` retains three P1 failures: common cannot invoke the sole production bootstrap, cleanup authority is recoverably self-signed, and destructive cleanup remains name-racy. Do not sign off ADR 0093, name this head in a native-execution ADR, invoke native selectors, dispatch/rerun the workflow, rely on artifacts, or authorize cloud/AWS/production/release/issue-closure activity.
