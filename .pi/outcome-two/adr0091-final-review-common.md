# ADR 0091 final hostile review — common/report/schema/workflow

**Disposition: BLOCKED**

**Exact implementation head reviewed:** `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Correction start:** accepted ADR commit `964dffe`

**Method:** fresh static/portable review only. No `--workflow-bound` selector, native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS action was run.

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 5 |
| P2 | 0 |
| P3 | 0 |

ADR 0091 requires no unresolved P0–P3. The findings below block common/workflow/schema signoff and any proposal for native authority.

## Findings

### P1-1 — The common API can publish a pass without calling a production operation

**Requirements:** cross-job common API binding; `AT91-BASE-01`, `AT91-SCHEMA-01`; ADR 0091 sections 2.1, 3, and 9.

`scripts/native-qualification/common.py:684-690` marks and invokes an operation but retains neither its closed result nor a success/failure terminal state. `ReportCandidate` remains caller-created check strings and metadata (`common.py:347-350`), while `publish()` checks only that settlement exists and publication is unused (`common.py:709-736`). It does not require `_operation_used`, does not require the operation to have returned successfully, and cannot bind candidate checks/metadata to the returned typed observation.

A portable scripted session was able to call `settle_native_phase()` immediately, submit all-pass C checks with empty metadata, and publish a schema/semantic-valid pass report while its `run_fixed_operation` seam was defined to raise if called. Output:

```text
PASS report published with run_fixed_operation never called
```

The checked-in drivers currently call the operation, but the shared authority is still claim-based and does not fail closed against skipped, failed-then-replaced, or copied observations. That is not an operation-bound common state machine.

### P1-2 — The report custodian is not the required durable identity-bound crash/upload transaction

**Requirement:** `AT91-REPORT-01`.

The implemented durable states contradict the accepted state machine:

- `.report.stage` is created as a named file at `common.py:563-566`; the receipt is not created until `580-585`. A crash in between leaves a nonempty receipt-less directory, although the receipt must be the first named intent.
- Publication uses neither anonymous `O_TMPFILE` generations nor the required receipt-bound `.cleanup.slot`. The receipt at `574-578` records only context, nonce/socket, digest, and size—not report/slot/directory identities or common/driver/workflow/schema generations.
- Post-upload cleanup compares pathname metadata and then directly unlinks `report.json` (`601-607`). Replacement after `_name_matches()` and before `unlink()` deletes the replacement. There is no `RENAME_EXCHANGE` capture/recheck/reverse path.
- Error cleanup repeats the same check-then-unlink race for stage/final/receipt (`627-634`). Thus mismatch preservation is not guaranteed on failure either.
- `cleanup_report()` merely reads a receipt pathname and connects to the still-live abstract socket (`638-665`). It has no D1–D5/C1–C3 classifier and cannot recover a custodian crash or lost socket from durable receipt-bound identities.

This fails short/interrupted/crash recovery, retained generation authority across upload, custodian-loss recovery, replacement preservation, and exact cleanup aggregation. Upload success/failure ordering in YAML cannot repair this missing transaction.

### P1-3 — Common baseline snapshots are not exact/stable observations

**Requirement:** `AT91-BASE-01`.

The shared observer does derive booleans rather than accepting cleanup booleans, and it watches the correct `/tmp/cogs-o2-runtime-v1` and per-job report directory. It does not, however, implement the required exact state observations:

- `_descriptor_snapshot()` lists once and then performs `F_GETFD`, `F_GETFL`, and one `fstat` per number (`common.py:267-284`). There is no before/after generation check or second stable enumeration, so close/reuse/change during observation can be recorded as a coherent baseline.
- `_children()` performs one breadth-first read (`295-311`). It has no stable recursive census and does not revalidate PID/start/executable around each edge. A descendant created after its parent was scanned, or PID identity drift between `/proc/<pid>/stat` and `/proc/<pid>/exe`, can be missed.
- `settle_native_phase()` treats one such returned mapping as authoritative equality (`698-707`); it has no state transition proving stable observations.

Consequently all seven booleans are common-derived but are not all derived from the exact baselines ADR 0091 requires. A leaked/racing descendant or descriptor can evade the purported restoration proof.

### P1-4 — Independent semantics accept prohibited A and integration substitutions

**Requirement:** `AT91-SCHEMA-01` and ADR 0091 section 2.6.

`_normalize_objects()` rejects duplicate `(sha256, size)` tuples but does not reject one digest appearing under conflicting roles when sizes differ (`common.py:408-420`). A portable report with the same SHA-256 as executable size 11 and loader size 12, with recomputed summaries, passed `_validate()`:

```text
A pass accepted one SHA-256 under executable and loader roles with different sizes
```

That directly violates the required “no digest with conflicting role” A invariant.

Independent semantics are implemented only for passing A and B (`common.py:443-459`). E and integration rely on structural schema alone. Two unrelated valid SHA-256 values were accepted as E policy digests, and two unrelated integration metadata sets—including arbitrary gzip/zstd output digests—were both accepted by `_validate()`:

```text
common._validate accepted two unrelated E policy digests and two unrelated integration digest sets
```

At minimum integration's output rows must be bound independently to the fixed marker digest; valid-digest substitution cannot be accepted as exact ordinary-result metadata.

### P1-5 — Mandatory REPORT/SCHEMA/WF acceptance remains token/helper coverage, not state-machine proof

**Requirements:** `AT91-REPORT-01`, `AT91-SCHEMA-01`, `AT91-WF-01`, and the explicit no-token-only rule.

`test/native-qualification-common.test.ts:149-209` uses a tiny fake `Ops`, a fake `Cust`, isolated helper patches, and literal source-token assertions. It never drives `_custodian_main()` or `cleanup_report()`, has no durable state inventory, no crash restart, no upload-failure path, no unlink/fsync/rename before-vs-after uncertainty, and no declared/selected/consumed/oracle case-set equality. `test/outcome-two-recovery-portable.py` exercises launcher recovery owners, not the native report custodian.

The schema registration at `scripts/validate-schemas.ts:231-246` checks only six synthetic pass/fail pairs, reversed checks, mask 15, and one oversize object. The common companion adds only five generic structural mutations and five A/B relation mutations. It does not supply the required isolated source/envelope/job/result/failure/each-cleanup and complete job-specific metadata mutant corpus.

The workflow companion extracts YAML blocks by string slicing and checks substrings/regex (`native-qualification-common.test.ts:211-226`). It calls the two predicate functions directly rather than parsing YAML and exercising CLI dispatch with a sentinel proving native functions unreachable. Therefore the actual YAML-to-dispatch state machine, exact upload/cleanup wiring, and no-native-call property are not oracle-proved as `AT91-WF-01` requires.

## Requirement disposition

| Requirement | Result | Reason |
| --- | --- | --- |
| `AT91-BASE-01` | **FAIL** | Common derives booleans, but fd/process baselines are not stable/exact and the common report API does not require a completed production operation. |
| `AT91-REPORT-01` | **FAIL** | Receipt ordering, durable identities, crash recovery, exchange capture, replacement preservation, and the mandatory fault matrix are absent. |
| `AT91-SCHEMA-01` | **FAIL** | Independent semantics accept conflicting-role and integration substitutions; isolated six-job mutation coverage is incomplete. |
| `AT91-WF-01` | **FAIL** | Static YAML wiring appears ordered and fail-closed, but mandatory parsed dispatch/no-native state-machine proof is replaced by text matching. |

## Positive observations and verification

- Exact reviewed tree was clean before this report was created.
- Workflow uses literal `--workflow-bound`, same-repository attempt-one predicates, individually named final results, upload before `always()` cleanup, and an `always()` final job.
- B schema/common semantics require seal mask `63` and the fixed marker output digest.
- Common, not callers, constructs the seven cleanup booleans and watches `/tmp/cogs-o2-runtime-v1` plus the real report directory.
- Portable Python suites passed: runtime closure, mapped closure, lifecycle, recovery, runtime report, and trusted launcher.
- Python AST parsing passed for all seven `scripts/native-qualification/*.py` files.
- `git diff --check 964dffe..a3f529a` passed.
- Gross additions are within accepted highs: trusted/portable `9,308 / 10,790`; native `3,329 / 5,400`; listed aggregate `12,637 / 16,250`. Common is exactly `750 / 750`; launcher is exactly `2,600 / 2,600`.
- Focused TypeScript tests, schema command, and typecheck could not be rerun because `node_modules` is absent. No network/dependency acquisition was attempted. This does not cure the static and portable counterexamples above.

## Final decision

**BLOCKED — NO SIGNOFF.**

The exact implementation head `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08` has unresolved P1 findings in every requested common acceptance area. It is not eligible for native execution authority, workflow dispatch/rerun, artifact reliance, cloud/AWS action, production, release, or issue closure.
