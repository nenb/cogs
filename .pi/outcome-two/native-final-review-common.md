# Outcome 2 native common/workflow/schema exact-head signoff review

- **Reviewed implementation:** `ea6e74fe709e02061e13be78922da13a8cf6f748`
- **Scope:** `scripts/native-qualification/common.py`, `schemas/native-qualification-report-v1alpha1.json`, `.github/workflows/ci.yml`, `test/native-qualification-common.test.ts`, and their A–E/integration report-contract interactions
- **Verdict:** **BLOCKED**

## Methods

- Confirmed the worktree began clean at the exact reviewed SHA and inspected the exact blobs and correction history from predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Read ADRs 0087–0090, the ADR index, the native design, and the first native hostile-review records.
- Traced workflow eligibility, exact selector/environment construction, all six driver/report paths, upload/cleanup sequencing, final `always()` result, schema branches, common schema/semantic validation, publication, and cleanup.
- Inspected A–E/integration producers where needed to compare report metadata and cleanup contracts.
- Ran one non-native, effect-free production-validator probe. It showed that `common._validate()` accepts an A pass with loader before executable, a 512 MiB executable, duplicate unresolved `needed` entries, and unrelated summary digests.
- Attempted `npx tsx --test test/native-qualification-common.test.ts` and `npm run schemas`; neither could run because this review checkout has no installed dependencies (`ajv`/`tsx` absent). No dependency installation or network access was attempted.
- Did not execute `--workflow-bound`, any native selector, sudo, namespace/mount/seccomp/`map_files` operation, cloud operation, or provider operation. No implementation file was modified.

## Findings

### P1 — Report recovery has no retained generation authority and can delete an unowned replacement

`common.py:252-280` implements `_remove_owned()` by unconditionally unlinking `.report.tmp` and `report.json` through a directory reopened or retained by name. It receives no expected file generation and performs no identity comparison at unlink. `cleanup_report()` validates `report.json` at `common.py:374-383`, closes it, and then calls that unconditional remover at lines 385-390, leaving a replacement window; even a replacement already detected as an error is subsequently unlinked. The publication exception path can similarly reopen the directory by pathname at lines 350-355 and remove whatever names now occupy it.

Crash recovery is also incomplete. If the driver dies after creating the directory or staged file but before publishing `report.json`, the workflow's `always()` cleanup enters `cleanup_report()`, attempts to open only `report.json` before its error-aggregation block, and cannot remove/authenticate the staged transaction (`common.py:368-375`). A pre-publication crash can therefore strand `.report.tmp` and the private directory rather than restore the report-path baseline.

This violates ADR 0090 sections 3 and 5: cleanup must be identity-bound to the exact published generation, preserve foreign/replaced state as uncertainty, and recover staged/publication cuts. A disposable runner and a failing final check do not substitute for exact recovery.

### P1 — Common does not own or bind the cleanup observations it publishes

ADR 0090 requires common code to capture the seven common baselines before the first job effect and to derive each cleanup value from the corresponding before/after observation. At this head, `WorkflowContext.from_environ()` checks only the report-directory absence, while `finalize_report()` accepts a caller-provided `Mapping[str, bool]` and couples pass solely to those booleans (`common.py:287-304`). There is no common baseline object, one-shot observation lease, or proof that the supplied values came from the admitted pre-effect state.

The six drivers instead carry separate, divergent snapshot implementations and hand their booleans to common. Consequently a driver regression or substitute caller can submit seven `true` values and common will publish pass authority; common cannot distinguish observed restoration from a prefilled claim. This leaves the exact cleanup/result coupling mandated for the shared API unenforced at the publication boundary.

### P1 — The discriminated metadata contract accepts and emits semantically false A/B evidence

The B producer requires the actual production result's seal mask to be `63`, then rewrites it to `15` before reporting (`job-b-compression.py:281-294`). The schema fixes `seal_mask` to `15` (`native-qualification-report-v1alpha1.json:142-155`), and the common test golden also fixes `15` (`native-qualification-common.test.ts:60-63`). The artifact therefore discards `F_SEAL_FUTURE_WRITE` and `F_SEAL_EXEC` from the exact six-seal production observation while claiming `gzip_sealed_exec`/`zstd_sealed_exec` pass. That contradicts ADR 0087's exact seal profile and ADR 0090's requirement that B bind the exact seal mask.

A is also not semantically closed. The schema permits each object up to 536,870,912 bytes rather than the fixed 134,217,728-byte object bound, does not require unique `needed` entries or provider closure, and only counts one executable/loader anywhere in the array (`schema:112-140`). Common's independent semantics checks counts and ID/digest uniqueness but not executable/loader/library order, dependency uniqueness/providers, size bound, or digest relationships (`common.py:221-226`). The production-validator probe described above was accepted. Thus schema validity plus common semantic validity does not discriminate the exact A authority being published.

### P1 — The mandatory portable acceptance gate is largely static-token coverage and misses the hostile production paths

`test/native-qualification-common.test.ts` does not implement ADR 0090 section 9's acceptance matrix:

- workflow coverage at lines 94-121 searches strings but does not model attempt 2, fork PR, push, malformed event fields, or failed/cancelled/skipped dependency conclusions;
- schema coverage at lines 124-152 exercises AJV with a small shared mutation set, but does not pass all six goldens and isolated metadata/source-envelope mutants through production `_validate_schema` and `_validate_semantics`;
- publication coverage at lines 154-170 executes only one C happy path and then checks for token names in source; it injects none of the required short/interrupted write, fsync, fstat, before/after close, fd reuse, reopen/read, schema/semantic divergence, canonical drift, collision, directory-fsync, staged unlink, post-upload replacement, upload-failure, or crash/recovery cuts; and
- `scripts/validate-schemas.ts` auto-compiles the schema but has no native valid sample per job or native hostile mutation corpus.

This is not merely missing test polish: ADR 0090 makes those portable/static cases a prerequisite to exact-head hostile signoff, and the untested production paths contain the P1 defects above.

## Verified boundaries

- The six workflow declarations use the literal `--workflow-bound` selector and construct the exact allowlisted driver environment with `/usr/bin/env -i`; incompatible native selectors are absent from the reviewed driver dispatches.
- Eligibility is always evaluated and explicitly fails non-PR, fork, malformed, or later-attempt contexts; A–E depend on eligibility and Quality, integration depends on A–E, and the final `always()` job requires eight successful dependencies.
- Upload paths are fixed per job, integration downloads no A–E artifacts, and cleanup steps participate in aggregate job success.
- Report fields remain metadata-only; no raw diagnostics, paths, descriptors, PIDs, maps, credentials, or generated bytes are placed in the artifact value.
- Reviewed native additions remain within ADR 0090's listed per-file and 4,000-line subtotal highs; `git diff --check` reported no scoped whitespace defect.

## Signoff

**BLOCKED.** The exact reviewed implementation has unresolved P1 findings in publication recovery/ownership, cleanup-proof coupling, A/B semantic discrimination, and mandatory portable production coverage. It must not receive native execution authority or artifact reliance until those findings are corrected and a fresh exact-head hostile review is clean through P3.
