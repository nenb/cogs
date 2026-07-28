# ADR 0093 exact-head hostile review — workflow, schema, and six-client semantics

- **Reviewed implementation:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** parsed CI exact-head eligibility/dependencies/upload-cleanup/final wiring; native report schema and independent A–E/integration semantics; real CLI exit behavior
- **Method:** static and portable-only hostile review. No `--workflow-bound` production operation, native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS action was run. No implementation file was edited.
- **Verdict:** **BLOCKED**

## P0–P3 verdict

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | None found |
| P1 | 2 | **Blocking** |
| P2 | 0 | None found |
| P3 | 0 | None found |

ADR 0093 requires no unresolved P0–P3 before native execution may be proposed. These findings deny signoff for the reviewed head.

## Findings

### P1-1 — Post-upload cleanup still has the forbidden check-then-unlink/rmdir race and publishes its generation-bearing intent too late

**Requirements:** ADR 0092 sections 4 and 9; ADR 0093 decisions 4 and 10.

`_quarantine_verified()` captures and checks a pathname generation, but then directly calls `os.unlink(quarantine, dir_fd=...)` after the final check (`scripts/native-qualification/common.py:1278-1302`). A same-UID replacement can occur after line 1300 and before line 1301, causing cleanup to delete the foreign replacement. The quarantine rename uses `RENAME_NOREPLACE` (`flags == 1`), not an exchange/capture operation that preserves the exact object through deletion. `_remove_report_directory()` repeats the defect: it checks the retired directory generation, closes retained directory authority, and then removes the predictable pathname (`common.py:1305-1317`), leaving a replacement window before `rmdir`.

A portable mocked interleaving returned the expected generation from the final pre-unlink observation, replaced the quarantine entry immediately afterward, and observed the foreign generation passed to `unlink`:

```text
counterexample: foreign replacement was unlinked
```

The checked-in helper test cannot expose this race. Its mocked `_identity_at` and `unlink` execute over one uninterrupted state and merely assert that already-classified states become empty (`test/native-qualification-common.test.ts:296-347`). It has no between-check-and-unlink or between-check-and-rmdir replacement cut, despite claiming every cleanup cut.

The required durable ordering is also inverted. `_publish_transaction()` links `.report.stage`, renames it to `report.json`, and only then creates and links `.owner.json` containing `report_generation` (`common.py:1175-1201`). The earlier `.cleanup.capability` record has digest and size but no report generation (`common.py:1113-1129`). Thus the generation-bearing durable intent is not present before the first staged named effect, contrary to the retained ADR 0092 ordering and ADR 0093's generation-bound durable-intent requirement.

**Required correction:** durably establish the complete authenticated intent before staging/publishing; capture names with the specified retained exchange/quarantine authority; eliminate the final pathname check-to-`unlink` and check-to-`rmdir` windows; and add causal replacement cuts at each boundary proving foreign state is preserved.

### P1-2 — Ineligible workflow contexts skip eligibility, and the parsed test never proves no native dispatch

**Requirements:** ADR 0090 section 2; ADR 0092 sections 8–9; ADR 0093 decision 9.

The eligibility job has a job-level predicate (`.github/workflows/ci.yml:166-168`). On a fork PR, push, malformed/missing PR context, or attempt 2, GitHub marks this job `skipped`; it never executes the non-native eligibility CLI. This directly contradicts the retained requirement that eligibility be always evaluated and explicitly fail rather than represent ineligibility as a skipped conclusion (`docs/adr/0090-correct-first-native-implementation-review.md:56-67`). The final job will reject the skip, but that does not turn the eligibility conclusion itself into the required explicit failed gate.

The new YAML parser test codifies the wrong shape by requiring that job-level predicate (`test/native-qualification-common.test.ts:349-353`). Its dependency simulation is a local `needs.every(result === "success")` function, not dispatch of the parsed workflow (`lines 383-390`). Invalid eligibility environments are then sent only to `common.py` (`lines 391-411`), while the six effect-sentinel invocations always call each client with the eligible `--workflow-bound` selector and assert that native selection **is reached** (`lines 413-418`). No case couples a parsed ineligible event/attempt or failed/skipped/cancelled eligibility conclusion to a real client entry and proves the sentinel remains untouched. The mandatory “no native call in ineligible contexts” acceptance remains absent.

**Required correction:** make eligibility an always-evaluated non-native failed gate, retain final rejection of every non-success conclusion, and drive eligible/ineligible parsed dispatch cases so the six real client entry points reach effect sentinels only in the eligible case.

## Positive verification

- Parsed static inspection found exact PR-head checkout refs on eligibility, A–E, integration, and required-final; A–E depend on Quality plus eligibility; integration depends on eligibility plus all five independent jobs and downloads no A–E artifacts; upload precedes `always()` cleanup; and required-final inventories every job, upload, and cleanup result.
- Static schema/common inspection found the six job/workflow discriminators, exact ordered check inventories, pass/fail coupling, seven cleanup fields, operation digests, fixed B seal mask, fixed E policy digest, fixed integration outputs, and independent semantic relationship checks. No separate P0–P3 schema or six-job report-semantics finding was identified.
- All six actual client `__main__` paths exited `0` under a non-native fake common/session success boundary. Every incompatible client selector exited `1` before common/native effects. The actual common `__main__` eligibility and final-result paths exited `0` for exact success environments and `1` for invalid environments. `SystemExit(0)` remains outside `except Exception` in common and all clients.
- Python AST parsing and scoped `git diff --check` passed. Gross additions remain within the reviewed ADR 0093 workflow/schema/common/client/common-test highs.
- Focused TypeScript/AJV and `npm run schemas` commands could not execute because this clean review worktree has no installed `tsx`/`node_modules`. No dependency installation or network action was attempted. This limitation does not affect the static violations or the portable cleanup counterexample above.

## Final decision

**BLOCKED — NO SIGNOFF.** Exact head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` retains two unresolved P1 defects: cleanup can delete replaced foreign state and lacks correctly ordered generation-bearing intent, while ineligible workflow contexts skip the required eligibility gate and the parsed acceptance does not prove no native dispatch. This head is not eligible for native execution authority, workflow dispatch/rerun, artifact reliance, cloud/AWS action, production, release, or issue closure.
