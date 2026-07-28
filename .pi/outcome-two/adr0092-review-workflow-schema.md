# ADR 0092 exact-head hostile review — workflow, schema, and six-client semantics

- **Reviewed implementation:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** CI eligibility/exact-head/dependency/upload-cleanup/final wiring; native report schema and independent A–E/integration semantics/mutations; real CLI exit behavior
- **Method:** static and portable-only hostile review. No `--workflow-bound` invocation, native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS action was run. No implementation file was edited.
- **Verdict:** **BLOCKED**

## P0–P3 verdict

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | None found |
| P1 | 2 | **Blocking** |
| P2 | 0 | None found |
| P3 | 0 | None found |

ADR 0092 requires no unresolved P0–P3 before native execution can even be proposed. The findings below therefore deny signoff for the reviewed head.

## Findings

### P1-1 — Common still publishes caller-fabricated pass checks for four operation profiles

**Requirements:** ADR 0092 sections 3, 5, 9, and 10; operation-bound publication and independent six-job semantic mutations.

`NativeSession` now retains an immutable result receipt, but publication does not independently derive or validate all job facts from it. At `scripts/native-qualification/common.py:1174-1202`, `_bind_candidate()` merely requires every caller-supplied check to be `"pass"`. Its A branch binds only objects and summary digests (`1183-1187`), B binds only tool/parser metadata (`1188-1190`), E binds only the policy digest (`1191-1193`), and integration binds only four digest rows (`1194-1197`). None of those branches rejects false or missing operation-result booleans. Only the metadata-free C/D branch examines all non-identity observations (`1198-1200`). `publish()` then turns the caller strings into pass authority at lines `1203-1231`.

A portable fake-ops session returned a receipt containing the exact E policy digest but `pid_one: false`. After the caller supplied all-pass E checks and matching policy metadata, common schema/semantic validation accepted and published:

```text
PASS authority published from operation receipt with pid_one=false
```

The same class of bypass exists for A's mapping/reap facts, B's complete runtime facts, and integration's complete ordinary-runtime facts. The checked-in clients currently reject such results, but ADR 0092 explicitly requires common to reject caller-fabricated claims and to recompute or independently bind them to the exact receipt. An admitted-client regression or substitution can therefore convert a failed exact production observation into a valid pass artifact.

The portable acceptance suite misses this boundary. `test/native-qualification-common.test.ts:203-249` exercises only C and tests one false C receipt. The separate A/B/E/integration client tests prove each helper in isolation, not common's receipt-to-publication authority, so the required independent six-profile mutation proof is absent.

**Required correction:** have common validate the exact closed result inventory, identities, booleans, metadata formulas, and check derivations for every profile (or invoke separately admitted pure validators), then add one receipt-level false/missing/substituted-result mutation per A–E/integration proving publication rejects.

### P1-2 — The mandatory workflow acceptance is still line/token inspection, not parsed dependency/dispatch semantics

**Requirement:** ADR 0092 section 9 and `AT91-WF-01`.

The checked-in YAML is statically well-shaped: eligibility, A–E, integration, and required-final all check out `github.event.pull_request.head.sha`; A–E need Quality and eligibility; integration needs eligibility plus A–E; uploads precede `always()` cleanup; and the final `always()` job names all dependency, upload, and cleanup outcomes.

The mandatory acceptance does not prove that wiring. `parsedJobs()` at `test/native-qualification-common.test.ts:125-142` is a line-oriented regular-expression splitter, not a YAML parser. The workflow test at lines `338-393` does not inspect any `needs` array, does not assert `if: always()` on each cleanup, and does not connect parsed final-job environment expressions to the independently constructed `finalKeys` passed directly to the Python CLI. Removing an A–E dependency, removing an upload/cleanup output expression, or making cleanup success-conditional can leave the direct helper matrix green. Its native sentinel calls `common._main(["--eligibility"])` directly rather than evaluating workflow event/job selection.

Thus the source currently looks correct, but ADR 0092's required parsed workflow dispatch proof—exact head, ineligible no-native behavior, every failed/skipped/cancelled dependency, and upload/cleanup/final linkage—has not been supplied. This is a binding acceptance gate, not optional test polish.

**Required correction:** parse the workflow as YAML; assert the exact job graph, checkout ref, selectors, outputs, upload-before-`always()`-cleanup conditions, and final `needs`/environment expressions; evaluate eligible and ineligible dispatch cases with a native-call sentinel; and derive the final mutation matrix from the parsed dependency/output inventory rather than a second hard-coded list.

## Positive verification

- The tracked native report schema discriminates all six job IDs, exact ordered check inventories, pass/fail coupling, cleanup, failure fields, metadata shapes, B mask `63`, E's fixed policy digest, and integration's fixed output digests.
- Common independent report semantics reject A role/digest and summary substitutions, B closure/parser/tool substitutions, E policy substitution, and integration fixed-output substitution.
- Static workflow inspection found exact PR-head checkout on eligibility, A–E, integration, and required-final; fixed same-repository attempt-one eligibility; literal `--workflow-bound`; no A–E artifact download by integration; fixed upload paths; upload-before-cleanup order; explicit outputs; and an `always()` final job.
- Real invalid-selector CLI invocations of common and all six clients each exited `1` without reaching native code. Source inspection and the added real-`__main__` success harnesses show `SystemExit` is now outside `except Exception`, preserving successful exit `0`.
- Scoped `git diff --check` passed. Gross additions from the accepted predecessor remain within the reviewed ADR 0092 highs for workflow, schema, common, clients, tests, and schema registration.
- `node_modules` was absent, so focused TypeScript/AJV commands were not rerun. No dependency installation or network access was attempted. Python AST/static inspection and the portable fake-ops counterexample required no native operation.

## Final decision

**BLOCKED — NO SIGNOFF.** Exact-head workflow source and artifact schema are substantially corrected, and CLI exits are repaired, but common still permits caller-fabricated pass authority for A/B/E/integration and the mandatory parsed workflow acceptance remains unimplemented. Head `3846383f0d88c190226356ca9aeeeda402943aaa` is not eligible for native execution authority, workflow dispatch/rerun, artifact reliance, cloud/AWS action, production, release, or issue closure.
