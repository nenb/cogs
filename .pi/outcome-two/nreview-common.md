# Outcome 2 native common/workflow hostile review

**Reviewed tree:** `6d7d86401d96dfc9971fd9a4e0f784d0169cda62`  
**Method:** static/portable review only; no native selector was executed.  
**Scope:** native common API, report schema, exact-head/event workflow wiring, artifact publication, and all A–E/integration invocations.

## Findings

### P1 — Three required workflow invocations cannot enter their native/report mode

`.github/workflows/ci.yml:186,236,261` invokes every driver with `--workflow-bound`, but Job A accepts only `--native-fixed` (`job-a-runtime-mappings.py:151-152`) and Jobs C/D accept only `--native` (`job-c-descriptors.py:129-136`, `job-d-process-lifecycle.py:170-177`). A therefore exits before creating any report. C and D likewise exit before running, and even their alternate native entries print private partial reports to stdout rather than calling `WorkflowContext.from_environ`/`finalize_report`; they can never create the artifact paths uploaded at workflow lines 239 and 264. Consequently A, C, and D always fail, integration never becomes runnable, and no complete six-report exact-run evidence can exist.

**Exact fix:** standardize A, C, and D on the workflow's fixed `--workflow-bound` entry; wire C/D through `WorkflowContext.from_environ("C"/"D", __file__)` and `finalize_report` for pass and fail; emit the complete seven-key cleanup object and schema-compatible pass/fail checks; remove or make unreachable the incompatible private stdout report path; add a portable test that compares each YAML selector with the corresponding accepted entry and verifies every driver references the common report API without executing it.

### P1 — Disallowed event/attempt states fail open as skipped checks

All six jobs use a job-level `if` that is false for a fork PR or `run_attempt != 1` (`ci.yml:169,194,219,244,269,294`). GitHub skipped/neutral required checks can satisfy branch protection, so rerunning a failed attempt (or presenting an ineligible PR) can replace the intended fail-closed native gate with skipped jobs and no artifacts. `needs` does not repair this because integration is itself skipped by the same condition.

**Exact fix:** add an always-evaluated PR eligibility/gate job that explicitly fails unless the event is a same-repository `pull_request` at attempt 1; make the final required native check run with `always()` and fail unless eligibility and A–E all concluded `success`; keep native code unexecuted for ineligible events; require that final gate in branch protection. Add static workflow tests for attempt 2, fork PR, failed/skipped dependency, and successful same-repository attempt 1 semantics.

### P1 — A failed report close/fsync can still publish a pass-authority artifact

`common.py:210-218` writes directly to the final upload pathname before `fsync`, identity checks, and `close` complete. If any of those operations fails, the driver exits nonzero but the final path remains partial or can contain a canonical `result:"pass"` report. Every upload step runs under `always()`, so that file is still uploaded. This violates the rule that close/cleanup uncertainty prevents publication of a pass report.

**Exact fix:** stage report bytes at a non-upload path, fully write/fsync/validate/close it, then atomically publish to the absent final path; on every pre-publication failure, attempt exact staged-file cleanup and leave no final artifact. Treat publication/cleanup failures as terminal, and add portable injected short-write, fsync, fstat, close, collision, and cleanup-failure tests proving that no pass-authority final path remains.

### P2 — The tracked schema accepts semantically false authority reports

`native-qualification-report-v1alpha1.json:24,30-49,109-140` validates fields independently. It accepts a `result:"pass"` report with arbitrary/wrong check IDs, failed checks, false cleanup booleans, and non-null failure fields; `uniqueItems` also permits the same check ID once with each outcome. It does not enforce each job's exact ordered check inventory or head/checkout and event-envelope semantic bindings. The producer currently checks some of these in Python, but the schema is the portable artifact contract and an independent schema consumer will accept a contradictory authority report.

**Exact fix:** add job-conditioned exact check arrays (fixed cardinality/order/IDs), pass/fail coupling for outcomes, cleanup, `failure_phase`, and `diagnostics_sha256`, plus an independent semantic validator for cross-field identities JSON Schema cannot compare (at minimum checkout=head and the pull-request envelope relationships). Register a valid native sample and hostile mutations in the general schema validation suite. Do not compress this into the remaining line allowance: authorize raised schema/common/test highs in a new ADR first.

## Verified items

- The checked-out source is explicitly the same-repository PR head and is compared with `HEAD^{commit}` before each invocation; credentials and a dirty checkout are rejected.
- B, E, and integration use the YAML selector and common API; no workflow artifact is downloaded or used to link A–E state.
- Artifact action pins, names, run/attempt/head dimensions, `if-no-files-found:error`, and seven-day retention are fixed.
- Common report generation bounds metadata/diagnostics, emits canonical JSON, records head/envelope/workflow/runner/blob identities, and couples its own generated pass result to all checks and cleanup booleans.
- No native surface was executed during this review.

## Readable highs at the reviewed tree

All listed per-file highs are met. Gross additions from predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa` total **2,086 / 2,200** native lines. Notable limits: workflow **150 / 180**, schema **144 / 150**, common **219 / 220**; A **160 / 160**, B **180 / 180**, C **139 / 140**, D **180 / 180**, E **240 / 240**, integration **170 / 170**. Remediation that exceeds a file high requires a new ADR; aggregate margin is not transferable.

## Exact fix order

1. Repair A/C/D selector and common-report integration.
2. Make PR event/attempt eligibility and the final required gate fail closed rather than skipped.
3. Make report publication atomic and failure-clean.
4. Authorize readable headroom, then strengthen schema semantics and hostile portable tests.
5. Re-run static/portable review before any one authorized native attempt-1 observation.
