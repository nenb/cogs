# Outcome 2 native holistic hostile review

- **Exact reviewed head:** `6d7d86401d96dfc9971fd9a4e0f784d0169cda62`
- **Scope:** A–E parallelism, portable/native ownership, workflow/common/production API integration, real-mode reachability, cleanup, report/schema contract, and ADR 0089 highs
- **Native execution:** **not performed**; no native selector, sudo, namespace, mount, seccomp, `map_files`, or integration route was executed
- **Verdict:** **BLOCKED**

## Findings

### P0-1 — Three workflow jobs can never invoke their native mode or produce the uploaded report

Every declaration invokes its driver with `--workflow-bound` (`.github/workflows/ci.yml:186,236,261`). Job A accepts only `--self-test` or `--native-fixed` (`job-a-runtime-mappings.py:145-154`); Jobs C and D accept only `--native` (`job-c-descriptors.py:129-136`, `job-d-process-lifecycle.py:170-177`). C and D also never load `common.py`, call `WorkflowContext.from_environ`/`finalize_report`, or create `/tmp/cogs-native-qualification-{C,D}.json`; they print an incompatible ad-hoc value to stdout. Thus A, C, and D fail before qualification, their exact artifact uploads fail, and `native-closure-integration` can never become runnable. The green static tests do not compare workflow argv with each driver's accepted argv or artifact path.

### P0-2 — Job B's fixed production bootstrap rejects the runner-owned checkout

Job B directly starts the launcher as the unprivileged runner (`job-b-compression.py:95-120`) and passes the checkout as fd 4. The launcher requires that fd to name a root-owned directory (`completion_trusted_runtime_launcher.py:1858-1861`). A GitHub checkout is runner-owned; unlike `thin-integration.py:38-55`, B creates no admitted user-namespace mapping before exec. Its real mode therefore reaches `fixed checkout root authority` and fails on the intended runner.

### P1-1 — Native jobs bypass or duplicate the accepted production owners

ADR 0087 specifies `prepare_fixed_runtime_closure()`, `launch_fixed_runtime_qualification()`, and `launch_fixed_sandbox_probe()` as the fixed production API. At this head the closure's nominal public constructor only rejects (`completion_trusted_runtime_closure.py:2095-2098`), and the two launcher entry points do not exist. Job A composes private `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, and `_stop_helper`; C and D implement separate descriptor and process supervisors; E reimplements root creation, mount setup, user/PID/network namespaces, process ownership, and rollback before calling private `_enter_boundary` (`job-e-sandbox.py:114-179`). This does not qualify the accepted production entry points and duplicates security/lifecycle logic already owned by the closure/launcher.

The duplicated paths are not execution-safe on failure: C can fork before `pidfd_open` registers the child, D can fork parent/descendant before `_register`, and E/integration use blocking `read`, `waitpid(..., 0)`, and sudo/subprocess calls without an operation deadline (`job-e-sandbox.py:99-112,140-164,183-205`; `thin-integration.py:56-111`). A failed primitive can leave an unowned process or wait until the workflow timeout rather than the required bounded, identity-held cleanup.

### P1-2 — Success reports assert cleanup that was never measured, and publication can retain a pass artifact after report failure

A, B, E, and integration pass `True` for all seven cleanup domains (`job-a-runtime-mappings.py:128-137`, `job-b-compression.py:168-169`, `job-e-sandbox.py:230-231`, `thin-integration.py:162-163`). A does not measure checkout, path, mount, namespace, or limit restoration; B does not measure all of those domains either. These are asserted facts, not exact baselines.

`finalize_report()` opens the final artifact path before write/fsync/close (`common.py:210-218`). A short write or close failure leaves a partial report or an already complete `result:"pass"` file at the exact path; the driver's outer handler returns failure, but the workflow's `always()` upload still publishes that file. This violates the rule that report-close/cleanup failure can produce only a fail report and never a pass artifact.

### P1-3 — The schema cannot validate the claimed job evidence

The schema allows any 7–17 unique check objects for any job and does not couple `job`, exact ordered IDs, `result`, failure fields, or cleanup outcomes. Its single generic metadata shape also cannot encode Job A's required SONAME/ordered-`DT_NEEDED` metadata or Job B's source/sealed hashes, seal mask, and mapping digest. Accordingly an A report carrying E check IDs, or a schema-valid pass with failed cleanup/non-null failure data, is accepted by AJV. `common.py` adds some producer-side checks, but the artifact schema is not an independent strict validator of the authority it labels.

### P2-1 — Numeric highs pass, but required corrections have no readable room

The native subtotal is `2,086/2,200`; workflow addition is `150/180`. However A, B, D, E, integration, common-test, and D-test are at their per-file highs, while C/common are only one line below. The production launcher is exactly `1,900/1,900` and remains cap-packed (193 lines over 120 columns and 28 inline `try` bodies). ADR 0089 requires ordinary readable formatting and a new ADR before a file/high/API/job/cleanup contract changes. The P0/P1 repairs cannot be hidden by further packing or moved into workflow/tests.

### P3 — None beyond the blocking findings above

## Exact fix list

1. Adopt a new measured ADR before implementation: preserve the A–E parallel DAG, raise only demonstrated readable highs, and explicitly settle the production API/envelope changes.
2. Give all six workflow drivers one literal workflow-bound ABI; make A–E and integration use `WorkflowContext` and the common canonical artifact path. Add a portable cross-file test that invokes each workflow argv under scripted operations and requires the exact artifact/schema result.
3. Make B enter the authenticated fixed bootstrap envelope that satisfies checkout authority without weakening root/source policy or copying integration bootstrap logic.
4. Restore/implement the accepted fixed production closure, qualification, and sandbox-probe entry points. Have A/B/E/integration call them; move C/D's reusable fd/process behavior into the production owner and delete duplicate native supervisors/root construction.
5. Register pidfd, start-time, gate, descriptors, roots, and namespace authority before release; cover every post-effect cut; replace raw-PID and blocking waits with one monotonic deadline and exact reap/cleanup.
6. Measure every reported cleanup domain (or encode an explicit schema-defined non-applicable outcome). Never synthesize all-true cleanup.
7. Publish through an identity-held private temporary: complete write/readback/fsync/close first, then atomically expose only a validated report. On any report/close failure, ensure no pass target exists; validate the exact file before upload.
8. Make the schema conditional per job with exact ordered check IDs, result/failure/cleanup coupling, and job-specific metadata, including A dependency metadata and B source/sealed/seal/mapping facts. Validate it independently in the driver/workflow.
9. Reformat and remeasure every changed production/native surface, rerun ordinary portable/static gates, then obtain a fresh exact-head hostile review before any native selector execution.

## Portable verification

- Seven direct isolated Outcome 2 Python portable suites: **PASS**.
- Targeted native companion plus Outcome 2 TypeScript tests: **22/22 PASS**; these passes are non-accepting because they omit the cross-file ABI and semantic artifact cases above.
- AST/JSON parsing and focused native-surface `git diff --check`: **PASS**.

NREVIEW COMPLETE
