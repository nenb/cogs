# Outcome 2 native A/B hostile review

- Review ID: `O2-NREVIEW-AB`
- Exact reviewed implementation head: `6d7d86401d96dfc9971fd9a4e0f784d0169cda62`
- Scope: Jobs A and B production composition, workflow/common report integration, cleanup, schema, portable/static coverage, and ADR 0089 highs
- Native execution: **not performed**; no native selector, workflow, `map_files`, compression executable, namespace, mount, seccomp, sudo, cloud, or deployment route was invoked
- Verdict: **BLOCKED**

## Findings

### P1-1 — Workflow Job A cannot enter its real mode

`.github/workflows/ci.yml:186` invokes `job-a-runtime-mappings.py --workflow-bound`, but `scripts/native-qualification/job-a-runtime-mappings.py:151-152` accepts only `--native-fixed`. Every real Job A run exits at argument validation before `WorkflowContext`, production closure composition, or report creation; the unconditional artifact upload then also has no file. `test/native-qualification-a.test.ts` checks rejected selectors and the self-test but never asserts that the literal workflow selector reaches the real entry.

### P1-2 — Job B composes the production launcher with host preconditions the workflow cannot satisfy

`job-b-compression.py:83-110` opens the ordinary actions checkout and launches the production bootstrap unprivileged. The bootstrap requires fd 4's checkout root to be root-owned (`completion_trusted_runtime_launcher.py:1860-1861`), whereas `actions/checkout` is runner-owned and the B workflow performs no trusted materialization or ownership transition. Even if that admission mismatch were bypassed, `_RootOwner.prepare()` creates `/run/cogs-o2-runtime-v1` before entering a user namespace (`:24`, `:1034-1048`), which the unprivileged workflow account cannot create. Thus B's nominal `--workflow-bound` mode is real code, but it is structurally unable to reach gzip/zstd qualification on the declared runner. The portable B test replaces `NativeAdapter` and cannot expose either production precondition.

### P1-3 — A/B publish cleanup facts they did not establish, and every report leaves an uncleaned path

Job A observes only fd and direct-child baselines (`job-a-runtime-mappings.py:81-113`) and Job B's outer adapter observes only fd/direct-child restoration, yet both pass `dict.fromkeys(CLEANUP_KEYS, True)` (`A:128-138`, `B:168-169`) for paths, mounts, namespaces, limits, and checkout. Neither workflow performs a post-run HEAD/porcelain check. `common.finalize_report()` then creates `/tmp/cogs-native-qualification-<job>.json` (`common.py:210-219`); the upload steps have no identity-bound post-upload unlink/residue check, including when upload fails. Consequently `cleanup.paths=true` and `cleanup.checkout=true` are not exact observations, and the completion requirement of no file/checkout residue is not proved.

### P2-1 — The tracked report schema is not the common API's exact semantic contract

`schemas/native-qualification-report-v1alpha1.json:31-49` permits generic 7–17 checks and independently nullable failure fields. It accepts wrong per-job IDs/order, contradictory pass/fail versus checks/cleanup, and a failed report missing either phase or diagnostic digest. `common.py:179` likewise requires only *one* of phase/diagnostics on failure, despite the contract requiring both, and `finalize_report()` never applies the tracked schema. The four-field metadata row also cannot represent Job A's required SONAME/ordered dependencies or Job B's source/sealed digest, seal-mask, and mapping metadata. The one common test validates only a generated golden plus an extra-property mutation, so these divergences remain green.

## Exact fix list

1. Make Job A's sole real selector and the literal workflow invocation identical (`--workflow-bound`), and add a no-effects static seam proving that exact selector dispatches to `_native_fixed` rather than executing it.
2. Redesign Job B admission/state-root composition for the unprivileged hosted workflow: pass generation-bound exact-head held source authority into the production bootstrap and use an authenticated runner-owned private root that can enter the user/mount transaction. Do not merely weaken root ownership or add sudo (B is not authorized to use sudo). Add portable production-entry tests for runner-owned checkout admission and private-root preparation.
3. Capture and compare the exact applicable cleanup baselines in A/B, including post-run checkout HEAD/porcelain; derive each cleanup boolean from those observations. Add an identity-bound post-upload report cleanup and independent absence check on success and failure, with final job enforcement.
4. Close the schema with job-discriminated exact check arrays and pass/fail/failure-field coupling; require both failure phase and diagnostic digest on failure; run the tracked schema from the producer or a genuinely independent validator; extend the mutation corpus. Add the specified A/B object/seal/mapping metadata or explicitly amend the accepted report contract before running.
5. Preserve every ADR 0089 per-file/subtotal high. Current relevant accounting is workflow `150/180`, schema `144/150`, common `219/220`, A `160/160`, B `180/180`, common test `120/120`, A test `67/70`, B test `69/70`, and native subtotal `2086/2200`; production launcher is already `1900/1900`. Stop for a new ADR before adding a surface, crossing a high, or changing the source/root authority model without accepted architecture.

## Static/portable verification

- Exact initial head: **PASS**.
- Seven isolated Outcome 2 Python portable suites: **PASS**.
- AST parse of common, A, B, ELF, closure, and launcher modules: **PASS**.
- `git diff --check 6d7d864^ 6d7d864`: **PASS**.
- TypeScript/AJV companions: **not run** because locked `node_modules` is absent.
- Native selectors: **not run**.

No P0 or P3 finding.

NREVIEW COMPLETE
