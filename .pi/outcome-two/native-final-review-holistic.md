# ADR 0087–0090 native qualification final holistic review

- **Implementation head reviewed:** `ea6e74fe709e02061e13be78922da13a8cf6f748`
- **Review mode:** fresh hostile static/portable exact-head review; no native selector, sudo, namespace, mount, seccomp, `map_files`, compression qualification, cloud, provider, or workflow execution
- **Scope:** ADR 0087–0090 workflow/common/schema, trusted parser/closure/launcher seams, Jobs A–E, thin integration, publication/cleanup, and focused portable/static tests
- **Disposition:** **BLOCKED**

## Method

I verified `HEAD` and the clean starting worktree, read ADRs 0087–0090 and the complete native composition, traced each workflow invocation through `WorkflowContext`, report publication, each job, the admitted launcher modes, closure ownership, and final result gate, and checked gross additions against the ADR 0090 highs. I also ran all seven Python trusted-closure portable suites; all passed. `py_compile` passed for the parser, closure, launcher, common, A–E, and integration scripts. Focused TypeScript companions could not be run because this checkout has no installed `tsx` package; no dependency installation or network access was attempted. `git diff --check` passed for both the ADR 0090 correction range and the complete Outcome 2 implementation range.

The native subtotal is 3,811/4,000 gross added physical lines and the reviewed files remain within their individual ADR 0090 highs. This supplies no acceptance credit for the findings below.

## Findings

### P1-1 — Job E is both unreachable on the declared runner and is not the independent sandbox primitive it reports

The workflow checkout is runner-owned. Job E deliberately crosses `sudo` and requires root in `--production-root` (`scripts/native-qualification/job-e-sandbox.py:219,324`), then root opens that checkout as fd 4 (`:341`). The admitted launcher rejects unless the fd-4 directory owner equals the launcher's effective UID (`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1866`). In Job E that effective UID is 0 while the GitHub checkout remains owned by the runner account, so the fixed route fails at source-root admission before any sandbox observation. The portable E test checks only source tokens and a fabricated production result and never composes this ownership predicate.

Even if that mismatch were fixed, E sends `cogs.runtime-source-admission/v1` (`job-e-sandbox.py:176-182`). That mode enters the complete `_coordinate_with_ops` closure, gzip, and zstd transaction (`completion_trusted_runtime_launcher.py:1873-1879`), not a sandbox-probe entry. No `launch_fixed_sandbox_probe()` exists. E therefore repeats and depends on A/B/integration work instead of independently qualifying only root/namespace/capability/seccomp/cleanup primitives as ADRs 0087 and 0090 require.

### P1-2 — Jobs A, C, and D qualify substitute coordinators rather than the accepted production owners

Job A's new admission value selects `_coordinate_admitted_mapping_only`. That function manually calls closure-private `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, `_stop_helper`, and `_close_objects` behind a separate `_MappingAuthority` (`completion_trusted_runtime_launcher.py:1563-1616`). It never enters the admitted `PreparedRuntimeClosure` constructor used by the runtime worker (`:1637-1643`). This is the exact private-mechanism composition ADR 0090 required A to remove, relocated into the launcher and selected by caller-provided admission version.

Jobs C and D import only `common.py`; they implement their own raw `close_range`/dup/limit and PDEATHSIG/pidfd/session/tree supervisors (`job-c-descriptors.py:7,77-210`; `job-d-process-lifecycle.py:72-319`). They never call the closure `_Ops.close_range` or launcher `_ProcessOwner` production primitives. A pass consequently demonstrates job-local replicas, not the production mechanisms claimed by ADR 0090. D also races its own evidence: `_wait()` revalidates identity through `/proc/<pid>/exe` before collecting an already-terminated process (`job-d-process-lifecycle.py:56-63,115-126`), so a normal zombie transition can turn an otherwise valid case into an environment/scheduling-dependent failure.

The nominal public closure constructor still only rejects (`completion_trusted_runtime_closure.py:2095-2097`), and neither required launcher entry `launch_fixed_runtime_qualification` nor `launch_fixed_sandbox_probe` is present. The three admission versions are therefore undeclared substitute APIs rather than thin callers of the fixed production APIs.

### P1-3 — A/B pass reports do not truthfully bind the native facts they advertise

Production reports the required executable seal mask as `_EXEC_SEALS == 63`. Job B verifies 63 and then deliberately rewrites it to 15 before publication (`job-b-compression.py:284-294`); the schema requires the substituted 15 (`schemas/native-qualification-report-v1alpha1.json:145-153`). Thus a passing artifact does not contain the exact observed seal profile. B also accepts any two equal output digests (`job-b-compression.py:295`) rather than comparing both to the fixed decompressed marker digest, unlike thin integration.

Job A copies arbitrary 64-hex `closure_sha256` and `mapping_sha256` values from its result into the report (`job-a-runtime-mappings.py:254-257`). Neither A nor common recomputes either digest from the published object rows. Common's A semantics only count roles and uniqueness (`common.py:222-226`); they do not enforce ordered dependencies/providers or bind either summary digest. A substituted summary therefore remains a schema-valid, semantic-valid pass-authority artifact.

These are authority-data defects, not merely missing test assertions: the Job B companion explicitly expects the 63-to-15 rewrite, and the common fixture is also built around mask 15.

### P1-4 — Cleanup and deterministic publication are not established by one exact common transaction

ADR 0090 assigns common baseline capture and exact report-path ownership to `common.py`, but each job implements a different snapshot. A/B/C/D use `os.listdir()` over `/proc/self/fd` (`job-a-runtime-mappings.py:42-55`, `job-b-compression.py:62-75`, `job-c-descriptors.py:22-32`, `job-d-process-lifecycle.py:19-29`) rather than bounded `getdents64` through the exact enumerator fd. That can include the runtime's transient directory duplicate and does not meet the required complete-fd proof.

The path baselines are also aimed at objects production does not use. E and integration observe `/run/cogs-o2-runtime-v1` (`job-e-sandbox.py:372-375`; `thin-integration.py:286-289`), while the launcher owns `/tmp/cogs-o2-runtime-v1` (`completion_trusted_runtime_launcher.py:25,1673`). C checks the obsolete flat `/tmp/cogs-native-qualification-C.json` (`job-c-descriptors.py:57`) while common publishes beneath `/tmp/cogs-native-qualification-C/report.json` (`common.py:237-239`). These jobs can set `cleanup.paths=true` without independently observing the actual production/report roots.

Finally, post-upload cleanup reopens whichever directory and report currently occupy the fixed names and `_remove_owned()` unlinks both names without comparing the directory/report generation to the generation returned by publication (`common.py:252-277,368-390`). The validated generation is not carried across the upload step. Replacement or inability to prove identity can therefore be converted into successful deletion and a restored-looking baseline, contrary to identity-bound one-shot publication/cleanup.

### P2-1 — Portable/static coverage validates the substitutions instead of the cross-file contracts

The Python closure suites pass, but the native companions are primarily source-token checks or scripted completed observations. They do not compose E's root-owned bootstrap with the runner-owned checkout, require A/C/D to enter production owners, recompute A's report digests, challenge B's fixed output digest, or point cleanup at the launcher's actual root. The B test explicitly asserts that observed mask 63 becomes reported mask 15. The common publication test exercises only an unopposed happy-path create/remove and cannot detect cross-step generation substitution.

The missing local `tsx` installation prevented executing these TypeScript companions in this worktree, but the defects above are statically present and are also encoded in their fixtures/assertions; installing dependencies would not resolve them.

## P0/P3 disposition

- **P0:** none identified independently of the blocking P1 defects.
- **P3:** none.

## Required correction before signoff

1. Make Job E's admitted source topology compatible with the declared sudo envelope and route it through a real fixed sandbox-only production entry that performs no closure discovery or compression.
2. Make A, C, and D call the actual admitted production owners/primitives; remove caller-selected substitute coordinators and job-local replicas from qualification authority.
3. Publish the exact observed seal mask and fixed output digest, and recompute/validate A closure and mapping summaries from the artifact rows.
4. Centralize exact bounded fd/child/path/mount/namespace/limit/checkout baselines in common code, observe `/tmp/cogs-o2-runtime-v1`, and carry identity-bound report-directory/report generations through post-upload cleanup.
5. Add portable cross-file tests for those real compositions and hostile replacement/fault cuts without invoking a native selector.

# Final decision: **BLOCKED**

`ea6e74fe709e02061e13be78922da13a8cf6f748` is not eligible for native execution authority, A–E/integration evidence reliance, or ADR 0087–0090 signoff while P1-1 through P1-4 and P2-1 remain unresolved.
