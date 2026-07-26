# ADR 0050: Authorize narrow Stage 2 post-candidate corrections and one final candidate

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Acceptance authority: Nick Byrne, or the delegated project lead acting under Nick Byrne's standing bounded-local delegation.
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing instruction to continue bounded local qualification, make required project decisions, and stop before AWS.
- Acceptance record: [GitHub pull request #219](https://github.com/nenb/cogs/pull/219), after corrected independent hostile review reported no P0–P3 findings. This acceptance grants only C1–C4 and the operationally selected one further non-authoritative candidate described below.

## Context

ADRs 0048 and 0049 authorized exactly one further non-authoritative Phase A candidate after the D1–D3 rootfs, structural-counter, evidence-v2, and test-portability work passed their retained gates. They required an immediate stop and explicit replan after that candidate for every outcome. They prohibited treating a failed candidate as authority for a retry, timeout increase, Phase B, a later stage, production, or cloud work.

That authorization was consumed by GitHub Actions run [30180567797](https://github.com/nenb/cogs/actions/runs/30180567797), `run_attempt: 1`, at exact clean pull-request head `0017ac2ec441301a252363b2b9ee90db65fda41e` (`0017ac2`). Its artifact was `stage2-phase-a-candidate-v2-30180567797-1`. The canonical unchanged sanitized report is retained at [`docs/test-reports/stage-2-phase-a-candidate-30180567797.canonical-json`](../test-reports/stage-2-phase-a-candidate-30180567797.canonical-json): exactly **3,255 bytes**, SHA-256 `d54c4c08dc3388f7d25426cc3294fed483f8c14438d1daa942053f26816f637e`. It passed validation against exact source-head v2 schema blob `ec607ad3c67721c418cbaed1f08bf579533a663e`; C3 must not rewrite it or require these historical bytes to satisfy the corrected live-v2 contract. It remains candidate-only evidence, not qualification publication or authority.

The retained JSON records:

- `authority: candidate`, `qualified: false`, and a null rootfs result;
- passed KVM, source, platform, and root preconditions;
- first-build work `failure/not-started` after **23,665 ms**;
- first inline cleanup and every later rootfs phase—second-build work and cleanup, equality, pin, post-verification, and settlement—blocked;
- one later recovery attempt succeeding in **4 ms**;
- an empty `runtime_assets` array with the stage-unfaithful `checks.runtime_assets: fail` summary;
- false runtime, network, SSH, and coordinator claims, not blocked phase rows; and
- `checks.cleanup: pass` and `checks.residue: pass` summaries.

The immutable workflow run and mandatory-stop record separately record report validation/upload, export cleanup, and independent post-export residue outcomes. The retained JSON does not contain those workflow-only fields. Neither evidence source supplies rootfs, Phase B, runtime, campaign, production, cloud, or issue-closure authority.

The [durable candidate diagnosis and mandatory-stop record](https://github.com/nenb/cogs/issues/42#issuecomment-5081194954) localizes the failure, and its independent defensive review found no P0–P3 defect in that localization. `_acquire_lock` captured a chain containing the pre-ledger `rootfs-v1` directory generation. `_new_active_ledger` created `.cogs-stage2-rootfs-ledger-v1`, proved the one-name parent delta, and changed the directory's full generation. The caller then constructed and validated a fresh chain but discarded it; after `genesis-settled`, `_begin_operation_unmasked` revalidated stale pre-ledger `locked.chain`. Exact validation correctly rejected obsolete caller authority before operation intent, operation-directory creation, or materialization.

The structural counters corroborate that boundary. First-build counters were `record_reference_copies: 0`, `byte_names_returned: 3435`, `parent_snapshots: 11`, `complete_legal_record_folds: 8`, `complete_filesystem_walks: 0`, and `incrementally_advanced_ledger_records: 3`. The three records are exactly `genesis-settled`, recovery `genesis-abort`, and recovery `retired`; eleven snapshots and zero walks locate the failure before the next operation snapshot. The later recovery reported only `byte_names_returned: 18`, with every other counter zero. Those counters corroborate control flow; the successful recovery result together with exact sentinel-and-lock and residue observations supplies idle-baseline authority.

Acquisition of all 16 fixed cache objects, their post-verification, the exact cache snapshot, and durable `cache-owned` state necessarily completed before first-build setup. The v2 renderer nevertheless derives `artifact_cache: fail` from the absent final rootfs result. Runtime assets are ordered after successful rootfs settlement and were not attempted, but are rendered as failure rather than prerequisite-blocked. This is fail-closed but stage-unfaithful presentation, not fixture-expiry or external-drift evidence.

The same exact-head pull request produced CI run `30180567774`. Its [durable issue comment](https://github.com/nenb/cogs/issues/42#issuecomment-5081197801) records two separate findings: the ledger TypeScript wrapper exhausted a fixed 30-second subprocess budget under parallel CI load, and a Linux hostile test demonstrated that initial mutable partial-asset identity can accept a replacement after immediate `(dev, ino)` reuse. The focused ledger suite passed independently. The cleanup finding did not cause run `30180567797`, whose runtime-asset stage was never selected.

The consumed candidate remains failed and non-authoritative. Passing rollback, cleanup, residue, and evidence export cannot promote it. No correction or rerun is available under ADR 0048; this proposed ADR is the required new decision.

### Required implementation baseline

C1–C4 may be implemented only on exact source head `0017ac2ec441301a252363b2b9ee90db65fda41e` or on a reviewed descendant whose Phase A and rootfs baseline is byte-equivalent before the C1–C4 patch. If the relevant runner, v2 schema, rootfs builder/build modules, ownership journal, or named tests differ for any other reason, stop and perform an explicit rebase and replan before implementation. A numerically similar or behaviorally inferred baseline is insufficient.

## Decision

If this ADR receives the accepted-by record required above, authorize **only** C1–C4. C1–C3 are narrow production/evidence corrections. C4 is one exact excluded test-wrapper correction. The fixed `asset-partial-final-owned` record authorized by C2 is the sole exception to the prohibition on a new transaction format; no other record, state, or transaction extension is authorized.

### C1: return an exact delta-derived post-ledger chain

`_new_active_ledger` must return `ActiveLedger` and a newly constructed `LockedState` whose `.chain` is exactly `_chain_after_parent(state_chain, before_snapshot.generation, after_snapshot.generation)`, whose `.state` is exactly that returned chain's final component node, and whose `.lock` is the already held lock. The returned state and original state share only their already owned descriptors; the original `LockedState` is immediately obsolete and is never used or closed independently. The caller must replace its local `locked` authority with the returned `LockedState` **before** appending `genesis-settled`. No `object.__setattr__` or other in-place authority mutation is permitted.

From ledger creation through durable `operation-create-intent` and the operation-create parent-delta transition, no `_state_chain` call, pathname recapture, generic refresh-on-mismatch, or adoption of live state may substitute for that returned generation. This transition-limited prohibition removes the discarded line-804 recapture. It does not remove pre-existing `_state_chain` observations at later, separately authorized lifecycle boundaries after operation establishment; those calls must be seeded from the rebound `LockedState` and retain all existing checks. An unexpected mismatch still fails closed and enters exact recovery.

C1 changes no chain component, full-generation field, `_revalidate_chain` rule, within-snapshot equality, `_parent_delta` rule, ledger record/hash/offset, append or `fsync` boundary, no-follow traversal, ownership rule, cleanup poisoning, uncertainty behavior, or genesis recovery transition.

Delete **only** the `original_new_ledger`/`new_ledger` wrapper and `builder._new_active_ledger = new_ledger` assignment in `test/aws-stage2-completion-rootfs-materializer.py`. Preserve that helper's unrelated Docker-only workspace-anchor, mount/device-policy, xattr, and other functional-policy adaptations. Docker remains non-authoritative and cannot satisfy C1's native-Linux regression.

Add a native-Linux checkpoint immediately after durable `operation-create-intent` and before operation-directory creation. From operation-establishment entry through that checkpoint, the current route must report exactly:

- **3** parent snapshots;
- **2** incrementally advanced records (`genesis-settled`, `operation-create-intent`); and
- **0** complete filesystem walks.

At that checkpoint the retained state-chain generation must equal the exact ledger-create post-generation. These are exact assertions, not lower bounds or merely values different from the failed run's 11/3/0 trace. If a reviewed implementation necessarily changes any checkpoint count, stop and review a named exact replacement before candidate authority.

Fault cuts before and after ledger creation, `genesis-settled`, rebound-authority return, the next chain proof, and operation intent must prove that a fresh owner either completes genesis-only recovery to the exact sentinel-and-lock baseline or preserves uncertainty without mutation.

### C2: durable final-generation ownership for partial runtime assets

Authorize exactly one new ownership-journal state, `asset-partial-final-owned`. It is legal only after the matching `asset-partial-owned`, for the same fixed component and fixed name, before cleanup, and before any sealed `asset-final-owned` state. Its body contains only that component, fixed name, and the final generation defined below. It does not claim successful download, digest verification, sealing, or publication.

For C2, a full final generation is exactly:

- `mount_id`, `dev`, `ino`, and regular-file `kind`;
- `mode`, `uid`, `gid`, `nlink`, and `size`; and
- `mtime_ns` and `ctime_ns`.

Every field must compare exactly. Equal-full-generation privileged ABA remains outside the inherited `PRIVILEGED_MUTATOR_EXCLUSION`; C2 makes no claim beyond that accepted threat boundary.

The only legal transition to `asset-partial-final-owned` is:

1. stop all non-cleanup mutation of the partial asset;
2. `fsync` the writable descriptor;
3. while it remains open, acquire a retained no-follow identity descriptor and prove exact continuity between writable, retained, and named authorities;
4. close the writable descriptor successfully;
5. through the retained descriptor, obtain stable held/name no-follow observations and prove one exact full final generation with the expected fixed name, regular-file type, and ownership constraints;
6. append the matching `asset-partial-final-owned` record, `fsync` the ownership journal, and read back the exact record and journal binding; and
7. only then permit scalar cleanup of that name, after a fresh no-follow reopen and exact full-generation revalidation.

`asset-partial-owned`, create-time identity, `(mount_id, dev, ino)` equality, plan membership, expected bytes, pathname, or containment is never deletion authority. A partial record without the matching durable final record must preserve the name. Cleanup may not select the first partial record, infer ownership, or upgrade it from observations.

A failure after linking the partial and final names but before removing the partial has `nlink == 2`. Preserve **both** names and report uncertainty; `asset-partial-final-owned` cannot authorize either unlink in that two-name state. A second scalar unlink transition is outside C2.

Any uncertainty before unlink—including mutation, `fsync`, writable close, held/name proof, journal append/sync/readback, reopen, full-generation comparison, timeout, cancellation, replacement, or descriptor error—prohibits unlink and preserves the name. Any error after unlink must be aggregated and reported as uncertainty; it cannot be described as preservation or undone. Immediate cleanup errors may not be swallowed or replaced by later success and must remain visible in the cleanup summary. Independently safe cleanup may continue only for the fixed asset, cache, rootfs, and evidence owners already named by the runner; no broad deletion is authorized.

The observe process must place a fixed categorical immediate-cleanup outcome in the existing observation diagnostics before `observation-owned` is appended. The later cleanup summary may report prior immediate-cleanup success only after exact readback of that owned observation. A missing or malformed owned observation, a retained `asset-partial-final-owned` record with an absent name but no durable successful immediate-cleanup outcome, or any cut after unlink and before that observation-owned durability boundary is cleanup uncertainty. Later absence or a later exact cleanup success cannot infer or replace the missing outcome. This uses the existing observation diagnostics and `observation-owned` route and authorizes no second ownership-journal state or kind.

C2 tests must include:

- deterministic hostile seam/model cases that force equal `(mount_id, dev, ino)` while independently drifting each of `kind`, `mode`, `uid`, `gid`, `nlink`, `size`, `mtime_ns`, and `ctime_ns` at every transition cut named above;
- separate mismatch cases for `mount_id`, `dev`, and `ino`;
- native-Linux no-follow same-name replacement using real descriptors and names;
- the two-name/nlink-2 preservation state;
- missing or malformed `observation-owned`, absent-name-with-retained-final-record, and every cut after unlink but before durable owned-observation readback, all yielding cleanup uncertainty; and
- every pre-unlink preservation and post-unlink uncertainty-reporting boundary.

A bounded real inode-reuse canary may supplement these gates, but cannot be their sole mandatory evidence unless its filesystem and bounded reuse procedure are fixed and proved. Reuse luck is not a test primitive.

### C3: exact stage-faithful Phase A v2 evidence

Add one required v2-only `stage_evidence` object with `additionalProperties: false` and exactly two required rows: `artifact_cache` and `runtime_assets`. Each row has exactly:

- `status`: `success`, `failure`, `blocked`, or `not-reached`; and
- `elapsed_ms`: an integer from 0 through **3,300,000**, measured monotonically for attempted `success` or `failure`; `blocked` and `not-reached` require zero.

`checks.artifact_cache` and `checks.runtime_assets` remain summaries with this exact mapping:

| Stage status | Summary check |
| --- | --- |
| `success` | `pass` |
| `failure` | `fail` |
| `blocked` | `blocked` |
| `not-reached` | `unknown` |

A missing, malformed, or unavailable stage fact also maps only its summary to `unknown`; it does not synthesize a stage status. Because `stage_evidence` is required, a canonical report with an unavailable row must fail final schema validation and export rather than fabricate `success`, `failure`, `blocked`, or `not-reached`.

Cache `success` is derived independently from verification of all 16 fixed objects, the exact cache snapshot, and successful append, `fsync`, and readback of `cache-owned`; it is never derived from rootfs. Cache `failure` means that cache stage was selected and attempted but did not complete that boundary. Cache `blocked` means a resolved earlier prerequisite prohibited selection. Cache `not-reached` means the bounded observer ended before selection without a resolved blocking prerequisite.

Runtime-asset `success` or `failure` is legal only after successful rootfs settlement and runtime-asset stage selection. Runtime `blocked` is required when failed or uncertain rootfs settlement prohibits asset-directory intent; `runtime_assets` must then be empty and elapsed zero. Runtime `not-reached` means the observer ended before runtime selection and before a resolved prerequisite failure; its array is also empty and elapsed zero.

The only allowed cache/runtime causal combinations are:

| `artifact_cache` | Allowed `runtime_assets` |
| --- | --- |
| `success` | `success`, `failure`, `blocked`, or `not-reached` |
| `failure` | `blocked` |
| `blocked` | `blocked` |
| `not-reached` | `not-reached` |

Add one required v2-only scalar `first_build_setup` with exactly this enum and trusted transition model:

- `not-reached`: before rootfs setup is selected;
- `fixed-input`: from rootfs setup selection until the runner has completed contract verification, acquisition and post-verification, the exact cache snapshot, and append, `fsync`, and durable readback of `cache-owned`;
- `rootfs-bootstrap`: from that runner `cache-owned` boundary until rootfs bootstrap and durable lifecycle ownership complete;
- `operation-establishment`: beginning before `_build_once_unmasked` performs its independent `plan.load_verified_build_inputs()` revalidation and including any failure in that repeated load or in `_begin_operation`, until `_begin_operation` returns an exact owned operation;
- `materializer-dispatch`: after exact operation ownership returns and before `_materialize` has entered; and
- `complete`: once `_materialize` work has entered.

The runner's initial fixed-input authority and `_build_once_unmasked`'s independent repeated load are distinct boundaries; a failure in the latter is always `operation-establishment`, not `fixed-input` or `rootfs-bootstrap`. The value advances only at these trusted boundaries and never from exception text, counters, paths, identities, or attacker-controlled data. Run `30180567797` maps to `operation-establishment`, but the retained historical report remains byte-for-byte unchanged and is not retroactively rewritten.

Validate and render rootfs phases, each stage-evidence row, `first_build_setup`, observation diagnostics, cleanup, residue, and summary checks in independent bounded branches. A malformed unrelated field may produce only its own fixed diagnostic or `unknown` summary; it cannot overwrite already validated phases, stage facts, setup state, recovery evidence, or cleanup evidence. If a required stage fact itself cannot be established, report production fails closed as above.

C3 does not restore or modify a v1 runner. `schemas/stage2-phase-a-candidate-v1.json` remains byte-for-byte identical to Git blob `1f16fa0966de9ff2117734dd188c7ffd641ccacf`, SHA-256 `7fb0d1e29f3e3789dcfc4a17e5f753fd7ad88c227f04d15c8003d870d4b72286`, and retains `$id` `https://cogs.invalid/schemas/stage2-phase-a-candidate-v1.json`. C3 changes only the live v2 runner/schema and v2 tests. It makes no live v1 renderer, state, export, or differential-runner claim.

### C4: one exact test-wrapper timeout

In `test/aws-stage2-completion-rootfs-ledger.test.ts`, change only the timeout on its sole `spawnSync("python3", [testPath], ...)` invocation from 30 seconds to exactly `60_000` milliseconds. No other 30-second wrapper, test workload, Python control, production deadline, workflow budget, retry, or invocation is authorized to change.

Static verification must prove the exact timeout, exactly one child invocation, and fail-closed handling of timeout, signal, null status, and nonzero status. That one invocation must pass once on the reviewed CI run. No synthetic or nondeterministic claim that CI was measurably contended is required.

## Verification before candidate selection

C1–C4 must be integrated on the required baseline at one exact revision and receive clean portable, hostile, schema, native-Linux, fault, counter, and ownership review. All ordinary repository checks must pass. Review must explicitly confirm:

1. delta-derived returned C1 authority, exact 3/2/0 checkpoint, unchanged validation, exact genesis recovery, and deletion of only the named Docker wrapper;
2. C2's legal journal sequence, complete generation, deterministic field-drift matrix, native replacement, nlink-2 preservation, and pre/post-unlink semantics;
3. C3's exact required rows, summary mapping, causal matrix, setup transitions, independent validation, frozen v1 schema, and unchanged historical report;
4. C4's single exact 60,000-ms wrapper and single-invocation checks;
5. all retained ADR 0048 D1–D3, structural-counter, poisoned cleanup-session, fixed-input, cleanup, export-cleanup, and independent residue gates; and
6. unchanged fixed 4,353-entry graph, 16 immutable cache artifacts, exact ten packages, manifest/ustar pins, runtime-asset pins, and direct one-writer/one-walker route.

Docker observations remain functional-only and cannot satisfy the required native-Linux identity, generation, recovery, cleanup, KVM, or candidate gates.

## Operational selection of one final candidate

No workflow edit is authorized. Instead, enforce this exact operational selection on the target open pull request:

1. Keep the `security` label absent during every integration push and review; if present, remove it before the first C1–C4 push.
2. After all gates pass, freeze the open pull request at the exact reviewed head SHA. No later synchronize or reopen event is authorized.
3. Perform one and only one trigger operation: one `labeled` event adding `security` to that frozen open pull request.
4. Authority is consumed when the first workflow run for that event and exact SHA is created, whether its job runs, skips, succeeds, fails, times out, cancels, or remains uncertain. If the event creates no run, stop and replan; a second label event is not authorized.
5. Only `github.run_attempt == 1` is authorized. Every rerun attempt, queued run from another matching event, synchronize/reopen run, or run for another SHA is unauthorized.

Record the pull-request number, exact SHA, event name and action, run ID, and run attempt in the durable post-run stop record. If more than one matching run is created, do not choose the favorable result: record a scope breach and stop. The authorization is one created run, not one favorable report.

The selected run remains `authority: candidate`, `qualified: false`, metadata-only, and non-authoritative. It may observe only existing Phase A surfaces plus C3's narrow v2 fields. It cannot issue a rootfs, Phase B, runtime, network, SSH, coordinator, campaign, production, release, issue-closure, or cloud permit.

Stop immediately after the one created run for exact measurement and replan. No correction, second run, qualification phase, or later-stage implementation follows by implication.

## Count and cap

ADR 0049's frozen counted set, retained physical-line method, exclusions, anti-evasion rule, and raw-addition/no-deletion planning method remain binding. At `0017ac2`, the reviewed values are **23,708 actual retained lines** and **24,683 no-deletion reserve lines**. The retained later named high remains **7,230** and may not be reduced merely to admit C1–C3.

The exact design above receives these conservative gross raw-addition ranges:

| Allowed counted production surface | Authorized purpose | Range |
| --- | --- | ---: |
| `deploy/aws-feasibility/remote/completion_rootfs_builder.py` | C1 returned rebound authority and checkpoint integration | 60–85 |
| `deploy/aws-feasibility/remote/completion_rootfs_build.py` | C3 trusted setup-boundary marker, only if required | 0–15 |
| `scripts/run-stage2-phase-a-candidate.py` | C2 journal/cleanup state and C3 independent stage rendering | 130–180 |
| `schemas/stage2-phase-a-candidate-v2.json` | C3 exact v2 wire validation | 110–170 |
| **C1–C3 total** |  | **300–450** |

No other counted production file is authorized. C4, tests, documentation, and the retained sanitized report remain excluded and create no cap credit. Deletions offset neither a surface nor the total.

The conservative reserve projection is `24,683 + 7,230 + 300–450 = 32,213–32,363`. It is **213–363 lines above** the 32,000 preferred target, accepted as readable review-correction margin, and **1,637–1,787 lines below** the unchanged 34,000 hard cap.

Stop and replan before further counted implementation if any per-surface high or the **450-line total high** would be exceeded; unused allowance on one surface cannot silently fund another. Before candidate selection, remeasure actual retained and no-deletion reserve counts at the exact reviewed head and revise every remaining named range. Stop if implementation reaches 34,000 or if `current no-deletion reserve + revised remaining high >= 34,000`. This ADR does not amend either cap.

## Explicit exclusions and retained gates

Except for the single fixed C2 `asset-partial-final-owned` record, this decision authorizes no new record or transaction format. It authorizes no broad, recursive, glob, containment, prefix, plan-membership, force, lazy, fallback, best-effort, or unknown/replaced/uncertain-to-absent deletion.

ADR 0047's shared 900-second build/materialization deadline, 600-second cleanup/recovery maximum, 2,400-second two-build envelope, 3,300-second observation bound, 90-minute workflow guard, scheduling boundaries, and final reserves remain unchanged. There is no production timeout increase, retry, rerun substitution, second recovery attempt, fallback, fixture refresh, pin refresh, alternate rootfs route, batching, group commit, paired/buffered transition, `fsync` removal/deduplication, or second writer/walker.

There is no workflow file, trigger-set, permission, artifact-retention, job-budget, runner, scheduling, or label-policy change. The one existing `labeled` event is selected operationally as specified above; no dispatch, push, schedule, synchronize-after-freeze, or reopen-after-freeze event is authorized.

There is no Phase B implementation or execution and no step 3 or later implementation or execution. The step-2 authority gate remains unsatisfied by run `30180567797`; steps 3–4 remain gated, the unconditional stop before step 5 remains binding, and steps 5–7 remain accounting only.

Every non-conflicting security and scope requirement of ADRs 0038–0049 remains binding, including exact inputs and pins, direct materialization, canonical mounts, retained lease, exact ownership, scalar durability, full reconciliation boundaries, uncertainty preservation, independent cleanup/residue, and Docker non-authority.

No AWS credential, CLI, account lookup, provider, OpenTofu plan/inventory/apply, SSM action, deployment, resource creation, cloud cleanup, campaign, evidence publication, release, production use, or issue closure is authorized. This documentation-only proposal performs no code, workflow, dependency, lockfile, network, candidate, Docker, KVM, provider, AWS, deployment, campaign, or production action.

## Consequences

If accepted by the named authority and durable record required above, the smallest reviewed corrections can fix the delta-rebinding defect, close partial-asset cleanup authority without adoption, make v2 evidence stage-faithful, and correct one contended test wrapper without changing production timing.

The canonical run report remains unchanged and locally verifiable after the workflow artifact expires. One exact selected run can test the corrected reviewed head, but it cannot qualify Stage 2. Every outcome ends at another mandatory stop and explicit replan.