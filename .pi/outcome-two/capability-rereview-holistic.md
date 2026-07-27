# Outcome 2 capability implementation — second exact-head holistic hostile review

**Reviewed head:** `ab578313c50f52768003fa3416c514627ba1946d`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Controlling decisions:** accepted ADR 0087 and accepted ADR 0088.

**Review inputs:** all five first capability reviews, `.pi/outcome-two/capability-implementation-gate.md`, `.pi/outcome-two/capability.md`, and the exact five capability implementation surfaces.

**Disposition:** review only. No capability observation or production path was executed or changed.

## Exact binding

This report binds the following exact source-head blobs at `ab57831`:

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| `.github/workflows/outcome-two-runner-capability.yml` | `38f8f5544240018ce8c38407609a1733ab1f468e` | `d5ce2bed8ba1b870102494bedea50c4d2f6ecd6055b47aa9a70132cccf05784f` |
| `scripts/runner-capability-probe.py` | `df34ff90d4f4d5bd55d7e69e2835f79701464b9c` | `5d35a9a8e65df225fa77405de2ee94a69acdcff12f63ff11b6810e5c7019f18c` |
| `schemas/runner-capability-probe-v1alpha1.json` | `7c158995005e5005a6d8ba7ff20e75c595d7e0d9` | `23949fc3e17daa5ffd3f586f82a5791e197e4b579d8a7d03439e65e9204731ca` |
| `test/runner-capability-probe.test.ts` | `c8edb7f36095b03fda1191a1fda8f3d230754d9f` | `390ff6f38b823c54c3ac0865859843e2e142cf3313ff4d7b125d6839e3a4f1c1` |
| `test/outcome-two-runner-capability-workflow.test.ts` | `854aeb65bf510ecf75b35341d4bdb140eaa42f00` | `ff792212f5c3d15902c600c6389e1a3564ab000c0f6038530b121b8af0ff504e` |

## Verdict

**BLOCK. The exact one same-repository PR `labeled` event, run attempt 1, ordinary-log-only observation is not safe at this head, even after ADR 0088 is merged. Do not apply the label, dispatch, or rerun this workflow.**

There are no P0 findings, but unresolved P1–P3 findings remain. In addition, this review is not the separate named event approval required by ADRs 0087 and 0088.

## P0

No findings.

## P1

### P1-1 — The required outer recovery topology and pre-release child authority are still absent

**Lines:** `scripts/runner-capability-probe.py:192-197,238-303,1185-1193,1461-1479`.

`probe_linux()` is both the effect worker and the only recovery process. It sets itself as subreaper and stores its ledger in module-global `ACTIVE_LEDGER`; there is no fixed outer supervisor that performs no capability case and monitors a separate effect worker. In-process exception cleanup cannot run after its SIGKILL or interpreter loss.

More immediately, `Ledger.run()` calls `subprocess.Popen()` before `register_child()`. The execed host-map, unshare, and sudo commands therefore begin work without a readiness gate and before pidfd/start/session authority is retained. `ChildIdentity` does not retain the expected executable or process-group identity, and cleanup signals with `killpg()` rather than through the retained pidfd. The sudo credential transition also has a period between the pre-exec parent-death setup and the root Python helper rearming it.

This leaves the first review's crash/stranding finding unresolved and violates ADR 0088 section 4. A worker crash or parent loss can occur after a privileged or irreversible effect starts but before the reviewed owner has exact recovery authority. One real attempt is therefore unsafe.

### P1-2 — Cleanup is not based on all required baselines or exact mount/name authority

**Lines:** `scripts/runner-capability-probe.py:199-217,619-654,1117-1168,1185-1193,1237-1248`.

The ledger captures only a descriptor snapshot and the current-directory generation. It does not capture the required child/descendant baseline, mount table, namespace identities, private-root pre-state, owner-registry baseline, or exact clean checkout state. Final checkout proof is only another `stat(".")`, not an exact-head/porcelain comparison.

`mounts_gone` and other aggregate claims still begin true. `private_mount_cases()` performs mount-namespace creation, two tmpfs mounts, tmpfile work, same-namespace O_PATH work, and across-namespace O_PATH work in one child. Mounts are registered only after a post-mount `stat`, are represented by pathname plus partial stat tuples rather than retained source/target and owning-namespace authority, and are unmounted by pathname. Private names are likewise recorded only after `mkdir` followed by a fallible `stat`; if that stat fails, cleanup has no registered generation for the created name.

This leaves the first cleanup/baseline and temporary/mount authority findings unresolved. A complete cleanup claim is not proved against the baseline contract in ADR 0088 section 4.

### P1-3 — The production semantic validator still accepts impossible complete reports

**Lines:** `scripts/runner-capability-probe.py:1270-1382`.

A direct mutation challenge of `fake_report()` against the exact production `validate_report()` was accepted in all of these cases:

- user-namespace `create=denied` while both UID/GID map observations remain successful;
- an after-capability-drop map case with `capability_sets_zero=false`;
- a complete report with `parent_proc_read_only=null`;
- `first_open_failure=ok` while fewer maps opened than were selected;
- a denied combined proc mount while successful child-proc facts remain present; and
- insufficient hard fd capacity represented by errno-null `unsupported` while the high `close_range` case remains successful.

The validator counts status objects and checks selected relationships, but it does not enforce the complete operation/prerequisite/postcondition matrix required by ADR 0088 section 3. The implementation can still validate semantically impossible `outcome="complete"` values. This is the first schema/holistic semantic finding, not a resolved replacement.

### P1-4 — The required portable hostile qualification still does not drive production control flow

**Lines:** `scripts/runner-capability-probe.py:1383-1458`; `test/runner-capability-probe.test.ts:742-839`.

The self-test's `ScriptedAdapter` and `ScriptedOwner` are a separate six-name in-memory toy owner. They do not drive `Ledger`, `probe_linux`, `resolve_fixed_tool`, `create_private_parent`, process registration/readiness/recovery, deadlines, mounts, namespace cases, descriptor restoration, or production cleanup through a scripted adapter. The TypeScript suite explicitly proves that the self-test reaches no production effect boundary and validates a preassembled `fake_report()`.

Consequently the required fault cuts for production open/dup/pipe/pidfd/fork/read/write/exec/readiness/PDEATH/status/TERM/KILL/wait/reap, identity reuse, baseline comparison, mount/name replacement, multiple cleanup errors, fresh outer-supervisor recovery, and deadlines before/after every production acquisition remain absent. This is the first tests and holistic portable-qualification finding, still unresolved.

## P2

### P2-1 — The credential gate and its tests still do not implement ADR 0088 section 6

**Lines:** `.github/workflows/outcome-two-runner-capability.yml:46-63`; `test/outcome-two-runner-capability-workflow.test.ts:41-53,119-141`.

The gate now checks canonical fetch/push URLs and scoped or unscoped extraheaders, resolving those two concrete bypasses. It still rejects only `credential.*.helper`/`credential.helper`, not every `credential.*` setting; it does not reject `core.askPass`; and it does not prove nonempty `GIT_ASKPASS` and `SSH_ASKPASS` routes absent.

The workflow test remains static string/mutation inspection. It does not extract and execute the credential sub-gate in temporary repositories and does not run the required clean and hostile canary cases for unscoped/scoped extraheader, helper, credential-bearing fetch/push URL, additional remote, and multiple URL entries. The first workflow credential finding is only partially resolved.

### P2-2 — The user-map report shape does not match ADR 0088's exact categorical contract

**Lines:** `schemas/runner-capability-probe-v1alpha1.json:190-200`; `scripts/runner-capability-probe.py:736,1223-1228,1345-1350`.

Numeric UID/GID rows and the old `uid_map`/`gid_map` keys are removed, so the original public-ID disclosure is resolved. However, ADR 0088 requires a UID-map status with its own nullable categorical boolean and a GID-map status with its corresponding nullable boolean. The schema and driver instead collapse both into one `exact_root_mapping` boolean. That loses which map matched when the two observations differ and is not the accepted exact shape.

## P3

### P3-1 — Schema numeric domains still disagree with ADR 0088 and the driver

**Lines:** `schemas/runner-capability-probe-v1alpha1.json:120-123`; `scripts/runner-capability-probe.py:1080-1083,1293-1294`; `test/runner-capability-probe.test.ts:559-563,644-647`.

ADR 0088 requires `run_attempt` to be exactly integer 1 and `pull_request_number` to be at most 2,147,483,647 everywhere. The driver and independent semantics use those limits, but the schema still accepts attempts 2–255 and PR numbers through 9,999,999,999. The schema tests challenge only 256 and 10,000,000,000, so they preserve the discrepancy. The first schema P3 remains unresolved.

## Prior-finding disposition

| First-review finding | Second-review disposition |
| --- | --- |
| Numeric UID/GID map rows in public log | **Resolved for raw rows**, but replacement shape has P2-2. |
| Forbidden `github_sha == event_merge_sha` | **Resolved.** Distinct identities are accepted and tested. |
| Incomplete semantic coupling/impossible complete reports | **Unresolved:** P1-3. |
| Fabricated seccomp query zeroes | **Resolved.** Query values are nullable with statuses. |
| Child proc distinction never measured | **Measured**, but broader proc semantic coupling remains in P1-3. |
| Numeric-domain mismatch | **Unresolved:** P3-1. |
| Optimistic cleanup and missing baselines | **Unresolved:** P1-2. |
| Crash/deadline can strand children | **Unresolved:** P1-1. The second-100 effect cutoff exists, but no outer worker/recovery topology or pre-release authority does. |
| Child stdout/stderr, cwd, environment, and excess fds | **Partially resolved.** Fixed child boundary redirects/clears/closes, but `Ledger.run()` starts execed work before registration/readiness; P1-1. |
| Root path component unauthenticated | **Resolved.** |
| Temporary/mount cleanup authority | **Unresolved:** P1-2. |
| Credential extraheader and push URL gaps | **Those two bypasses resolved; overall accepted gate and executable tests unresolved:** P2-1. |
| Portable suite does not drive production adapters/lifecycle | **Unresolved:** P1-4. |
| Independent semantics omit relationships | **Unresolved:** P1-3/P1-4. |
| Workflow can miss unnamed fourth step | **Resolved.** Actual step entries are counted and hostile mutation is present. |
| Optimized-mode rejection untested | **Resolved.** |
| Two per-file highs exceeded | **Resolved by accepted ADR 0088 highs; all current surfaces are within high.** |
| Exact diff-format gate red | **Resolved.** |

## Accounting

Gross physical additions from the exact predecessor are:

| Surface | Actual | ADR 0088 high | Result |
| --- | ---: | ---: | --- |
| `.github/workflows/outcome-two-runner-capability.yml` | 86 | 120 | within by 34 |
| `schemas/runner-capability-probe-v1alpha1.json` | 637 | 700 | within by 63 |
| `scripts/runner-capability-probe.py` | 1,488 | 1,900 | within by 412 |
| `test/runner-capability-probe.test.ts` | 852 | 900 | within by 48 |
| `test/outcome-two-runner-capability-workflow.test.ts` | 141 | 160 | within by 19 |
| **Aggregate** | **3,204** | **3,780** | **within by 576** |

No line high is crossed.

## Verification performed

After installing the locked dependencies without package scripts:

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- `/usr/bin/python3 -I -B -O scripts/runner-capability-probe.py --self-test` — rejected with exit 2 and empty stdout/stderr.
- `npx --no-install tsx --test test/runner-capability-probe.test.ts test/outcome-two-runner-capability-workflow.test.ts` — passed, 7/7.
- `npm run schemas` — passed, 15 schemas.
- `npm run format:check` — passed.
- `npm run typecheck` — passed.
- ADR 0088's five-surface `git diff --check` — passed.
- `git diff --check HEAD~1..HEAD` — passed.
- Direct production-validator hostile mutation challenge — six impossible reports accepted, as listed in P1-3.

Green retained checks do not cure the missing production fault matrix, lifecycle/cleanup contract, credential qualification, or semantic holes.

## Attempt-safety decision

**NO — not safe.** Even if a separate approval were to bind exactly head `ab57831`, the three workflow/driver/schema blobs listed above, exactly one same-repository PR label event, `github.run_attempt == 1`, and ordinary-log-only retention, that approval would bind an implementation with unresolved P1–P3 defects. The event could start privileged or irreversible effects before exact recovery ownership, cannot prove the accepted cleanup baselines, and can produce or accept semantically contradictory completion state. A one-shot event must not be spent on this head.

The JSON remains non-authoritative (`authority="none"`, `qualified=false`), and the workflow has no artifact/upload route. Those properties limit authority and retention; they do not make the effectful attempt safe.

CAP-R2-HOLISTIC COMPLETE