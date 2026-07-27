# Outcome 2 capability workflow exact-head hostile rereview

- **Reviewed head:** `ab578313c50f52768003fa3416c514627ba1946d`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Authorities read:** ADR 0087, ADR 0088, `.pi/outcome-two/capability.md`, the implementation gate, and all five first capability review reports.
- **Implementation read:** all five exact capability surfaces at the reviewed head.
- **Primary focus:** workflow admission, credentials, event/attempt binding, source/blob identities, driver environment, and ordinary-log disclosure.
- **Disposition:** review only; no capability workflow or production operation was run.

## Verdict

**BLOCKED. There are unresolved P1 and P2 findings. One effectful capability attempt is unsafe and is not authorized.**

The corrections resolve the numeric UID/GID disclosure, forbidden envelope equality, root-component check, child stdout/stderr inheritance, actual-step counting, optimized-mode regression, line highs, and diff-format failure. They do not provide the required outer recovery topology, exact baselines, production-driven hostile tests, complete semantic separation, or complete credential gate. ADR 0087/0088 also still require a separate named exact-head/blob/event/public-log approval; no reviewed material supplies it.

## P0

No findings.

## P1

### P1-1 — The required outer recovery supervisor does not exist, and `Ledger.run()` releases work before identity registration

**Lines:**

- `scripts/runner-capability-probe.py:293-305`
- `scripts/runner-capability-probe.py:1185-1193`
- `scripts/runner-capability-probe.py:1461-1480`

`main()` directly calls the effectful `probe_linux()` process. That same process installs itself as subreaper, owns the ledger, performs cleanup, and emits the report. There is no fixed outer recovery supervisor with a separate effect worker.

Worse, `Ledger.run()` calls `subprocess.Popen()` and only then opens the pidfd, records start/session identity, and inserts the child in `live_children`. The execed child has no release gate and can begin host-map, sudo/root, or unshare work before that registration. `ChildIdentity` also records no expected executable, and `matches()` does not use the retained pidfd or executable identity when granting signal authority.

A fatal crash/SIGKILL of the effect process therefore removes the only cleanup/reap authority. PDEATHSIG does not satisfy ADR 0088's required outer recovery topology, particularly across sudo's privileged transition. This leaves the first driver/holistic crash-recovery finding unresolved and makes an effectful attempt unsafe.

**Required resolution:** implement the specified outer-supervisor/effect-worker topology; require closed readiness and parent release for every child boundary; retain and revalidate pidfd, start time, executable, session, and process group through exact reap.

### P1-2 — Cleanup still lacks the required pre-effect baselines and identity-bound mount authority

**Lines:**

- `scripts/runner-capability-probe.py:199-218`
- `scripts/runner-capability-probe.py:621-654`
- `scripts/runner-capability-probe.py:1185-1193`
- `scripts/runner-capability-probe.py:1237-1248`

The ledger captures only an fd snapshot, the current directory's stat generation, and the rlimit pair. It does not capture exact child/descendant, mount-table, namespace-identity, private-root-state, clean checkout porcelain/head, or registry baselines before effects. Final checkout comparison is only `stat(".")`, which cannot detect tracked/untracked content changes.

Mounts are registered in the local `mounted` list only after successful `mount(2)`, and cleanup authority is an absolute path plus stat tuple. No owning-namespace identity or retained target/source authority is registered before the mount effect. `mounts_gone` begins true and is derived from child-returned booleans rather than comparison with an exact outer baseline.

This leaves the first driver P1-2/P2-1 and holistic P1-2 cleanup findings unresolved.

**Required resolution:** capture every ADR 0088 baseline before effects; register mount/name/fd/child authority before the next fallible effect; compare exact checkout, mount, namespace, child, fd, rlimit, name, and registry baselines before any complete report.

### P1-3 — Unattempted operations are still assigned prerequisite-operation results

**Lines:**

- `scripts/runner-capability-probe.py:682-690`
- `scripts/runner-capability-probe.py:1257`
- `scripts/runner-capability-probe.py:1338-1352`

In the across-namespace O_PATH case, a failed namespace creation or propagation operation is copied directly into `bind_mount_from_proc_fd`, although the bind was not attempted. In the combined namespace case, `proc_mount` is populated from the later `maps_read` result, so a successful util-linux proc mount followed by a denied/error maps read is falsely represented as that proc-mount result. `cleanup` is unconditionally `ok` whenever a combined payload exists.

The production validator checks local status shapes but has no distinct namespace-propagation/proc-mount/cleanup facts capable of rejecting these states. This is the same failure-copying class reported in the first schema review P1-3 and contradicts ADR 0088's requirement that each operation remain separate and unattempted dependents be `blocked` by the exact failed prerequisite.

**Required resolution:** represent each prerequisite and operation independently; never reuse namespace, propagation, maps-read, or payload-presence results as another operation or cleanup result.

### P1-4 — The required hostile adapter tests still do not drive production lifecycle/effect control flow

**Lines:**

- `scripts/runner-capability-probe.py:1407-1458`
- `test/runner-capability-probe.test.ts:742-839`
- `test/outcome-two-runner-capability-workflow.test.ts:115-141`

`ScriptedAdapter` and `ScriptedOwner` are a six-name toy state machine used only by `self_test()`. They do not drive `Ledger`, `probe_linux`, child registration/readiness, pidfds, PDEATHSIG, deadlines, tool resolution, namespace/mount operations, rlimit restoration, or production cleanup. The TypeScript test verifies the toy's summary instead of injecting faults through production control flow.

The workflow test remains purely static. It does not extract and execute the credential sub-gate in temporary repositories, and it does not perform ADR 0088's required clean/hostile credential canary matrix. The required wait/reap/identity/deadline/baseline and credential-gate matrices therefore remain absent even though the seven current tests pass.

This leaves first tests P1-1/P1-2 and holistic P1-4 unresolved.

**Required resolution:** drive production state/codec/semantic/syscall/process/baseline/deadline/cleanup paths through a deterministic adapter, and execute the exact extracted credential gate against every required hostile repository/configuration case.

## P2

### P2-1 — Credential admission still accepts forbidden credential and askpass routes

**Lines:**

- `.github/workflows/outcome-two-runner-capability.yml:46-63`
- `test/outcome-two-runner-capability-workflow.test.ts:47-62`
- `test/outcome-two-runner-capability-workflow.test.ts:119-141`

Fetch and push URL equality and scoped/unscoped extraheader rejection are now present. However, the gate rejects only `credential.*.helper`; ADR 0088 requires rejection of every `credential.*` setting, `core.askPass`, and nonempty `GIT_ASKPASS`/`SSH_ASKPASS` routes across visible scopes.

A temporary-repository challenge against the exact current regex showed all of these survive:

- `credential.username=SECRET-USERNAME`;
- `credential.useHttpPath=true`;
- `core.askPass=/tmp/SECRET-ASKPASS`;
- `GIT_ASKPASS=/tmp/SECRET-ENV-ASKPASS`; and
- `SSH_ASKPASS=/tmp/SECRET-ENV-ASKPASS`.

The current test only mutates source text and cannot detect these live bypasses. The first workflow P2-1 finding is therefore only partially resolved.

**Required resolution:** reject all accepted ADR 0088 credential/askpass routes without printing values and add the exact executable canary challenges.

### P2-2 — Event numeric domains still disagree between schema and production admission

**Lines:**

- `schemas/runner-capability-probe-v1alpha1.json:120-123`
- `scripts/runner-capability-probe.py:1068-1085`
- `scripts/runner-capability-probe.py:1292-1294`
- `test/runner-capability-probe.test.ts:550-565`
- `test/runner-capability-probe.test.ts:640-647`

ADR 0088 requires `run_attempt` to be exactly integer `1` and PR number to be `1..2,147,483,647`. The schema still permits attempts `1..255` and PR numbers through `9,999,999,999`, while production parsing/semantics enforce the accepted domains. Direct mutation confirmed AJV accepts `run_attempt=2` and `pull_request_number=2,147,483,648`, while `validate_report()` rejects both.

The independent semantic tests reject attempt `2` and PR number `2,147,483,648`, but the schema-bound mutations use only attempt `256` and PR number `10,000,000,000`; they never require AJV to reject the production boundaries. This leaves first schema P3-1 unresolved.

**Required resolution:** make schema, driver, golden fixture, and exact boundary mutations use the same accepted domains.

### P2-3 — Forked Python case children still lack the required pre-case filter and closed-fd proof

**Lines:**

- `scripts/runner-capability-probe.py:161-181`
- `scripts/runner-capability-probe.py:344-374`
- `scripts/runner-capability-probe.py:1197-1235`

`child_boundary()` clears environment, changes to `/`, redirects stdout/stderr, and attempts to close excess descriptors, resolving important parts of the first child-output finding. It does not install the fixed socket/io_uring filter, does not fail on an excess-fd close error, and does not prove the child descriptor baseline before release. `fork_case()` then releases tmpfile, mount, close-range, namespace, seccomp, and KVM functions directly.

This leaves the first holistic P2-1 isolation finding partially unresolved.

**Required resolution:** fail closed on and prove the fixed child fd table before release; install the accepted filter before case code wherever technically possible, with only the explicitly documented unavoidable windows.

## P3

No additional P3 findings.

## Prior-finding resolution ledger

| First-review finding class | Rereview result |
| --- | --- |
| UID/GID map values in public log | **Resolved**: only categorical map facts remain. |
| Forbidden `github.sha == event_merge_sha` assumption | **Resolved**: identities are distinct and independently shaped. |
| Per-file/aggregate highs | **Resolved** under ADR 0088: 86/637/1,488/852/141; aggregate 3,204. |
| Credential fetch/push and extraheader admission | **Partially resolved**; P2-1 remains. |
| Exact semantic coupling / copied prerequisites | **Partially resolved**; P1-3 and P2-2 remain. |
| Nullable seccomp queries and proc distinction | **Resolved** for those exact fields. |
| Outer recovery, baseline, deadline, child identity, cleanup | **Not resolved**; P1-1/P1-2 remain. |
| Root component policy | **Resolved**. |
| Child cwd/environment/stdout/stderr isolation | **Partially resolved**; P2-3 remains. |
| Production-driven hostile lifecycle matrix | **Not resolved**; P1-4 remains. |
| Actual workflow step count and unnamed extra step | **Resolved for the current workflow/static check**. |
| Optimized-mode regression | **Resolved**. |
| Exact diff-format gate | **Resolved**. |

## Workflow admission/environment/log observations with no additional finding

- Trigger is only same-repository `pull_request:labeled` with the exact label and attempt-one job condition.
- Concurrency is PR-scoped and non-cancelling; timeout is three minutes.
- Exactly three current steps exist; only the pinned checkout action is used, with exact PR-head ref and `persist-credentials:false`.
- Checkout HEAD, repository, clean workspace, and workflow/driver/schema source-head blob digests are checked before driver invocation.
- Source-head workflow digest remains correctly named and is not claimed as executed-workflow identity.
- Driver invocation uses `/usr/bin/env -i`; ambient `PATH`, `HOME`, proxy, locale, token, and complete GitHub/runner environments are not passed.
- Source, base, GitHub, workflow, and merge identities remain separately named.
- No upload, artifact, cache, summary, comment, attestation, post-processing, retry, or fallback step exists.
- Probe success remains one canonical ordinary-log line with `authority="none"` and `qualified=false`; child stdout/stderr are redirected away from the log.

## Accounting

Gross additions from the accepted predecessor:

| Surface | Actual | ADR 0088 high | Result |
| --- | ---: | ---: | --- |
| Workflow | 86 | 120 | within |
| Schema | 637 | 700 | within |
| Driver | 1,488 | 1,900 | within |
| Contract test | 852 | 900 | within |
| Workflow test | 141 | 160 | within |
| **Aggregate** | **3,204** | **3,780** | **within** |

## Verification performed

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- Optimized self-test — rejected with exit 2 and empty stdout/stderr.
- Capability TypeScript tests — passed, 7/7 after installing locked dependencies.
- `npm run schemas` — passed.
- `npm run format:check` — passed.
- `npm run typecheck` — passed.
- Exact five-surface predecessor diff check — passed.
- Correction-commit ordinary diff check — passed.
- Dynamic credential bypass challenge — reproduced P2-1.
- AJV/production numeric-domain comparison — reproduced P2-2.
- Worktree remained clean before this report was added.

## Attempt safety and authority decision

**NO ATTEMPT. UNSAFE AND UNAUTHORIZED.** Do not apply the capability label, dispatch, rerun, or otherwise execute this workflow at `ab57831`.

The unresolved recovery, baseline, semantic, testing, credential, and child-boundary findings independently block an effectful attempt. Separately, neither ADR 0087, ADR 0088, nor this rereview supplies the required named approval binding this exact head, exact workflow/driver/schema blobs, one exact labeled event, attempt 1, and accepted public-log disclosure. A future corrected implementation would still have to stop for that separate approval.

CAP-R2-WORKFLOW COMPLETE.
