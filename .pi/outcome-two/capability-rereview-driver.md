# Outcome 2 capability driver second exact-head hostile review

**Reviewed head:** `ab578313c50f52768003fa3416c514627ba1946d` (`review/cap-r2-driver`)  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Authorities read:** accepted ADR 0087, ADR 0088 as present at the reviewed head, all five first capability reviews, the implementation gate, and the exact five capability implementation surfaces.  
**Scope:** review only. No capability workflow or privileged/native probe was run and no production implementation was changed.

## Verdict

**BLOCK. The prior findings are not all resolved, and one real attempt is unsafe.** There are unresolved P1–P3 findings. In addition, ADR 0087/0088 still provide no separate exact-head/event/blob/public-log attempt approval. Do not apply the label, dispatch, or rerun this workflow.

## P0

No findings.

## P1

### P1-1 — The required outer recovery supervisor does not exist, and process cleanup lacks retained exact authority

**Lines:** `scripts/runner-capability-probe.py:65`, `151-179`, `203-343`, `777-813`, `1185-1194`, `1460-1479`.

`main()` calls `probe_linux()` directly, and that same process sets itself as subreaper, owns `ACTIVE_LEDGER`, performs all effects, and relies on its own exception handler for recovery. There is no outer supervisor/effect-worker topology. A fatal interpreter failure, `SIGKILL`, or workflow timeout therefore removes the only ledger and cleanup executor.

The child model does not repair that gap:

- `Ledger.run()` starts and releases a subprocess before `register_child()` has captured it; it has no readiness/release handshake.
- `ChildIdentity` does not retain expected executable or process-group identity, `matches()` never validates the pidfd, and `stop()` signals with `killpg()` using PID/start/session only.
- registration failure falls back to `os.kill(pid, SIGKILL)` without proved exact identity.
- the nested PID-namespace child is not registered in the ledger.
- credential transitions such as sudo can clear `PDEATHSIG`; the root Python helper rearms only after the unprotected sudo/exec interval.

Thus the implementation cannot prove that a privileged helper, namespace child, or descendant is stopped and exactly reaped after worker crash or timeout. This is the central prior P1 lifecycle finding and remains an attempt-safety blocker.

### P1-2 — `Ledger.run()` destroys both of its own data channels before exec

**Lines:** `scripts/runner-capability-probe.py:161-179`, `293-333`, `737-754`, `1169-1184`, `1214`.

`subprocess.Popen()` creates stdin/stdout pipes, but its `preexec_fn=child_boundary` is called without a record-fd allowlist. `child_boundary()` then duplicates `/dev/null` over fd 0, 1, and 2 and closes every other descriptor. Consequently:

- fixed helper stdout cannot reach `process.stdout`; and
- the sudo root helper invoked as `/usr/bin/python3 -I -` cannot receive `FIXED_CASE_HELPER` through `process.stdin`.

The parent still writes and reads the now-disconnected pipes. Host-map, sudo-map, and user/combined unshare helper records therefore cannot be returned as designed. A real attempt would at best misclassify these cases and become incomplete; likely write failure also poisons cleanup. The portable suite never exercises this production path.

### P1-3 — Cleanup claims still lack the required baselines and exact fd/name/mount/rlimit restoration

**Lines:** `scripts/runner-capability-probe.py:137-149`, `203-217`, `280-291`, `619-653`, `665-723`, `900-932`, `1117-1168`, `1187-1248`.

The only captured baselines are the supervisor fd snapshot, cwd stat generation, and outer `RLIMIT_NOFILE`. `children_reaped`, `mounts_gone`, and `temporary_names_gone` still begin true. There is no exact pre-effect child/descendant, mount-table, namespace, private-name-root, registry, or clean-checkout baseline and no final comparison for those domains.

Further cleanup-authority gaps are concrete:

- private parent/subnames are registered only after `mkdir()` followed by another fallible `stat()`; failure in between leaves an unregistered created name;
- the private parent's pre-open `stat` generation is not compared with the opened descriptor before adoption;
- mount and O_PATH cases re-resolve absolute paths, retain no parent fd or owning-namespace identity in their local mount records, and unmount by pathname after a racy stat check (or no target check in `opath_one()`);
- the close-range child raises its soft limit and never restores or reports restoration before exit;
- cleanup after the absolute deadline is not bounded operation-by-operation, and `stop()` at an expired deadline can signal without any remaining reap interval.

These gaps permit an optimistic complete cleanup object without proving the ADR 0088 child/mount/namespace/name/limit/checkout baselines. Process exit or runner disposal is not the required restoration evidence.

### P1-4 — Production semantic validation still accepts impossible complete reports

**Lines:** `scripts/runner-capability-probe.py:619-723`, `736`, `1218-1259`, `1281-1382`; `test/runner-capability-probe.test.ts:291-531`.

A direct mutation challenge against the exact production `validate_report()` accepted all of the following while retaining `outcome="complete"`:

- `child_owned_proc_after_cap_drop.capability_sets_zero=false`;
- `close_range_low.invocation=blocked` by an unrelated denied `sudo.noninteractive` prerequisite;
- a tool `observation=error` while successful-looking mode/size/digest metadata remained present; and
- `combined_user_mount_pid_fork.proc_mount=denied` with successful cleanup and proc postconditions.

The validator checks that a blocked path names *some* non-`ok` status, not the operation's exact prerequisite. It does not enforce capability-drop postconditions, complete tool nullability, or the combined proc/mount/read-only/PID-1 matrix. The producer also assigns the combined case's `proc_mount` from `maps.before.maps_read`, so a maps-read result is presented as the mount result. In `opath_one()`, namespace/propagation failures are copied directly onto `bind_mount_from_proc_fd` instead of producing a blocked operation with the failed setup prerequisite.

This leaves the first reviews' status/prerequisite/postcondition finding unresolved and allows categorically false complete observations.

### P1-5 — The required production fault matrix is still replaced by an unrelated toy owner

**Lines:** `scripts/runner-capability-probe.py:1407-1457`; `test/runner-capability-probe.test.ts:739-841`.

`ScriptedAdapter` and `ScriptedOwner` model only six strings in an independent acquire/release list. They do not drive `Ledger`, child registration/readiness/PDEATH, process identity, deadlines, fixed-tool resolution, fd reuse, mount/name generations, rlimit restoration, helper codecs, or production cleanup/recovery. The TypeScript suite invokes that self-test and guards against real effects, but supplies no scripted adapter to production lifecycle control flow.

There is still no production-path injection for pipe/fork/pidfd/exec/read/write/TERM/KILL/wait/reap, partial name creation, mount/unmount, descriptor reuse/close, deadline cuts, outer-worker crash, or repeated poisoned cleanup. This is the first tests/holistic review's P1 finding, not a new optional coverage request.

## P2

### P2-1 — Forked children are closed but not proved closed or filtered before case work

**Lines:** `scripts/runner-capability-probe.py:66`, `161-179`, `344-400`, `619-723`, `777-813`, `900-932`, `1062-1098`.

`child_boundary()` discards close failures and sends no readiness record proving its fd boundary. It also does not install `FIXED_CHILD_FILTER`. Generic `fork_case()` children therefore begin tmpfile, mount/O_PATH, close-range/rlimit, namespace, seccomp-query, and KVM work without the fixed socket/io_uring filter required for every forked/execed case where technically possible. Only selected exec helper strings install the filter later.

The implementation performs no network operation and contains no acquisition/network client, which is good, but absence of a client is not the contracted child network-denial boundary.

### P2-2 — Helper/result parsing is neither strict nor canonical

**Lines:** `scripts/runner-capability-probe.py:381-402`, `737-754`, `887-899`.

All three internal decoders use ordinary `json.loads()`. They accept duplicate keys, insignificant extra whitespace, reordered/noncanonical bytes, and JSON numeric extensions accepted by Python. They do not compare one strict UTF-8 value against canonical bytes. That violates ADR 0088's closed helper grammar and means malformed or duplicated helper output can become a categorical result rather than mismatch/error plus cleanup.

### P2-3 — The credential gate and workflow suite still omit required hostile checks

**Lines:** `.github/workflows/outcome-two-runner-capability.yml:44-62`; `test/outcome-two-runner-capability-workflow.test.ts:12-137`.

The gate now checks canonical fetch and push URLs and catches scoped/unscoped extraheaders, resolving part of the first workflow finding. It still rejects only `credential.*.helper`, not every `credential.*` setting; it does not reject `core.askPass`, nonempty `GIT_ASKPASS`, or nonempty `SSH_ASKPASS` as ADR 0088 requires.

The workflow test remains static regex/string mutation. It does not extract and execute the credential sub-gate in temporary repositories for clean, unscoped/scoped extraheader, helper, fetch-userinfo, push-userinfo, extra-remote, and multiple-URL cases, and it does not parse the actual YAML `steps` sequence. Therefore the prior credential and workflow-test findings are only partially resolved.

## P3

### P3-1 — Schema numeric domains still differ from the driver, ADR, and independent semantics

**Lines:** `schemas/runner-capability-probe-v1alpha1.json:120-123`; `scripts/runner-capability-probe.py:1101-1115`, `1288-1295`; `test/runner-capability-probe.test.ts:349-353`, `557-564`.

ADR 0088 requires `run_attempt` to be exactly 1 and `pull_request_number` to be at most 2,147,483,647 everywhere. The driver and independent semantics enforce those bounds, but the schema still permits attempts 1–255 and PR numbers through 9,999,999,999. The schema tests even use 256 and 10,000,000,000 as rejection boundaries, preserving the mismatch instead of testing the controlling bounds.

## Prior-finding resolution audit

| Prior area | Disposition at `ab57831` |
| --- | --- |
| Numeric UID/GID rows in public output | **Resolved for disclosure:** old keys/rows are removed from schema/report; no new numeric-ID disclosure found. |
| Forbidden `github.sha == event_merge_sha` equality | **Resolved:** source/envelope identities are distinct and no equality remains. |
| Status/errno/prerequisite/postcondition matrix | **Unresolved:** P1-4. |
| Seccomp query fabrication / child-proc distinction | **Partially resolved:** nullable query statuses and a distinction observation were added, but combined proc semantics remain false/incomplete under P1-4. |
| Optimistic baselines, crash/deadline/PDEATH, exact process/fd/mount/name/rlimit cleanup | **Unresolved:** P1-1 and P1-3. The 100-second effect cutoff is useful but does not supply outer recovery or exact cleanup. |
| Child cwd/environment/fd/output isolation | **Partially resolved:** cwd/env/stdout/stderr are closed, but P1-2 breaks the intended channels and P2-1/P2-2 leave proof/filter/grammar gaps. |
| Root path-component authentication | **Resolved:** `/` now receives root-owner/non-writable policy checks. |
| Root helper fixed bytes / no checkout crossing sudo | **Structurally preserved, but unsafe lifecycle:** fixed in-memory bytes and fixed executables remain; P1-1 and P1-2 block their safe use. |
| Credential admission | **Partially resolved:** canonical push URL and unscoped extraheader are covered; P2-3 remains. |
| Portable production lifecycle/fault matrix and workflow hostile execution | **Unresolved:** P1-5 and P2-3. |
| Per-file/aggregate highs | **Resolved:** 86/120, 637/700, 1,488/1,900, 852/900, and 141/160; aggregate 3,204/3,780. |
| Exact-surface diff whitespace | **Resolved:** both required diff checks are clean. |
| Network/acquisition | **No active network/acquisition route found:** only the accepted pinned checkout can acquire repository bytes; no driver network/package/cloud client exists. P2-1 still blocks the promised per-child filter boundary. |

## Attempt-safety decision

**UNSAFE — NO ATTEMPT.** This is independent of the still-missing separate approval. The absent outer worker/recovery topology, non-authoritative signaling/reap model, broken subprocess channels, partial name/mount/rlimit cleanup, and missing production fault qualification make an effectful attempt unsafe. Do not apply `outcome-two-runner-capability`, dispatch, or rerun at this head.

## Checks performed

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- Optimized self-test rejection — exit 2 with empty stdout/stderr, passed.
- Exact production semantic mutation challenge — reproduced all four P1-4 acceptances.
- `git diff --check` over the five exact surfaces from the accounting predecessor — passed.
- `git diff --check ab57831^..ab57831` — passed.
- Gross-addition accounting — 3,204 total, every corrected ADR 0088 high satisfied.
- Workflow TypeScript tests — 2/2 workflow tests passed before the driver suite failed to load.
- Combined TypeScript suite, `npm run schemas`, `npm run format:check`, and `npm run typecheck` — not runnable in this clean worktree because dependencies are not installed (`ajv`, `tsx`, `biome`, and `tsc` unavailable). No dependency/network installation was performed for this review.
- No sudo, namespace, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, network, container, provider, cloud, or workflow operation was invoked.

CAP-R2-DRIVER COMPLETE
