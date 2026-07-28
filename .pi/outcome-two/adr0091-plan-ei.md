# ADR 0091 corrective plan — Job E, thin integration, and shared authority

- **Status:** architecture plan only; not an ADR and not execution authority
- **Reviewed implementation:** `ea6e74fe709e02061e13be78922da13a8cf6f748`
- **Review-record head:** `4eb9da3d2c98dd4a59e1e59817d34643bfba0d46`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Controlling decisions:** ADRs 0087–0090, except where a future accepted ADR 0091 expressly adopts this correction
- **Scope of this plan:** E, integration, the production launcher seams they require, common outer baselines, report-generation authority, and their portable hostile acceptance

This plan performs no implementation and authorizes no test command, native selector, sudo, namespace, mount, seccomp, `map_files`, compression execution, workflow run, provider, cloud, or AWS action.

## 1. Disposition of the reviewed architecture

The exact reviewed head remains blocked. A clean worktree check and a digest assertion do not admit bytes across an exec boundary. Running a checked-out pathname as root is especially not admission. A root-only owner check also cannot authenticate a normal runner-owned checkout merely by accepting UID 0 as an alternate owner.

ADR 0091 should replace the E/integration composition with these invariants:

1. **Source admission precedes privilege.** The runner-side admitted process opens, completely reads, generation-binds, and exact-head-binds every production source byte needed by E before `sudo` can execute root code.
2. **Root never opens or executes the checkout.** Root receives a closed, bounded capsule of already-held bytes. It executes one small exact bootstrap already held by the admitted runner. No checkout pathname or fd crosses sudo.
3. **E selects a sandbox-only production entry.** It does not prepare a closure, parse ELF, use `map_files`, seal or execute gzip/zstd, or return the runtime-integration result.
4. **Integration is a caller, not a launcher implementation.** Production code owns its fd transport, gates, fork/exec, pidfds, deadlines, TERM/KILL/reap, result framing, and cleanup.
5. **Common owns common observations and report publication.** A driver cannot turn a supplied seven-boolean mapping into cleanup authority. Report cleanup requires the exact staged/published generation, including across the upload step.
6. **The production state root is exactly `/tmp/cogs-o2-runtime-v1`.** `/run/cogs-o2-runtime-v1` is deleted from baselines, tests, and claims.

These changes address the E/integration and shared-common findings only. They do not disposition the separate A/B or C/D owner/mechanism findings in the final reviews.

## 2. Source and privilege topology

### 2.1 Runner-side admission

The workflow exact-head shell gate remains T0. Job E then starts unprivileged through literal `--workflow-bound`. Before any sudo process exists, the runner-side admitted launcher bootstrap must:

- open the fixed checkout root descriptor with no-follow directory semantics;
- require the checkout owner to equal the runner EUID, not root;
- bind HEAD and the clean checkout to the exact same-repository PR head already carried by `WorkflowContext`;
- descriptor-relatively open the exact launcher, parser, closure, and tracked-schema names;
- completely read and retain their bytes and generations;
- authenticate the source set against the exact reviewed Git tree and canonical source-set digest;
- authenticate fixed `/usr/bin/python3` and retain the identity needed for the root readback; and
- construct the complete bounded root capsule before creating or releasing a sudo child.

The mutable pathname is no longer used after its bytes are held. A pathname reread, a second worktree lookup, or an asserted digest over bytes that are not executed is not a substitute.

The ordinary owner rule remains strict: checkout-backed admission requires `source_root.st_uid == caller_euid`, fixed mode/non-writability, exact Git binding, and stable held generations. ADR 0091 must not change that predicate to “runner or root,” special-case UID 0, trust a revision supplied in JSON, or let root reopen a runner-owned tree.

### 2.2 Exact root bootstrap

The admitted production launcher contains one small fixed root-bootstrap byte constant, separately bounded below Linux's per-argument limit. The runner extracts that constant only from the already-held exact launcher generation. Production-owned supervision invokes exactly:

```text
/usr/bin/sudo -n --close-from=3
  /usr/bin/env -i
  /usr/bin/python3 -I -B -c <held-root-bootstrap-bytes>
```

The capsule is supplied on stdin; stdout is the one bounded canonical result channel and stderr is a bounded categorical failure channel. Default `close-from=3` remains unchanged. No preserved checkout/source fd, environment value, temporary script, `python PATHNAME`, shell, or caller-selected argument is permitted.

The root bootstrap is trusted T1 code because the runner held and authenticated its exact bytes before root execution. It performs only the fixed envelope and capsule transition:

1. require EUID 0, empty environment, exact argv, and exactly fds 0–2;
2. set and reread parent-death behavior before the next effect;
3. read one complete canonical capsule under fixed per-blob and aggregate bounds;
4. reject duplicate fields, unknown source names, digest/size/version mismatch, trailing data, wrong source-set cardinality, wrong runner-parent transaction, or wrong Python object identity;
5. compile/execute the held launcher generation and its fixed admitted dependencies in the synthetic package; and
6. consume a one-shot live bootstrap capability into the sandbox-only coordinator.

No namespace, mount, private root, helper, closure, report, or T2 effect may occur before step 5 succeeds. Root does not claim to independently rediscover Git provenance; provenance was established by the exact runner-side holder. Root proves that it consumed exactly that holder's closed byte capsule through the live parent transaction. This is a privilege transfer of admitted authority, not a relaxed root ownership rule.

The sandbox capsule version is fixed as `cogs.runtime-source-admission/sandbox-v1`. Root rejects the ordinary runtime, mapping, and compression versions. Conversely, non-root ordinary bootstrap rejects sandbox-root mode. Replay, a second packet/capsule, copied Python objects, or a second coordinator call consumes/fails the transaction.

## 3. Real sandbox-only production entry

ADR 0091 should restore a distinct production result and fixed entry equivalent to the original accepted API:

```python
launch_fixed_sandbox_probe() -> SandboxQualificationResult
```

In the implemented private bootstrap architecture this is reached only by the admitted sandbox version above; it is not a public caller-selected mode. Its result version is exactly `cogs.sandbox-qualification/v1`. Its closed field inventory contains source revision/source-set digest, the observed installed seccomp-program digest, and only sandbox observations. It contains no closure digest, gzip/zstd output, sealing row, ELF/mapping metadata, fd/PID/path/mount identity, or raw diagnostic.

The sandbox-only coordinator must reuse the same production root, namespace, process-owner, capability, securebits, NNP, seccomp, observation, and rollback primitives used by runtime T2. It may use an internal compile-time scenario type so that shared mechanisms cannot drift, but no caller value may select primitive order or policy.

The fixed probe is already-loaded code. It needs no executable handoff and performs no post-drop exec. It constructs and observes:

- the coupled user/PID/mount/network namespace transaction;
- singular UID/GID maps, supplementary groups cleared in the accepted order, and PID 1 where required;
- the exact private chroot and mount readback;
- checkout and host executable paths absent from T2;
- no proc mount;
- read-only, `nosuid`, `nodev`, `noexec` final mounts;
- all capability sets zero, locked `noroot`, and NNP;
- the exact x86-64 seccomp bytes/digest/mode plus actual fixed socket, io_uring, namespace, mount/root, capability, executable-object, authority-duplication, and filter-replacement denial observations;
- the exact final fd set and absence of acquisition authority;
- exact process/descendant reap, namespace-handle release, unmount, root removal, and baseline restoration.

Every result fact starts `UNOBSERVED` and is populated only by a typed production readback. Operation labels and all-true constructors are forbidden. Unsupported or denied required primitives produce typed `RuntimeLauncherUnavailable` only after observed cleanup. Cleanup uncertainty remains a different terminal failure.

The Job E driver becomes a narrow adapter: common context/baseline lease, exact held-launcher admission, one production sandbox invocation, exact `SandboxQualificationResult` decode, check mapping, and common report finalization. The policy metadata digest comes from the result's observed installed-program field, not a second call to private `_seccomp_digest()`.

## 4. Truly thin integration

The integration route keeps ordinary runtime admission and the exact `RuntimeQualificationResult`. It does not use sudo. Its native driver must own none of the following:

- admission/result pipes;
- `fork`, `unshare`, UID/GID map writes, fd-number installation, `execve`, or pidfd acquisition;
- release gates, status transport, output multiplexing, deadlines, TERM/KILL/reap, or close aggregation;
- root/mount/namespace setup; or
- a second source-admission codec or process owner.

After exact held-launcher admission, the driver makes one call to the fixed production runtime invoker. The admitted launcher owns the complete outer invocation state machine:

```text
NEW
 -> SOURCE_ADMITTED
 -> TRANSPORT_REGISTERED
 -> CHILD_BLOCKED_AND_REGISTERED
 -> RELEASED
 -> RESULT_VALIDATED
 -> NATIVE_RESOURCES_CLEAN
 -> RETURNED
or any state -> POISONED -> exactly recovered or terminal uncertainty
```

Every pipe/socket/fd lease is registered immediately after each creation and before the next fallible create. A child performs no assigned effect until PID, pidfd, start-time, expected executable phase, session/process-group transition, release/status fds, and deadline authority are registered. Planned `setsid`/exec transitions are explicit identity phases; later validation never compares against a knowingly stale pre-transition identity. All output/status reads are bounded. TERM and KILL reserve separate time inside one absolute deadline, and successful return requires exact nonblocking reap and empty production registries.

The production invoker returns exactly one closed versioned result after its own closure, handoff, gzip/zstd, T2, and cleanup transaction has settled. Integration independently checks the fixed marker and gzip/zstd output digest, exact result type/field order, source binding, and absence of linked A–E evidence. It does not repeat A–E matrices or consume their artifacts.

A static acceptance rule should reject `fcntl`, `resource`, `select`, `signal`, `ctypes`, `os.pipe*`, `os.fork`, `os.unshare`, `os.exec*`, `pidfd_*`, `wait*`, and kill/supervision logic in `thin-integration.py`. The only process/resource lifecycle visible there is the common baseline/report lease.

## 5. Exact root and common cleanup authority

### 5.1 Production root

The sole production private state name is:

```text
parent: /tmp
leaf:   cogs-o2-runtime-v1
full:   /tmp/cogs-o2-runtime-v1
```

Production opens and retains `/tmp` as a no-follow directory authority, records leaf absence or the exact owned leaf before mutation, registers create/mount intent before effect, and carries directory/root/mount generations until exact rollback. Cleanup never uses `/run`, a caller path, `rm -rf`, recursive/lazy/force unmount, or pathname-only deletion. Replacement or inability to prove the exact leaf/mount is uncertainty, not absence.

The outer common baseline observes the exact `/tmp/cogs-o2-runtime-v1` leaf through a retained `/tmp` descriptor before the first job effect and after production return. It does not pretend all of shared `/tmp` is immutable. E and integration additionally require the production result's independently observed inner `paths_restored`, `mounts_restored`, and namespace facts.

### 5.2 Common baseline lease

`common.py` creates one non-forgeable, one-shot `CommonBaselineLease` before the first driver effect. It captures with production operations:

- bounded `getdents64` enumeration through the exact `/proc/self/fd` descriptor, excluding only that descriptor;
- direct children and the owned-descendant baseline;
- mountinfo digest and user/PID/mount/network namespace identities;
- soft/hard `RLIMIT_NOFILE`;
- exact `/tmp/cogs-o2-runtime-v1` leaf state;
- the job's exact `/tmp/cogs-native-qualification-{job}` report-root absence; and
- exact HEAD plus porcelain/config state.

Finalization consumes the lease and performs every reread itself. Drivers receive typed per-domain observations but cannot submit a cleanup mapping. Unknown, faulted, mismatched, or uncertain observations are false. This removes the current authority hole where any caller can pass seven `true` values.

### 5.3 Report-generation owner across upload

Pathname validation followed by close and unlink cannot carry generation authority across a separate upload step. ADR 0091 should make report publication a separate surviving common-owned lease.

A fixed common report supervisor is started blocked and registered before report-directory creation. It retains the `/tmp` parent fd, exact private-directory fd/generation, staged/published file lease/generation, report digest/bytes, and one fixed control endpoint. It alone performs staged creation, complete write, fsync, close-once, independent schema/semantic/canonical validation, no-replace publication, directory fsync, and post-publication validation. Only then does it expose `/tmp/cogs-native-qualification-{job}/report.json` to the upload step.

The native-resource cleanup lease is already settled before this publication lease exists, so the report supervisor is not falsely counted as a leaked job child. It is an explicit transferred publication owner. The workflow uploads only `report.json`, never the control endpoint or private ledger.

The fixed `common.py --cleanup JOB` client executes under `always()` after upload, connects to that exact live owner, and requests release. The owner reopens the published name through its retained directory authority and compares it to the retained generation and bytes before unlink. It removes only registered exact generations, fsyncs, removes the exact directory, proves the report-path/process baseline, and exits/reaps under a fixed deadline. Duplicate cleanup fails closed. Upload failure takes the same route.

If a staged/final/directory name has been replaced, the foreign generation is preserved and the job ends in terminal uncertainty; common never deletes it merely to make the path look absent. If the driver dies before publication, the surviving owner detects client EOF and recovers every registered pre-publication state. If the supervisor dies or exact recovery cannot be proved, no final required success is possible. Runner disposal is not evidence.

The implementation may use a closed write-ahead generation receipt in the private transaction, but a receipt, nonce, report digest, same UID, or pathname alone is not cleanup authority. The retained live directory/file leases are authoritative. No generation/device/inode value enters the native report, artifact name, log, or workflow output.

## 6. Portable hostile acceptance

All tests below use private scripted production-operation adapters. They execute no real sudo, namespace, mount, chroot, seccomp, `map_files`, compression tool, native selector, network, provider, or cloud operation.

### 6.1 Root/source cases

- wrong/replaced launcher, parser, closure, schema, bootstrap constant, Git row, revision, source-set digest, generation, owner, mode, and short read;
- replacement after runner hold but before sudo release proves the held bytes, not the replacement, are consumed;
- runner-owned checkout succeeds at runner admission while root never opens it; root-owned, “runner-or-root,” pathname fallback, and root fd-4 checkout routes are unreachable;
- root command is exact, environment empty, close-from-3 retained, fds exactly 0–2, and no checkout path appears in argv/capsule;
- capsule truncation, excess, duplicate/unknown fields, wrong cardinality/order, trailing packet, replay, wrong peer/parent/Python identity, and per-source/aggregate bounds;
- branch-removal sentinels prove no root/namespace effect before capsule admission.

### 6.2 Sandbox-only cases

- authenticated bootstrap selects only `sandbox-v1` and returns only `SandboxQualificationResult`;
- sentinels make any closure constructor, ELF parser, `map_files`, sealing, gzip, zstd, handoff, or runtime coordinator call fail the test;
- every root/namespace/map/capability/securebit/NNP/seccomp/fd/path/process/cleanup typed observation is independently missing, false, malformed, or reordered and prevents a later phase/result;
- before/after-effect cuts at parent/root create, mount/remount/readback, namespace owner, maps, child registration/release, PID 1, chroot, capability drop, policy install/readback/denials, result write, TERM/KILL/reap, unmount, and root removal;
- unsupported with proved cleanup, ordinary failure, and cleanup uncertainty remain three distinct outcomes;
- E rejects runtime-result substitution and derives its policy digest only from the observed sandbox result.

### 6.3 Integration/production-invoker cases

- exact integration result golden plus every missing, extra, renamed, false, wrongly typed, reordered, wrong-version, wrong-marker, wrong-source, and wrong-output mutation;
- before/after cuts for each transport create/register/close, fork, pidfd/identity phase, gate, write/read/EOF, malformed/oversized result, early exit, timeout, TERM, KILL, waitid, reap, and primary-plus-cleanup composition;
- child effects are impossible before complete registration; fd reuse and close uncertainty retire a lease once;
- source/bootstrap replay and cross-mode result substitution fail;
- static AST/import checks prove the integration driver contains no transport, namespace, or supervision implementation and invokes production exactly once.

### 6.4 Common/report cases

- every common baseline acquisition and reread is live; a driver cannot construct or copy a cleanup lease or pass booleans;
- exact `getdents64` enumeration excludes only its own fd and handles bounds, malformed records, closed stdio, fd reuse, and close uncertainty;
- common observes `/tmp/cogs-o2-runtime-v1`; any `/run/cogs-o2-runtime-v1` token fails;
- short/zero/interrupted writes and reads, schema/semantic disagreement, canonical drift, every fsync/fstat/open/reopen/close cut, no-replace collision, directory replacement, and supervisor/client crash;
- staged, published, and post-upload replacement at every cut preserves foreign state and prevents success;
- upload success, upload failure, duplicate cleanup, lost control endpoint, supervisor timeout/death, and cleanup-client death;
- every case proves either one exact validated publication followed by exact baseline restoration, or no authority artifact plus explicit terminal uncertainty.

Fixture manifests must be closed: declared = selected = consumed = oracle-proved. Token/regex-only assertions and preassembled all-true results are not accepting coverage.

## 7. Measured correction envelope

At the review head, exact gross additions from `bec0a19...` are: launcher **1,897/1,900**, launcher portable suite **790/800**, common **400/400**, E **449/450**, integration **350/350**, common test **197/200**, E test **112/180**, and integration test **107/150**. Native total is **3,811/4,000**. The trusted/portable counted text plus current fixture LF convention is approximately **7,899/8,930**. Thus this correction cannot fit ADR 0090's per-file or subtotal highs.

ADR 0091 should reserve the following readable highs for this slice. They are gross physical additions from the unchanged accounting predecessor, with no deletion, rename, generated-data, code-movement, compression, or packed-line credit.

| Surface | Reviewed gross | Planned final gross | Proposed hard high |
| --- | ---: | ---: | ---: |
| `completion_trusted_runtime_launcher.py` | 1,897 | 2,500–2,600 | 2,700 |
| `test/outcome-two-trusted-launcher-portable.py` | 790 | 1,080–1,140 | 1,200 |
| `scripts/native-qualification/common.py` | 400 | 650–700 | 750 |
| `scripts/native-qualification/job-e-sandbox.py` | 449 | 560–620 | 700 |
| `scripts/native-qualification/thin-integration.py` | 350 | 410–450 | 550 |
| `test/native-qualification-common.test.ts` | 197 | 390–440 | 500 |
| `test/native-qualification-e.test.ts` | 112 | 220–260 | 300 |
| `test/native-qualification-integration.test.ts` | 107 | 190–225 | 250 |

E and integration should become materially shorter by deleting duplicate bootstrap/transport code, but the estimates do not spend that deletion as permission for another surface. The launcher allowance pays for one shared production invoker, one bounded root bootstrap/capsule parser, and one sandbox-only coordinator—not three compatibility routes. The common allowance pays for one common baseline lease and one report-generation owner, not job mechanism ownership.

No E/integration correction requires changing the native report schema's check inventory or metadata disclosure, so its ADR 0090 high remains 300. Workflow wiring should remain within 300. If implementation proves either premise false, stop for a measured amendment rather than compressing schema/YAML or borrowing another file's allowance.

For this slice, raise the native subtotal from 4,000 to **5,400** and reserve a trusted/portable subtotal of at least **9,500**. These are minimum non-additive envelopes: the holistic ADR 0091 plan must recompute exact non-overlapping A/B, C/D, common, launcher, test, and aggregate totals before acceptance. This slice alone implies an overall Outcome Two production/portable/native aggregate of at least **14,500**; it is not authority to consume that aggregate in an unrelated file.

Stop and amend ADR 0091 before crossing a file/subtotal/aggregate high, adding an implementation surface or dependency, changing report disclosure/check inventory, adding a sudo mode, weakening source ownership, or moving production transport/security behavior into tests, fixtures, schema, or workflow YAML.

## 8. Correction and review order

1. Freeze `ea6e74f` as the blocked implementation input and preserve all final review records.
2. Correct common baseline/report-generation authority and its complete hostile adapter first.
3. Add runner-side held-source admission, the bounded root capsule/bootstrap, and production-owned outer invoker.
4. Add the sandbox-only production coordinator/result and route E exclusively to it.
5. Delete E's checked-out root exec and duplicate supervisor; delete integration's admission codec, namespace/fd transport, and supervisor.
6. Point all outer path observations at exact `/tmp/cogs-o2-runtime-v1`.
7. Complete the cross-file hostile matrices and exact gross remeasurement.
8. Obtain fresh independent source/root-bootstrap, sandbox, integration/supervision, common/report, portable-test, and holistic exact-head reviews with no unresolved P0–P3.
9. Only a later accepted execution decision may authorize one same-head attempt-1 native workflow. E and integration remain blocked until A–D, all six report transactions, upload cleanup, and the final required result are also clean.

No pass from portable tests can establish Linux applicability. No future E result grants closure/compression authority, and no future integration result grants AWS, provider, deployment, production, release, campaign, or issue-closure authority.
