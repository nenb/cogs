# Outcome 2 capability implementation gate — hostile review

**Status:** implementation and execution are blocked until the contract below is accepted.  
**Scope:** the proposed metadata-only GitHub-hosted runner capability probe, its tracked driver, closed schema, portable tests, and thin workflow.  
**Not authority:** this review does not authorize implementation, a workflow event, a probe attempt, native qualification, production closure work, artifacts, or any Outcome 2 claim.

## Authorities reviewed

- `OUTCOME-TWO-PLAN.md`.
- `.pi/outcome-two/capability.md` and the other four Wave 1 reports.
- `SECURITY.md`, `SECRET-INJECTION.md`, and `docs/security-evidence/README.md`.
- Accepted ADRs 0008, 0010, and 0052–0055.
- Existing exact-head/native workflow patterns and schema validation surfaces.

The controlling rule is narrower than “the script passed”: security claims require an applicability-aware authoritative profile. This probe is deliberately not one. Repository content and workload content are untrusted until the reviewed workflow/source boundary admits the exact bytes; sudo/root is part of trusted preparation, not an adversary against which this probe proves isolation.

## Gate verdict

**BLOCK.** `.pi/outcome-two/capability.md` is a useful field and operation inventory, but it is not implementable together with the requested tracked driver/schema/workflow without changing its contract. The no-checkout rule conflicts directly with tracked execution; sudo has an unresolved mutable-checkout trust path; output rules conflict with version output; and three different kinds of “report” are currently easy to confuse as authority.

Do not solve these conflicts by embedding a second implementation in YAML, copying the schema into Python, weakening exact-head checks, uploading the observation as evidence, or interpreting a denied capability as a qualified pass.

## Contradictions and required resolutions

| ID | Conflict | Hostile consequence | Required resolution |
|---|---|---|---|
| C1 | The capability design requires “no checkout action and no other action,” while the upcoming design calls for a tracked driver and tracked schema. | A tracked file cannot be executed without acquiring repository bytes. An inline YAML copy creates two implementations and defeats source/schema review. | Permit exactly one pinned `actions/checkout` step as a documented exception, followed by fixed shell verification and one direct tracked-driver invocation. No other action is permitted. Supersede the no-checkout sentence explicitly; do not silently violate it. |
| C2 | The design requires workflow permissions `{}`, but pinned checkout normally consumes the automatic token. | Claiming “no token” would be false; relying on an empty-token public checkout is unqualified behavior. | Job permission is exactly `contents: read`; checkout uses `persist-credentials: false`. The token may exist only inside the pinned checkout action. The driver, sudo child, probe children, and later steps receive no token or secret. Prove no Git extraheader/credential remains before invoking the driver. |
| C3 | “No repository content execution” conflicts with direct invocation of a tracked driver. | The stated trust boundary would be fiction. | Replace it with: no checked-out content executes before the fixed exact-head gate; the driver is the first and only checked-out executable content. Schema bytes are data only. This follows ADR 0055’s fresh-job ordering argument and is not a general pathname-integrity proof. |
| C4 | A source-head workflow digest does not prove which workflow GitHub executed. `github.sha`, `github.workflow_sha`, event merge SHA, base SHA, and PR head can differ. | A report can collapse synthetic envelope values into source identity or claim the checked-out workflow was executed. | Record every envelope value separately. Name the checked-out digest `source_head_workflow_blob_sha256`; never call it the executed-workflow digest. Exact-head review must bind GitHub’s external run record to the source blob. For this probe, that binding still grants no authority. |
| C5 | The workflow/driver may use sudo, while checkout files are runner-owned and writable. | Root opening or importing a checked-out helper creates a check/use race and lets a mutable checkout become root code authority. Root ownership checks on host tools do not fix this. | The tracked driver starts unprivileged. Any sudo command executes only fixed `/usr/bin/*` programs. Root Python receives a bounded helper already held as an in-memory driver constant over stdin, runs `-I`, uses an empty fixed environment, and never opens/imports the checkout or a runner-writable helper. Root output is a closed categorical record. |
| C6 | Sudo/root observations are phrased like independent proof of trust. | A trusted root helper can alter or fabricate host state; “root owned” can be mistaken for provenance. | State explicitly that GitHub host root and sudo are inside T0/T1 trust. The probe characterizes their behavior only. Root ownership/non-writability is an object policy check, not proof against a malicious trusted host. |
| C7 | The proposed global “fresh network namespace before any probing child” is not reconciled with runner-identity sudo tests, user-namespace cases, and possible denial of unprivileged network unshare. | The supervisor can become root, test the wrong identity, or fail before observing the capability it was meant to characterize. | Do not make successful global network unshare a bootstrap prerequisite. The supervisor performs no network operation; every executable child gets the fixed socket/io_uring seccomp denial before case work where technically possible. Network-namespace creation remains its own disposable observation. Any unavoidable pre-filter loader/runtime window is a documented T1 limitation, not “network denied” evidence. |
| C8 | Tool identity requires direct `O_NOFOLLOW` on `/usr/bin/python3`, while that fixed path can be a symlink. | The bootstrap tool can be classified absent/error even when the approved logical path exists; following it normally introduces a race. | Treat `/usr/bin/python3` as a bootstrap prerequisite and resolve every fixed logical tool through a bounded component-by-component, root-owned, non-writable symlink chain. Open the final component no-follow, hash through the held fd, and revalidate the chain/generation. Output only the approved logical path, never the resolved target. |
| C9 | Python is both the probe interpreter and an optional `ToolIdentity`. | If `/usr/bin/python3` is absent, no Python report can say it is absent. | Schema semantics require Python `present=true` for a complete report. Bootstrap failure produces job failure and no report, never a fabricated complete observation. |
| C10 | “No raw command output” conflicts with `version_line`; “no diagnostic hash derived from uncontrolled bytes” conflicts with `version_output_sha256`. | Public logs retain attacker-/host-controlled bytes or opaque digests with unclear privacy semantics. | Remove both fields and do not execute `--version`. Exact file SHA-256, bounded size, mode policy, and generation status are the tool identity for this probe. A future version-output need requires a new reviewed schema version. |
| C11 | The design says the final JSON is the only retained output, but checkout and workflow steps produce ordinary action logs. | Reviewers can be told a stronger disclosure claim than the workflow can meet. | Say “the probe process emits exactly one JSON line on stdout and no stderr on success.” Pinned-action and fixed-shell logs remain external GitHub envelope logs and must be separately disclosure-reviewed. No probe child output reaches them. |
| C12 | A supervisor crash, SIGKILL, or job timeout cannot reliably emit an incomplete JSON object. | An impossible output guarantee encourages partial/fabricated reports in shell cleanup. | A normal classified failure may emit one canonical `outcome=incomplete` report and then fail. Crash, SIGKILL, timeout, bootstrap failure, or encoder failure emits no report and fails the job. Workflow shell must not synthesize probe facts. |
| C13 | The report is described as canonical metadata, while capability says no evidence authority and native design later uploads qualification artifacts. | The probe log can be promoted accidentally into native, closure, or security evidence. | Keep `authority="none"`, `qualified=false`, and no upload action. Define the four report domains in the authority table below. Schema validity never promotes authority. |
| C14 | The schema-shaped field list is not a complete semantic contract. Many status/boolean combinations are impossible but schema-valid. | `state=denied` can coexist with a successful postcondition; cleanup uncertainty can coexist with `outcome=complete`. | Add a production semantic validator in the driver and an independent portable validator in tests. Couple every status to errno and nullable postconditions; `complete` requires every case classified and all cleanup booleans true with `uncertainty=false`, not every capability successful. |
| C15 | `O_TMPFILE`, mount, proc, namespace, seccomp, KVM, and sudo cases in one process can contaminate later cases. | A capability result can depend on earlier irreversible state or leaked privilege/mounts/fds. | The supervisor remains unprivileged and effect-minimal. Every irreversible or privileged case runs in a dedicated bounded child with a fresh pipe and exact cleanup. No case result is used as fallback setup for another; a missing prerequisite is `blocked`, not repaired. |
| C16 | “One report” plus retry/rerun prohibitions do not prevent GitHub reruns or concurrent label events. | Multiple attempts can be assembled into one apparently complete capability set. | Gate the only authorized event to run attempt 1, use non-cancelling concurrency, and require one separately approved exact-head event. A later attempt is a separate failed/non-authoritative observation and cannot fill fields. Never merge observations across run IDs or attempts. |

## Recommended secure integration contract

This is the contract the implementation decision should accept before code is written. If a different contract is chosen, stop and re-review rather than treating this document as partial approval.

### 1. Exact surfaces

Allow only these new or changed implementation surfaces:

```text
.github/workflows/outcome-two-runner-capability.yml
schemas/runner-capability-probe-v1alpha1.json
scripts/outcome-two-runner-capability.py
test/outcome-two-runner-capability.py
test/outcome-two-runner-capability.test.ts
scripts/validate-schemas.ts              # sample/semantic registration only, if needed
```

The driver must not import production closure, Kata, rootfs, launcher, provider, AWS, KVM qualification, or deployment modules. It may use only the Python standard library and fixed libc syscalls through a narrow local adapter. No generated executable, compiler, package install, dependency, lockfile, production file, existing CI job, or security-evidence schema is in scope.

Before implementation, record the exact predecessor and gross-addition highs per file and in total. Deletions give no credit; unused allowance is not transferable. Exceeding a high, needing another surface, or moving logic into YAML/tests to evade a high is an immediate replan stop.

### 2. Workflow boundary

The capability job is a fresh `ubuntu-24.04` job with:

- no container, service, matrix, cache, setup action, artifact action, secret context, or environment dump;
- one separately authorized, exact-head, same-repository event only; no push, schedule, broad PR, or standing-success route;
- `github.run_attempt == 1` and an externally reviewed one-event approval; this document supplies no such approval;
- `permissions: { contents: read }` solely for the pinned checkout exception;
- `timeout-minutes: 3`, non-cancelling concurrency, and no retry;
- exactly three steps: pinned checkout with exact head and no persisted credentials; fixed shell exact-head/clean-workspace/blob verification; direct `/usr/bin/env -i <fixed-public-controls...> /usr/bin/python3 -I -B scripts/outcome-two-runner-capability.py --workflow-bound`;
- the direct driver invocation as the first checked-out code executed; and
- no upload or post-processing step, including on failure.

The fixed shell gate must validate same repository, canonical exact head, checkout equality, clean tracked and untracked workspace, absence of persisted Git credentials/extraheaders, and SHA-256 of the driver, schema, and source-head workflow blobs against the corresponding Git blobs. These are source observations under the fresh-runner ordering assumption, not proof against a malicious T0.

Only these public control values may reach the driver in a newly constructed environment: repository; workflow path/job; event/action; run ID/attempt; PR number; head repository/SHA; base SHA; `github.sha`; `github.workflow_sha`; event merge SHA; runner image allowlist fields; and the three reviewed blob digests. `PATH`, `HOME`, `GITHUB_TOKEN`, complete `GITHUB_*`, `RUNNER_*`, proxy variables, and locale inherited from the runner are not passed. The driver uses fixed paths and supplies `LC_ALL=C` only where explicitly required.

### 3. Trust levels

- **T0 — external trusted envelope:** GitHub control plane, fresh hosted VM, runner, fixed workflow declaration, and the pinned checkout action. Its read-only token use is acknowledged.
- **T1 — reviewed trusted preparation:** the exact tracked driver after the fixed gate, fixed host executables, libc/kernel interfaces, and narrowly invoked sudo/root helpers. T1 may inspect and characterize the host but may not acquire or qualify production closure.
- **T2 — disposable case children:** fixed, bounded children that return only closed categorical records. They receive no checkout path, arbitrary argv, caller path, token, environment, namespace handle beyond the case, or authority field.

This probe has no untrusted workload and does not prove T1 resists a malicious GitHub host/root. Root helpers never interpret checkout bytes by pathname. Sudo descriptor-policy cases use a fixed minimal `-c` literal; larger root cases consume fixed helper bytes from stdin with `/usr/bin/python3 -I -`, empty environment, bounded output, and exact parent validation.

### 4. Operation ownership

The driver owns an explicit state machine:

```text
NEW -> BASELINED -> RUNNING -> CLEANING -> COMPLETE
                              \-> POISONED -> FAILED
```

Each child, fd, temporary name, mount, and namespace handle is registered before the next fallible operation. Every case has one deadline and one typed result. Cleanup attempts every independently safe reverse operation and aggregates errors. No broad process scan, group-wide unauthenticated kill, recursive delete, lazy/force unmount, fd enumeration as `close_range` success, retry, alternate path, or runner disposal counts as cleanup.

The final complete report is encoded only after exact children/fds/mounts/names/limits are restored. Cleanup uncertainty forces `outcome=incomplete`, `cleanup.uncertainty=true`, and job failure. If canonical failure reporting itself is unsafe, emit nothing and fail.

### 5. Revised report contract

Keep the field coverage from `.pi/outcome-two/capability.md`, subject to these changes:

1. Remove `ToolIdentity.version_line` and `version_output_sha256`; do not invoke tool version commands.
2. Require complete Python bootstrap identity rather than permitting Python absence in a complete report.
3. Replace ambiguous `source.workflow_sha256` with separate source and envelope records:
   - source: exact PR head, checkout SHA, driver SHA-256, schema SHA-256, and source-head workflow blob SHA-256;
   - envelope: repository, fixed workflow/job, event/action, run ID, attempt, PR number, base SHA, `github.sha`, `github.workflow_sha`, and event merge SHA.
4. Keep `authority="none"`, `qualified=false`, and `outcome="complete"|"incomplete"` as constants/closed enums.
5. Require lexical object keys, fixed array order, strict UTF-8, compact separators, integer-only numeric values, duplicate-key rejection, and exactly one LF. Maximum remains 32,768 bytes.
6. `ProbeStatus` coupling is exact:
   - `ok` => `errno=null` and all required postconditions non-null and successful;
   - `unsupported` => absent fixed object with `errno=null`, or only `ENOSYS`/`EOPNOTSUPP`;
   - `denied` => only `EPERM`/`EACCES`;
   - `blocked` => `errno=null`, named fixed prerequisite status non-`ok`, operation not attempted;
   - `mismatch` => syscall succeeded, `errno=null`, exact postcondition false;
   - `error` => another allowlisted numeric errno.
7. Null all postconditions not actually observed. Never infer a boolean from exit status alone.
8. `outcome=complete` means every fixed case has a valid categorical result and cleanup is exact. It does not mean capabilities are available and must not make the job pass if the separately accepted run policy requires a capability that was denied.
9. Output no arbitrary path, resolved symlink target, fd target, address, PID, UID/GID, inode/device, namespace/mount identity, maps text, command/argv, exception, errno string, environment value outside the public envelope allowlist, tool output, or diagnostic bytes/digest.

The JSON Schema is closed at every object. The driver’s semantic validator is authoritative only for producing its own non-authoritative record; independent AJV and test semantics must reject all adjacent impossible states.

### 6. Output and artifact authority

| Object | Retention | Authority |
|---|---|---|
| Capability-probe JSON | One line in ordinary GitHub job log; no upload | `none`; mutable-runner observation only |
| Native A–E report (future) | Separately reviewed exact-run artifact | Only that job’s exact primitive/run/attempt after hostile review |
| Trusted closure canonical report (future) | Sealed descriptor passed by production preparation | Runtime metadata authority inside its accepted integration contract; not CI evidence by itself |
| Security evidence report | Applicability-aware schema/profile under `docs/security-evidence/README.md` | Authoritative only when that profile and semantic validator say so |

No object inherits authority from another. A schema-valid capability log cannot be uploaded later and relabelled. A native artifact cannot authenticate production closure bytes from a different runner. If JSON and a human summary disagree, no human summary exists for this probe and no inference is permitted.

## Hostile implementation-review checklist

### Workflow and source

- [ ] A capability-specific decision explicitly accepts C1–C16 and the exact file/line scope.
- [ ] The event is narrow and dormant until separate one-attempt approval; this review is not that approval.
- [ ] Same-repository and exact-head checks occur before driver execution.
- [ ] `github.sha`, `github.workflow_sha`, event merge SHA, base SHA, head SHA, and checkout SHA remain separately named and validated against their own source.
- [ ] Only the pinned checkout action appears; no setup, cache, artifact, third-party, local composite, or `always()` cleanup action appears.
- [ ] Checkout is exact-head, credentials are not persisted, permissions are only `contents: read`, and no credential reaches the driver.
- [ ] The driver is the first and only checked-out executable content.
- [ ] YAML contains no Python, BPF, syscall wrapper, mount parser, report codec, or failure classifier.
- [ ] No existing CI/KVM/candidate workflow or trigger is broadened.

### Driver and privilege

- [ ] Driver entry requires `-I`, rejects optimized mode, rejects imports outside stdlib, and uses fixed absolute executables only.
- [ ] Production entry accepts no path, argv, fd number, executable, library root, timeout, case list, output path, or retry selector.
- [ ] Test seams are unreachable from `--workflow-bound` and cannot be selected by environment.
- [ ] Sudo invocations are exact, noninteractive, bounded, and use no environment preservation.
- [ ] Root never opens, imports, executes, chmods, chowns, mounts, or deletes the checkout.
- [ ] Root-helper bytes are fixed in the already-loaded driver; child input/output grammars are closed and bounded.
- [ ] Each privileged/irreversible case is isolated; it cannot change later case prerequisites.
- [ ] Symlink chains and final object generations are authenticated without outputting resolved targets.
- [ ] Python bootstrap failure cannot become a complete report.
- [ ] Missing/denied/unsupported is categorical observation, never fallback, skip, retry, or success.

### Bounds, lifecycle, and cleanup

- [ ] Supervisor deadline is 120 seconds within the 180-second job limit; every child has the declared 5/10-second deadline.
- [ ] Cumulative/live child, fd, path, byte, map-line, map-object, and output limits are enforced before effects.
- [ ] Sparse fd 4096 never becomes permission to open thousands of fds.
- [ ] Every acquired resource is registered before the next fault point.
- [ ] TERM/KILL/reap uses exact owned identity; no broad kill or process scan supplies authority.
- [ ] Mount cleanup uses exact owned targets and no lazy/recursive/force operation.
- [ ] Temporary cleanup is fd-relative and identity-bound; no `rm -rf` or adoption.
- [ ] Original soft `RLIMIT_NOFILE` and all applicable baselines are restored even on failure.
- [ ] Close/reap/unmount/unlink errors are aggregated; cleanup uncertainty cannot be rewritten as absence.
- [ ] Signal, timeout, and partial-initialization paths produce failure and no false complete report.

### Schema, codec, disclosure, and authority

- [ ] Schema is Draft 2020-12, strict, and `additionalProperties:false` recursively.
- [ ] Independent semantics enforce every status/errno/postcondition and outcome/cleanup coupling.
- [ ] Two fixture-mode executions produce byte-identical canonical bytes.
- [ ] Duplicate keys, floats, noncanonical numbers/escapes/order, invalid UTF-8, extra LF, and over-limit bytes fail.
- [ ] No version command runs and no child stdout/stderr is retained.
- [ ] Static forbidden-field/value canaries cover credentials, proxy values, arbitrary paths, maps, IDs, commands, output, and diagnostics.
- [ ] Success emits one JSON line and no driver stderr; failure emits at most one safe incomplete line.
- [ ] Workflow has no upload step and report constants remain `authority:none`, `qualified:false`.
- [ ] README/comments do not use “evidence,” “attestation,” “qualified,” “native pass,” or “runner guarantee” for this output except to deny those meanings.

## Exact required tests before any workflow attempt

The implementation decision may rename files only before implementation begins. Once accepted, these are required commands and cases; they are portable/static and do not invoke the real probe.

```text
/usr/bin/python3 -I -B test/outcome-two-runner-capability.py
npx --no-install tsx --test test/outcome-two-runner-capability.test.ts
npm run schemas
npm run format:check
npm run typecheck
git diff --check <accepted-exact-predecessor>...HEAD
```

`test/outcome-two-runner-capability.py` must use a scripted syscall/process adapter and execute production state/codec logic for:

1. one fully complete all-`ok` fixture and one complete mixed `unsupported`/`denied`/`blocked` fixture;
2. every allowed errno class and every forbidden status/errno pair;
3. every nullable postcondition when its operation was not attempted;
4. malformed, duplicate, extra, truncated, overlong, non-UTF-8, float, noncanonical, and reordered input/output;
5. absent Python bootstrap as hard failure and absent gzip/zstd/unshare as categorical observations;
6. fixed-path symlink-chain success, loop, depth overflow, mutable component, non-root owner, writable component, final replacement, short read, and size overflow;
7. descriptor exhaustion at every open/dup/pipe/memfd site;
8. child fork/exec/status/read/timeout/TERM/KILL/wait failures and malformed/overflow child records;
9. partial initialization and one injected failure after every resource acquisition/effect;
10. close, reap, unmount, unlink/rmdir, rlimit-restore, and baseline-compare failures, including multiple simultaneous cleanup errors;
11. repeat cleanup after success and after poison without false recovery;
12. two independent fixture runs producing byte-identical bytes and one-LF output;
13. output redaction canaries in environment, exception text, paths, maps, tool output, stderr, and helper messages; and
14. proof that no fixture/test selector is reachable in workflow-bound mode.

`test/outcome-two-runner-capability.test.ts` must independently:

1. compile the tracked schema with strict AJV;
2. validate one canonical golden object and reject one mutation for every required field, enum, bound, array cardinality/order, and additional property at every depth;
3. cross-check semantic status/errno/postcondition and outcome/cleanup mutations rather than relying on schema alone;
4. inspect workflow structure: exact trigger policy, run attempt, runner, timeout, permissions, pinned checkout, exact ref, `persist-credentials:false`, three-step order, and literal direct driver command;
5. reject forbidden workflow constructs/actions, heredoc programs, package/network commands, upload paths, wildcard paths, `continue-on-error`, retry, fallback, `always()`, and secret contexts;
6. inspect the driver for fixed executable paths and absence of production/cloud imports, PATH lookup, shell execution, package/network clients, and output/artifact paths; and
7. invoke the Python portable suite with bounded timeout and optimized-mode rejection.

`npm run schemas` must register a valid sample for the new schema and reject unknown top-level and nested properties. Tests must not call sudo, unshare, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, gzip/zstd, network, Docker, provider, cloud, or a workflow.

## Stop conditions

### Stop before implementation

- No accepted capability-specific decision resolves C1–C16.
- Exact predecessor, file ownership, and gross line highs are missing.
- The design still claims both tracked execution and no checkout/token/action.
- The workflow event and one-attempt approval mechanism are not separately defined.
- Any requirement depends on a capability value that has not yet been observed.

### Stop during implementation/review

- Any allowed file high or total high is reached; another file/dependency/action is needed.
- YAML starts carrying executable probe logic or tests duplicate production logic instead of driving it.
- Root opens the checkout, or sudo requires preserving a nonstandard high fd through hosted policy.
- The driver needs PATH, ambient imports/environment, package installation, network, retry, alternate executable, broad cleanup, or caller-selected input.
- A complete report can be emitted before cleanup, after uncertainty, or with impossible status coupling.
- Output contains uncontrolled bytes or the report exceeds 32,768 bytes.
- Workflow can upload, cache, comment, attest, publish, or persist the observation.
- Ordinary portable/schema/format/type/static tests are not all green at one exact clean head.
- Hostile review has any unresolved P0–P3 finding.

### Stop before the one real probe attempt

- No separate named approval binds the exact clean head, exact workflow/driver/schema blobs, event, run-attempt policy, and public-log disclosure.
- Quality for that exact head is not green, or any relevant blob changed afterward.
- The event is a fork, push, schedule, rerun, duplicate, unexpected label/action, or run attempt other than 1.
- Permissions, runner label, timeout, step list, trigger, action pin, or checkout ref differ from the reviewed contract.
- Any secret/credential exposure beyond the acknowledged pinned-checkout token, artifact, cache, package or network acquisition beyond the pinned checkout, KVM VM, container, cloud, provider, OpenTofu, AWS, production closure, or workload action is present.

### Stop after an attempted observation

- No canonical report exists, the report is incomplete, cleanup is uncertain, or job/run metadata disagree.
- Any raw/uncontrolled output escaped, or GitHub logs disclose more than the reviewed envelope.
- A rerun is proposed to fill a denied/missing/error field.
- Anyone proposes treating the observation as a pin, prerequisite guarantee, native qualification, runtime-closure result, security evidence, production permit, or issue-closure input.

A complete observation may inform the later architecture ADR. It may not directly change production policy. Any production/native design that relies on an observed value must state whether it is a portable prerequisite or a per-run assertion and must fail closed when it changes.

## Exit criterion for this gate

This gate is satisfied only when an accepted decision incorporates the secure integration contract, implementation stays within its exact surfaces/highs, all listed portable/static checks pass at one clean exact head, and a fresh hostile review signs off. Satisfaction permits only a separately approved single capability observation; it does not permit production implementation or confer Outcome 2 authority.
