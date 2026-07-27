# ADR 0087: Prepare the exact runtime closure before capability removal

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Exact planning and implementation-accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Supersedes: ADRs 0065–0086 only where they define Outcome 2 Phase B/runtime-discovery, the single native-runtime-preflight, post-drop host discovery, workflow-embedded security programs, their event sequence, or their numeric implementation highs. Their accepted records, observations, failed runs, and non-conflicting security and cloud boundaries remain history.
- Capability-gate resolution: Explicitly resolves C1–C16 in `/tmp/cogs-o2-cap-review/.pi/outcome-two/capability-implementation-gate.md`; conflicting probe wording in `.pi/outcome-two/capability.md` is superseded by section 4 below.

## Context

Outcome 1 ended at exact source `de027e33312be49e5b825c0abc7e864688ae2aaa`. ADR 0065 records hosted rootfs run `30218838605`, attempt 1, for that source. That rootfs result remains an Outcome 1 record; it is not Outcome 2 runtime-closure authority.

The later candidate branch attempted to discover Python, gzip, zstd, loader, and library state inside one increasingly large native sandbox. ADRs 0065–0070 coupled closure discovery to Phase B archives and one-shot candidate events. ADRs 0071–0086 then repeatedly changed checkout-descriptor, UID-map, mount, procfs, PID-namespace, and descriptor-limit mechanisms in response to hosted failures. The last candidate head, `d96b58ab55e932dda8b1cc007b7f88ad483f336e`, still failed before completing native preflight.

The useful observations are retained, but the trust boundary was wrong. In particular, a proc superblock created in the initial user namespace denied `map_files` after the child entered a later user namespace and dropped all capabilities. Requiring the untrusted child to rediscover the host closure made procfs and namespace ownership part of closure authority when they need not be.

The Wave 1 audits also found that the candidate implementation:

- inspected the already-import-heavy runner rather than a fresh exact Python helper;
- accepted unknown Python executable mappings;
- reopened gzip and zstd by pathname after authentication instead of sealing from the held authenticated generation;
- mixed closure resolution, mapping, archive execution, recovery, and cleanup in an 1,829-line process module;
- placed 386 lines of security behavior in workflow YAML; and
- lacked portable hostile coverage for host generation drift, mapped-closure changes, sealing failures, descriptor exhaustion, partial initialization, and complete cleanup.

Outcome 2 needs one trusted preparation boundary, portable hostile qualification, five independent native primitive jobs, and one thin integration—not another correction to the frozen candidate sandbox.

## Decision

### 1. Exact trust boundary and order

Outcome 2 has three ordered domains.

#### T0 — external execution envelope

For native evidence, T0 is the fresh GitHub-hosted job, reviewed workflow declaration, exact same-repository PR head, run ID and attempt, and separately named GitHub envelope, workflow, merge, base, and source-head identities. A synthetic merge SHA is never the source-head SHA. T0 grants only the authority explicitly claimed by that exact job and attempt.

#### T1 — tracked trusted preparation

Tracked, exact-head-authenticated code performs all host discovery and acquisition of host-object authority **before** chroot, final user/PID/mount namespace entry, capability removal, `no_new_privs`, and the workload seccomp boundary. T1 must complete all of the following:

1. Invoke tracked Python as fixed `/usr/bin/python3 -I -B` with an empty fixed environment and authenticated fixed import root.
2. Resolve only this compile-time table, with no `PATH` lookup or caller-selected path:

   ```python
   FIXED_TOOL_TABLE = (
       ("python3-parser", "/usr/bin/python3"),
       ("zstd", "/usr/bin/zstd"),
       ("gzip", "/usr/bin/gzip"),
   )
   ```

3. Authenticate every path component and final executable, loader, and library. Open final objects with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`; require regular files, UID 0, no group/world write bit, size `1..134217728`, and stable type, mode, UID, GID, device, inode, size, mtime, and ctime before and after complete bounded reading.
4. Parse strict ELF64 metadata from held descriptors. Require one interpreter, one loader, one provider per SONAME, ordered unique `DT_NEEDED`, no unresolved or ambiguous candidate, no duplicate role identity, no forbidden search/audit tag, at most 128 objects per tool, at most 512 MiB per tool, and at most 512 MiB across the deduplicated fixed closure. A bound failure is terminal.
5. Start a fresh, minimal, blocked helper from each exact authenticated executable. Before releasing input, read complete trusted `/proc/<pid>/maps` to EOF under a 4 MiB/4,096-line bound, open every executable nonzero-inode mapping through `map_files`, authenticate it against exactly one resolved object, permit only explicitly enumerated kernel synthetic mappings, reread maps byte-for-byte, and require exact resolved/mapped closure equality. Python is never represented by the long-lived preparation process.
6. Copy gzip and zstd directly from their still-held authenticated source descriptors into anonymous executable memfds. Use `MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC`, set mode `0555`, verify complete same-fd readback and source-generation stability, and require the exact seal profile `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE | F_SEAL_EXEC | F_SEAL_SEAL`. Unsupported required flags or missing seals fail; there is no pathname reopen or weaker profile.
7. Build, independently validate twice, and seal the canonical closure report defined below.
8. Terminate and exactly reap every helper, close every source/proc/map/status/temporary descriptor, and prove the preparation baselines restored before handoff.

No repository, workload, archive, package, environment, or caller value may add a path, library root, executable, argv, report field, descriptor number, cleanup name, or retry route to this phase.

#### T2 — untrusted qualification

Only after T1 has settled may the launcher construct the final read-only sandbox, install the fixed child fd table, enter the final namespaces/chroot, clear supplementary groups and all five capability sets, lock securebits `noroot`, set `no_new_privs`, and install the fixed seccomp deny policy.

T2 receives only stdin/stdout/stderr as fixed by the scenario, sealed gzip and zstd executable descriptors, one sealed report descriptor, and fixed data descriptors. It may hash and inspect those descriptors, check seals and report metadata, and execute one deterministic gzip and zstd workload. It may not inspect host `maps`/`map_files`, search `PATH`, resolve `/usr/bin`, inspect host library directories, reopen a reported object, acquire a package or archive, use a host network route, or expand the supplied authority.

If a proc mount is not required by the minimal sandbox workload, it is omitted. If one is required, the final user/PID/mount ownership tuple is created together and qualified only as a sandbox primitive; procfs is not used to rediscover host closure state.

### 2. Exact production APIs

Create a pure parser in `deploy/aws-feasibility/remote/completion_elf.py`. It exposes typed byte-input parsing only and accepts no path or descriptor:

```python
def parse_elf64(data: bytes) -> ElfMetadata: ...
```

Create the authority-bearing owner in `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` with this complete public API:

```python
def prepare_fixed_runtime_closure() -> PreparedRuntimeClosure: ...

class PreparedRuntimeClosure:
    @property
    def canonical_report(self) -> bytes: ...

    def settle_fixed_handoff(self) -> RuntimeClosureHandoff: ...
    def close(self) -> None: ...
    def __enter__(self) -> "PreparedRuntimeClosure": ...
    def __exit__(self, exc_type, exc, traceback) -> None: ...

@dataclass(frozen=True)
class RuntimeClosureHandoff:
    gzip_executable_fd: int
    zstd_executable_fd: int
    report_fd: int
```

`prepare_fixed_runtime_closure()` is the sole production constructor. It accepts no path, tool, environment, command, PID, report value, fd number, or policy override. Test fault seams are private and cannot be imported through the production entry point.

The owner state machine is exactly:

```text
NEW -> PREPARING -> READY -> HANDED_OFF -> CLOSED
                 \-> POISONED ---------> CLOSED only after proved recovery
```

`canonical_report` is available only in `READY`. `settle_fixed_handoff()` succeeds exactly once from `READY`, transfers ownership of exactly three `CLOEXEC` descriptors, and leaves no source/proc/helper descriptor in the owner. A second settlement fails. `close()` is a no-op only after a proved successful close; a poisoned or uncertain close repeats the same failure and never turns into success.

Create the fixed launcher in `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` with these public entry points only:

```python
def launch_fixed_runtime_qualification(
    handoff: RuntimeClosureHandoff,
) -> RuntimeQualificationResult: ...

def launch_fixed_sandbox_probe() -> SandboxQualificationResult: ...
```

Both calls consume the supplied handoff or internal resources on every path. They accept no argv, executable/path selector, mount source/target, fd target, environment, namespace option, seccomp option, timeout, or cleanup path. All descriptor numbers, mounts, inputs, deadlines, markers, and policies are module constants. The first call composes the one gzip/one zstd integration scenario; the second is Job E's minimal boundary probe and performs no closure discovery.

`completion_kata_process.py` remains outside this API and must not regain host-closure, map discovery, sealing, native harness, or archive-recovery ownership.

### 3. Exact trusted closure report

Track `schemas/trusted-runtime-closure-v1.json`. The schema ID/version literal is `cogs.trusted-runtime-closure/v1`. The top-level value is exactly:

```json
{
  "closure_sha256": "<lowercase-64-hex>",
  "tools": [
    {
      "closure_sha256": "<lowercase-64-hex>",
      "mapping_sha256": "<lowercase-64-hex>",
      "objects": [
        {
          "needed": [],
          "role": "executable",
          "sha256": "<lowercase-64-hex>",
          "size": 1,
          "soname": null
        }
      ],
      "seal_profile": null,
      "sealed_executable": false,
      "tool": "python3-parser"
    }
  ],
  "version": "cogs.trusted-runtime-closure/v1"
}
```

The schema is closed with `additionalProperties: false` at every object. JSON is strict UTF-8 with lexically sorted object keys, compact `,`/`:` separators, no duplicate keys, no floats, no non-JSON number, and exactly one terminal LF. The encoded report is at most 131,072 bytes.

Semantic constraints are exact:

- `tools` is exactly `python3-parser`, `zstd`, `gzip` in that order.
- Each `objects` array has exactly one executable first, exactly one loader second, then libraries ordered by SONAME UTF-8 bytes and SHA-256.
- `role` is only `executable`, `loader`, or `library`; `size` is `1..134217728`; `soname` is null only where the ELF object has no SONAME; and `needed` preserves ELF order with unique SONAME strings.
- Every needed SONAME has exactly one provider in the same tool closure. Every object appears once by authenticated identity.
- For Python, `sealed_executable` is false and `seal_profile` is null. For zstd and gzip, `sealed_executable` is true and `seal_profile` is exactly `linux-memfd-exec-seals-v1`.
- The per-tool `closure_sha256` is SHA-256 over canonical JSON bytes, without LF, of that tool's `objects` array.
- The per-tool `mapping_sha256` is SHA-256 over canonical JSON bytes, without LF, of the mapped unique sequence `[role, sha256]` after maps-before/maps-after equality and exact resolved/mapped equality. It is evidence of mapping validation, not an address digest.
- The top-level `closure_sha256` is SHA-256 over canonical JSON bytes, without LF, of the `tools` array after omitting each `mapping_sha256` and retaining the per-tool closure digest and seal fields.

The report contains no fd number, host/library/checkout path, address, map line, environment, command output, PID, account, device/inode, timestamp, run identifier, archive data, or cleanup claim. Private source generations remain owner state and are never report metadata. The report is validated by the tracked schema and an independent semantic codec, re-encoded byte-identically twice, and delivered through a read-only memfd with the same write/grow/shrink/future-write/seal protections. It is not issued until preparation cleanup succeeds.

### 4. Capability probe is observation, never authority

The capability probe is a separate, effect-minimal runner observation. This subsection supersedes the conflicting no-checkout, permission, repository-execution, global-network-namespace, tool-version, output, incomplete-report, artifact, semantic, process-isolation, and rerun wording in `.pi/outcome-two/capability.md`. It resolves C1–C16 as follows.

#### C1–C4 — checkout, credential, code, and source boundary

- **C1:** Permit exactly one action: pinned `actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` at the exact same-repository PR head. This is the explicit exception to the earlier no-checkout/no-action rule. No setup, cache, artifact, upload, local, composite, or other action is permitted.
- **C2:** Workflow/job permission is exactly `contents: read`, solely for checkout, with `persist-credentials: false`. The checkout token may exist only inside the pinned action. Before driver invocation, fixed workflow shell proves that no Git credential helper, credential-bearing remote, or HTTP extraheader remains. No token or secret reaches the driver, sudo/root helper, case child, or later step.
- **C3:** No checked-out content executes before a fixed shell gate verifies same repository, canonical PR-head SHA, checkout `HEAD`, a clean tracked/untracked workspace, credential cleanliness, and the source-head workflow/driver/schema blob digests. `scripts/runner-capability-probe.py` is the first and only checked-out executable content. The schema and tests are data/review surfaces and are never executed by the observation workflow. This fresh-runner order is a reviewed trust admission, not a general pathname-integrity claim.
- **C4:** The report keeps PR head, checkout SHA, base SHA, `github.sha`, `github.workflow_sha`, and event merge SHA as separately named values. The checked-out workflow digest is named `source_head_workflow_blob_sha256`; it is never called the executed-workflow digest. External exact-head review may bind GitHub's run record to the source blob, but that binding cannot promote this probe above authority `none`.

The fixed workflow has exactly three steps: pinned checkout; the fixed non-repository shell gate; then direct `/usr/bin/env -i ... /usr/bin/python3 -I -B scripts/runner-capability-probe.py --workflow-bound`. Only allowlisted public source/envelope controls and the reviewed workflow/driver/schema blob digests enter that newly constructed environment. Ambient `PATH`, `HOME`, token, proxy, locale, and complete `GITHUB_*`/`RUNNER_*` environments do not.

#### C5–C9 — privilege, isolation, fixed tools, and bootstrap

- **C5:** The tracked driver starts unprivileged. Every sudo command is noninteractive, bounded, and invokes only fixed `/usr/bin/*` programs with no environment preservation. Root never opens, imports, executes, chmods, chowns, mounts, deletes, or otherwise resolves the checkout. A larger root Python helper is an already-loaded immutable driver constant sent over stdin to `/usr/bin/python3 -I -` with an empty fixed environment; root output is one closed bounded categorical record. No checkout fd or runner-writable helper crosses sudo.
- **C6:** GitHub host root and sudo are inside trusted T0/T1. The probe characterizes their behavior; it does not prove resistance to malicious host/root. Root ownership and non-writability are object-policy observations, not provenance against that trusted host.
- **C7:** There is no global network-namespace prerequisite. The unprivileged supervisor performs no network operation. Network-namespace creation is one disposable observation and is never setup for another case. Each executable child receives fixed socket/io_uring seccomp denial before case work where technically possible; an unavoidable loader/runtime pre-filter window is a documented T1 limitation, not network-denial evidence.
- **C8:** `/usr/bin/python3` is the bootstrap prerequisite. Every approved logical tool path is resolved through a bounded component-by-component root-owned, non-group/world-writable symlink chain. The final component is opened no-follow, hashed through the held descriptor, and the chain and generation are revalidated. Only the approved logical path is reportable; a resolved target is never output.
- **C9:** A complete report requires Python `present=true` with a successful authenticated identity. Missing, mutable, or unauthenticated bootstrap Python fails the job and emits no report; it cannot be represented as a complete absent-tool observation.

The probe has no untrusted workload. T2 consists only of disposable, fixed, bounded case children receiving no checkout path, arbitrary argv, caller path, token, ambient environment, persistent namespace handle, or authority selector.

#### C10–C13 — output and authority

- **C10:** `ToolIdentity` has no `version_line` or `version_output_sha256`. The driver executes no `--version` command. Tool identity consists only of approved logical path, bounded size, SHA-256, mode/ownership policy, symlink-chain policy, generation result, presence, and categorical status.
- **C11:** On success the probe process emits exactly one canonical JSON line on stdout and no stderr. Probe-child output is captured, validated categorically, and never reaches the log. Pinned checkout and fixed shell output remain external GitHub envelope logs and require disclosure review; the ADR does not claim the JSON is the job's only log content.
- **C12:** A normal safely classified failure may emit at most one canonical `outcome="incomplete"` line and then fails the job. Crash, SIGKILL, job or supervisor timeout, Python bootstrap failure, codec/encoder failure, or unsafe cleanup uncertainty may emit no report and must fail. Workflow shell never synthesizes or completes probe facts.
- **C13:** The JSON appears only as one line in the ordinary attempt-1 GitHub job log. There is no upload, artifact, cache, summary, comment, attestation, publication, wildcard output, or post-processing step, including on failure. It always contains `authority="none"` and `qualified=false`; schema validity, external source binding, or a complete outcome cannot turn it into native qualification, closure metadata, security evidence, production authority, or a runner guarantee.

The four report domains remain disjoint: a capability log has no authority; a future native A–E artifact has only its reviewed exact-run primitive authority; a trusted closure report is runtime metadata only inside its accepted handoff; and a security-evidence report is authoritative only under an applicability-aware profile in `docs/security-evidence/README.md`. No report inherits authority from another.

#### C14–C16 — semantic coupling, case ownership, and one attempt

- **C14:** `schemas/runner-capability-probe-v1alpha1.json` is recursively closed Draft 2020-12 JSON Schema, and the driver has a production semantic validator independently challenged by portable tests. For every `ProbeStatus`: `ok` requires `errno=null` and every required postcondition observed and successful; `unsupported` permits an absent fixed object with null errno or only `ENOSYS`/`EOPNOTSUPP`; `denied` permits only `EPERM`/`EACCES`; `blocked` requires null errno, one named fixed prerequisite non-`ok`, and no attempted operation; `mismatch` requires a successful syscall, null errno, and an exact false postcondition; `error` requires another allowlisted numeric errno. Every unobserved postcondition is null. Exit status alone never supplies a boolean. `outcome="complete"` requires every fixed case categorically classified, all cleanup booleans true, and `cleanup.uncertainty=false`; it means neither availability nor qualification.
- **C15:** The supervisor remains unprivileged and effect-minimal. Its state is exactly `NEW -> BASELINED -> RUNNING -> CLEANING -> COMPLETE` or `RUNNING/CLEANING -> POISONED -> FAILED`. Every privileged or irreversible sudo, tmpfile, mount, proc, namespace, seccomp, KVM, and descriptor-limit case runs in a dedicated bounded child with a fresh closed pipe, case deadline, pre-registered resources, and exact cleanup. No case result changes another case's setup or selects a fallback; a missing prerequisite is `blocked`, not repaired. Cleanup attempts every independently safe reverse action, restores fd/child/mount/name/namespace/rlimit baselines, aggregates failures, and cannot turn uncertainty into absence.
- **C16:** The workflow trigger is only same-repository `pull_request` `labeled` with exact label `outcome-two-runner-capability`; a separate approval must bind that one event to the exact clean head and reviewed blobs. The job requires `github.run_attempt == 1`, uses PR-scoped non-cancelling concurrency (`cancel-in-progress: false`), has a three-minute job timeout and 120-second supervisor deadline, and permits no retry. A duplicate label event, rerun, later attempt, concurrent run, or different run ID is a separate non-authoritative observation and may not fill, replace, or merge any field. This ADR supplies no event approval and authorizes no attempt.

#### Exact capability report changes

The schema version remains `cogs.runner-capability-probe/v1alpha1`, with lexical object keys, fixed array order, strict UTF-8, compact separators, integer-only numbers, duplicate-key rejection, exactly one LF, and a 32,768-byte maximum. It retains the field coverage in `.pi/outcome-two/capability.md` subject to these controlling changes:

- `source` contains exact PR head, checkout SHA, driver SHA-256, schema SHA-256, and `source_head_workflow_blob_sha256`.
- `envelope` separately contains repository, fixed workflow/job, event/action, run ID, attempt, PR number, base SHA, `github.sha`, `github.workflow_sha`, and event merge SHA.
- `authority` is exactly `none`, `qualified` is exactly false, and `outcome` is exactly `complete` or `incomplete`.
- Python identity is mandatory for `complete`; gzip, zstd, and unshare absence remains categorical.
- Tool version fields and commands are absent.
- No arbitrary/resolved path, fd target, address, PID, UID/GID, inode/device, namespace/mount identity, maps text, command/argv, exception, errno string, environment outside the public envelope allowlist, child/tool output, diagnostic bytes, or diagnostic digest is allowed.

Historical candidate failures and a future complete probe remain observations about one runner only. The production architecture does not depend on a favorable value. Required primitives are asserted by their production owner and qualified by applicable same-head native Jobs A–E. Missing, denied, unsupported, changed, mismatched, or uncertain behavior never selects a production fallback. KVM remains outside Outcome 2 and under ADR 0010.

#### Exact capability implementation surfaces

Only these five implementation surfaces are permitted:

```text
.github/workflows/outcome-two-runner-capability.yml
schemas/runner-capability-probe-v1alpha1.json
scripts/runner-capability-probe.py
test/runner-capability-probe.test.ts
test/outcome-two-runner-capability-workflow.test.ts
```

The driver is standard-library-only and imports no production closure, Kata, rootfs, launcher, provider, AWS, KVM-qualification, or deployment module. No generated executable, compiler, dependency, lockfile, production file, existing CI workflow/job, schema registry, or sixth capability surface is in scope. Portable tests must drive scripted state/syscall/process adapters, strict schema and independent semantic mutations, canonical determinism, hostile lifecycle/cleanup cuts, workflow structure, forbidden disclosures/imports/actions, and proof that fixture/test selectors are unreachable from `--workflow-bound`. They invoke no real sudo, namespace, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, compression tool, network, container, provider, cloud, or workflow.

No capability implementation or observation may begin until these exact contracts receive a clean hostile review with no unresolved P0–P3 finding. A separate approval is still required for one exact-head attempt-1 observation.

### 5. Portable qualification owns hostile branches

Ordinary tests use bounded synthetic ELF, map, fd, process, report, and fault fixtures to drive production calls. They must cover at least:

- valid closure; missing loader/library; duplicate candidate; SONAME/role mismatch; unknown interpreter; forbidden tag; object and byte bounds;
- mode/owner/generation drift, replacement and short read before, during, and after authentication;
- stable exact mappings, maps drift, unknown/unopenable/ambiguous mapping, missing role/dependency, and map bounds;
- seal success plus partial write, fsync, readback, digest, source drift, `F_ADD_SEALS`, `F_GET_SEALS`, and close failures;
- descriptor exhaustion at every open site, partial initialization, handoff failure, helper setup/exec/wait/reap failure, primary-plus-cleanup errors, fd reuse, and double close;
- crash/recovery from a fresh supervisor process with no inherited module state;
- two independent byte-identical reports, enumeration-order independence, digest mutation, duplicate key, noncanonical bytes, schema rejection, and prohibited metadata; and
- no residual tracked descriptor, child, file, mount, namespace handle, or checkout mutation.

Native jobs do not duplicate these parser, schema, injected-fault, or recovery matrices.

### 6. Native Jobs A–E and thin integration

After Quality and all portable suites pass, one workflow creates five independent jobs on fresh runners. They share no artifact, process, state directory, ordering, or runner. They run in parallel from the same exact source head:

- **A — runtime mappings:** exact real Python ELF closure, fresh blocked Python helper, trusted-side `map_files`, mapping stability/equality, and exact cleanup.
- **B — compression executables:** exact gzip/zstd source generations, required sealed executable descriptors, `execveat(AT_EMPTY_PATH)`, fixed deterministic decompression, no PATH/network/unexpected child or mapping, and exact cleanup.
- **C — descriptor behavior:** measured hard/soft `RLIMIT_NOFILE`, soft normalization to exact 8,193 only when hard capacity permits, exact fds 198 and 4,096, genuine production `close_range`, CLOEXEC/inheritance, limit restoration, and exact cleanup.
- **D — process lifecycle:** PDEATHSIG before and after release, parent handshake, pidfd plus start-time identity, owned session/process group, bounded TERM/KILL, exact descendant reap, and exact cleanup.
- **E — sandbox boundary:** same-namespace trusted mount setup, read-only checkout, final user/PID/mount/network namespaces, PID 1 where required, chroot, locked `noroot`, all capability sets zero, NNP, fixed socket/io_uring/namespace/seccomp-replacement denial, no acquisition route, unchanged checkout, and exact mount/namespace/process cleanup. E does not inspect `map_files`, parse ELF, run gzip/zstd, or repeat C/D.

Only Job E may use `sudo`, through fixed noninteractive default close-from-3 behavior. No job installs a package, downloads, uses KVM, starts Kata/containerd/Docker, contacts cloud services, or treats an environment limitation as pass.

Workflow YAML contains only exact-head gates, job declarations, permissions, `needs`, timeouts, fixed tracked-script invocations, and exact report upload. ELF parsing, seccomp programs, mount parsing, supervision, failure classification, and cleanup live in tracked code.

Track `schemas/native-qualification-report-v1alpha1.json`. Every job emits one canonical metadata-only value with fixed version, job enum, separately named source/envelope/workflow/merge/base identities, workflow and driver blob digests, run/attempt, allowlisted runner/kernel metadata, authority `exact-run-native-qualification`, result, ordered fixed check IDs, bounded job-specific digest/size metadata, and explicit descriptor/child/path/mount/namespace/limit/checkout cleanup booleans. It contains none of the prohibited closure-report data plus no raw diagnostic, argv, proc row, UID/GID, mount ID, hostname, generated byte, or credential. A pass report is finalized only after all applicable cleanup booleans are true.

Only after A–E pass on the same exact clean head and run attempt may `native-closure-integration` run on a sixth fresh runner. It does not download or trust A–E artifacts. It calls the production closure owner and fixed launcher, passes only the fixed sealed descriptors and report, runs one gzip and one zstd input, and proves the exact marker/digest plus no linked evidence, descriptor, child, checkout change, mount, pathname, or namespace residue. It does not repeat internal A–E or portable matrices.

A–E and integration reports qualify only their own exact source, workflow blobs, run, attempt, and reviewed applicability. They grant no Phase B archive event, AWS, provider, OpenTofu, deployment, production, release, or issue-closure authority.

### 7. Exact cleanup contract

Every owner registers a descriptor, child identity, path, or mount **before** the next fallible effect. Cleanup runs in reverse order and attempts every independently safe action while preserving the primary error.

The trusted supervisor records exact pre-effect fd, child, mount/namespace, `RLIMIT_NOFILE`, private-state-root, and checkout baselines. Cleanup must:

1. close release/input gates;
2. revalidate each child by pidfd, PID start time, session, process group, and expected executable identity;
3. send TERM, wait to a fixed deadline, send KILL only to still-matching identities, and reap every child/descendant;
4. close every tracked descriptor and aggregate all close failures;
5. unmount only exact owned mounts while in their owning namespace, without lazy/force/recursive unmount;
6. unlink/rmdir only exact names authenticated through retained parent descriptors, without `rm -rf`;
7. restore the original soft descriptor limit if changed;
8. prove the exact source head and checkout porcelain unchanged; and
9. recompare every baseline and prove all owner registries empty.

No broad process scan is signaling authority; no module-global fd/child set is cleanup authority; no runner disposal is cleanup evidence. A failed close, failed reap, foreign/replaced object, unexpected resource, inability to compare, timeout, or other uncertainty is terminal and prevents a pass report or handoff. After handoff, the launcher owns the three descriptors and applies the same rule. On trusted-process crash, its fixed outer supervisor owns recovery; anonymous fds close on process death, PDEATHSIG children are still revalidated/reaped, and any named/mount state is removed only by retained exact authority.

## Measured readable highs

All highs count gross added physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`, with no deletion, rename, generated-file, compression, or code-movement credit. Blank/comment lines count because readable presentation is required. Highs are non-transferable; the aggregate does not permit a file to cross its own high.

The closure highs are based on the measured 162-line parser span, 925-line candidate host-discovery region, 55-line shared sealing region, 1,180–1,690 Wave 1 production/schema estimate, and 1,000–1,500 portable-test estimate. Native highs are based on the measured 386-line embedded workflow and 1,523 gross-addition historical five-surface harness.

### Non-authoritative capability observation

| Exact capability surface | Hard high |
| --- | ---: |
| `.github/workflows/outcome-two-runner-capability.yml` | 80 |
| `schemas/runner-capability-probe-v1alpha1.json` | 650 |
| `scripts/runner-capability-probe.py` | 1,600 |
| `test/runner-capability-probe.test.ts` | 400 |
| `test/outcome-two-runner-capability-workflow.test.ts` | 100 |
| **Capability subtotal and hard high** | **2,830** |

The capability hard high is **2,830 gross physical lines** from the same exact predecessor. It is separate from, and grants no credit to or from, the 7,000-line Outcome 2 production/portable/native/integration high below. Unused capability allowance is non-transferable to another capability surface or any production surface. Capability code supplies no production implementation authority.

### Trusted closure, launcher, schema, and portable qualification

| File/surface | Hard high |
| --- | ---: |
| `deploy/aws-feasibility/remote/completion_elf.py` | 240 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | 1,220 |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | 600 |
| `schemas/trusted-runtime-closure-v1.json` | 230 |
| `scripts/validate-schemas.ts` Outcome 2 registration only | 30 |
| `test/outcome-two-runtime-closure-portable.py` | 250 |
| `test/outcome-two-mapped-closure-portable.py` | 240 |
| `test/outcome-two-sealing-portable.py` | 210 |
| `test/outcome-two-lifecycle-portable.py` | 290 |
| `test/outcome-two-recovery-portable.py` | 290 |
| `test/outcome-two-runtime-report-portable.py` | 230 |
| `test/outcome-two-trusted-launcher-portable.py` | 280 |
| `test/outcome-two-portable.test.ts` | 120 |
| `test/fixtures/outcome-two/**` aggregate | 500 |
| **Trusted/portable subtotal** | **4,730** |

### Native qualification and integration

| File | Hard high |
| --- | ---: |
| `.github/workflows/ci.yml` gross Outcome 2 addition | 180 |
| `schemas/native-qualification-report-v1alpha1.json` | 150 |
| `scripts/native-qualification/common.py` | 220 |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 160 |
| `scripts/native-qualification/job-b-compression.py` | 180 |
| `scripts/native-qualification/job-c-descriptors.py` | 140 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 180 |
| `scripts/native-qualification/job-e-sandbox.py` | 240 |
| `scripts/native-qualification/thin-integration.py` | 170 |
| `test/native-qualification-common.test.ts` | 120 |
| `test/native-qualification-a.test.ts` | 70 |
| `test/native-qualification-b.test.ts` | 70 |
| `test/native-qualification-c.test.ts` | 60 |
| `test/native-qualification-d.test.ts` | 70 |
| `test/native-qualification-e.test.ts` | 100 |
| `test/native-qualification-integration.test.ts` | 90 |
| **Native subtotal** | **2,200** |

The Outcome 2 production, portable, native, and integration implementation hard high is **7,000 gross physical lines**, separate from the capability probe's 2,830. The production-listed per-file highs total 6,930; the remaining 70-line aggregate margin is not transferable to a listed file and authorizes no unlisted file. Stop and adopt a new ADR before crossing either separate aggregate or any file high, adding an implementation file, moving security behavior into YAML/tests/generated data, compressing readable control flow, or changing an API, schema, trust boundary, primitive claim, cleanup rule, job, or integration scenario.

## Integration order and gates

1. Preserve Outcome 1 and the frozen ADR 0065–0086 candidate history.
2. Implement the capability probe only on the five exact surfaces above, complete its portable/static review, then stop for a separate exact-head approval before one attempt-1 metadata-only log observation. Do not upload it or use it as a production prerequisite.
3. Implement the parser, trusted closure owner, schema, launcher, and portable hostile suites from the exact predecessor above; the independent 7,000-line production high is unchanged by capability implementation.
4. Obtain independent trust-boundary, descriptor/process, filesystem/cleanup, schema/determinism, and native-environment reviews with no unresolved P0–P3 finding.
5. Add and qualify Jobs A–E in parallel after Quality.
6. Run thin integration only after same-head A–E success.
7. Bind final evidence to one exact clean head, workflow blobs, run, attempt, artifacts, measured lines, and hostile review.

No implementation or workflow execution is performed or authorized by this documentation commit itself. Every existing mandatory AWS, cloud, provider, OpenTofu, deployment, production, campaign, and issue-closure stop remains in force.

## Consequences

Host-object authority is established while trusted procfs and fixed host paths are legitimately available, then reduced to sealed descriptors and canonical metadata before capability removal. The untrusted phase verifies supplied authority rather than rediscovering the host. Portable suites own branch complexity; native jobs prove only kernel- and runner-sensitive primitives; integration remains thin.

This deliberately abandons the candidate's monolithic Phase B/native-preflight mechanisms and numeric caps. It does not rewrite or delete those accepted ADRs, deny their recorded observations, or retroactively turn failed executions into success. They remain the history explaining why this architecture supersedes them.
