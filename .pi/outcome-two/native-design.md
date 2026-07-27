# Outcome 2 native-proof design

Status: Wave 1 design only; no implementation or execution was performed.

Planning baseline: `908041cf6473c10667a030c11c6798cb2338c5d4` (`research/outcome2-native`).
Historical audit target: `d96b58ab55e932dda8b1cc007b7f88ad483f336e` (`feat/issue42-candidate-tar-remediation`).

## Decision summary

Outcome 2 should use five small, independent, same-head native jobs. They run in parallel after Quality:

- **A — runtime mappings:** real ELF/Python closure and trusted-side `map_files`.
- **B — compression executables:** sealed gzip/zstd execution and deterministic decompression.
- **C — descriptor behavior:** `RLIMIT_NOFILE`, high descriptors, `close_range`, CLOEXEC, and exact inheritance.
- **D — process lifecycle:** PDEATHSIG, identity, TERM/KILL, process groups, and exact reap.
- **E — sandbox boundary:** mounts/chroot, namespaces, zero capabilities, NNP, seccomp, and a read-only checkout.

There is no A-to-B-to-C sequencing. Each job gets a fresh runner, makes its own baselines, invokes only its own tracked driver, emits only its own canonical metadata report, and proves its own cleanup. A later thin integration job depends on all five but does not repeat their internal matrices.

The native implementation belongs in tracked scripts. Workflow YAML may declare jobs, exact-head inputs, timeouts, permissions, and artifact upload; it must not contain Python programs, mount parsers, seccomp programs, process supervisors, failure classifiers, or cleanup algorithms.

## Historical audit and lessons

### What the candidate branch became

Against exact preflight baseline `18f26441b6115091233d0c4cd44ced8f058d014f`, the final candidate has these no-rename gross additions:

| Surface | Gross additions | Gross deletions |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` | 386 | 0 |
| `test/aws-stage2-completion-kata-process.py` | 436 | 254 |
| `test/aws-stage2-completion-kata-process.test.ts` | 50 | 20 |
| `test/stage2-phase-a-candidate.py` | 181 | 0 |
| `test/stage2-phase-a-candidate.test.ts` | 470 | 50 |
| **Total** | **1,523** | **324** |

The native job itself occupies all 386 lines from line 299 through line 684 of the candidate workflow. The workflow grew from 298 physical lines at the clean Outcome 2 planning head to 684 lines on the candidate. Forty-two first-parent commits touched `.github/workflows/ci.yml` after `18f2644`.

The 386-line job embeds several distinct programs and policies: checkout/evidence ownership, descriptor observers, mount construction, two mountinfo parsers, a descriptor bind wrapper, a 59-instruction seccomp program, a final namespace launcher, an outer evidence manager, a large diagnostic classifier, and two native test invocations. This is production-like security code hidden in YAML, not thin CI wiring.

### Failure-driven architecture churn

The retained ADR and commit history is useful research, but it is not a design to extend:

| History point | Observed or reviewed problem | Durable lesson |
| --- | --- | --- |
| ADR 0071 | QEMU returned `ENOSYS` for required `close_range`; native Linux was genuinely needed. | Keep only kernel-sensitive facts native; parser/fault matrices remain portable. |
| ADRs 0071–0074 | `/sandbox` assumptions, incomplete mount identity, output byte grammar, and duplicated portable matrices drove large harnesses. | Use tracked code, private owned state, strict metadata, and do not retest portable branches natively. |
| `d87ff2e` / ADR 0076 | Root-only mapping could not traverse the runner-owned checkout. | Authenticate/open host objects on the trusted side, before capability removal. |
| `e4650ab` / ADR 0078 | Hosted sudo policy rejected preserving fd 3 via a changed close boundary. | Characterize sudo first; do not make all jobs depend on a non-default sudo policy. |
| `d53b116` / ADR 0079 | Exact Bash fd-number assumptions failed on CLOEXEC interpreter state. | Put fd lifecycle in a tracked process, not Bash internals or shell observers. |
| `3dd2b0e` / ADR 0080 | External `mount` could not bind the proc-fd source. | Use a narrow tracked syscall wrapper where a syscall is the primitive under proof. |
| `bed2d05` / ADR 0081 | An `O_PATH` fd opened in the wrong mount namespace produced `EINVAL`. | Open and consume authority in the same trusted mount namespace. |
| `9cb67fd`–`7128579` / ADRs 0082–0083 | Checkout-owner mapping depended on util-linux overwrite/subordinate-ID behavior. | Finish host-object preparation while trusted; do not map arbitrary checkout owners into the untrusted phase. |
| `7282309` / ADR 0084 | Inherited soft `RLIMIT_NOFILE` was too low for fd 4096. | Descriptor normalization is its own measured primitive (Job C), not incidental sandbox setup. |
| `86e6974` / ADR 0085 | Parent-user-namespace-owned proc denied zero-capability `map_files`. | Perform mapped-closure discovery at the trusted boundary (Job A); do not require it after capability removal. |
| `d9ef36e` / ADR 0086 | Child-user-namespace proc creation failed because the retained PID namespace had a different owner. | Job E should prove sandbox controls without rediscovering the host closure; if proc is needed, user/PID/mount ownership must be created as one reviewed tuple. |
| `d96b58a` | The branch ends with another fixed final-namespace failure classification, not a recorded passing final preflight. | Stop speculative correction chains. Probe capabilities, split primitives, and change one bounded owner at a time. |

The accepted security policy and ADRs add four constraints:

1. A process-local script cannot prove that its visible PID 1 is the hosted runner init. Authority is the composite of reviewed workflow declaration, GitHub execution envelope, exact source head, and script observations (ADR 0052).
2. Synthetic merge/envelope SHAs and the tested PR-head SHA are separate fields and must never be collapsed (ADR 0053).
3. Native evidence qualifies only its exact run, attempt, workflow blob, and reviewed source revision; it does not promise future runner capability (ADRs 0010, 0052–0055).
4. Reports and logs contain metadata only—no source, arbitrary paths, commands, maps, addresses, raw output, credentials, or environment dumps (ADR 0008 and `docs/security-evidence/README.md`).

## Exact trust boundary

### T0: externally trusted execution envelope

The authority root is:

- GitHub's control plane and immutable run/event metadata;
- one fresh GitHub-hosted `ubuntu-24.04` VM per job;
- the reviewed job declaration in `.github/workflows/ci.yml`;
- the existing pinned `actions/checkout` revision;
- same-repository `pull_request` only;
- job-level `contents: read`, no service, container, matrix, cache, credential, or secret;
- `persist-credentials: false`; and
- the exact run ID and run attempt.

A local run, Docker run, script-emitted “host” classification, namespace-local PID 1, or copied report is non-authoritative. A rerun is a distinct observation, never a representation of attempt 1.

### T1: reviewed trusted preparation

After checkout, but before any other checked-out code, fixed workflow shell must:

1. require the event head repository to equal `github.repository`;
2. require the event PR head to be canonical lowercase 40-hex;
3. require checkout `HEAD^{commit}` to equal that exact PR head;
4. require a clean tracked/untracked workspace;
5. record the source-head workflow blob SHA-256 and selected driver/common blob SHA-256 values;
6. retain `github.sha`, `github.workflow_sha`, event merge SHA, base SHA, and PR-head SHA as separately named values; and
7. directly invoke the one literal tracked driver for that job with isolated `/usr/bin/python3 -I`.

The tracked driver and the production APIs it calls are **trusted preparation code under review**. They may authenticate host objects and use only the primitives assigned to their job. They receive no token or secret and may not install, acquire, contact the network, import from ambient locations, use `PATH`, or execute caller-selected commands.

The source-head workflow digest is an observation, not proof that GitHub executed that blob. Exact-head authority requires final review to bind the external workflow/run record to that digest, as ADR 0052 requires. The synthetic execution-envelope SHA is never accepted as the source SHA.

### T2: untrusted qualification

Only the bounded helper/workload children are untrusted. Before such a child executes, trusted preparation must:

- close every unneeded descriptor;
- pass only explicitly numbered metadata/input/output descriptors;
- provide no token, host pathname selector, namespace descriptor, or control socket;
- use fixed executables and empty/fixed environments;
- apply the job's timeout and process ownership; and
- for Job E and integration, enter the exact chroot/namespaces, drop all capability sets, set `no_new_privs`, and install seccomp.

The untrusted phase validates supplied sealed descriptors and canonical metadata. It never opens unrestricted host procfs, discovers host libraries, walks the host checkout, or reacquires an object by pathname.

## Common contract for Jobs A–E

Each job is independently fail-closed:

- `needs: quality`, without `always()`;
- same-repository PR head only;
- fresh `ubuntu-24.04`, no container/service;
- fixed 10-minute timeout (Job E: 12 minutes if measurement proves 10 insufficient; no dynamic extension);
- no package installation, download, cache, KVM, rootfs, containerd, Kata, cloud, or AWS;
- no retry or “environment-limited” success;
- missing primitive, unexpected runner fact, unsupported syscall, timeout, ambiguity, drift, or uncertain cleanup is `fail`, never skip/pass;
- one private mode-0700 state root, authenticated by descriptor and identity before mutation;
- fixed maximum 16 live children, 64 live descriptors above baseline, 32 temporary names, and 16 MiB generated bytes per job;
- fixed operation deadlines no greater than 30 seconds; and
- exact baseline restoration before a pass report can be finalized.

Shared code may encode exact-head validation, report encoding, deadlines, descriptor/process baseline collection, and cleanup aggregation. It must not implement ELF parsing, sealing, process supervision, mount construction, or seccomp; those remain in production owners or their one job driver. This prevents `common.py` from becoming a second monolith.

## Job A — runtime mappings

**Single claim:** on the hosted Linux runner, trusted preparation can authenticate the exact fixed Python ELF closure and bind it to the executable mappings of the actual fixed Python helper before untrusted work.

### Required primitives

- fixed `/usr/bin/python3`; no PATH lookup;
- `openat`/`open` with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, `fstat`, bounded `pread`;
- strict production ELF parser for interpreter, SONAME, and ordered `DT_NEEDED`;
- root ownership, non-group/world-writable mode, regular type, bounded size, and before/after generation checks;
- one blocked helper executed from the authenticated fixed Python;
- trusted reads of `/proc/<pid>/maps`, `/proc/<pid>/exe`, and `/proc/<pid>/map_files/<range>`;
- descriptor-open/hash comparison of every executable nonzero-inode mapping;
- a second maps read proving no drift;
- `pidfd_open` where available as a required hosted primitive, fixed release pipe, bounded signal/wait/reap; and
- exact fd/child cleanup.

No address, raw map line, device/inode, or host library path is emitted. Unknown executable mappings, ambiguity, a generation change, inaccessible `map_files`, map drift, or an extra child fails.

### Metadata checks

`elf_real`, `python_closure_exact`, `map_files_trusted`, `mapped_closure_equal`, `mapping_stable`, `helper_reaped`, `cleanup_restored`; object role/size/SHA-256/SONAME/ordered-needed metadata; closure digest and mapping digest.

## Job B — compression executables

**Single claim:** authenticated gzip and zstd bytes can be copied to sealed anonymous executable objects and execute deterministic decompression without PATH, network, unexpected descendants, or unaccounted executable mappings.

### Required primitives

- fixed `/usr/bin/gzip` and `/usr/bin/zstd` authenticated by the production closure owner;
- `memfd_create(MFD_CLOEXEC|MFD_ALLOW_SEALING)`;
- bounded descriptor-to-descriptor copy from one authenticated generation;
- `F_ADD_SEALS` and exact verification of `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`;
- `execveat(..., AT_EMPTY_PATH)` of the sealed descriptor (no `/proc/self/fd` pathname fallback);
- fixed generated gzip and zstd inputs, each at most 64 KiB;
- a pre-input gate so trusted preparation validates actual executable mappings before release;
- inherited seccomp denial of socket, namespace, seccomp-replacement, and io_uring setup syscalls;
- exact one-child-per-case ownership, timeout, reap, output byte comparison, and mapping/fd cleanup.

The source and sealed size/hash must match. Absence of either tool, unsupported sealing/`execveat`, a pathname exec, nondeterministic output, extra mapping, extra child, or network syscall success fails.

### Metadata checks

`gzip_source_exact`, `gzip_sealed_exec`, `zstd_source_exact`, `zstd_sealed_exec`, `decompression_deterministic`, `network_denied`, `children_exact`, `cleanup_restored`; role/size/source SHA-256/sealed SHA-256/seal mask/output SHA-256/mapping digest.

## Job C — descriptor behavior

**Single claim:** the hosted kernel supports the exact descriptor-limit, high-fd, CLOEXEC, inheritance, and `close_range` behavior required by production.

### Required primitives

- `getrlimit`/`setrlimit(RLIMIT_NOFILE)`;
- require hard capacity for 8,193 and set only soft to exact 8,193, then reread;
- `F_DUPFD_CLOEXEC`/`F_DUPFD` at exact low fd 198 and high fd 4,096;
- genuine `close_range` syscall over the production ranges, including exact flags used by production;
- `pipe2(O_CLOEXEC)`, fixed `dup3`, and fixed `/usr/bin/python3 -I` exec child;
- child proof of the exact inherited descriptor set and CLOEXEC effects through a dedicated metadata fd; and
- restore the original soft limit and exact descriptor baseline in `finally`.

`ENOSYS`, `EINVAL`, iteration or proc enumeration as a closure substitute, a dynamically lowered high fd, changed hard limit, accepted alternate fd, or leak fails.

### Metadata checks

`nofile_measured`, `nofile_normalized`, `fd_198_exact`, `fd_4096_exact`, `close_range_exact`, `cloexec_exact`, `inheritance_exact`, `limit_restored`, `cleanup_restored`. Numeric output is limited to the fixed target values and normalized soft/hard capacity class; no fd target text is emitted.

## Job D — process lifecycle

**Single claim:** the hosted kernel and production supervisor provide exact parent-death, identity, process-group/session, bounded termination, and reaping behavior.

### Required primitives

- `prctl(PR_SET_PDEATHSIG, SIGKILL)` in the child before release;
- parent identity handshake across setup and release;
- `/proc/<pid>/stat` start-time identity opened/read only by trusted supervision;
- `pidfd_open`, `pidfd_send_signal` where production uses it, `waitid`/`waitpid(WNOHANG)`;
- fixed `setsid`/process-group ownership and one bounded descendant;
- two separate cases: parent death before release and after release;
- fixed TERM deadline, then KILL only for the exact revalidated identity;
- exact child/descendant reap and independent absence proof; and
- no broad process scan as signaling authority.

A PID-only match, leader-only absence, group-wide signal without member authentication, inherited test state, blocking unbounded wait, retry, or unreaped descendant fails.

### Metadata checks

`pdeathsig_armed`, `parent_handshake_exact`, `before_release_death`, `after_release_death`, `starttime_revalidated`, `session_owned`, `process_group_owned`, `term_kill_bounded`, `all_reaped`, `cleanup_restored`. PIDs, start times, argv, proc rows, and process names are never emitted.

## Job E — sandbox boundary

**Single claim:** trusted preparation can construct the exact read-only sandbox and execute a minimal probe as PID 1 with no capabilities, NNP, inherited seccomp, no acquisition route, and no writable checkout.

### Required primitives

This is the **only** A–E job permitted to use `sudo`. The tracked driver invokes exact noninteractive `sudo -n --close-from=3` into a fixed trusted setup mode. No checked-out helper is interpreted before the exact-head gate, and no untrusted probe runs while host-root authority remains.

Trusted setup requires:

- fresh mount, network, PID, and final root-only user namespaces; the final PID and mount namespaces are owned by the final child user namespace if proc is mounted;
- recursively private mount propagation;
- descriptor-authenticated checkout bind in the same trusted mount namespace, then exact `ro,nosuid,nodev,noexec` remount/reverification;
- fresh tmpfs root and writable tmp only; fixed read-only `/usr` and loader/library binds; only fixed `/dev/null` and `/dev/urandom` device binds;
- no `/run`, `/home`, host proc, daemon socket, KVM, or old-root descriptor in the final view;
- exact chroot root/cwd transition;
- singular root UID/GID maps, empty supplementary groups, locked `noroot`, all five capability sets zero, and `no_new_privs=1`;
- literal x86_64 seccomp denial of socket operations, `io_uring_setup/enter/register`, namespace entry/creation, and filter replacement;
- child `getpid()==1`; child uses `capget`/`prctl` and actual denied syscalls rather than requiring host mapping discovery;
- exact inherited fds 0–2 plus one fixed metadata output fd only if the report protocol cannot use fd 1; and
- failed writes to `/src`, no checkout changes, exact reap, namespace death, mount-baseline restoration, and identity-bound state-root removal.

Job E must **not** call the production ELF parser, inspect `map_files`, run gzip/zstd, test fd 4096, or repeat PDEATHSIG matrices. Those belong to A–D. If an in-sandbox proc mount is not needed by the minimal probe, omit it. If implementation requires proc, the architecture ADR must bind the single combined user/PID/mount ownership tuple before code is written.

### Metadata checks

`mount_view_exact`, `checkout_read_only`, `user_namespace_exact`, `pid_namespace_exact`, `mount_namespace_exact`, `network_namespace_exact`, `pid_one`, `capabilities_zero`, `noroot_locked`, `nnp_set`, `seccomp_socket_denied`, `seccomp_io_uring_denied`, `no_acquisition_route`, `checkout_unchanged`, `all_reaped`, `mounts_restored`, `cleanup_restored`.

## Metadata-only report

Add one strict schema, `schemas/native-qualification-report-v1alpha1.json`. Every job emits one canonical JSON object and no raw diagnostic stream. Routine passing reports are immutable workflow artifacts; release use still requires applicability-aware review under `docs/security-evidence/README.md`.

Required common fields:

- fixed schema version;
- job enum `A`, `B`, `C`, `D`, `E`, or `integration`;
- exact source-head SHA;
- separately named GitHub envelope SHA, workflow SHA, event merge SHA, and base SHA;
- workflow path/blob SHA-256, job ID, run ID, run attempt, and PR number;
- runner image/version, kernel release, and architecture from a fixed allowlist (no raw `uname -a`);
- fixed authority value `exact-run-native-qualification`;
- result `pass` or `fail`;
- ordered fixed check IDs and categorical outcomes;
- bounded role/digest/size metadata allowed for that job;
- fixed failure phase plus SHA-256 of bounded captured diagnostics on failure; and
- exact cleanup booleans for descriptors, children, paths, mounts, namespaces, limits, and checkout as applicable.

Prohibited fields/content: environment dumps, source, arbitrary or checkout paths, command/argv, raw maps, address ranges, PIDs, UID/GID values, device/inode/mount IDs, cgroups, process rows, hostnames, query strings, raw tool output, diagnostics, credentials, tokens, or generated/archive bytes.

Canonical encoding uses sorted object keys, fixed array order, UTF-8, no insignificant whitespace, and one terminal LF. The driver validates its value before writing. The workflow uploads only this JSON, under an exact job/head/run-attempt artifact name, with no wildcard path. Failure to encode, validate, close, fsync, or identity-bind the report fails the job. A pass report may be finalized only after cleanup. A cleanup failure produces only a fail report with cleanup false; it can never be rewritten to pass.

## Exact cleanup protocol

Each job records these trusted baselines before its first effect:

- exact source head and clean-worktree status;
- trusted process descriptor set and identities;
- direct-child set and process-group/session state;
- mountinfo digest and namespace identities;
- `RLIMIT_NOFILE`; and
- absence or authenticated ownership of its private state root.

Cleanup is reverse-order and identity-bound:

1. Stop input/release gates.
2. Revalidate each exact child by pidfd plus start-time identity.
3. TERM, wait to a fixed deadline, KILL only remaining exact identities, and reap all children.
4. Close every tracked descriptor; aggregate close errors rather than hiding them.
5. Unmount only exact driver-owned mounts while still in the owning namespace; never use recursive/lazy/force unmount.
6. Unlink/rmdir only objects whose retained directory descriptor and device/inode identity prove ownership; preserve foreign/replaced objects and fail uncertain.
7. Restore the original soft descriptor limit where changed.
8. Prove the checkout head and porcelain status unchanged.
9. Recompare fd, child, mount, namespace, limit, and private-path baselines.
10. Only then finalize a pass report.

Unexpected process, descriptor, pathname, mount, namespace handle, checkout mutation, failed close, failed reap, uncertain object identity, or inability to compare a baseline is terminal. Job-local disposable-runner teardown is not cleanup evidence.

## Thin integration route

Add `native-closure-integration` only after A–E have stable exact-head passes. It has:

```text
quality ─┬─ A ─┐
         ├─ B ─┤
         ├─ C ─┼── native-closure-integration
         ├─ D ─┤
         └─ E ─┘
```

The integration job runs on a sixth fresh runner and has `needs` on all five explicit job IDs. It does not download or trust their reports as inputs; `needs` proves only that the same workflow run/attempt completed them. It repeats the exact-head gate on its own checkout.

Its only scenario is:

1. trusted production launcher authenticates exact head and fixed host paths;
2. production closure owner resolves/authenticates Python, gzip, zstd, loader, and libraries;
3. trusted helper validates actual Python mappings;
4. production sealer creates fixed gzip/zstd executable descriptors;
5. production launcher constructs the already-qualified sandbox and passes only sealed descriptors plus canonical closure metadata;
6. untrusted code validates those descriptors and performs one fixed gzip and one fixed zstd decompression;
7. parent enforces timeout/reap; and
8. parent proves exact marker, closure digest, no linked evidence, no descriptors/children, unchanged checkout, and no path/mount/namespace residue.

The job does not enumerate parser failures, repeat high-fd cases, repeat PDEATHSIG timing cases, mutate mount rules, or test seccomp tables. A failure routes to the owning portable suite or Job A–E; integration code is not patched with another embedded special case.

## Dependency DAG

Implementation dependencies, distinct from CI scheduling:

```text
Architecture ADR + capability report
             │
             ├── strict report schema/common codec
             ├── trusted runtime-closure production API ──┬── A
             │                                             └── B
             ├── trusted launcher/sandbox production API ───── E
             ├── descriptor production primitive ───────────── C
             └── process supervisor production primitive ───── D

A + B + C + D + E + trusted closure + trusted launcher
                         │
                         └── thin integration
```

Portable hostile tests are prerequisites of each production API and Quality. Native jobs consume those APIs; they do not become their branch-coverage suites. A–E share only the strict common report/head/baseline utility and immutable source revision, not artifacts, processes, directories, runners, or ordering.

## Proposed measured file and line budgets

Counting rule: gross added physical lines from exact implementation predecessor, no rename or deletion credit, after ordinary formatting. Highs are non-transferable. The planning predecessor is `908041c`; the architecture ADR must replace it with the exact implementation predecessor if the branch advances. Stop and replan before any file or aggregate high is exceeded.

The estimates below were measured by allocating one formatted line per required validation/effect/cleanup transition above, plus imports/types and 20% review margin. They are intentionally below the historical 386-line embedded job and keep every primitive owner under 240 lines.

| Proposed file | Planned lines | Hard high |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` (five declarations plus thin integration; no embedded programs) | 155 | 180 |
| `schemas/native-qualification-report-v1alpha1.json` | 120 | 150 |
| `scripts/native-qualification/common.py` | 190 | 220 |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 130 | 160 |
| `scripts/native-qualification/job-b-compression.py` | 145 | 180 |
| `scripts/native-qualification/job-c-descriptors.py` | 110 | 140 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 145 | 180 |
| `scripts/native-qualification/job-e-sandbox.py` | 190 | 240 |
| `scripts/native-qualification/thin-integration.py` | 135 | 170 |
| `test/native-qualification-common.test.ts` | 95 | 120 |
| `test/native-qualification-a.test.ts` | 55 | 70 |
| `test/native-qualification-b.test.ts` | 55 | 70 |
| `test/native-qualification-c.test.ts` | 45 | 60 |
| `test/native-qualification-d.test.ts` | 55 | 70 |
| `test/native-qualification-e.test.ts` | 80 | 100 |
| `test/native-qualification-integration.test.ts` | 70 | 90 |
| **Tracked native design total** | **1,775** | **2,200** |

Subtotals at the hard highs:

- thin workflow only: **180** (53% below the historical 386-line embedded job);
- schema plus seven tracked scripts (common, A–E, and integration): **1,440**;
- seven focused static/portable companions: **580**;
- aggregate: **2,200**.

These budgets exclude the trusted runtime-closure and launcher production modules and their portable hostile tests because Wave 1 Agents 3/4 and the architecture ADR must place and budget those owners. Native drivers may call those APIs but may not duplicate their logic to stay within these highs. If a native driver needs more than its high, first move reusable behavior into the correct already-budgeted production owner; do not move it into YAML, a test, generated code, or `common.py` as cap evasion.

## Integration and review gates

Before implementation:

1. Accept one architecture ADR fixing T0/T1/T2 operations, report schema, production APIs, capability-report assumptions, exact predecessor, and these or lower highs.
2. Complete the non-authoritative hosted-runner capability report; do not infer primitives from the candidate's changing failure labels.
3. Complete portable closure/launcher hostile suites.

Before relying on a native result:

1. exact clean source head and workflow blob are reviewed;
2. Quality and all applicable portable tests pass first;
3. the one job's canonical metadata artifact and GitHub run envelope agree;
4. cleanup is all true;
5. no later commit has changed workflow, driver, common code, schema, or production dependency; and
6. an exact-head hostile review binds source, workflow, run ID, run attempt, artifact digest, runner applicability, trust boundary, and measured lines.

Outcome 2 requires A–E and thin integration to pass on one exact clean head. A passing job is authority only for its own primitive and exact run. No A–E or integration result grants Phase B, AWS, provider, OpenTofu, deployment, production, or issue-closure authority.

## Explicit non-goals

- No giant YAML or embedded Python/BPF/mount parser/process supervisor.
- No native duplication of parser, schema, crash, ambiguity, or recovery branch matrices.
- No untrusted `/proc/map_files` discovery.
- No PATH lookup, package install, download, network acquisition, KVM, container, or cloud action.
- No automatic promotion of runner observations into fixed production pins.
- No retry interpreted as success and no environment-limited pass.
- No implementation or run is authorized or performed by this report.
