# Outcome 2 runner-capability probe

## Status and recommendation

This report specifies **one metadata-only, non-authoritative probe** for a GitHub-hosted `ubuntu-24.04` Linux-amd64 runner. It does not implement or run the probe, change production, authorize a workflow event, or qualify Outcome 2.

The probe should be a single job and a single supervisor invocation. Its namespace subprocesses are cases within that invocation, not separate jobs or retries. The report must always say:

```json
{"authority":"none","qualified":false}
```

A completed observation may inform the Outcome 2 architecture ADR. It cannot become an attestation, production permit, KVM qualification, native-primitives qualification, runtime-closure result, or evidence that a later runner has the same properties.

## Inputs reviewed

- `OUTCOME-TWO-PLAN.md`.
- `SECURITY.md`, especially the requirement that security claims come from an applicability-aware authoritative profile.
- `IMPLEMENTATION.md` sections 47 and 49.
- Accepted ADR 0010 (GitHub KVM is asserted per run, never assumed).
- Accepted native-runtime ADRs 0071–0086 on `feat/issue42-candidate-tar-remediation`, including their supersessions.
- The branch implementation and history through exact head `d96b58ab55e932dda8b1cc007b7f88ad483f336e`.
- Historical GitHub Actions metadata and bounded failed-job logs for PR #230.
- Local history around util-linux mapping, `O_PATH`, procfs, descriptor limits, and `map_files`.

## Historical audit

### What the hosted history establishes

PR #230 is still open at exact head `d96b58a`. The branch is research material, not a successful native qualification. From the introduction of `native-runtime-preflight` at `a7914db` through `d96b58a`, the branch has no successful CI run. The final run is [30292638819](https://github.com/nenb/cogs/actions/runs/30292638819); Quality, Native C1, images, and secret scan passed, but Native runtime preflight failed.

The relevant hosted jobs used:

- runner label/image: `ubuntu-24.04`;
- observed runner-image version: `20260720.247.2`;
- observed image-provisioner version: `20260707.563`;
- same-repository pull-request heads;
- an exact-head checkout with persisted credentials disabled.

Those image values are observations from 2026-07-27 logs, not constraints GitHub promises for a future run.

The useful failure progression is:

| Exact head | Run | Bounded result | Fact supported |
|---|---:|---|---|
| `d87ff2e` | [30261305894](https://github.com/nenb/cogs/actions/runs/30261305894) | `checkout-access`, 150 bytes | A root-only child user namespace could not traverse the runner-owned checkout ancestry after capability removal. |
| `e4650ab` | [30265013266](https://github.com/nenb/cogs/actions/runs/30265013266) | 49-byte failure; ADR 0078 records sudo close-from rejection | Hosted sudo accepted its default `--close-from=3` route but did not permit the attempted `--close-from=4` descriptor-preservation policy. |
| `d53b116` | [30268105408](https://github.com/nenb/cogs/actions/runs/30268105408) | `launcher-fds`, 112 bytes | Trusted Bash retained implementation-internal high descriptors; exact numeric open-set assumptions were invalid. This did not prove those descriptors could survive exec. |
| `3dd2b0e` | [30273723176](https://github.com/nenb/cogs/actions/runs/30273723176) | `mount-fd3`, exit 32, 230 bytes | The util-linux `mount --no-canonicalize --bind /proc/self/fd/3 ...` frontend did not provide a usable descriptor bind in that envelope. |
| `bed2d05` | [30275927878](https://github.com/nenb/cogs/actions/runs/30275927878) | direct bind `EINVAL`, 110 bytes | An `O_PATH` descriptor opened before the final mount namespace was rejected as that later namespace's bind source. This is not evidence that `fstat` on the descriptor failed. |
| `9cb67fd` | [30277864818](https://github.com/nenb/cogs/actions/runs/30277864818) | `permission`, 151 bytes | Opening the nonzero-runner-owned checkout after entering a root-only user namespace failed. |
| `7128579` | [30280897936](https://github.com/nenb/cogs/actions/runs/30280897936) | 60-byte bounded diagnostic, SHA-256 `f3cd…2147` | Together with util-linux 2.39 source review, repeated plural map options overwrite rather than append; an arbitrary owner extent also depends on subordinate-ID authorization. ADR 0083 abandoned that design. |
| `7282309` | [30286623708](https://github.com/nenb/cogs/actions/runs/30286623708) | 40-byte process failure | ADR 0084 localizes this to `F_DUPFD(4096)`: inherited soft `RLIMIT_NOFILE` was below 4,097. |
| `86e6974` | [30289588414](https://github.com/nenb/cogs/actions/runs/30289588414) | 36-byte process failure | ADR 0085 localizes this to `mapped-files`: a proc superblock created by the initial user namespace denied self `map_files` access after the late child had zero capabilities. |
| `d9ef36e` | [30291262603](https://github.com/nenb/cogs/actions/runs/30291262603) | bounded mount failure | ADR 0086 records `EPERM` from final `--mount-proc`: the child user namespace did not own the retained outer PID namespace. |
| `e1e007f` / `d96b58a` | [30292309051](https://github.com/nenb/cogs/actions/runs/30292309051), [30292638819](https://github.com/nenb/cogs/actions/runs/30292638819) | same 141-byte diagnostic hash; final classification `final-proc-count` | Adding a final child-owned PID namespace reached a later verifier, but the final branch still did not complete proc verification or execute the native matrix. |

Other supported observations:

- The trusted setup could create fresh network, PID, and mount namespaces and perform substantial private mount setup on these runs.
- A later setup successfully raised only the child process's soft `RLIMIT_NOFILE` to 8,193 while preserving a hard limit of at least 8,193; otherwise execution could not have advanced beyond ADR 0084.
- Fixed `/usr/bin/python3`, `/usr/bin/gzip`, and `/usr/bin/zstd` existed and passed earlier root-ownership/setup checks. Their exact bytes and versions were not recorded by this native preflight.
- Native C1 passed at final head, but its scope is not a substitute for the runtime-capability fields in this report.
- The QEMU Linux/amd64 envelope discussed by ADR 0071 returned `ENOSYS` for required `close_range`. That says nothing conclusive about the GitHub host kernel.

### What the history does not establish

No historical run on this branch proves all of the following together:

- successful native-host `close_range`, especially the genuine high-fd case;
- successful zero-capability `map_files` access through a correctly child-owned proc superblock;
- a valid final proc mount/view after the child-owned PID-namespace correction;
- `O_TMPFILE` behavior on the exact filesystems a new closure design would use;
- current KVM availability or useful KVM ioctl behavior;
- exact gzip/zstd file identities or version output;
- current runner-image, kernel, sudo, util-linux, rlimit, or seccomp behavior;
- cross-namespace `O_PATH` semantics beyond the one failed descriptor-bind construction;
- complete descriptor and process cleanup for a successful native matrix.

The historical job was also too coupled to interpret as a capability report. Its fixed classifiers improved disclosure, and later diagnostics were limited to 65,537 bytes and hashed, but one monolithic sandbox mixed runner properties, util-linux frontend behavior, verifier assumptions, production behavior, and cleanup defects. Generic classes such as `python`, `permission`, or `uid-text` did not identify a runner fact without a later code/source review. The branch's 0071–0086 correction chain is therefore evidence for decomposition, not a template to extend.

## The single probe

### Execution envelope

When separately authorized, run exactly one attempt of one job named `runner-capability-probe` with:

- `runs-on: ubuntu-24.04`;
- Linux amd64 required at runtime;
- `timeout-minutes: 3`;
- workflow permissions `{}` (no repository or token permission);
- no checkout action and no other action;
- one inline, reviewed, standard-library Python supervisor supplied by workflow source;
- `stdin` from `/dev/null`, stdout reserved for the final JSON line, and all child stderr captured and discarded after categorical classification;
- only fixed absolute executables: `/usr/bin/python3`, `/usr/bin/sudo`, `/usr/bin/unshare`, `/usr/bin/gzip`, and `/usr/bin/zstd`;
- an initially empty child environment after the parent has copied only the allowlisted public values `ImageOS`, `ImageVersion`, `RUNNER_ARCH`, and `RUNNER_ENVIRONMENT` into validated arguments;
- a fresh network namespace with no configured interface before any probing child runs;
- a seccomp filter that returns `EPERM` for socket creation/connection and io_uring setup/entry/registration; and
- all descriptor, mount, user, PID, proc, KVM, and tool cases executed as bounded subprocesses of that one supervisor.

The report is complete when every fixed case has either an observation or an allowlisted categorical failure. A denied/unsupported capability does not make the JSON invalid. A supervisor crash, malformed field, cleanup uncertainty, output overflow, or timeout fails the job after emitting at most one fixed `probe-incomplete` diagnostic; it must not emit partial raw data.

No rerun or retry may be interpreted as success. A later attempt is a different, still non-authoritative observation and cannot fill a missing field in the first report.

### Closed status type

Every syscall observation uses this exact closed object:

```text
ProbeStatus = {
  state: "ok" | "unsupported" | "denied" | "blocked" | "mismatch" | "error",
  errno: null | integer in [1, 4095]
}
```

Rules:

- `ok`: the exact operation and its postcondition succeeded.
- `unsupported`: only `ENOSYS`, `EOPNOTSUPP`, or an absent fixed executable/device.
- `denied`: only `EPERM` or `EACCES`.
- `blocked`: a declared prerequisite (for example hard fd capacity) was absent, so the syscall was not attempted.
- `mismatch`: syscall succeeded but the exact postcondition did not.
- `error`: another allowlisted numeric errno occurred.
- No exception text, `strerror`, command stderr, path recovered from procfs, or raw command output is retained.

### Exact output fields

The output is one canonical JSON object. Keys are emitted in lexical order, UTF-8 is strict, separators are `,` and `:`, there is one trailing LF, duplicate keys and non-integer JSON numbers are forbidden, and `additionalProperties` is conceptually false at every level.

```text
schema = "cogs.runner-capability-probe/v1alpha1"
authority = "none"
qualified = false
outcome = "complete" | "incomplete"

source = {
  repository: "nenb/cogs",
  head_sha: lowercase 40-hex,
  workflow_sha256: lowercase 64-hex,
  run_id: canonical unsigned decimal string,
  run_attempt: integer in [1, 255]
}

runner = {
  requested_label: "ubuntu-24.04",
  environment: "github-hosted" | "unexpected",
  image_os: null | validated ASCII [a-z0-9.-]{1,32},
  image_version: null | validated ASCII [A-Za-z0-9._-]{1,64},
  runner_arch: "X64" | "unexpected",
  image_metadata_status: ProbeStatus
}

kernel = {
  sysname: "Linux" | "unexpected",
  release: validated printable ASCII of 1..128 bytes,
  machine: "x86_64" | "unexpected",
  uname_status: ProbeStatus
}

rlimit_nofile = {
  soft: integer in [0, 2^63-1] | "infinity",
  hard: integer in [0, 2^63-1] | "infinity",
  high_fd_4096_possible: boolean
}

sudo = {
  executable: ToolIdentity,
  noninteractive: ProbeStatus,
  close_from_3: {
    invocation: ProbeStatus,
    fd3_closed: boolean | null,
    fd4_closed: boolean | null,
    exit_code: integer in [0,255] | null
  },
  close_from_4: {
    invocation: ProbeStatus,
    fd3_preserved: boolean | null,
    fd4_closed: boolean | null,
    exit_code: integer in [0,255] | null
  }
}

descriptors = {
  exec_cloexec: {
    invocation: ProbeStatus,
    non_cloexec_fd_198_survived: boolean | null,
    cloexec_fd_199_closed: boolean | null
  },
  close_range_low: {
    syscall_number_amd64: 436,
    flags: 0,
    first: 198,
    last: 198,
    invocation: ProbeStatus,
    known_fd_closed: boolean | null
  },
  close_range_high: {
    syscall_number_amd64: 436,
    flags: 0,
    first: 4096,
    last: 4096,
    invocation: ProbeStatus,
    known_fd_closed: boolean | null
  },
  inherited_baseline_restored: boolean
}

temporary_files = {
  runner_temp: TmpfileCase,
  private_tmpfs: TmpfileCase
}

opath = {
  same_mount_namespace: OpathCase,
  across_mount_namespace: OpathCase
}

namespaces = {
  network: { create: ProbeStatus, distinct_from_parent: boolean | null },
  mount: { create: ProbeStatus, distinct_from_parent: boolean | null },
  pid: {
    create: ProbeStatus,
    child_is_namespace_pid_1: boolean | null,
    nspid_final_component_is_1: boolean | null
  },
  user_direct_root: {
    create: ProbeStatus,
    uid_map_status: ProbeStatus,
    uid_map: null | array of at most 5 [inside,outside,count] uint32 triples,
    gid_map_status: ProbeStatus,
    gid_map: null | array of at most 5 [inside,outside,count] uint32 triples,
    setgroups: "deny" | "allow" | "absent" | "unexpected"
  },
  combined_user_mount_pid_fork: {
    create: ProbeStatus,
    child_is_namespace_pid_1: boolean | null,
    proc_mount: ProbeStatus,
    cleanup: ProbeStatus
  }
}

procfs = {
  host_runner: MapFilesCase,
  host_sudo_root: MapFilesCase,
  child_userns_parent_proc_before_cap_drop: MapFilesCase,
  child_userns_parent_proc_after_cap_drop: MapFilesCase,
  child_owned_proc_before_cap_drop: MapFilesCase,
  child_owned_proc_after_cap_drop: MapFilesCase,
  parent_proc_read_only: boolean | null,
  child_proc_read_only: boolean | null,
  child_proc_distinct_from_parent: boolean | null,
  child_proc_view_has_pid_1: boolean | null
}

seccomp = {
  initial_mode: 0 | 1 | 2,
  initial_no_new_privs: 0 | 1,
  set_no_new_privs: ProbeStatus,
  install_filter: ProbeStatus,
  final_mode: 0 | 1 | 2 | null,
  network_syscalls_policy: "fixed-eperm-filter-installed" | "filter-unavailable"
}

kvm = {
  device_present: boolean,
  character_device: boolean | null,
  open_read_write: ProbeStatus,
  get_api_version: ProbeStatus,
  api_version: integer in [0,255] | null,
  check_extension_user_memory: ProbeStatus,
  user_memory_extension: integer in [0,2^31-1] | null
}

tools = {
  python3: ToolIdentity,
  gzip: ToolIdentity,
  zstd: ToolIdentity,
  unshare: ToolIdentity
}

cleanup = {
  children_reaped: boolean,
  descriptors_restored: boolean,
  mounts_gone: boolean,
  temporary_names_gone: boolean,
  namespace_handles_retained: false,
  uncertainty: boolean
}
```

Closed reusable objects are:

```text
ToolIdentity = {
  path: one corresponding fixed literal path,
  present: boolean,
  regular_file: boolean | null,
  root_owned: boolean | null,
  mode: null | canonical four-digit octal string,
  size: null | integer in [1,134217728],
  sha256: null | lowercase 64-hex,
  version_line: null | printable ASCII of 1..160 bytes,
  version_output_sha256: null | lowercase 64-hex,
  observation: ProbeStatus
}

TmpfileCase = {
  filesystem: "ext4" | "xfs" | "tmpfs" | "other" | "unknown",
  open_otmpfile: ProbeStatus,
  initial_nlink_zero: boolean | null,
  owner_is_probe_identity: boolean | null,
  initial_mode_0600: boolean | null,
  linkat_empty_path: ProbeStatus,
  linked_identity_matches: boolean | null,
  cleanup: ProbeStatus
}

OpathCase = {
  open_opath_directory: ProbeStatus,
  fstat_stable: boolean | null,
  bind_mount_from_proc_fd: ProbeStatus,
  bind_target_identity_matches: boolean | null,
  cleanup: ProbeStatus
}

MapFilesCase = {
  proc_mount_created_in: "host" | "parent-userns" | "child-userns",
  capability_sets_zero: boolean,
  maps_read: ProbeStatus,
  executable_mappings_selected: integer in [0,8],
  map_files_opened: integer in [0,8],
  first_open_failure: ProbeStatus | null,
  all_opened_descriptors_closed: boolean
}
```

`version_line` is retained only if the complete first line matches a tool-specific allowlist (`sudo`, `unshare`, GNU gzip, zstd, or Python) and contains no control characters. Otherwise it is `null`; only the digest of the bounded complete output is retained. `ToolIdentity` stat values are read before and after hashing/version execution and the observation becomes `mismatch` on generation drift. Device numbers, inode numbers, ctime/mtime, account names, and package-manager metadata are not output.

### Exact operations and syscalls

The semantically relevant operations are fixed below. Normal dynamic-loader and Python-runtime implementation syscalls are not claimed as evidence and are not traced.

1. **Kernel and limits**
   - `uname(2)`; omit nodename and domainname.
   - `getrlimit/prlimit64(RLIMIT_NOFILE)`; do not change the supervisor limit.
2. **Tool identity**
   - `openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)`, `fstat`, bounded `read`, SHA-256 in-process, second `fstat`, and `close` for each fixed binary.
   - One `fork`/`execve`/bounded `wait4` per fixed `--version` invocation, empty environment with only `LC_ALL=C`; capture at most 4,096 bytes total and kill/reap on the 5-second deadline.
3. **Sudo descriptor policy**
   - Open only `/dev/null` sentinels normalized to fds 3 and 4.
   - Invoke exactly `sudo -n --close-from=3` and separately `sudo -n --close-from=4` to a fixed inline root helper. Suppress sudo stderr. The helper uses only `fcntl(F_GETFD)` to classify sentinel presence, then exits.
   - Do not call `sudo -l`, read sudoers, preserve the environment, or modify policy.
4. **Exec/CLOEXEC and `close_range`**
   - Use `fcntl(F_DUPFD)`/`F_SETFD` to create known fds 198 and 199 and a separate child case for fd 4,096.
   - `execve` a fixed helper to prove non-CLOEXEC survival and CLOEXEC closure.
   - On x86_64 call syscall 436 exactly as `close_range(198,198,0)` and `close_range(4096,4096,0)`. Verify each known fd returns `EBADF` to `fcntl(F_GETFD)`. Do not enumerate-close or fall back. If hard `RLIMIT_NOFILE < 4097`, mark the high case `blocked`.
5. **`O_TMPFILE`**
   - On each of two private empty directories, call `openat(dirfd,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600)`, then `fstat`.
   - Write exactly one fixed byte, `fsync`, and call `linkat(fd,"",dirfd,"published",AT_EMPTY_PATH)` once.
   - Authenticate the linked inode through descriptor/path metadata, unlink the one fixed name, `fsync` the parent, and close. No retry or alternate publication mechanism.
6. **`O_PATH` and mount namespaces**
   - Create one empty fixed source and one empty target in a private tmpfs.
   - Same-namespace case: `openat(O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, `fstat`, then direct libc `mount("/proc/self/fd/<fixed-fd>",target,NULL,MS_BIND,NULL)` once.
   - Cross-namespace case: open the source first, then `unshare(CLONE_NEWNS)`, make propagation private, and issue the same direct bind once.
   - Compare source/target type and stable identity internally; output no fd target, mountinfo, path, device, or inode. `umount2(target,0)` and remove only exact private names.
7. **Namespaces and maps**
   - Create network and mount namespaces with `unshare(2)` in disposable children.
   - Create PID namespaces with `clone/unshare(CLONE_NEWPID)` followed by exactly one `fork`; verify PID/NSpid internally.
   - Exercise util-linux only through fixed `/usr/bin/unshare --user --map-user=0 --map-group=0` and the combined `--user --map-user=0 --map-group=0 --mount --pid --fork --mount-proc=<fixed-private-target>` form. Read at most 4 KiB each from `uid_map`, `gid_map`, and `setgroups`; parse at most five canonical rows. Do not use plural map options, `newuidmap`, `newgidmap`, `/etc/subuid`, or `/etc/subgid`.
8. **Procfs and `map_files`**
   - For each fixed stage, read at most 1 MiB and 4,096 lines from `/proc/self/maps`; select at most eight executable, nonzero-inode mappings.
   - Open the corresponding self `map_files/<address-range>` entries with `openat(O_RDONLY|O_CLOEXEC)`, immediately `fstat` and close. Addresses, paths, symlink text, inode/device values, and mapping bytes never leave memory and are never hashed or output.
   - Test separate disposable cases for host runner, host sudo root, child user namespace retaining parent proc, and the combined child-owned user/mount/PID/proc tuple. In each userns case test once before capability removal and once after an irreversible `capset` to all-zero permitted/effective/inheritable sets plus empty bounding/ambient sets. No capability is re-added and no fallback path is used.
9. **Seccomp**
   - Read `PR_GET_SECCOMP` and `PR_GET_NO_NEW_PRIVS`; set `PR_SET_NO_NEW_PRIVS=1`.
   - Invoke `seccomp(SECCOMP_SET_MODE_FILTER,0,<fixed x86_64 BPF>)` once. The filter returns `EPERM` for the complete x86_64 socket-call table used by the project plus `io_uring_setup`, `io_uring_enter`, and `io_uring_register`, and allows other probe syscalls. Re-read mode. Do not perform a network self-test.
10. **KVM**
    - `lstat` fixed `/dev/kvm`, require a character device, then `open(O_RDWR|O_NOFOLLOW|O_CLOEXEC)`.
    - Issue only `ioctl(KVM_GET_API_VERSION=0xAE00)` and `ioctl(KVM_CHECK_EXTENSION,KVM_CAP_USER_MEMORY)`; close immediately.
    - Do not call `KVM_CREATE_VM`, map guest memory, create a vCPU, start QEMU, or claim ADR 0010 qualification.

### Bounds

- One job, one supervisor, no retries.
- Job timeout: 180 seconds; supervisor deadline: 120 seconds.
- Each subprocess/operation deadline: 5 seconds; namespace/proc case: 10 seconds.
- At most 16 live subprocesses cumulatively and at most 4 simultaneously.
- At most 32 simultaneously open descriptors. Fd number 4,096 is sparse and does not permit 4,096 live descriptors.
- At most 8 private pathnames simultaneously and 24 cumulatively; every name is a fixed literal under one mode-0700 private parent.
- At most 128 MiB per tool file and 384 MiB aggregate tool bytes read.
- At most 4 KiB per command output, 1 MiB per maps read, 4,096 map lines, and 8 selected mappings per stage.
- Final canonical JSON: at most 32,768 bytes including LF.
- No raw stderr, environment, `/proc` snapshot, mountinfo, map address, process ID, namespace inode, host path other than approved fixed tool/device paths, or failure text is output.
- Cleanup is exact-name, exact-child, and exact-mount cleanup. No `rm -rf`, broad kill, lazy unmount, process scan, or runner disposal is accepted as cleanup proof.

### Prohibited behavior

The probe must contain no:

- secret, token, credential, `GITHUB_TOKEN`, environment dump, account name, SSH material, or credential-bearing descriptor;
- checkout, repository content execution, package manager, package database query, cache, artifact download/upload, action download, archive, container, image, compiler, linker, build, or generated executable;
- DNS, HTTP, HTTPS, Unix-socket, netlink configuration, cloud metadata, provider, AWS, OpenTofu, or other network/acquisition route;
- QEMU/Kata/containerd/Docker operation, KVM VM creation, workload, or production runtime;
- raw command output, exception, mountinfo, maps, map-files target, sudo policy, procfs file, or diagnostic hash derived from uncontrolled bytes;
- retry, fallback, timeout increase, alternate tool path, PATH lookup, descriptor enumeration as a `close_range` substitute, or denial interpreted as success;
- report artifact, attestation, issue comment, committed runner pin, or evidence authority.

The only retained output is GitHub's ordinary bounded job log containing the one canonical JSON line and fixed workflow metadata.

## Expected GitHub Linux constraints

The architecture decision should expect, but not assume, the following:

1. The label selects a mutable GitHub-hosted Ubuntu 24.04 image. Image contents, kernel, sudo, rlimits, preinstalled zstd, filesystems, and KVM can change without a repository change.
2. Historical image `20260720.247.2` allowed noninteractive sudo and its default close-from-3 path, but a close-from-4 override was rejected. Descriptor handoff across sudo must not depend on widening that policy.
3. The inherited soft fd limit was below 4,097 in run 30286623708. The hard limit was later demonstrated to be at least 8,193. Trusted setup must measure before choosing a high-fd proof; portable code must not assume the ambient soft value.
4. util-linux 2.39 plural mapping arguments are not append operations, and arbitrary owner maps are subordinate-ID-policy-sensitive. Outcome 2 should use direct singular maps only where required and should not base closure architecture on runner checkout-owner mapping.
5. `O_PATH` is useful for identity and dirfd operations, but a proc-fd bind source opened before the destination mount namespace failed with `EINVAL`. Open and consume mount-bound descriptors in the same final mount namespace unless an independently qualified primitive says otherwise.
6. A proc superblock's PID/user-namespace ownership matters. Parent-created proc plus a later zero-capability user namespace denied `map_files`; creating only a child mount namespace was insufficient to mount proc for an outer PID namespace.
7. Trusted Bash may hold CLOEXEC implementation descriptors. Security properties should be expressed as inheritance/CLOEXEC and exact checked-process sets, not an assumed transient Bash fd-number set.
8. `/dev/kvm` is not contractually guaranteed. Even a successful KVM API ioctl in this probe would be per-run metadata only; ADR 0010 still requires active QEMU/QMP/guest evidence for KVM qualification.
9. Existing hosted logs disclose runner-image metadata and workflow source. Probe source and output must therefore be safe if public; secrecy cannot depend on log redaction.

## Facts that remain uncertain after this report

Until the probe is separately authorized and run, every new field is unknown. Even after one run, these broader facts remain uncertain:

- whether the observation repeats on another GitHub runner or image revision;
- whether GitHub guarantees any observed sudo, namespace, procfs, rlimit, filesystem, tool, or KVM behavior;
- whether successful `map_files` self-access survives the exact future trusted-preparation and zero-capability design rather than the probe's minimal case;
- whether a child-owned proc result is stable across kernel updates and proc mount-policy changes;
- whether `O_PATH` can support any cross-namespace operation other than the exact tested direct bind;
- whether `O_TMPFILE` and `linkat(AT_EMPTY_PATH)` work on the future production destination filesystems;
- whether gzip/zstd version and file digests represent their complete ELF loader/library closure;
- whether `close_range` works in every child lifecycle and seccomp profile needed by production;
- whether KVM can create and run a VM (deliberately not tested);
- whether the final `d96b58a` `final-proc-count` failure is a kernel/util-linux constraint, a mount-verifier defect, or both;
- whether the candidate branch's production closure code should be reused at all; that is the separate production-audit decision;
- exact cleanup behavior under signal, timeout, crash, and partial initialization; the metadata probe tests only its own narrow normal/failure cleanup;
- any Outcome 2 authority, production readiness, cloud capability, workload isolation, or issue-closure claim.

## Gate for the lead architecture decision

Use a future probe result only as one immutable, non-authoritative runner observation. The lead should separately decide:

- which trusted preparation operations are actually needed;
- which probe fields become portable prerequisites versus per-run assertions;
- whether `map_files` is needed only before capability removal, as `OUTCOME-TWO-PLAN.md` proposes;
- whether KVM belongs in later independent primitive qualification rather than the closure path;
- the authoritative report schema and cleanup contract; and
- the separately authorized trigger for the one probe attempt.

Do not copy a successful value directly into production policy or revive the monolithic native preflight. A production or native-qualification implementation requires its own accepted architecture decision, portable hostile tests, exact-head review, and independently authorized jobs.
