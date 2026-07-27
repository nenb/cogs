# ADR 0084: Set the native sandbox soft descriptor limit

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct the native runtime preflight after execution at exact head `7282309a240b1a9314e0bcd57e2b8763415a492c` reached the checked workload and failed at fixed phase `descriptor-fcntl`, proving that the inherited soft `RLIMIT_NOFILE` was below 4,097. The fixed embedded final-mount-namespace child, while still trusted host root and before any checked code, imports `resource`, reads the inherited soft and hard limits, requires hard capacity for 8,193 descriptors, sets only the soft limit to exactly 8,193 while preserving the hard limit, and re-reads the exact pair. Failure is terminal. The checked workload retains exact `F_DUPFD(4096)` and high-descriptor closure evidence. Descriptor normalization, mount setup, late user namespace, chroot, capability removal, seccomp, and all other caps and boundaries remain unchanged except that the CI high rises 372→376, the exact-five-file aggregate rises 2,652→2,656, and the global projection rises to at most `33,360 <= 34,000` for readable lines. No run, acquisition, cloud, or AWS authority is added.

## Context

ADR 0083's accepted implementation was integrated history-preservingly and corrected the user-namespace order. At exact clean implementation head `7282309a240b1a9314e0bcd57e2b8763415a492c`, the native checked process passed the fixed namespace, mount, descriptor, chroot, map, capability, NNP, and seccomp envelope assertions. It opened `/dev/null`, duplicated one descriptor to exact fd 198, and then attempted the retained genuine high case:

```python
high = fcntl.fcntl(base, fcntl.F_DUPFD, 4096)
assert high == 4096
```

The fixed terminal report was `native-process-failure:descriptor-fcntl`. Linux `F_DUPFD` cannot allocate at or above the process soft `RLIMIT_NOFILE`; failure at this exact operation, after the preceding open and fd-198 duplication succeeded, proves that the inherited soft limit is below the minimum 4,097 needed to create fd 4,096. This is an execution-envelope defect, not evidence that the high case should be lowered, mocked, skipped, retried with another descriptor, or replaced by descriptor enumeration.

The existing post-sudo embedded child is the narrow trusted place to establish a deterministic process limit. It runs as namespace PID 1 in fresh network, PID, and mount namespaces but remains host root in the initial user namespace. Its source is fixed workflow text, it has not read or executed checkout content, and every later trusted setup and checked process descends from its terminal process chain. A soft-limit change there is inherited by that chain without changing host configuration or another process.

## Decision

### Exact correction ancestry

The exact implementation predecessor is clean branch head `7282309a240b1a9314e0bcd57e2b8763415a492c` on `feat/issue42-candidate-tar-remediation`. It contains the exact `descriptor-fcntl` diagnostic and descends from merge `a1e0a3443aa3eacc11bbc84c7e104428f5b76e2a`, whose first parent is ADR 0083 implementation predecessor `712857918e64663699bcf8d5d13fb4319a3a94d8` and whose second parent is accepted main commit `85268e4b7f3ee8c71292974ad077589c5ae3031a`, containing ADR 0083.

The exact accepted documentation parent for ADR 0084 is that same current main commit, `85268e4b7f3ee8c71292974ad077589c5ae3031a`. The accepted commit containing this ADR must be based directly on that exact parent. Implementation must start at exactly `7282309a240b1a9314e0bcd57e2b8763415a492c` and integrate the exact accepted ADR 0084 commit by a history-preserving merge before the correction commit. That integration merge must have `7282309a240b1a9314e0bcd57e2b8763415a492c` as first parent and the accepted ADR 0084 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from the documentation branch is prohibited. Final implementation head must descend from both exact parents. If either line advances before integration, an explicit accepted amendment must bind the replacement; a moving-head substitution is prohibited.

### Exact trusted soft-limit transition

The fixed isolated outer launcher and its exact `sudo`, `setpriv`, and network/PID/mount `unshare` transition remain unchanged. No resource limit is changed in the ordinary runner, before sudo, in an outer shell, or through host configuration.

The existing fixed embedded child launcher in the final mount namespace adds the standard-library `resource` import. While it is still trusted host root in the initial user namespace and before opening, importing, resolving, or executing checked code, it performs exactly this logical sequence:

1. Call `resource.getrlimit(resource.RLIMIT_NOFILE)` once and retain the returned soft and hard values.
2. Require that the retained hard limit can represent at least 8,193 open descriptors. `RLIM_INFINITY` satisfies that capacity bound; every finite hard value below 8,193 fails.
3. Call `resource.setrlimit(resource.RLIMIT_NOFILE, (8193, hard))` exactly once. This sets the soft limit to exactly 8,193 and supplies the retained hard value unchanged.
4. Call `resource.getrlimit(resource.RLIMIT_NOFILE)` again and require the result to equal exactly `(8193, hard)`.

An exception, unavailable module or constant, malformed observation, finite hard limit below 8,193, failed set, soft value other than 8,193, or changed hard value is terminal before checkout setup or checked execution. The launcher may not raise, lower, normalize, replace, or otherwise write the hard limit. It may not retain an inherited soft value even when already sufficient, select `max`, choose a host-dependent target, invoke `prlimit`, use shell `ulimit`, edit a configuration file, retry, lower the checked descriptor, or take a root-only, no-high-fd, enumeration, procfs, or other fallback path.

The value is intentionally 8,193, not merely 4,097. The checked proof still requires exact fd 4,096, while the fixed process tree receives one explicit deterministic ceiling with room through fd 8,192. This numeric choice grants no additional descriptor, mount, namespace, pathname, process, or execution authority.

### Unchanged descriptor and sandbox lifecycle

After the exact re-read succeeds, ADR 0083's launcher behavior is unchanged: authenticate and open the checkout once in the final mount namespace; normalize sole inheritable fd 3 and close aliases; execute only the fixed trusted sandbox; perform the two descriptor observations; build and verify the fixed tmpfs/chroot mount view; make the one direct descriptor bind; remount the checkout read-only with `nosuid,nodev,noexec`; reverify it; close fd 3; reap children; and prove the post-closure descriptor state.

Only then may the retained terminal `unshare --user --map-user=0 --map-group=0`, chroot, locked `noroot`, all-zero capability sets, NNP, timeout, literal seccomp launcher, fresh-proc map checks, and checked-module exec occur. The limit change does not move checked code into the host-root phase and does not weaken any initial-map, direct-root-map, ownership, mount, old-root, descriptor, capability, seccomp, timeout, or exact-exec assertion.

The native checked workload at `test/aws-stage2-completion-kata-process.py` is unchanged from the exact predecessor. It must continue to:

- create exact inheritable low fd 198;
- call genuine `fcntl.F_DUPFD` with minimum 4,096 and require the returned descriptor to be exactly 4,096;
- make fd 4,096 inheritable;
- run both genuine zstd and gzip archive cases;
- prove each archive child inherited neither fd 198 nor fd 4,096 after the production high `close_range` path; and
- close the parent descriptors and restore the exact baseline descriptor set.

`ENOSYS`, `EINVAL`, a lower or dynamically selected duplicate minimum, an accepted different returned fd, skipped compression route, descriptor iteration, procfs enumeration as closure, mocked closure, leak uncertainty, or residue remains failure. ADR 0074's exact genuine low/high no-fallback closure requirement remains binding.

### Process scope and zero residue

`RLIMIT_NOFILE` is process-scoped. The exact soft value is inherited only down the fixed namespace PID-1 process tree; it changes no unrelated process and creates no namespace handle, file, service, sysctl, PAM limit, systemd setting, shell profile, credential, or host configuration. The namespace PID-1 process terminally execs through the retained chain rather than returning to a privileged caller. On success or failure that process tree exits, its namespace dies, and the adjusted process limit disappears with it.

No acquisition, download, package, dependency, helper, daemon, persistent state, named evidence, host mutation, cleanup command, or residue is required or authorized. Failure to establish or verify the limit occurs before checked code and follows the retained namespace teardown and anonymous-evidence lifecycle.

### Exact authorized files and revised highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | In the fixed embedded final-mount-namespace child only, add the standard-library resource import and readable exact get/finite-hard-check/set/re-read sequence before the unchanged descriptor and mount lifecycle. | **376** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the exact trusted limit sequence and unchanged exact fd-4,096/high-closure workload; reject hard-limit writes, dynamic targets, fallback, and checked-code placement. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact launcher ordering and process-scoped/no-residue boundary while retaining the complete descriptor, mount, late-userns, chroot, capability, and seccomp lifecycle. | Retained **600** gross additions from `18f2644` |

The CI maximum rises only from 372 to 376 so the exact observation, hard-capacity failure, set, and re-read remain ordinarily readable. The checked-in Python highs remain 750 and 850, and neither checked-in Python file may change from the exact predecessor. The five non-transferable no-rename gross-addition maxima from exact `18f26441b6115091233d0c4cd44ced8f058d014f` are therefore `376 + 750 + 80 + 850 + 600 = 2,656`. Deletion, movement, replacement, consolidation, generated placement, or removal creates no credit. Compression to fit a high is prohibited.

No production module, production runner, checked-in Python file, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new implementation file may change. No behavior beyond the exact process soft-limit correction and its directly dependent static assertions is authorized. All other per-file and aggregate caps remain unchanged.

## Evidence and gates

Portable static companions and final hostile review must prove exact ancestry and first/second-parent integration; exact placement in the fixed embedded final-mount-namespace child while it remains trusted host root; no checked code before the transition; standard-library `resource` only; one initial `RLIMIT_NOFILE` read; hard capacity at least 8,193; one set to exact `(8193, retained_hard)`; no hard-limit change; one exact re-read; and terminal failure for every mismatch or exception.

Review must separately prove that the predecessor's exact checked Python bytes are unchanged and that genuine `F_DUPFD(4096)` returns exactly 4,096, both compression children prove closure of inherited fd 4,096, and the parent restores its descriptor baseline. It must reject a lower test descriptor, a soft target other than 8,193, retaining an ambient sufficient soft value, changing the hard limit, `prlimit`/`ulimit`/configuration, retry, fallback, descriptor enumeration, mock, skip, host residue, or resource acquisition.

The final implementation commit must retain the complete ADR 0083 descriptor normalization, mount, late-userns, chroot, map, capability, NNP, timeout, seccomp, anonymous-evidence, and cleanup boundaries; retain all prior reviewed implementation and the tracked Phase B schema; be clean; pass ordinary portable checks; and remain within exact highs 376/750/80/850/600 and aggregate 2,656. Production, checked-in Python, schema, Gitleaks bytes, and every unauthorized surface must be unchanged from predecessor `7282309a240b1a9314e0bcd57e2b8763415a492c`. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0083 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The Phase B aggregate high remains 3,310. The conservative global projection rises only four lines from 33,356 to at most `33,360 <= 34,000`; the 32,000 preferred target and 34,000 hard cap remain unchanged, with at least 640 lines of hard-cap margin. Those numeric bounds grant no implementation or execution authority.
