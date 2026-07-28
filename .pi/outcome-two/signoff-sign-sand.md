# Outcome 2 exact-head signoff — sign-sand

- Exact reviewed head: `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`
- Scope: only the five final-review findings and corrections through `aa45a04`; focused on T2 observations, seccomp/exec authority, final maps, and cleanup
- Decision: **BLOCKED — native Jobs A–E implementation is not ready**

## Unresolved findings

### P1-1 — The corrected seccomp policy blocks the boundary record required before exec

`_DENIED_SYSCALLS` now correctly includes `sendto` and `sendmsg` (`completion_trusted_runtime_launcher.py:49-58`), and `_enter_boundary()` installs that filter before returning (`:1130-1157`). `_child_fd_install()` then calls `status.send(...)` only after `_enter_boundary()` (`:1173-1175`). On Linux x86-64, Python's socket send reaches the denied socket-send syscall, so the boundary record fails with `EPERM`; the child reports an exec-setup failure and never reaches `execveat`, the clean exec EOF, either final-map gate, or input. The nominal native qualification path therefore cannot succeed.

### P1-2 — Root/setup rollback still has uncovered write-ahead cuts and cleanup failure is demoted to the primary error

`_RootOwner.prepare()` records create intent, performs `mkdir`, and only then opens/stores the root identity (`:1052-1063`). Its cleanup removes the path only when `identity` is already known (`:1064-1079`). `_run_tool_with_ops()` creates both pipe pairs and the status pair, then calls `root_owner.prepare()` and reads the limits baseline before entering its recovery `try` (`:1483-1496`). A fault after `mkdir` but before root identity assignment therefore bypasses the tool finalizer and leaves the path and leased descriptors outside recovery. A focused fault at that exact cut confirmed that even an explicit `root_owner.cleanup()` leaves the created path because `identity is None`.

At the outer layer, cleanup observations may subsequently be false, but `_coordinate_with_ops()` raises the original primary at `:1733-1735` rather than converting failed restoration into terminal `cleanup-uncertain`. Thus root/path/fd uncertainty can still escape as a generic setup error or an unavailable result instead of the required cleanup error.

### P1-3 — The corrected portable launcher/recovery gate still does not challenge the named T2, seccomp, exec, map, and cleanup branches

The launcher model's `trip()` manufactures both the fixture-selected error code and the row's sentinel (`test/outcome-two-trusted-launcher-portable.py:204-212`). Every `_coordinate_with_ops` row trips on the initial proc-fd `open` regardless of its declared T2 observation fault (`:228-233,626-631`); every `_run_tool_with_ops` row trips at `socketpair` (`:265-269,618-624`); and every `_enter_boundary` row trips at the first `prctl`, before capability or seccomp observations. The root adapter invokes `_materialize_root()` without `_RootOwner` and manually removes the fixture path (`:650-660`). Focused traces showed `seccomp-missing-route` stopping at `chroot`, `obs-seccomp-denials` stopping at the first fd-snapshot open, and `root-after-create` stopping at mount.

Recovery likewise preconstructs three registered leases and synthetic domain fds, then injects the crash by calling the model's marker/error generator rather than crashing `_worker_main`, `_namespace_owner`, `_materialize_root`, or `_run_tool_with_ops` at the declared cut (`test/outcome-two-recovery-portable.py:88-151`). These tests remain green if the production seccomp assembler, boundary-send ordering, final-map/input gates, or root write-ahead rollback is removed. The mandatory `AT-SECCOMP-01`, `AT-T2-OBS-01/02`, `AT-EXEC-01`, `AT-EXEC-ONCE-01`, `AT-ROOT-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, and branch-removal portion of `AT-FIXTURE-01` therefore remain unproved.

## Verification

- Seven isolated portable Python suites: passed.
- Seven optimized-Python rejection runs: passed.
- Correction-range `git diff --check de7f0e4..aa45a04`: passed.
- `git fsck --no-progress --no-dangling`: passed.
- No native, privileged, namespace, mount, seccomp, `map_files`, compression-tool, workflow, provider, cloud, or deployment operation was run.

## Native implementation readiness

**NO.** Three genuine P1 findings remain. Native Jobs A–E and thin integration stay blocked pending correction and a new exact-head zero-finding signoff.

SIGNOFF COMPLETE
