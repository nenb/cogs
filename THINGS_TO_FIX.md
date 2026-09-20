# Things to Fix

This file tracks findings from the non-authoritative Issue #42 AWS diagnostic
cycles. Unless explicitly described as a harness correction, working behavior
below exists only as a disposable tracer hotpatch. It is not yet part of the
authoritative implementation.

## Working diagnostic hotpatches to implement properly

### Scoped umask for SSH input creation

AWS SSM starts the command under `umask 077`. `ssh-keygen` therefore created
`client.pub` as `0600`, while the input owner requires `0644`.

The tracer temporarily uses `umask 022` only around `create_inputs` and restores
the previous umask afterward. This has passed repeatedly. The corresponding
behavior still needs to be integrated into the core implementation and tested
under an inherited `umask 077`.

### Scoped umask for Kata runtime staging

The inherited `umask 077` caused `/run/vc/vm/cogs-stage2-ssh-v1` to be created
as `0700`, while runtime custody requires `0750`.

The tracer temporarily uses `umask 022` only around `stage_runtime` and restores
the previous umask afterward. This has passed repeatedly. The corresponding
behavior still needs to be integrated into the core implementation and tested
under an inherited `umask 077`.

A global `umask 022` hotpatch was tested and rejected because it disturbed
rootfs lease custody. The final correction must remain scoped to the exact
creation boundaries.

### Explicit IPv4 forwarding ownership

The AWS host starts with `/proc/sys/net/ipv4/ip_forward` set to `0`. SSH traffic
and direct-denial probes crossed the expected path, but guest routed probes did
not reach the host nftables forward-chain sensors, leaving both routed denial
counters at zero.

The tracer records the original value, sets forwarding to `1` for the cycle,
and restores the original value in `finally`. This behavior has enabled a
complete successful full cycle. The core network owner still needs an explicit,
fail-closed implementation with restoration proof.

## Diagnostic harness corrections already made

These are harness defects rather than production workload defects:

- Replaced the initial all-zero placeholder plan commitment with a nonzero
  diagnostic commitment.
- Require SSM `Status == Success` and `ResponseCode == 0`; a failed SSM command
  can no longer appear as a successful workflow step.
- Increased the SSM execution timeout to 5,400 seconds.
- Bounded verbose trace output so SSM's 8 KB stderr response limit preserves
  terminal failures and tracebacks.
- Removed cycle mode from `argv`, which violated cycle authority, and now use a
  root-owned diagnostic mode marker while preserving exact `sys.argv`.
- Split the seven sequential cycles across dependent jobs for cycles 1–3 and
  4–7. This preserves one workflow run, head, and batch while avoiding GitHub's
  six-hour per-job limit.
- Added per-cycle destruction and zero-inventory verification for ordinary
  success and failure paths.

## Unresolved intermittent workload failures

### Rootfs-chain generation drift

Two observations may have the same underlying cause:

1. An earlier empty-message `RootfsFsError` occurred during `open_operation`,
   before exact path and generation-field tracing was installed.
2. A later failure occurred during `remove_container` when `/var/lib` changed:
   its link count moved from `47` to `48`, and its `mtime` and `ctime` changed.
3. The instrumented recurrence during cycle 3 of run `35474910191` identified
   the exact added direct child as `/var/lib/fwupd`. The failure occurred during
   `remove_rootfs`; subsequent residue-observation errors were secondary.

The immediate AWS cause is now diagnosed: ambient `fwupd` activation creates
its state directory while strict rootfs custody is active. The disposable
tracer now runtime-masks and stops `fwupd-refresh.timer`,
`fwupd-refresh.service`, and `fwupd.service` before rootfs acquisition, and
verifies that none remains active.

The production issue is **not yet fixed**. The host-preparation owner must
quiesce the relevant ambient service before custody without weakening
fail-closed identity checks. The earlier `open_operation` failure also remains
unattributed unless the `fwupd` correction eliminates it under repetition.

Required follow-up:

- Prove the scoped `fwupd` hotpatch through repeated AWS cycles.
- Decide and implement the authoritative host-preparation ownership boundary.
- Add deterministic inherited-host-state and service-activation regression
  tests.
- Repeat the exact corrected AWS cycles.

### Containerd cgroup transaction baseline drift

A full cycle failed during `stop_task` when `_prepare_cgroup()` reported:

```text
daemon transaction cgroup baseline differs
```

The mismatch may involve the cgroup base generation, expected leaf set, daemon
leaf generation, or Kata runtime leaf generation. Subsequent runtime-removal
errors were secondary to this failure.

This is **not fixed**. The tracer now records expected and actual base
generations, leaf names, daemon-leaf generations, and runtime-leaf generations
when the failure recurs. The exact delta has not yet been captured.

Required follow-up:

- Capture the exact cgroup delta.
- Identify whether it is an asynchronous Kata/containerd transition, an owner
  sequencing defect, or unexpected ambient mutation.
- Correct transaction-profile refresh or lifecycle ordering without accepting
  foreign cgroup state.
- Add a deterministic regression test and repeat the AWS cycles.

## Cleanup limitation requiring correction

Hard cancellation of the former single-job workflow terminated its instance but
interrupted Terraform destruction, leaving eight tagged control-plane resources.
They were removed manually and independent inventory returned to zero.

Ordinary success and failure cleanup works, but hard cancellation is not yet a
durable cleanup mechanism. Before relying on this diagnostic harness for future
long runs, provide an independently durable cleanup path or avoid hard
cancellation and perform explicit bounded shutdown.

## Exit condition

Do not treat a non-recurrence as a fix. The diagnostic phase is complete only
when:

1. the unresolved rootfs and cgroup failures have an identified cause and a
   proper correction;
2. the working umask and forwarding behavior has been moved into core code;
3. the exact corrected candidate completes seven sequential non-authoritative
   AWS cycles with zero inventory after every cycle; and
4. those exact bytes are then frozen into a fresh formal `H -> G -> Q -> R`
   chain.
