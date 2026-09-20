# ADR 0351: Correct AWS host boundaries before a new H

- Status: Accepted
- Date: 2026-09-20
- Decider: Nick Byrne
- Scope: bounded pre-H implementation, tests, non-authoritative rehearsal, and later fresh H/G/Q; no formal evidence reuse

## Context

Historical implementation H `1ef6aae3506fded805d8277ec4bce02e585c0650`,
control G `fce64662b39b2a21e9b384eba8408ecd5311047a`, and qualification
Q `4e16c314b220c59330a1b4fb898c532f9ca6460e` completed their non-AWS
qualification. Every formal AWS generation through R8 is terminal and cannot be
retried or stitched to later evidence.

The explicitly non-authoritative AWS convergence lane then exercised the real
`c8i-flex.large` host and found three host-boundary assumptions that historical
H did not own:

1. SSM enters with `umask 077`. The SSH key commands therefore produced the
   public key as mode `0600`, and Kata inherited the restrictive mask through
   the long-lived containerd daemon and created its VM directory as `0700`.
2. The Ubuntu AWS host enters with IPv4 forwarding disabled. Guest-routed
   denial traffic never reached the owned nftables forward-chain sensors until
   forwarding was enabled for the cycle.
3. Ambient `fwupd-refresh.timer`, `fwupd-refresh.service`, or `fwupd.service`
   may create `/var/lib/fwupd` while rootfs ancestor custody is active. Strict
   generation checking correctly rejected that mutation.

A disposable tracer corrected only those boundaries by scoping mode creation,
owning and restoring forwarding, and runtime-masking the exact fwupd units
before custody. One full cycle passed, followed by one contiguous seven-cycle
campaign at diagnostic head `a29da2776851c8a01958410e44813641e75268cf`:
one full route and six readiness routes, all SSM responses successful, all
per-cycle destruction checks zero, and an independent all-enabled-region scan
zero. This is diagnostic evidence only.

One earlier cycle also rejected an unexplained containerd cgroup transaction
baseline change. The later seven-cycle campaign, a three-second pre-preparation
stress, and a ten-second stale-profile stress did not reproduce it. A rejected
thirty-second experiment instead consumed the already-established command
work cutoff and says nothing about cgroup state. No exact cgroup delta exists,
so weakening cgroup generation, identity, or leaf-census checks would convert
an unexplained fail-closed observation into unsafe acceptance.

## Decision

Make only these production corrections:

- In the command child, after release and immediately before `execveat`, set
  `umask 022` only for the two SSH private-key generation commands, the two SSH
  public-key extraction commands, and the long-lived containerd start. Every
  other child inherits the unchanged supervising mask, which remains `077` on
  AWS; the supervising Python process never changes its mask. This gives
  OpenSSH its required public-file modes and makes the Kata VM
  directory inherit the reviewed runtime mode without weakening rootfs,
  journal, receipt, or custody creation.
- In the AWS remote host-preparation shell, inspect exactly
  `fwupd-refresh.timer`, `fwupd-refresh.service`, and `fwupd.service` before
  immutable preparation. Admit exact `not-found` as absence. Otherwise require
  `loaded|masked`, runtime-mask and stop the unit, verify its exact runtime
  mask, and require exact `inactive|failed` state from systemd. Do not accept
  an observation error as inactivity or relax any rootfs generation check.
- Immediately before the admitted cycle command, require the approved exact
  `/proc/sys/net/ipv4/ip_forward` baseline `0`, set it to `1`, and verify it.
  Install an exit trap that restores and verifies `0` while preserving the
  workload status, but returns a cleanup failure status if restoration fails.
  Signal exits use the same restoration path. Cooperative exits and catchable
  signals must restore; hard termination makes no trap-execution claim and is
  settled only by destroying the dedicated one-cycle instance. Do not make
  forwarding a persistent sysctl setting. Runtime fwupd masks intentionally
  remain until instance destruction so cleanup cannot reintroduce the mutator.
- Preserve the cgroup implementation byte-for-byte in this correction. Any
  later cgroup mismatch remains terminal and receives no retry credit. Before
  another candidate, investigate it only through a bounded non-authoritative
  exact-delta diagnostic; non-recurrence is not proof of a cgroup correction.

Add focused regression assertions for the exact child command set, the child-
only placement of the mask, exact fwupd unit handling before immutable custody,
and forwarding enable/verified restoration on success, workload failure, and
signal-shaped exits. Preserve the historical diagnostic artifacts as
non-authoritative and do not copy their hotpatch wrapper into production.

The corrected implementation first receives local validation, review,
protected PR checks, and exact-head non-AWS checks. It then requires a fresh
non-authoritative static observation/control package and a complete seven-cycle
AWS rehearsal of those exact selected source bytes with one batch and zero
inventory after every cycle. A failure, recurrence, cancellation, or uncertain
cleanup retires that rehearsal generation.

A clean rehearsal cannot itself authorize or produce H. Its accepted evidence
may only be an input to a separate reviewed and accepted decision that explicitly
authorizes freezing the unchanged implementation as a new H. G must then have
that exact H as its sole parent, and Q must have that exact fresh G as its sole
parent. Fresh mixed preflight, seven-runner qualification, and formal R
planning/approval/campaign are then required. Historical H/G/Q, diagnostic
plans, approvals, cycles, artifacts, or passed ordinals cannot supply authority
to that chain.

## Accounting

This correction remains inside ADR0338's existing cumulative hard stops. Admit
this ADR to governance. Admit only
`deploy/aws-feasibility/remote/completion_kata_process.py` and its existing
focused Python test to the pre-H portion of `final-HGQ`; the provider and its
existing fake test remain in `local-tofu-ssm`. The new ADR raises the tracked
file high from 1,545 to 1,546. The deterministic readiness refresh receives no
deletion credit: reallocate 600,000 prospective bytes from `local-tofu-ssm` to
`readiness-ci`, making their active highs 3,500,000 and 8,200,000 bytes. No task
line high, tranche total, global forecast, serialized-inventory limit, or
source-byte limit changes. Deletions and rewrites provide no credit.

## Consequences

The successful disposable campaign proves feasibility, not production
correctness or authority. This ADR does not authorize formal H/G/Q/R evidence,
production eligibility, release, or Issue 42 closure. It authorizes the bounded
source correction and exact non-authoritative rehearsal sequence above under
the owner's standing instruction to continue until behavior is resolved.

Stage 4 remains separate and consumes accepted Stage 2 evidence only after the
fresh Stage 2 chain closes; it does not rerun or substitute for H, G, or Q.
