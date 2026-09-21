# ADR 0351: Correct AWS host boundaries before a new H

- Status: Accepted
- Date: 2026-09-20
- Decider: Nick Byrne
- Scope: bounded pre-H correction, direct fresh H/G/Q after protected validation, and one split formal AWS campaign; no formal evidence reuse

## Context

This accepted text supersedes the earlier unmerged ADR 0351 draft titled
“Authorize a second Stage 2 R rehearsal.” That draft never became authority,
is not an additional prerequisite, and must not be interpreted as a separate
accepted decision or as a reason to create ADR 0352.

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
protected PR checks, and exact-head non-AWS checks. The already completed
contiguous seven-cycle diagnostic described above is sufficient convergence
information for this bounded correction; a second seven-cycle AWS rehearsal is
not a prerequisite. After those protected checks pass and the correction is
merged, this decision directly authorizes freezing the reviewed unchanged merge
result as fresh H. G must have that exact H as its sole parent, and Q must have
that exact fresh G as its sole parent. Fresh mixed preflight and seven-runner
qualification remain mandatory. Historical H/G/Q, diagnostic plans, approvals,
cycles, artifacts, or passed ordinals cannot supply authority to that chain.

The later authoritative AWS campaign uses only approval v6 and evidence v4 and
is one generation split into exactly two sequential GitHub jobs: cycles 1--3
and cycles 4--7 plus final zero inventory.
The second job may start only after the first succeeds in the same run and first
attempt. The first job consumes the one-shot approval once, reaches zero after
cycle 3, retires its independently acquired executor and observer credentials,
and publishes only a canonical credential-free continuation. That continuation
is bound to the exact approval and batch, H/G/Q, run ID and attempt, first-apply
deadlines, accumulated cost, typed cycle records, approval-consumption record,
and journal checkpoint. It is signed by keyless Cosign under the exact protected
campaign workflow identity, uploaded and read back by exact artifact ID and
archive digest. The second job independently verifies the artifact metadata, producer and
consumer job identities, original approval artifact metadata, bytes, signature,
and committed trusted root offline under fixed root custody. Root staging emits
a canonical handoff-authentication admission receipt bound to all of those
facts, and only the adapter may exchange that receipt for the private sealed
phase-two capability. It reconstructs consumption and journal continuity
without consuming the approval again, and independently acquires fresh executor
and observer credentials. The final v4 evidence and v2 publication receipt bind
the continuation, signature-bundle hash, admission commitment, producer and
consumer jobs, artifact ID/digest, and cycle-3 zero. Replay, cross-run or
cross-attempt substitution, partial stitching, direct in-memory handoff, and an
alternate authoritative single-job seven-cycle entry are rejected.

The approval bounds for that one generation are exactly ten hours of validity,
a 480-minute effect deadline anchored to the original first apply, a 30-minute
cleanup reserve, a 150-minute maximum per cycle, and 1,100,000 micro-USD. Job
bounds are 300 minutes for cycles 1--3 and 330 minutes for cycles 4--7; each
retains a 30-minute recovery path and derives a separate short-lived role
session duration from the remaining approval lifetime within the approved AWS
maximum. Before approval consumption, at least the full 480-minute effect
window, 30-minute cleanup reserve, and fixed 15-minute first-plan allowance
must remain; the workflow conservatively requires at least 32,400 actual
seconds before the first credential. Job 1 requests exactly 18,000 seconds and
job 2 exactly 19,800 seconds of role lifetime only after proving the signed
absolute and inherited first-apply deadlines have that runway; each executor
and observer uses a fresh single-step OIDC/STS exchange that re-samples those
deadlines and rejects a returned expiration outside them. The diagnostic lane
requests exactly 30,600 seconds for both roles, proves that each lower-bound
expiration exceeds the absolute 480-minute job end by at least 900 seconds,
and requires the shared executor and observer roles to have
`MaxSessionDuration >= 30600` (therefore also satisfying the prior 23,400-second
formal requirement). An unsupported role maximum fails before effects. Zero inventory after every cycle, global identity distinctness,
strict cgroup checks, cleanup certainty, and pass-only evidence issuance after
cycle 7 and final zero are unchanged. Any publication, verification, download,
admission, campaign, cancellation, or cleanup uncertainty terminates the run;
no ordinal is reusable. The R diagnostic remains a separate explicitly
non-authoritative path: it returns only its dedicated diagnostic receipt, never
constructs a formal campaign candidate, calls the formal evidence issuer, or
publishes production evidence.

No previously selected H, G, or Q is edited or retroactively reclassified.
These corrections land before selection of a new H; a new G then controls that
exact H and a new Q qualifies that exact G. The prerequisite map records this
ordering and does not make the earlier diagnostic or the earlier unmerged ADR
into a freeze prerequisite.

## Accounting

This correction remains inside ADR0338's existing cumulative hard stops. Admit
this ADR to governance. Admit only
`deploy/aws-feasibility/remote/completion_kata_process.py` and its existing
focused Python test to the pre-H portion of `final-HGQ`; the provider and its
existing fake test remain in `local-tofu-ssm`. The new ADR raises the tracked
file high from 1,545 to 1,546. The deterministic readiness refresh receives no
deletion credit: the host correction reallocated 600,000 prospective bytes from
`local-tofu-ssm` to `readiness-ci`. This split implementation reallocates another
200,000 prospective bytes for the mandatory refreshed tracked-source inventory,
making those intermediate highs 3,300,000 and 8,400,000 bytes.

Because this ADR remains an unmerged draft, its R3 correction expressly
reallocates task authority before merge. Its first zero-sum amendment raised
`governance` from 6,200 to 7,033 lines (+833) and `local-tofu-ssm` from 5,100 to
5,446 lines (+346), funded by reducing `final-HGQ` from 5,300 to 4,121 lines
(-1,179). It also transferred 300,000 prospective bytes from `final-HGQ` to
`readiness-ci`, making their active byte highs 5,200,000 and 9,000,000.

The readable final security correction exhausts the 307 lines that remained
unused across the other pre-H task caps. The draft therefore makes a second,
explicit zero-sum line amendment rather than compressing security-sensitive
production code or tests to observed-use highs. It transfers exactly 2,600
lines out of the provisional `final-HGQ` post-H reserve and reallocates all
five task highs as follows: `governance` 7,033 to 8,400 (+1,367), `product`
5,057 to 5,050 (-7), `local-tofu-ssm` 5,446 to 6,800 (+1,354), `readiness-ci`
500 to 400 (-100), and `final-HGQ` 4,121 to 1,507 (-2,614). Within the new
`final-HGQ` high, the pre-H cap is 607 lines (-14) and a truthful positive
900-line post-H reserve remains. These rounded, deliberate highs leave
bounded headroom above measured readable use; none is pegged to observed use.
The 3,500,000-byte post-H reserve is unchanged. The final deterministic Stage
4 refresh requires a second explicit byte reallocation: 300,000 prospective
bytes move from the genuinely unused `product` allocation, reducing it from
2,900,000 to 2,600,000 bytes, to `readiness-ci`, increasing it from 9,000,000
to 9,300,000 bytes. The final package-verification correction makes a third
explicit zero-sum byte reallocation: 400,000 prospective bytes move from
`product` (2,600,000 to 2,200,000), split equally between `governance`
(1,100,000 to 1,300,000) and `readiness-ci` (9,300,000 to 9,500,000).
All transfers leave deliberate headroom above measured use.

These are explicit zero-sum reallocations for the reviewed split campaign
governance/contracts, lifecycle implementation/tests, and generated readiness
inventory; they are authorization, not a silent adjustment to observed use.
The tranche remains exactly 22,157 lines and 21,500,000 bytes, the global
forecast is unchanged, and deletions or rewrites still receive no credit.

The 12 additive split-campaign contract, implementation, test, and
fixture paths raise the tracked-file high from 1,546 to 1,558. No pre-existing
tracked file is retired for accounting: historical workflows, tests, evidence
and approval schemas, validators, renderers, and fixtures--including v3
evidence and v5 approval--remain tracked and byte-compatible. Deletions and
rewrites provide no line or byte credit.

## Consequences

The successful disposable campaign proves feasibility, not production
evidence or authority. This ADR authorizes the bounded correction to proceed
directly through protected review and merge into a fresh H/G/Q chain, followed
only by the newly split one-shot formal R sequence above. It does not accept the
diagnostic evidence as formal evidence, authorize release, or by itself close
Issue 42.

Stage 4 remains separate and consumes accepted Stage 2 evidence only after the
fresh Stage 2 chain closes; it does not rerun or substitute for H, G, or Q.
