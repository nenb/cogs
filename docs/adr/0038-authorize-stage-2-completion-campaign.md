# ADR 0038: Authorize the bounded Stage 2 completion campaign

- Status: Accepted
- Date: 2026-07-22
- Decision owner: Nick Byrne
- Acceptance: Nick Byrne explicitly approved authenticated SSH into a standalone Kata sandbox and local-only implementation. The delegated project lead accepts seven sequential fresh launches for issue #42 p50/p95 and a deterministic `dpkg-deb` build plus local `dpkg` install as the representative package build/install workload under Nick Byrne's standing delegation to continue autonomously and make project decisions without waiting.

## Context

Accepted campaign 8 provides partial issue #42 evidence for one `c8i-flex.large`: active nested KVM, a root Kata 3.32.0 QEMU guest with a distinct kernel, seven Kata cold boots, warm CPU/filesystem measurements, host-only Git/build baselines, one apply-to-running and one SSM-online observation, bounded cost, destroy, and zero inventory. It does not provide repeated fresh EC2 launch percentiles, authenticated sandbox SSH-ready percentiles, or representative Git and package build/install measurements inside Kata.

The current Stage 2 operations boundary authorizes only one SSM-managed EC2 campaign, explicitly does not treat SSM-online as SSH-ready, and forbids repeated launches or SSH expansion without separate review. ADR 0012 selected virtual AWS nested KVM as the Stage 4 candidate but did not authorize this completion campaign. ADR 0037's four-package Git disk is scoped only to issue #71 and is not reusable authority for issue #42.

Public source research established a bounded path without changing the cloud resource graph:

- containerd `v2.2.1` maps `ctr run --with-ns network:<path>` into the OCI network namespace path while preserving `--rootfs` and the checked runtime config;
- Kata `3.32.0` reads that path, rejects host networking, scans a configured veth, and uses QEMU's `tcfilter` default to connect it to the guest;
- the already pinned Debian 13 slim OCI base contains `dpkg`/`dpkg-deb` 1.22.22; and
- a selected exact pinned ten-package candidate extraction set is small enough to qualify as a possible OpenSSH and local Git closure without a compiler or guest network; its runtime sufficiency has not been proven.

This decision authorizes local capability implementation only. It creates no cloud execution authority and records no new measurement evidence.

## Decision

Authorize a local-only Stage 2 completion harness with exactly seven fresh, sequential create/measure/destroy cycles. At most one EC2 instance and the existing exact 16 managed resources may exist at any time: one VPC, internet gateway, subnet, route table, route, route-table association, security group, host IAM role, host policy attachment, instance profile, launch template, EC2 instance, terminator IAM role, terminator IAM policy, Scheduler schedule, and Budget. Every cycle must use one clean source revision, `us-east-1`, `c8i-flex.large`, two vCPUs, 4096 MiB, the existing encrypted disposable 30 GiB gp3 root, nested virtualization, IMDSv2, the existing no-ingress security group, SSM controller access, budget, Scheduler termination, and guest-local termination fallback.

The seven cycles are one bounded batch, not seven concurrent instances and not samples synthesized by stop/start. One cycle runs the full runtime and representative workload suite. Six cycles run the minimum identical runtime and authenticated SSH-ready path. Seven independent apply-to-running and Kata-launch-to-authenticated-SSH samples are sufficient for the issue #42 p50/p95 decision using the existing nearest-rank percentile method.

### Time, cost, and cleanup bounds

All seven cycles share one absolute expiry no more than four hours after the first apply. Later cycles must not refresh or extend it. The normal batch deadline is 90 minutes, followed by cleanup even on timeout.

- Expected aggregate cost must remain below USD 0.25.
- Publishable aggregate estimated cost must remain below USD 0.50.
- The existing USD 20 budget and three alerts remain defense in depth, not a hard stop.
- Every cycle must destroy immediately and independently report zero inventory before the next plan.
- Final success additionally requires a separate independent zero inventory after cycle 7.
- Any apply, runtime, measurement, validation, timeout, interrupt, destroy, or inventory uncertainty prevents final evidence and aborts later cycles.

The OpenTofu graph remains unchanged. Each cycle must pass the existing exact create-only plan checker. Direct `RunInstances`, stop/start, force deletion, or direct resource deletion outside the state-bound destroy path is not authorized.

## Authenticated Kata SSH semantics

SSH-ready means elapsed time from immediately before the fixed Kata `ctr ... run --detach` operation until the first strict authenticated command returns one exact fixed marker. A listener, banner, process, SSM state, key scan, or unauthenticated connection is not SSH-ready.

The fixed internal topology is:

- network namespace `/run/netns/cogs-stage2-ssh`;
- one veth pair, host end `c42h0` at `192.0.2.1/30` and namespace/guest `eth0` at `192.0.2.2/30`;
- loopback plus that interface only, with no guest default route;
- Kata QEMU `internetworking_model=tcfilter` and `disable_new_netns=false`;
- containerd `v2.2.1` `--with-ns network:/run/netns/cogs-stage2-ssh` on the checked `--rootfs`/`io.containerd.kata.v2` path;
- host firewall rules allowing only host-originated SSH return traffic and denying guest-initiated host or forwarded traffic; and
- no EC2 ingress, public SSH, EC2 key pair, host network namespace, CNI, bridge/NAT, EKS, or fallback.

Each cycle generates fresh Ed25519 client and OpenSSH host keys. The controller constructs `known_hosts` from the generated host public key before launch. The guest receives one `restrict` client public key. Password, keyboard-interactive, PAM, agent, TCP/stream-local forwarding, X11, tunnel, TOFU, and `ssh-keyscan` authority are forbidden. Key material, fingerprints, internal addresses/ports, SSH errors, and complete commands must not enter publishable evidence.

The caller owns the namespace, veth, and firewall objects. Normal teardown must stop and independently observe the Kata task as `STOPPED`, remove the caller-owned namespace, remove the task/container without force, observe QEMU exit, remove exact owned firewall state, and prove network/QEMU/task/container baselines are restored. Unknown or contradictory identity fails closed rather than deleting an uncertain object.

## Upstream interface basis

- containerd v2.2.1 `--with-ns`, runtime-config, and container flags: <https://github.com/containerd/containerd/blob/v2.2.1/cmd/ctr/commands/commands.go>
- containerd v2.2.1 Linux OCI spec construction: <https://github.com/containerd/containerd/blob/v2.2.1/cmd/ctr/commands/run/run_unix.go>
- Kata 3.32.0 OCI network-path conversion: <https://github.com/kata-containers/kata-containers/blob/3.32.0/src/runtime/pkg/oci/utils.go>
- Kata 3.32.0 namespace setup and host-network rejection: <https://github.com/kata-containers/kata-containers/blob/3.32.0/src/runtime/pkg/katautils/network_linux.go>
- Kata 3.32.0 veth/tcfilter design: <https://github.com/kata-containers/kata-containers/blob/3.32.0/docs/design/architecture/networking.md>
- Kata 3.32.0 QEMU `tcfilter` default: <https://github.com/kata-containers/kata-containers/blob/3.32.0/src/runtime/Makefile#L461-L467>
- Debian snapshot InRelease: <https://snapshot.debian.org/archive/debian/20260713T000000Z/dists/trixie/InRelease>
- Debian snapshot package index: <https://snapshot.debian.org/archive/debian/20260713T000000Z/dists/trixie/main/binary-amd64/Packages.xz>

## Pinned rootfs and candidate package extraction set

### Debian OCI base

The rootfs starts from the exact Debian 13 slim OCI artifacts:

| Artifact | SHA-256 digest | Bytes |
| --- | --- | ---: |
| OCI index | `28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2` | 8,973 |
| linux/amd64 manifest | `a617c1cdde36a7e0194b2f07dff669e1753c03c3205356b94f9f350b0f9a57d1` | 1,021 |
| config | `84645f91e8d166d709fcef984301b2576198bf880c15eb3ce9f4c8fad305c4ea` | 451 |
| gzip rootfs layer | `e95a6c7ea7d49b37920899b023ecd0e32796c976c1748491f76cae53ba86d13a` | 29,785,419 |
| uncompressed diff ID | `3edb2192497af6e965b9b7e57dc6dbdce1f3ea721d14a98110419d4ded523298` | n/a |

The Debian snapshot is exactly `20260713T000000Z`. Its Debian 13.6 trixie `main/binary-amd64/Packages.xz` is 9,672,648 bytes with SHA-256 `3ab4e811cf4f3e5a335d382c58cc19d85f1abe7a4ef4689160ca1f637fa0e9b3` and is bound by the snapshot's signed `InRelease`.

### Ten-package candidate extraction set

The host may fetch only these snapshot artifacts over TLS, verify regular-file identity, exact size, SHA-256, package, version, and architecture, and extract them with fixed `dpkg-deb -x`. They are the selected exact pinned candidate extraction set to qualify, not a proven operational closure. Their maintainer scripts and normal service-manager installation dependencies must not run.

| Package | Version | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `git` | `1:2.47.3-0+deb13u1` | 8,861,572 | `3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722` |
| `openssh-server` | `1:10.0p1-7+deb13u4` | 602,372 | `b4a02524fd2be375624d917ee8102a16567e9e8dd786b41c35e22360cdd37f9d` |
| `libcom-err2` | `1.47.2-3+b11` | 25,036 | `e1feff126b3e8b3a7b18087e88681469b70d8f6d1b7c4e4b89d98577e1a2fdd7` |
| `libgssapi-krb5-2` | `1.21.3-5+deb13u1` | 138,356 | `30847c1fde4240567d7ed3aeab4f655dd591203758b857e85e824045aae70299` |
| `libk5crypto3` | `1.21.3-5+deb13u1` | 81,152 | `7da07ee674b47f1f0be7cc89317c25310086a1f1761217d0f72e6ae2c5a69b84` |
| `libkeyutils1` | `1.6.3-6` | 9,456 | `0b11ad17be0300b63ad4eeb4c6450fed24d34b7b740f23e5363dcb29ee6d5eba` |
| `libkrb5-3` | `1.21.3-5+deb13u1` | 326,056 | `47d71d6a7f2e59b9bae5f89602397594805113b95889ad18fa703cd53abafc97` |
| `libkrb5support0` | `1.21.3-5+deb13u1` | 33,124 | `3a0acd8b37955c0e102c756b52c97df2a31f67b96453c35dab70df218d309117` |
| `libwrap0` | `7.6.q-36` | 55,256 | `cde12afa15d6b1556c5e0564d22edf3b99e6b8fa94c59ccd8b8eebbb62dc19ec` |
| `libwtmpdb0` | `0.73.0-3+deb13u1` | 13,056 | `8d6bc1c961d734da58b2d4c35b0a3cd6ad2fe81655bd982c655a97c2255b1c9b` |

The added package inputs total exactly 10,145,436 bytes. Checked implementation has not yet proven this candidate set's runtime sufficiency. Qualification must postwalk type/path/owner/mode/link bounds, create a fixed privilege-separation account without running package scripts, remove generated identity/cache state, pass dynamic-link and version checks for the fixed Git/OpenSSH executables, pass `sshd -t` and strict authenticated SSH, and pass the fixed local Git operations. Any missing dependency is a stop-and-replan condition requiring a new decision; implementation must not silently add an eleventh package.

The composed rootfs digest is an output of the implementation authorized here. The implementation must build it twice in clean temporary roots, prove identical output, and pin that digest before any cloud execution. Generated fixture digests follow the same rule. Exact immutable inputs are sufficient to authorize the builder; unpinned output is not sufficient to authorize a campaign.

## Representative sandbox workloads

### Git

The fixture is synthetic and contains no Cogs or user source. Its generator creates one bare repository from 512 files named by a fixed numeric sequence, each with 128 deterministic lines, and one fixed commit. Each of seven full-cycle samples clones locally into a fresh directory, checks out the fixed commit, modifies exactly 32 tracked files, creates exactly 8 untracked files, runs `git status --porcelain`, requires exactly 40 expected entries, and deletes the sample directory. No remote Git helper, URL, credential, or guest network is permitted.

### Package build and install

A deterministic local Debian package build plus local `dpkg` install satisfies issue #42's representative package build/install criterion; no compiler is required. The fixture package is `cogs-stage2-fixture`, version `1.0`, architecture `all`, with no dependency or maintainer script and exactly 256 deterministic 4096-byte payload files.

Each of seven samples uses a fresh directory, normalized mtimes, fixed `SOURCE_DATE_EPOCH`, `dpkg-deb --build --root-owner-group --compression=xz --compression-level=6 --threads-max=1`, and a fresh `dpkg --admindir`/`--instdir` installation root. Package build and package install are separate timed summaries. The result must match the pinned generated package and installed-tree digests before the sample is accepted. No apt, package index, compiler, external package, or guest network is part of the timed path.

Raw fixture source/content, package bytes, Git objects, tool output, commands, URLs, keys, or paths are not evidence. Final evidence may contain only fixed workload version/dimension enums, booleans, and recomputed timing summaries.

## Evidence and schema boundary

The accepted `cogs.aws-stage2-measurement-evidence/v1alpha1` schema, validator, renderer, and campaign-8 report remain historical and unchanged. Completion capability must use a new strict schema/version and separate validator/renderer. It must require exactly seven ordered cycles, one full plus six readiness modes, common source/artifact semantics, seven raw launch and authenticated-SSH samples, recomputed min/p50/p95/max, full-cycle workload summaries, per-cycle cleanup/zero inventory, final independent zero inventory, aggregate duration/cost bounds, and strict additional-property/redaction rejection.

No failed, interrupted, timed-out, cleanup-uncertain, mixed-source, mixed-artifact, partial, duplicated, or cross-batch sample may enter final evidence. Human rendering occurs only after final validation and all cleanup.

## Manual gates and authority

Local implementation remains closed unless this accepted ADR is present. The existing phrases `COGS_AWS_APPLY_APPROVED=apply-one-cpu-instance` and `COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED=run-one-stage2-measurement-campaign` do not authorize the completion batch.

A future implementation must require this distinct exact outer phrase:

```text
COGS_AWS_STAGE2_COMPLETION_APPROVED=run-seven-sequential-stage2-completion-launches
```

The phrase in code is a fail-closed mechanism, not standing cloud approval. Before one execution, Nick Byrne must separately approve the exact clean revision, account binding, region/type, plan shape and digests, resolved AMI, composed rootfs and fixture digests, current price/quota, expiry/deadline, cost limits, destroy/recovery path, and this gate for one named batch. No such execution approval exists in this ADR.

## Line budget

The measured Stage 2 non-test/non-doc baseline is 2,581 lines. Count `deploy/aws-feasibility/**/*.{sh,py,tf}`, Stage 2 AWS evidence schemas, and Stage 2 AWS validator/renderer scripts.

- Preferred cumulative target: 4,600 lines.
- Hard cumulative cap: 5,100 lines.

Tests and docs are excluded but must remain readable. Exceeding the hard cap requires a measured scope/cap ADR; it must not cause compressed timeout, cleanup, networking, SSH, artifact, validation, or redaction logic. This ADR does not change production `src` or launcher caps.

## Qualification gates before cloud execution

Local implementation must stop before requesting cloud approval until all of these pass:

1. two clean rootfs builds from the pinned inputs produce one identical output digest, and that digest is pinned;
2. generated Git/package fixture and expected installed-tree digests are deterministic and pinned;
3. the selected exact pinned ten-package candidate extraction set passes postwalk, dynamic-link, version, `sshd -t`, strict authenticated SSH, and fixed Git operations;
4. local KVM with Kata 3.32.0/containerd 2.2.1 proves the /30 `--with-ns`/veth/tcfilter path, strict marker timing, no default route, and no host-network fallback;
5. normal, failed, timed-out, and interrupted teardown prove no task, container, QEMU, namespace, veth, TAP, tc-filter, firewall, key, rootfs, or fixture residue;
6. fake-command tests prove seven-cycle ordering, no overlap, per-cycle destroy/zero, final independent zero, source/expiry binding, and no partial publication;
7. the completion schema/validator/renderer hostile matrix and sensitive-content scans pass;
8. the cumulative Stage 2 line count remains below 5,100; and
9. an execution-readiness review records exact pins, bounds, limitations, and the continued absence of cloud authority.

A failed qualification is a stop/replan condition, not permission to add packages, broaden networking, relax timeouts, use retries, or execute in AWS for debugging.

## Stop gates

Another ADR or explicit human decision is required for:

- any cloud resource outside the current 16-resource shape or more than one concurrent instance;
- a different region/type, larger disk, GPU, bare metal, EIP, NAT, endpoint, load balancer, EFS, EKS, ECS, or Auto Scaling;
- EC2 ingress, public/unmanaged SSH, EC2 key pairs, host networking, CNI, bridge/NAT, a guest default route, or guest network package/workload fetches;
- any rootfs/package/version/size/hash drift or an eleventh extracted package;
- Dropbear or another SSH daemon, password/TOFU/keyscan/forwarding, or a non-authenticated readiness substitute;
- Cogs/user source, prompts, credentials, arbitrary paths/URLs/packages/commands, a compiler, Docker daemon, or general OCI/package tooling;
- changes to `src`, `dev/launcher`, workflows, package dependencies/lockfile, accepted v1alpha1 evidence, ADR 0012, or ADR 0037;
- cross-batch samples, partial evidence, forced cleanup, timeout relaxation, or retry/rerun substitution;
- expected cost at or above USD 0.25, accepted aggregate cost at or above USD 0.50, expiry over four hours, or normal deadline over 90 minutes;
- cumulative Stage 2 non-test/non-doc code over 5,100 lines; or
- AWS/provider/OpenTofu/workflow/deploy/release/production scope.

## Non-claims and consequences

This ADR authorizes only local implementation of a bounded standalone Stage 2 completion capability. It does not create AWS resources, authorize planning/apply/inventory, approve a workflow, provide measurement evidence, or close issue #42.

It does not authorize or establish EKS, Kubernetes, `RuntimeClass`, CNI/NetworkPolicy, scheduled-to-ready p99, the Stage 4 under-30-second gate, EBS workspace behavior, warm pools, autoscaling, real Cogs/Pi/model/OpenBao/proxy/WAL/telemetry integration, multi-session isolation, Stage 5 resilience/load, release, production, compliance, general availability, or regional capacity. ADR 0012 remains the accepted Stage 4 candidate decision and all of its mandatory EKS reruns remain required.

Implementation may now build the exact local capability and generate deterministic rootfs/fixture outputs for pinning. It must stop after local execution-readiness validation until a separate named cloud approval is recorded.
