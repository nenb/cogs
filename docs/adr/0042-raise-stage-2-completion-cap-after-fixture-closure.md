# ADR 0042: Raise Stage 2 completion cap after fixture and closure replan

- Status: Accepted
- Date: 2026-07-24
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead on 2026-07-24 under Nick Byrne's explicit instruction to continue local work and make required decisions while retaining the separate AWS deployment gate.

## Context

ADR 0041 raised the issue #42 Stage 2 completion preferred cumulative target to 14,000 lines and its hard cumulative cap to 15,000 lines. It did not change the frozen count or the scope fixed by ADRs 0038–0040.

The local issue #42 work descends from `origin/main` at `d0cccb86ad844346284f6917cf509116872d1114`. At clean local head `07d592b3de3a5ae0bc1690cb3ee0cfd18489ac17`, the frozen count is now **10,855 physical lines**:

| Frozen counted set | Lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 10,264 |
| Frozen historical schemas, validators, and renderers listed by ADR 0039 | 591 |
| **Measured cumulative total** | **10,855** |

The 591-line subtotal remains the exact five files frozen by ADR 0039: `schemas/aws-stage2-measurement-evidence-v1alpha1.json`, `scripts/validate-aws-stage2-measurement-report.ts`, `scripts/render-aws-stage2-measurement-report.ts`, `schemas/aws-feasibility-report-v1alpha1.json`, and `scripts/validate-aws-feasibility-report.ts`. Any new Stage 2 completion evidence schema, validator, or renderer also enters the counted set when added. Retained counted files never stop counting because a replacement or shared implementation is added.

Tests, documentation, reports, generated evidence, and fixed artifact or pin contracts remain excluded. They remain mandatory and readable. Production behavior may not be moved into an excluded category, generated file, dense data contract, test helper, or documentation to evade the cap. The measurement remains physical file lines, not logical statements or formatted-line estimates, and assumes no deletion credit.

The deterministic fixture and static runtime-closure slice added 588 counted lines. That exhausted ADR 0041's 350–600-line estimate in practical planning terms before the executed fixture materializer, guest qualification contract, or package-output pin transaction was implemented. Only 3,145 lines remain to the preferred target and 4,145 lines to the hard cap.

A corrected named-module replan estimates **4,340–6,720 net counted lines** remaining. Applied to the measured 10,855-line baseline, its cumulative range is **15,195–17,575 lines**. Even the low case exceeds ADR 0041's 15,000-line hard cap by 195 lines. The safe high exceeds it by 2,575 lines. Implementation therefore stopped before another production slice; remeasurement during implementation cannot make an already insufficient cap safe to implement under.

### Why the earlier forecasts missed

The miss is not new workload, package, cloud, or deployment scope.

First, ADR 0039 estimated the complete deterministic rootfs at 650–950 lines. ADR 0040's mechanism-specific replan estimated 1,330–1,820 lines for its R2 and R3 work. Hostile review then required explicit fd-relative identity, write-ahead recovery, hardlink generation, publication, close/error, and uncertainty-preserving behavior. ADR 0041 corrected that miss only after much of the rootfs work had already crossed its stop gate.

Second, ADR 0041 grouped deterministic fixtures and exact-package runtime closure into 350–600 lines. The measured static fixture/closure foundation alone consumed 588 lines. The prior estimate did not include enough production integration for executing the modeled fixture and closure under Kata.

Third, the prior plan treated the historical 751-line runtime script as a stronger reuse basis than review supported. It omitted a separately owned guest-work mount with crash-recoverable mount identity, durable lifecycle identities, the exact ADR 0038 teardown order, the authenticated result boundary, and complete failure cleanup. Guest-mutated work cannot share the read-only rootfs ledger or rely on recursive host deletion.

Fourth, the earlier package-workload estimate did not include the non-circular package-output pin bootstrap. Authoritative readiness and full modes cannot accept an unpinned package, so a fixed local-only candidate transaction must derive the package digest, size, and installed-tree identity before the final runtime contract is committed. It cannot be a campaign mode or evidence source.

Finally, controller and evidence estimates had been reduced based on projected reuse rather than measured compatible implementation. The corrected plan restores ranges sufficient for the fixed seven-cycle state machine and separate strict evidence boundary, without deletion credit.

### Corrected measured remaining plan

Ranges are net counted physical lines. They include production integration and strict loaders and do not relocate behavior into excluded contracts, tests, documentation, reports, or generated evidence.

| Slice and named production modules | Low–high |
| --- | ---: |
| Executed closure and contracts: extend `completion_runtime_closure.py`; add `completion_runtime_contract.py`, `completion_fixture_materializer.py`, `completion_guest_qualification.sh`, and `completion_package_candidate.py` | 700–1,100 |
| Separate guest-work mount ownership: `completion_work_mount_state.py` and `completion_guest_work_mount.py` | 420–650 |
| Retained verified rootfs runtime lease: `completion_rootfs_lease.py` plus narrow `completion_rootfs_build.py` integration | 180–300 |
| Kata lifecycle: `completion_kata_process.py`, `completion_kata_operation.py`, `completion_kata_network.py`, `completion_kata_ssh.py`, `completion_kata_runtime.py`, and `run-stage2-completion-remote.sh` | 1,370–2,130 |
| Fixed in-guest samples: `completion_guest_workloads.sh` | 300–480 |
| Seven-cycle state machine: `run-stage2-completion-campaign.sh`, `run-stage2-completion-cycle.sh`, and `completion_campaign_state.py` | 500–780 |
| Separate completion schema, validator, and renderer | 690–980 |
| Local readiness and fixed expiry/integration changes | 180–300 |
| **Total remaining** | **4,340–6,720** |
| **Projected cumulative from 10,855** | **15,195–17,575** |

This decomposition is an accounting plan for the already accepted capability, not authority to add interfaces or scope. In particular, the separate guest-work owner may expose no caller-selected path, size, label, command, or cleanup target and may not import, extend, imitate, or write the rootfs ledger. It owns one fixed, bounded `nosuid,nodev,noexec` tmpfs by durable boot, mount-namespace, mountpoint, mount ID, device, source-label, option, root-inode, and sentinel identities. Unknown, replaced, nested, busy, attached, or otherwise contradictory state is preserved. Cleanup follows the ADR 0038 order first, uses only bounded normal unmount, performs no recursive host walk or pathname deletion of guest-mutated content, removes only an exact empty owned mountpoint, and aggregates primary, recovery, fsync, unmount, and close errors.

The package pin bootstrap is likewise a fixed implementation of the existing deterministic package requirement, not a package or campaign expansion. A strict committed candidate-input contract intentionally contains no output digest. One private, fixed, local-only candidate transaction performs two fresh normalized guest builds and installs, requires byte-identical package output and equal installed-tree identities, returns only a bounded candidate tuple, and releases it only after complete identity-bound cleanup and zero residue. That tuple is then committed into the separate final runtime contract. Public `readiness` and `full` modes accept only the final pinned contract. The candidate path cannot select arbitrary inputs, publish evidence, contribute a campaign sample, invoke AWS, or become a campaign mode.

## Decision

Amend only ADR 0041's numeric cumulative Stage 2 targets:

- preferred cumulative target: **17,500 lines**;
- hard cumulative cap: **19,000 lines**.

The preferred target leaves 6,645 lines from the measured baseline, 75 lines less than the corrected 6,720-line remaining high; equivalently, it is 75 lines below the projected 17,575-line cumulative high. It is a target, not a requirement to compress, combine, or omit security behavior.

The hard cap leaves 8,145 lines from the measured baseline. It is 1,425 lines above the projected 17,575-line cumulative high, equal to **21.2%** of the 6,720-line remaining high. That margin is reserved for readable review-driven corrections, not added scope.

All numeric 14,000 preferred-target and 15,000 hard-cap references, projections, and stop gates in ADR 0041 are superseded by 17,500 and 19,000 respectively. Earlier numeric caps in ADRs 0038–0040 remain transitively superseded. The frozen counted set, exclusions, anti-evasion rule, and physical-line method remain exactly unchanged.

This is a cap-only decision. It grants no scope change, AWS authority, workflow authority, provider authority, OpenTofu authority, deployment authority, or campaign approval.

## Retained scope and requirements

Every non-numeric requirement and every stop gate in ADRs 0038–0041 remains binding. This includes, without weakening or substitution:

- the exact immutable Debian 13 slim OCI base and `20260713T000000Z` snapshot inputs;
- the exact ordered ten-package set: `git`, `openssh-server`, `libcom-err2`, `libgssapi-krb5-2`, `libk5crypto3`, `libkeyutils1`, `libkrb5-3`, `libkrb5support0`, `libwrap0`, and `libwtmpdb0`, with their accepted versions, sizes, hashes, and amd64 architecture;
- no package scripts, package drift, eleventh package, compiler, guest fetch, host `chroot`, external or staged extractor, host tar, fallback, alternate rootfs writer, or caller-selected rootfs behavior;
- ADR 0040's one direct fixed fd-relative rootfs materializer and walker, immutable final graph, explicit root identity, complete postwalk, two independent builds, deterministic canonical output, strict publication and recovery, committed pins, and retained read-only rootfs ownership;
- deterministic fixed fixtures, complete transitive runtime closure, executed Kata qualification, and the fixed synthetic Git and deterministic `dpkg-deb` build/local `dpkg` install workloads, including immediate verified deletion of every sample before the next sample;
- host-private controls distinct from the guest-visible read-only input and read-write work subtrees, with private keys, trust, state, raw output, candidate results, source checkout, cache, rootfs source, and ledgers never exposed to the guest;
- the fixed standalone Kata 3.32.0/containerd 2.2.1 authenticated-SSH path, `/30` namespace/veth/tcfilter topology, only `lo` and `eth0`, no default route, fixed read-only root, two fixed guest mounts, fresh restricted Ed25519 identities, preconstructed trust, one strict marker, no host network, CNI, bridge, NAT, forwarding, retry, TOFU, or keyscan;
- the ADR 0038 teardown order unchanged: revoke readiness; stop and independently observe the exact task as `STOPPED`; remove the exact caller-owned namespace and observe its links absent; remove task then container without force; observe exact QEMU exit; remove exact owned firewall state; only then detach guest mounts, normally unmount guest work, dispose exact controls, release the rootfs through its owner, close descriptors, and re-observe every baseline;
- identity-bound normal, startup-failure, timeout, interrupt, and recovery cleanup; uncertainty preserves unknown or replacement state while independently safe cleanup continues in order; no force, lazy/detach/recursive unmount, broad kill, broad firewall flush, broad deletion, `|| true`, or unknown-to-absent conversion;
- exactly seven fresh sequential cycles with modes `[full, readiness, readiness, readiness, readiness, readiness, readiness]`, at most one instance, unchanged exact 16-resource shape, no overlap, retry, rerun, stop/start substitution, or continuation after uncertainty, per-cycle state-bound destroy and independent zero inventory, plus a distinct final zero inventory;
- one source/pin/batch binding, one absolute expiry no more than four hours after first apply, a 90-minute normal deadline, expected cost below USD 0.25, publishable accepted estimated cost below USD 0.50, and the unchanged region, type, disk, capacity, SSM, IMDSv2, budget, Scheduler, and termination constraints;
- a new separate additional-property-closed completion evidence schema, validator, and renderer with seven ordered records, recomputed nearest-rank summaries, workload timings, cleanup and final-zero proof, strict dimensions and sensitive-content rejection, and no failed, partial, duplicate, mixed, cross-batch, cleanup-uncertain, candidate, fake, Docker, or local-readiness evidence;
- all authoritative Linux-amd64, EUID-0, KVM, Kata, containerd, real-cache, hostile-test, residue, fake-controller, evidence, readiness, and clean-exact-revision gates; and
- no changes to `src`, `dev/launcher`, workflows, dependencies or lockfile, accepted v1alpha1 evidence, ADR 0012, ADR 0037, release, production, or issue-closure scope.

Local Docker remains functional-only under Nick Byrne's separate authorization. This ADR neither creates nor broadens Docker authority. Docker cannot establish authoritative Linux/KVM, production-workspace, campaign, AWS, or cleanup evidence and cannot replace any required local KVM qualification.

The outer phrase `COGS_AWS_STAGE2_COMPLETION_APPROVED=run-seven-sequential-stage2-completion-launches` remains only a fail-closed mechanism and explicitly is not approval. Even after all local readiness gates pass, AWS remains closed until Nick Byrne separately approves one exact named batch bound to the clean revision, account, region and type, checked plan and digests, AMI, rootfs/fixture/package/closure pins, current price and quota, expiry and deadline, costs, and destroy/recovery path.

## Staged remeasurement and stop discipline

After this ADR, implementation and remeasurement proceed only in these stages:

1. separate guest-work mount ownership and retained verified rootfs lease;
2. minimal Kata process, operation, network, SSH, runtime, and remote-entry lifecycle, including authoritative local cleanup qualification;
3. executed closure, fixture materialization, strict candidate input, candidate transaction, final package pin, and clean post-pin rerun;
4. final runtime contract, qualification, fixed workloads, per-sample deletion, and one authoritative seven-sample local full run;
5. exact seven-cycle production controller and complete no-AWS fake matrix;
6. separate strict completion schema, validator, renderer, and hostile/redaction matrix; and
7. local readiness aggregation and excluded generated report.

At every completed production slice, report the actual frozen cumulative physical-line count and a named-module estimate for every remaining slice, with no deletion credit. **Stop before further production implementation whenever `actual frozen count + revised remaining high >= 19,000`, or whenever implementation itself would reach 19,000.** Reaching 17,500 is not permission to compress code, weaken tests, omit a security transition, or continue without remeasurement.

Stop for another ADR or explicit owner decision on any immutable input or package drift, an eleventh package, inability to establish the exact closure in Kata, alternate SSH/network/rootfs/mount route, unresolved or replaced ownership identity, inability to qualify on authoritative local KVM, scope expansion, changed teardown order, cloud/provider/workflow activity, or a revised cumulative high at or above the hard cap.

## Non-authority and consequences

No AWS CLI, provider, OpenTofu plan, inventory, apply, SSM command, workflow dispatch, resource creation, campaign operation, or cloud cleanup is authorized while implementing or validating this plan. The readiness checker accepts no cloud or account input and invokes none of those operations. Its strongest possible conclusion remains only **ready to request review for one exact named batch**.

Local issue #42 implementation may resume within the corrected measured cap without compressing mount ownership, runtime lifecycle, package pinning, cleanup, controller, validation, or redaction behavior. This ADR supplies no rootfs, fixture, package, closure, qualification, workload, campaign, or AWS evidence. It does not close issue #42 or establish Stage 4, EKS, release, production, compliance, availability, or regional-capacity claims.
