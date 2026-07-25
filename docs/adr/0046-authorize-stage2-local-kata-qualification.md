# ADR 0046: Authorize narrow local Stage 2 Kata qualification on GitHub KVM

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's latest explicit instruction to test locally, push to GitHub, continue until the next action would be AWS, and stop. This instruction authorizes the narrow local/GitHub qualification path below; it does not waive ADR 0045's staged stops or authorize AWS, provider, OpenTofu, workflow-dispatch, deployment, or campaign activity.

## Context

ADR 0045 records a frozen Stage 2 cumulative baseline of **17,442 physical lines**, a preferred cumulative target of **24,000**, and a hard cumulative cap of **25,500**. It permits no production slice on the current macOS arm64 host. Its next gate is exact-head qualification and replanning on Linux amd64 as EUID 0 with active KVM, the fixed source location, the exact private artifact cache, Kata 3.32.0, and containerd 2.2.1. ADR 0045 separately prohibits a workflow change without another accepted decision.

The existing GitHub `linux-kvm` job establishes generic runner and Stage 3 conformance facts only. It does not materialize the issue #42 fixed source, acquire the exact Stage 2 rootfs inputs, install the pinned standalone Kata/containerd fixtures, open the Stage 2 owners, or prove the accepted standalone lifecycle and residue boundary. Its reports therefore remain non-authoritative for issue #42.

The reviewed fastest local-first route is one isolated GitHub-hosted qualification job after portable tests pass locally. The job must distinguish discovery from authority: a first candidate run can establish exact environmental observations for review, but those observations cannot grant authority in the same run. Only a later exact clean revision containing the reviewed attestations can pass the committed-attestation gate.

## Decision

Authorize one new, narrow qualification workflow with all of these fixed properties:

- trigger only from a `pull_request` carrying the repository's `security` label;
- run only on GitHub-hosted `ubuntu-24.04`, Linux amd64;
- check out the exact pull-request head with persisted credentials disabled and `contents: read` only;
- execute the sealed qualification route as actual EUID 0 and require readable/writable `/dev/kvm` plus QMP proof that KVM is present and enabled;
- use a dedicated job with a **90-minute** outer timeout, bounded internal phases, cleanup reserve, and no software-emulation fallback;
- use its own concurrency group with cancellation disabled so a newer push does not intentionally interrupt exact cleanup;
- contain no `workflow_dispatch`, `push`, `schedule`, AWS credential, AWS CLI, provider, OpenTofu, SSM, deployment, or campaign route; and
- run independently of the existing generic KVM and Stage 3 jobs; neither job's result substitutes for the other.

A missing label, wrong event, wrong operating system or architecture, non-root execution, absent or inaccessible KVM, QMP failure, timeout, cancellation, or incomplete cleanup produces no qualification authority.

This ADR authorizes the workflow and qualification setup boundary only. It makes no production mechanism change, does not open any currently closed production owner, and does not accept a caller boolean, environment value, candidate report, or workflow success status as a production permit.

## Two-phase authority

### Phase A: candidate observation

The first phase may materialize the exact fixed source, acquire and verify the fixed public artifacts, install the pinned local runtime fixtures, and collect bounded host-tool/runtime/network/SSH candidates. It must leave the committed production preflight closed and label its result `candidate` and non-authoritative.

Candidate output may be used only to review exact executable closures, archive layout, configuration digest, containerd output, iproute2/tc/nftables JSON shapes, stored-spec shape, Kata process/share observations, SSH behavior, and cleanup behavior. It may not be consumed as a permit, copied automatically into a committed contract, or promoted by another step in the same workflow run.

### Phase B: committed-attestation qualification

A later clean pull-request head may qualify only when it contains separately reviewed, committed attestations for every required source, host tool, runtime, network, SSH, KVM, and output contract. The same job must independently reproduce and compare every fact against those committed values before the sealed preflight can issue authority.

Path, version, byte size, SHA-256, ELF closure, dynamic tag, configuration, output shape, mount, process, source, KVM, or residue drift fails closed. An all-true candidate object or report remains non-authoritative. The exact committed collector, not workflow YAML or caller-created data, remains the only route to a production preflight gate.

## Fixed source and rootfs inputs

The job must materialize the checked exact revision at:

`/var/lib/cogs/stage2-completion-v1/source`

The fixed chain is root-owned with the modes already required by the Stage 2 filesystem policy. Materialization includes only exact tracked source blobs and approved modes; it excludes `.git`, dependency directories, ignored state, generated output, and caller-selected files. It creates the fixed source sentinel and canonical source manifest, binds that manifest to the exact revision, and verifies the result through the existing fd-relative source authority before any Stage 2 owner is opened. A bind mount, symlinked checkout, recursive copy, host tar composition, writable source, or source-manifest mismatch is a stop.

The existing `cogs.stage2-completion-artifacts/v1` contract and hardened acquisition route remain the sole authority for the **exact 16** rootfs artifacts. They remain in the private root-owned cache below the fixed source. Acquisition must retain its explicit one-use approval, ambient proxy/credential/AWS rejection, HTTPS and redirect restrictions, exact count/size/digest checks, no-overwrite publication, strict metadata/package preflight, and post-verification. The cache is reverified before and after rootfs construction and is never uploaded.

The existing direct rootfs planner, two independent builds, pin comparison, publication rules, and retained lease remain unchanged. Qualification must reproduce the committed rootfs entry count, manifest and ustar sizes/digests, hold the exact lease through Kata use, and release it only after the accepted teardown and input-removal proofs. A different build, pin, cache identity, root path, or lease transition fails closed.

## Pinned host runtime assets

Runtime assets are separate from the fixed 16 rootfs artifacts and cannot alter that count or the exact ten-package guest set.

The Kata asset is exactly:

- release: `3.32.0`;
- asset: `kata-static-3.32.0-amd64.tar.zst`;
- size: **1,547,940,938 bytes**;
- SHA-256: `1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01`.

The containerd asset is exactly:

- release: `2.2.1`;
- asset: `containerd-static-2.2.1-linux-amd64.tar.gz`;
- size: **33,645,699 bytes**;
- SHA-256: `af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883`.

This complete digest was read from the GitHub release asset API metadata for release asset `330296666`, whose name and size exactly match the asset above. Acquisition must fully verify all 64 lowercase hexadecimal digits against the downloaded bytes before extraction; a missing, malformed, partial, or mismatched digest is a stop.

Both assets require a fixed HTTPS URL, exact response bound, no ambient credentials or proxy, no retry substitution, no-overwrite staging, complete digest verification before extraction, strict archive path/type preflight, bounded extraction into a private staging root, and a complete postwalk before atomic publication. Extraction directly into `/`, use of an unpinned distro containerd, or creation of a compatibility symlink is forbidden.

Kata must run from its exact `/opt/kata` layout. Its archive-owned QEMU configuration must be verified unchanged and require exactly `shared_fs = "virtio-fs"`; copy, 9p, disabled sharing, TCG, or automatic fallback fails. Containerd must run as one private, exact-PID daemon with dedicated root, state, socket, namespace, configuration, and process identity. The job must not start, stop, reconfigure, replace, or depend on the runner's system containerd.

Exact committed host-tool contracts are required for `ctr`, `ip`, `tc`, `nft`, `ssh`, and `ssh-keygen`, including absolute logical paths, executable/loader/library identities, sizes, digests, allowed dynamic metadata, version output, and command-specific output fixtures. The workflow may not infer an executable from `PATH` or treat a package version as an executable closure.

## Qualification and cleanup boundary

Committed-attestation qualification must exercise normal, startup-failure, timeout, interrupt, and durable recovery paths. Each path must preserve the accepted fixed `/30`, no-default-route network, canonical eleven-entry OCI mount list, virtio-fs input sharing, strict authenticated SSH, fixed process/share identities, and teardown order.

Success requires an independent final observation of zero exact-owned task, container, shim, QEMU, virtiofsd, namespace, veth/TAP, tc, firewall, Kata share-path, host mount, input/control, operation, and rootfs-lease residue, plus restoration of every captured baseline. The private containerd daemon may stop only after its exact PID/starttime is revalidated and all operation-owned runtime state is conclusively absent.

Cleanup uses only the production exact-owner/recovery routes and exact setup manifests. It may not use force or lazy unmount, recursive discovery deletion, `rm -rf`, broad kill, `pkill`, broad firewall flush, Docker cleanup, unknown-to-absent conversion, or runner disposal as proof. Unknown, replaced, over-bound, unreapable, contradictory, timed-out, or interrupted cleanup state is preserved and qualification fails.

The workflow must reserve time for an `always()` exact cleanup and a separate read-only residue check before its 90-minute outer limit. Qualification, cleanup, report validation, and artifact upload outcomes are enforced after upload. A job-level timeout or platform cancellation cannot produce a pass.

## Artifact and disclosure boundary

Workflow artifacts are metadata-only, bounded, schema-validated qualification and cleanup reports. They may include the exact source revision, committed public contract digests, public component versions, categorical phase/scenario outcomes, duration, and zero-residue booleans.

They must exclude downloaded archives and caches, rootfs bytes, source contents, private or public key material, `known_hosts`, fingerprints, internal addresses or ports, raw SSH output/errors, complete commands, containerd state, raw operation ledgers, raw mountinfo or `/proc` snapshots, Kata share contents, and unredacted runtime logs. Failure diagnostics are fixed categorical codes, not raw exception or command output. Artifacts use short retention and are not release, campaign, or AWS evidence.

## Retained scope, accounting, and stops

ADR 0045's **24,000 preferred target**, **25,500 hard cap**, frozen counted set, retained-file accounting, physical-line method, exclusions, anti-evasion rule, no-deletion-credit method, and `actual frozen count + revised remaining high >= 25,500` stop remain unchanged. Workflow and documentation work does not create credit to compress or relocate production behavior.

The accepted staged order remains unchanged. This workflow exists only to establish the Linux-amd64/EUID-0/KVM environment and authoritative step-2 qualification required by ADR 0045. Stop before step 3 unless every step-2 authority gate passes. Later local steps remain subject to their existing gates, and the mandatory stop on arrival at step 5 remains binding.

The owner's instruction to continue until AWS means: run portable tests locally, push the reviewed clean head, use this narrowly triggered GitHub qualification, and continue only through local stages already authorized by ADR 0045. It means stop when the next action would be AWS. It is not approval to implement the step-5 controller, dispatch a workflow manually, plan, inventory, apply, invoke SSM, create a resource, run a campaign, publish completion evidence, or perform cloud cleanup.

## Non-authority

This decision grants no AWS CLI, credential, account, provider, OpenTofu, plan, inventory, apply, SSM, workflow-dispatch, deployment, resource, campaign, release, production, issue-closure, or Stage 4 authority. No AWS secret is available to the job, and no cloud action is required to obtain either candidate observations or committed-attestation qualification.

AWS remains closed until Nick Byrne separately approves one exact named batch under the retained ADR 0038–0045 requirements. Reaching a clean local qualification result requires a stop and report; it is not permission to cross that boundary.
