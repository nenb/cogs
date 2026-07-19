# ADR 0031: Require a trusted launcher SSH runtime root

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 authorized the issue #70 development launcher with strict profiles and no fallback. ADR 0029 established that full trusted Envoy composition requires a qualifying Linux host with the exact `/run/cogs/egress` tmpfs boundary. ADR 0030 raised the issue #70 launcher line cap for readable worker, composition, cleanup, inventory, and evidence code without widening the development-only scope.

The production launch schema requires `sandbox.client_key_path` to match an absolute path under `/run/cogs/ssh/`. Production SSH composition reads that launch value as the host path to the client private key. The current development profile drivers instead create and retain their source client keys in strict profile-owned state:

- `insecure-container` stores its source key and SSH controls under its profile state and records a loopback port and pinned `known_hosts` entry;
- `linux-kvm` stores its source key and pinned `known_hosts` entry under its profile state and uses its fixed guest endpoint.

Using the profile-state path in the launch document would violate the production schema. Supplying a fictitious `/run/cogs/ssh/...` value while configuring the SSH manager from the profile-state path would make the immutable launch document untruthful. Weakening the schema or adding a symlink, bind, profile, or path fallback would expand the trust boundary rather than resolve it.

The measured trusted-composition plan estimates about 980 additional non-test launcher lines from the current 7,301-line baseline, for a projected launcher total of about 8,281 lines. The revised full issue projection is 9,531–9,781 lines. It may exceed ADR 0030's preferred 9,400-line target but remains below its hard 10,200-line cap.

## Decision

Full trusted issue #70 launcher composition requires an **externally provisioned** SSH runtime root at the exact path `/run/cogs/ssh` alongside, but separate from, ADR 0029's `/run/cogs/egress` prerequisite.

Before any trusted composition uses the SSH runtime root, the launcher must prove that `/run/cogs/ssh` is:

- the canonical exact path;
- a Linux tmpfs;
- a non-symlink directory;
- mode `0700`;
- owned by the current uid; and
- initially empty.

The launcher does not create or mount this root. Host setup outside the launcher must provision it. A missing or invalid root is an explicit fail-closed prerequisite result before trusted services start.

### Source control validation

The launcher strictly reads only the exact SSH controls for the selected profile. It must use no-follow file access and prove expected ownership, mode, link count, bounded size, and stable device/inode/size across path inspection, open, read, and reread. It must reject malformed, extra, replaced, hard-linked, symlinked, oversized, or changing controls.

For `insecure-container`, the strict inputs are the source client private key, the pinned `known_hosts` record, and the recorded loopback SSH port. For `linux-kvm`, they are the source client private key and pinned `known_hosts` record for the fixed guest endpoint. Host-key pin derivation must use the strictly read profile control; it must not use key scanning or trust-on-first-use.

The source private key remains profile-owned. Worker cleanup must not remove or rewrite it.

### Runtime materialization

After validating the source controls, the launcher exclusively creates one state-named regular file beneath `/run/cogs/ssh`. It must:

1. keep the verified source descriptor open while copying;
2. bound all raw private-key bytes;
3. create the destination with no-follow, exclusive-create semantics and mode `0600`;
4. require current-uid ownership, one link, and a stable recorded destination inode;
5. fsync the destination file and runtime root;
6. reread and compare the destination through its open descriptor, then reinspect the source descriptor; and
7. wipe every temporary raw-key buffer.

The validated launch document and `SshConnectionManager` must both use exactly this materialized runtime path. The launcher must not continue using the repo/profile source path secretly.

Private-key bytes, the runtime key path, key digests, and source paths must not enter telemetry, status, evidence, snapshots, or error messages. Reporting is limited to fixed metadata such as whether the SSH runtime prerequisite and materialization checks passed.

### Reverse cleanup and uncertainty

Reverse cleanup unlinks only the exact destination inode recorded at materialization. It then fsyncs `/run/cogs/ssh` and proves that the state-named file is absent and the externally owned root is empty.

The launcher leaves `/run/cogs/ssh` itself mounted and present. A replaced inode, unknown entry, failed unlink/fsync/reinspection, or any uncertain ownership or absence proof is a cleanup failure. The launcher preserves recovery controls and reports uncertainty; it must not remove an unproven file or report cleanup success.

### Applicability and prohibited fallbacks

This prerequisite applies to full trusted composition for both implemented profiles:

- `insecure-container` remains functional-only on a qualifying Linux host;
- `linux-kvm` remains the sole authoritative local security profile.

Native macOS full composition remains unsupported. `macos-vm` remains optional absent-fail and functional-only if a reviewed driver is later added. The launcher must not switch profiles when either runtime root is unavailable.

The following are explicitly prohibited:

- hidden `sudo` creation or mounting of `/run/cogs/ssh`;
- weakening or bypassing the production launch schema;
- a fictitious launch path;
- symlink, bind-mount, or repo-path fallback;
- secretly configuring SSH from the profile source path;
- profile fallback; and
- compressing security checks to meet a preferred line target.

ADR 0030's preferred 9,400-line target and hard 10,200-line cap do not change. Remeasure after trusted composition. Exceeding the preferred target requires explicit reporting; approaching or exceeding the hard cap requires another stop gate rather than compression.

## Consequences

Host documentation and future full launcher smoke instructions must state both independent Linux tmpfs prerequisites: `/run/cogs/egress` for trusted egress material and `/run/cogs/ssh` for the truthful launch-bound SSH client key. Neither prerequisite is implemented or evidenced by this docs-only decision.

The runtime copy creates a second, short-lived private-key instance. Strict descriptor-bound copying, bounded wiped buffers, exact launch/manager use, and inode-bound cleanup contain that exposure. The profile source key remains under profile ownership so profile verification and lifecycle behavior do not change.

A production schema redesign that allows another truthful key-reference mechanism remains a possible alternative, but it is a separate architecture and production-code stop gate. This ADR does not authorize it.

Using the profile-state path in the launch document is rejected because it violates the current schema. Hidden mounting, symlinking, binding, or substituting a path is rejected because it obscures or widens the trust boundary. Supplying a fictitious runtime path while using another path is rejected because the launch document would not describe the active SSH configuration.

This ADR does not claim implementation, workflow coverage, real smoke evidence, production readiness, or release readiness. It does not authorize a daemon, scheduler, production authentication service, cloud or AWS behavior, deployment, release, new production dependency, or production `src` change. All ADR 0027 through ADR 0030 scope, no-fallback, cleanup, readability, evidence, and line-budget constraints remain binding.
