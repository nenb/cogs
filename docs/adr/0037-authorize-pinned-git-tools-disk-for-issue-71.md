# ADR 0037: Authorize pinned Git tools disk for issue #71 KVM scenario

- Status: Accepted
- Date: 2026-07-21
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0036 authorizes only the fixed issue #71 integrated authoritative Linux/KVM S3-09 scenario and explicitly keeps the no-new-dependency boundary unless a new reviewed decision supersedes it. During PR #170 diagnostics, the normal Linux/KVM launcher smoke and native Pi raw-export hardening reached the expected boundary, but the literal S3-09 path still requires a real Git executable inside the guest because Cogs records Git observations through the fixed `/usr/bin/git` command path.

The pinned Debian cloud image used by the Linux/KVM launcher scenario is `debian-13-generic-amd64-20260712-2537.qcow2`; its canonical manifest is:

<https://cloud.debian.org/images/cloud/trixie/20260712-2537/debian-13-generic-amd64-20260712-2537.json>

That manifest proves `curl` is present at version `8.14.1-2+deb13u4`, but `git` is absent. Installing packages from inside the guest would add guest network and package-manager state to the trusted evidence path. Broadening the launcher to arbitrary packages, images, scripts, or paths would violate ADR 0036. The correct narrow stop-gate resolution is a new ADR that authorizes only a fixed, host-prepared, read-only Git tools disk for this issue #71 scenario.

A separate continuous SSE fix for PR #170 exists locally and unpushed. This ADR does not depend on that implementation and does not authorize pushing it, changing workflow timeouts, or adding runtime dependencies outside the narrow tools disk described below.

## Decision

Authorize a no-guest-network, read-only pinned Git tools disk solely for the issue #71 Linux/KVM S3-09 scenario. This ADR supersedes only ADR 0036's `no new dependencies` boundary for the fixed Git tools needed by the issue #71 KVM scenario. All other ADR 0036 constraints remain binding.

The host may download exactly these Debian trixie amd64 packages over TLS and must verify the exact SHA-256 digest before extraction:

| Package | Version | Pool URL | Size (bytes) | SHA-256 |
| --- | --- | --- | ---: | --- |
| `git` | `1:2.47.3-0+deb13u1` | `https://deb.debian.org/debian/pool/main/g/git/git_2.47.3-0+deb13u1_amd64.deb` | `8861572` | `3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722` |
| `libcurl3t64-gnutls` | `8.14.1-2+deb13u4` | `https://deb.debian.org/debian/pool/main/c/curl/libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb` | `384336` | `351bf3bb1c816c1d88900cbfe59dc79433f20fb962947d78313028a00f97c856` |
| `libngtcp2-16` | `1.11.0-1+deb13u1` | `https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-16_1.11.0-1+deb13u1_amd64.deb` | `131904` | `627eec81ebbd48c4e6091f5cd9dc5070b792b7075000eed60ab08c7daa961caf` |
| `libngtcp2-crypto-gnutls8` | `1.11.0-1+deb13u1` | `https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb` | `29524` | `2a7f109c0c4db6a800e4661c5e5e34e1f1f83c8162482276183d1ada9da7c96c` |

The host must extract the verified packages with fixed `dpkg-deb` usage into a dedicated small ext4 image. The guest must mount that image at fixed `/opt/cogs-git` as read-only with `nosuid,nodev`, and QEMU must attach the image read-only. The guest must not run `apt`, install packages, or use network to obtain tools. `curl` remains an image-provided prerequisite proven by the pinned cloud-image manifest; this ADR does not authorize adding curl.

The scenario may expose Git through only a fixed root-owned wrapper and symlink:

- `/opt/cogs-git/bin/git` wrapper, root-owned, non-writable by group/other;
- `/usr/bin/git` root-owned symlink to that wrapper;
- wrapper sets only `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, and `LD_LIBRARY_PATH` to fixed `/opt/cogs-git` locations; and
- wrapper then execs the pinned Git binary without accepting arbitrary binary, package, image, path, environment, or command selection.

## Required verification

Before S3-09 acceptance evidence may rely on the tools disk, the Linux/KVM workflow must verify fixed metadata-only predicates:

1. the tools disk has the expected label and is mounted at `/opt/cogs-git` read-only with `nosuid,nodev`;
2. QEMU attaches the tools disk read-only;
3. wrapper, symlink, and extracted tool roots are root-owned with non-writable modes;
4. package versions and Git binary version match the pinned set above;
5. dynamic library resolution has no missing dependencies for the pinned Git binary;
6. the guest can run basic real Git operations: `init`, `add`, `commit`, `rev-parse`, and `notes`; and
7. the S3-09 scenario uses actual Git objects produced by those real Git operations.

Guest/tool observations remain untrusted. Cogs may record Git observations only as metadata and must continue treating them as observations rather than authority.

## Evidence and cleanup boundaries

Cache and download state for the pinned packages must live outside launcher trust roots. The tools image and raw packages are local build inputs only; they must not be uploaded as evidence artifacts. Cleanup must be exact and owned. Evidence reports may include only fixed booleans or bounded version enums if needed. Evidence, telemetry, status, manifests, ordinary logs, and uploaded artifacts must not include package URLs, private paths, raw digests, commands, tool output, prompts, credentials, ports, opaque session IDs, inode values, or other forbidden content.

This ADR does not alter the production `src/**/*.ts` cap, the issue #71 launcher caps, or the development-only status of the launcher. It does not authorize a production daemon, scheduler, production authentication service, cloud deployment, AWS/provider calls, release work, compliance claims, or production-readiness claims. PR #170's Quality job timeout remains a separate diagnostic; this ADR does not authorize relaxing workflow timeouts.

## Stop gates

Implementation must stop for another ADR or explicit human decision if any of the following become necessary:

- any additional package beyond the four pinned packages listed above;
- package version or SHA-256 drift;
- writable tools mount or writable QEMU tools attachment;
- guest package installation, guest package-manager use, or guest network to obtain tools;
- arbitrary package/image/path/command/script selection;
- broad driver selection or broad VM image selection;
- uploading raw packages, the tools disk, package URLs, or raw digests as evidence;
- weakening Git observations into trusted authority;
- production `src` cap changes or broad production `src` expansion;
- workflow timeout relaxation or retry/rerun substitution for deterministic correctness; or
- provider/cloud/deploy/release/production scope.

## Consequences

Issue #71 can satisfy the literal integrated S3-09 Git requirement without relying on guest package installation, broad new dependencies, or arbitrary tooling. The dependency expansion is narrow, pinned, host-verified, read-only, and local to the authoritative Linux/KVM scenario.

Future #71 implementation must keep this tools disk fixed and metadata-only, preserve all ADR 0036 no-fallback and cleanup boundaries, and stop if the exact pinned package set is insufficient.
