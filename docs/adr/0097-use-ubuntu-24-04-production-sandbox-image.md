# ADR 0097: Use Ubuntu 24.04 LTS for the production sandbox image

- **Status:** Accepted
- **Decision date:** 2026-08-03
- **Decision owner:** delegated implementation owner under the user's explicit production sandbox OS-remediation instruction
- **Baseline:** `e09bbea` (reviewed production package minimization)

## Context

ADR 0095 and ADR 0096 deliberately withheld image-construction authority. The minimized Debian 13 production sandbox retains the intended seven direct package roots, but the pinned release-equivalent Trivy database reports blocking HIGH and CRITICAL OS findings. Suppression, ignore rules, VEX, or removal of package-manager metadata would conceal rather than remediate that result.

The existing design permits Ubuntu or Debian. Local feasibility evidence found that an Ubuntu 24.04 package-complete image can retain the production behavior and pass the same unsuppressed release scanner boundary. Ubuntu 24.04 is recognized by the pinned Trivy release and has stronger scanner support than the newer Ubuntu 26.04 alternative.

## Decision

Migrate only `images/sandbox/Dockerfile` from Debian 13 to Ubuntu 24.04 LTS under this exact construction contract:

1. The base is the immutable OCI index `ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90`, and construction requires `linux/amd64`.
2. APT uses Ubuntu's signed snapshot mechanism fixed at `20260801T000000Z` for exactly `noble`, `noble-updates`, and `noble-security`, with only `main universe`. The source stanzas, global snapshot default, zero retries, any-error update mode, archive keyring, and rejection of insecure or unauthenticated repositories are fixed. There is no live package-candidate fallback.
3. Initial CA trust comes only from these checksum-constrained official snapshot artifacts, whose package, version, and architecture are checked before unpacking:
   - `openssl_3.0.13-0ubuntu3.12_amd64.deb`, SHA-256 `321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b`;
   - `ca-certificates_20260601~24.04.1_all.deb`, SHA-256 `6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50`.
4. The complete direct package roots and exact versions are Bash `5.2.21-2ubuntu4`, CA certificates `20260601~24.04.1`, Git `1:2.43.0-1ubuntu7.3`, OpenSSH client and server `1:9.6p1-3ubuntu13.18`, OpenSSL `3.0.13-0ubuntu3.12`, and Python 3 `3.12.3-0ubuntu2.1`. OpenSSH server's Ubuntu dependency closure may include `openssh-sftp-server`; the configured subsystem remains `internal-sftp`, and that dependency is not a new direct root.
5. Preserve `/etc/os-release`, APT indexes/configuration, and dpkg status/ownership metadata. The existing dpkg-based forbidden-package closure guard remains fail closed for conformance clients and network probes. No conformance package is added.
6. Preserve the existing entrypoint, fixed-input capture, SSH root identity, internal-SFTP, proxy/trust environment, ambient-credential rejection, and external-runtime non-authority labels except for the truthful Ubuntu package-policy label.
7. Static tests and pin checks must bind the OCI index, platform, snapshot stanzas, bootstrap checksums and identities, exact roots, metadata retention, forbidden closure, and unchanged behavior.
8. Release-equivalent evidence must use the exact pinned Trivy image and both exact database images, scan all severities with `ignore_unfixed=false`, pass the repository jq report validator, identify OS family `ubuntu` and version `24.04`, contain nonempty OS package results and inventory, and report exactly zero HIGH and CRITICAL findings. Dpkg, Trivy, and SPDX/Syft package evidence must be compared closely enough to reject an empty or materially blind scanner result.
9. A refresh of the base, snapshot, direct versions, Trivy image, either Trivy database, package closure, or scanner-recognition semantics invalidates this vulnerability conclusion and requires the full gate again.

Historical Debian evidence, development/conformance images, Stage 2 fixtures, and prior ADR wording remain unchanged.

## Required local evidence

- exact `linux/amd64` Docker build from the tracked context;
- dpkg closure inventory/count, direct-version checks, required binary and SSH configuration checks, and forbidden package/binary checks;
- entrypoint and input-capture smoke coverage without changing their behavior;
- strict pinned Trivy scan and raw-report jq validation, including scanner identity, database identities, Ubuntu 24.04 recognition, inventory non-emptiness, and zero HIGH/CRITICAL;
- Syft SPDX generation when locally feasible and package-count comparison;
- focused and full repository checks;
- repeated byte-identical Stage 4 readiness regeneration.

Any package-authentication failure, snapshot drift, scanner blindness, or remaining HIGH/CRITICAL finding blocks success. It must not be suppressed or represented as passing.

## Explicit non-authority

This decision authorizes local Docker pull/build/scan and the repository changes/evidence regeneration necessary for this OS remediation. It grants no AWS/provider/OpenTofu/SSM/Kubernetes/Kata deployment or qualification, image push/publication/signing/promotion, campaign, external-model operation, production-readiness, release-eligibility, Stage 4 exit, or provider/runtime truth claim. Local image bytes are not a published release image set and do not replace the protected-main publication workflow.

## Consequences

The production guest remains a minimal root-capable SSH/SFTP userland whose isolation and network security require the external Kata/runtime controls. Ubuntu changes transitive package closure and versions but does not widen direct production capabilities. Future release publication remains separately authorized and must rebuild and re-evaluate the exact protected-main source rather than trusting this local image.
