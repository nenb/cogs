# ADR 0027: Issue #70 development launcher scope and line budget

- Status: Accepted
- Date: 2026-07-17
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

Issue #70 is the Stage 3 S3-08 workstream for the local development launcher and cleanup flow in `IMPLEMENTATION.md` §§27-29. `IMPLEMENTATION.md` §34 also describes a temporary resource launcher boundary and explicitly states that launcher tooling is test tooling and must not be shipped as the future production daemon.

The clean `main` baseline for this decision is `c67e62ee962e04f8eaae65d0559789556b60f2d0` with:

```sh
find src -name '*.ts' -print0 | xargs -0 wc -l | tail -1
# 21295 total
```

Existing accepted constraints remain authoritative:

- `DESIGN.md` says the external daemon eventually creates and binds trusted worker/proxy and untrusted sandbox resources; Cogs itself does not receive Kubernetes or cloud lifecycle permissions.
- `DESIGN.md` labels local insecure container and optional macOS VM approaches as development/functional only; a KVM-capable Linux workstation or runner is the authoritative local VM security profile.
- ADR 0003 keeps real credentials, trusted proxy state, and CA private keys outside the sandbox VM.
- ADR 0015 through ADR 0019 define secure egress, OpenBao, WAL, Envoy, and Stage 3 runtime-manager constraints.
- ADR 0026 keeps policy/telemetry metadata-only and records the sticky fail-closed WAL limitation.

Issue #70 must compose the already merged Stage 3 components locally without weakening their boundaries or creating a shadow production runtime.

## Decision

Authorize issue #70 implementation of a development-only local launcher under `dev/launcher`.

The launcher may orchestrate one local sandbox profile, local trusted services, and one Cogs API worker for development smoke/evidence. It must not become or claim to be a daemon, scheduler, production authentication service, release launcher, deployment system, or cloud provisioner.

No AWS, cloud, deploy, release, or production daemon scope is authorized by this ADR. No new production dependency is authorized.

## Authorized profiles

The launcher may accept only this exact profile enum:

- `insecure-container`: functional-only local profile using the existing insecure container SSH/SFTP driver; no guest-root, default-deny, VM-isolation, or release evidence claim.
- `linux-kvm`: authoritative local security profile requiring KVM/QMP/root-network prerequisites and host-enforced network controls; this is the only local profile that can satisfy guest-root/default-deny security evidence.
- `macos-vm`: optional functional-only profile allowed only through a fixed reviewed driver path/config; if that reviewed path/config is absent, the launcher must fail closed.

There is no fallback between profiles. Missing prerequisites must not fall back to local tools, runc, software-emulated security claims, open egress, anonymous API access, or another profile.

## Authorized operations

The launcher may expose only fixed operations:

- `create`
- `reset`
- `status`
- `run`
- `abort`
- `history`
- `export`
- `shutdown`
- `destroy`
- `smoke`

Arguments must be exact and bounded: profile enum, one state name, optional bounded timeout, optional JSON/status flag, bounded history cursor/limit, a prompt file for `run`, and a local output path for `export`. The launcher must not accept arbitrary command strings, shell fragments, generic child argv, arbitrary executable paths, or user-selected images.

Child processes must use fixed argv arrays and absolute or repo-pinned paths/images. Process groups, deadlines, output caps, PID identity checks, ownership checks, and symlink defenses are required.

## Reuse requirements

Issue #70 must reuse existing reviewed seams where safe instead of duplicating security validation:

- existing `dev/insecure-sandbox` driver lifecycle, labels, SSH/SFTP contract, and cleanup checks;
- existing `dev/linux-kvm` driver lifecycle, KVM/QMP proof, SSH host-key pin, tap/firewall setup, and cleanup checks;
- existing OpenBao fixture image/config and loopback/version/digest checks;
- existing Stage 3 real-runtime helper logic for OpenBao setup, OTLP fixture behavior, upstream fixtures, Envoy runtime manager composition, WAL/completion/revocation semantics, and KVM relay/bypass evidence where reusable;
- existing API server, Pi session, launch lifecycle, static policy, raw export, telemetry, and egress runtime-manager modules.

Safe extraction of test/helper code is allowed when it preserves validation behavior. Reimplementation that bypasses reviewed validation is not authorized.

## State, identity, and persistence

The launcher must use one strict launcher state directory:

- direct child of the launcher state root;
- one path segment only;
- mode `0700`;
- owned by the current user;
- no symlink parent or state directory;
- protected by a per-state lock;
- containing a sentinel and canonical non-secret manifest.

The manifest may include only non-secret metadata: source revision, launcher version, profile, state id, fixed resource names, ports, readiness state, and cleanup status. It must not contain model credentials, integration credentials, prompts, model output, source content, tool output, HTTP bodies, account IDs, raw provider IDs, or cloud identifiers.

Development identities are ephemeral and local. Model and integration credentials may exist only in environment/runtime memory. Persisted local control capabilities are limited to API bearer token and SSH client key/known-host pin, mode `0600`, state-owned, and removed at cleanup.

## Create and smoke behavior

`create` must start, in order:

1. the selected profile driver and verified SSH host-key pin;
2. actual local OpenBao;
3. a bounded local OTLP collector;
4. fixture services;
5. the selected Envoy proxy/runtime through existing egress runtime composition;
6. one Cogs API worker/session.

CI may use a deterministic fake model stream for launcher smoke, but it must not bypass API authentication, launch lifecycle, policy, SSH/SFTP tool boundaries, worker telemetry, egress runtime, WAL, history, export, or cleanup boundaries. Real provider model calls remain reserved for S3-09.

`smoke` should cover create, run, abort, history, export, shutdown, destroy, cleanup inventory, and failed-prerequisite paths. Raw export remains sensitive local output only.

## Cleanup and evidence

Cleanup must always be attempted in reverse order and must be idempotent. Final inventory must prove no owned processes, containers, volumes, tap devices, firewall rules/chains, fixture ports, OpenBao containers, OTLP collectors, persisted local API/SSH capabilities, or launcher state remain, except an optional immutable image cache under a separately named cache directory.

Uncertainty is failure. The launcher must retain a recovery sentinel when cleanup cannot prove success and must never report false success.

The launcher collector reset/destroy must be explicit. Raw ignored state must be cleaned after accepted evidence. Evidence reports must be committed separately after accepted runs. The known WAL full limitation remains: max 1 MiB / 10,000 records is sticky fail-closed for credentialed egress; telemetry can report bounded metadata but in-session recovery is not required.

## Line-budget measurement

Planning estimate from `/tmp/cogs-issue70-launcher-plan.md`:

| Area                                                                                 | Estimated non-test `dev/launcher/**/*.{ts,sh}` lines |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------: |
| CLI parser, exact operations, state validation, locking, manifest                    |                                                  650 |
| Child process runner, fixed argv, process groups, deadlines, output caps             |                                                  450 |
| Profile adapter contracts for insecure-container/linux-kvm/macos-vm absent-fail path |                                                  550 |
| OpenBao/OTLP/fixture helper extraction/reuse wrappers                                |                                                  650 |
| Egress runtime/API/Pi/lifecycle composition                                          |                                                  900 |
| Operation implementations                                                            |                                                  900 |
| Inventory, cleanup, recovery sentinel, reports                                       |                                                  600 |
| **Planned non-test launcher addition**                                               |                                            **4,700** |

Binding cap for issue #70 non-test launcher code: **4,800** lines under `dev/launcher/**/*.{ts,sh}`.

Implementation should try to land at or below 4,500 lines by extracting/reusing helpers rather than duplicating validation. Exceeding 4,800 lines requires a replan or superseding ADR.

Production `src/**/*.ts` growth should be zero. If a small exported helper is unavoidable, issue #70 establishes a new production `src/**/*.ts` hard cap of **22,000** total lines unless a superseding ADR justifies a new cap. Every implementation PR must report both measured counts.

Tests, docs, and generated evidence are excluded from these code caps, but must not be compressed to hide complexity or cleanup obligations.

## Required tests and evidence

Issue #70 implementation must include tests or smoke evidence for:

- exact operation/argument validation and rejection of arbitrary commands;
- state directory direct-child, mode, sentinel, lock, symlink, and ownership defenses;
- missing prerequisite fail-closed behavior without profile fallback;
- create/reset/status/run/abort/history/export/shutdown/destroy/smoke paths;
- API bearer authentication and bounded SSE/history/export behavior;
- deterministic fake model stream preserving auth/tool/worker boundaries;
- SSH host-key pin and profile-specific authority labels;
- OpenBao fixture startup, loopback binding, cleanup, and absence from guest;
- bounded OTLP collector reset/destroy;
- allowed and denied egress through existing Envoy/OpenBao/WAL path;
- reverse-order cleanup and zero-inventory verification;
- recovery sentinel on uncertain cleanup;
- no credential/content persistence in manifest, reports, or ordinary logs.

Normal CI must not require AWS. Later implementation may extend existing insecure-container and KVM workflows for launcher smoke. macOS evidence is nonauthoritative if implemented.

## Non-decisions and exclusions

This ADR does not authorize:

- production daemon, scheduler, auth service, or cloud lifecycle implementation;
- AWS, EKS, cloud, deploy, release, or production readiness claims;
- new production dependency;
- fallback to local tools, runc, open egress, anonymous auth, or another profile;
- arbitrary command or shell parsing;
- registry/image selection by users beyond fixed reviewed pins;
- persistent model/integration credentials;
- moving OpenBao identity, integration credentials, proxy private material, or CA private keys into the guest;
- restore/import, cloud export, sanitized export, or archive distribution;
- real provider model acceptance for S3-08; real provider work remains reserved for S3-09.

## Stop gates

Implementation must pause for review and, if necessary, a superseding ADR if any of the following occur:

- a new production dependency is needed;
- production `src/**/*.ts` would exceed 22,000 total lines;
- non-test `dev/launcher/**/*.{ts,sh}` would exceed 4,800 lines;
- raw model or integration credentials would be persisted;
- profile fallback, local tool fallback, runc fallback, open egress, or anonymous auth is proposed;
- arbitrary command/shell execution is proposed;
- AWS/cloud/deploy/release/daemon/scheduler scope is requested;
- cleanup cannot prove zero inventory yet would report success;
- duplicated security validation would replace existing reviewed drivers/helpers.

## Consequences

Issue #70 can proceed as bounded development tooling that composes the existing Stage 3 system locally. The launcher provides repeatable local smoke and cleanup evidence without expanding the trusted production runtime, weakening profile authority boundaries, or creating cloud/release claims.
