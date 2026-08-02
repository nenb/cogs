# ADR 0096: Authorize production worker composition and entrypoint

- **Status:** Accepted
- **Decision date:** 2026-08-02
- **Decision owner:** delegated project lead under the user's explicit production-worker instruction
- **Baseline:** `89cff6f` (ADR 0095 runtime foundation plus Basic proxy capability)
- **Baseline production count:** 23,683 physical lines under `src/**/*.ts`

## Context

ADR 0095 deliberately stopped before composition. The branch now has the strict runtime document, trusted file capture, Kubernetes-workload OpenBao identity, and the corrected canonical Basic proxy capability, while the production worker still has no owner that joins the existing Stage 3 components. The development launcher cannot be promoted: it owns local OpenBao/OTLP/model fixtures, development streams, Docker-oriented controls, and launcher state.

The measured pre-implementation estimate was:

| Production surface | Low | High |
| --- | ---: | ---: |
| ordered production composition, narrow seams, loss propagation, and reverse cleanup | 500 | 760 |
| process entrypoint and bounded signal ownership | 60 | 120 |
| minimal API bind and identity-error redaction corrections | 0 | 30 |
| review correction margin | 0 | 90 |
| **Aggregate addition** | **560** | **1,000** |

The aggregate high yields an absolute production cap of `23,683 + 1,000 = 24,683` physical lines. Tests are measured separately; deletion, movement, generated code, tests, and compression provide no production credit.

## Decision

Authorize one production worker, not a daemon or launcher:

1. `src/runtime/compose.ts` reads `/etc/cogs/runtime.json`, the fixed launch document, API bearer, proxy capability, and projected JWT only through the ADR 0095 trusted-file boundary. It accepts only effective-worker-owned fixed-mode files and emits one generic production error.
2. Startup is linear and fail closed: runtime, launch, API bearer, proxy capability, OpenBao identity, OTLP worker sink, model store, lifecycle construction, persistent storage/private and OCI stores, SSH, proxy admission, model-key probe, WAL parent, OpenBao PKI/revocation/egress manager with worker-owned Envoy, authenticated Pi session with SSH tools and authenticated skills, authenticated API construction, then API bind. Readiness is unavailable until the final bind and a final dependency check.
3. `LaunchLifecycle` owns its six existing dependencies in their declared order. Composition owns later resources. Cleanup is API, Pi persistence/disposal, lifecycle (therefore egress through storage in reverse dependency order), then worker telemetry. Any timeout, rejected close, uncertain dependency close, unexpected loss, or Pi fatal path remains a generic failed closure.
4. Envoy is a detached worker child group through the existing production process port, uses only `/usr/local/bin/envoy`, and must be reaped by its existing TERM/KILL close contract. No sidecar or externally owned proxy is accepted.
5. OpenBao is the only model and egress credential authority. Production rejects organization/session model or integration API-key handles: model and integration handles must begin with `users/<launch.user_id>/`. The proxy handle must equal `sessions/<session_id>/proxy` and its value comes only from the trusted capability file.
6. Skills come only from the authenticated local OCI layout and user-namespaced private content-addressed store. Pi receives no development stream, OAuth, ambient auth, local model fallback, or built-in filesystem/shell tools.
7. Session and agent roots are fixed persistent worker-owned directories. Shutdown first closes API admission, then asks an idle Pi session to flush/checkpoint and create its existing raw sensitive export before disposal. A running turn is aborted by disposal rather than falsely reported settled. Production does not enable Pi-owned deletion.
8. The API may bind only the runtime contract's `127.0.0.1` or `0.0.0.0`, remains bearer-authenticated except for liveness, and exposes only the already implemented raw export path; no sanitizer, restore, or alternate export mode is added.
9. `src/main.ts` accepts no arguments or environment-selected credentials. SIGINT and SIGTERM share one idempotent close, have a 31-second hard process deadline, and leave a nonzero status on startup, spontaneous runtime, or uncertain cleanup failure.
10. Review correction: production composition delegates egress startup to the retained `createCogsEgressRuntimeLaunchDependency` owner. Shutdown records the request before awaiting startup and closes a manager even when it resolves after abort; generic composition never treats an unresolved egress acquisition as unowned. Proxy capabilities use one base64url-without-padding grammar of 32 through 128 characters in worker, manager, authorization server, launcher relay, and sandbox.

No dependency is added.

## Numeric bounds and measured result

| Surface | High | Implemented gross addition |
| --- | ---: | ---: |
| `src/runtime/compose.ts` | 760 | 540 |
| `src/main.ts` | 120 | 74 |
| API bind and identity-error redaction support | 30 | 4 |
| aggregate production addition | 1,000 | 618 |
| focused composition/entrypoint tests | 900 | 552 |
| absolute `src/**/*.ts` count | 24,683 | 24,298 |

All figures are physical lines measured after formatting. The API file's replaced lines receive no credit; support counts its three API additions plus one identity-error stack-redaction line gross. The remaining aggregate margin is correction-only and authorizes no new subsystem.

## Required evidence

Seam-based tests must execute no external model, network, OpenBao, OTLP, SSH, or Envoy process. They cover every ordered startup seam, rollback of acquired owners, exact reverse cleanup, SSH and egress dependency loss, startup and close secret redaction, close uncertainty, signal idempotence and running-turn disposal, user-scoped API-key handles, production import boundaries, fixed Envoy ownership, API bind restrictions, and main-process loss behavior. Existing focused Envoy tests remain the process-group TERM/KILL/reap authority.

The complete repository checks remain required before commit.

## Explicit non-authority

This decision does not authorize or claim:

- any `dev/**` import, fixture stream/model/service, OAuth/refresh-token route, environment credential, or local fallback;
- a daemon, scheduler, controller, launcher, admission service, lease service, identity issuer, or worker supervisor;
- Kubernetes API/SDK/client code, service-account creation, token issuance, discovery, RBAC, CNI, CSI, manifests, Helm promotion, or apply/install behavior;
- AWS or another provider/cloud SDK, Terraform/OpenTofu, Docker, image build/pull/push/signing, Kata/QEMU/KVM execution, or infrastructure mutation;
- external calls or Envoy execution as test evidence;
- deployment, isolation, production-readiness, release-eligibility, compliance, Stage 4 exit, or provider/model support claims.

The Kubernetes identity name remains the HTTPS OpenBao login protocol over an externally materialized regular JWT file. The entrypoint is one in-pod worker process only.

## Consequences

A production image and deployment may later invoke `src/main.ts`, but this ADR supplies no image or deployment authority. Runtime material provisioning, sandbox creation, network isolation, and release qualification remain external blockers. Any need for discovery, resume selection beyond the existing launch/session contract, a controller, a new credential source, or a new process owner requires a new ADR and measured budget.
