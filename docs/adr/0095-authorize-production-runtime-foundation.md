# ADR 0095: Authorize the production runtime foundation

- **Status:** Accepted
- **Decision date:** 2026-08-02
- **Decision owner:** delegated project lead under the user's explicit instruction to implement only productionization slices 1 and 2
- **Baseline:** `dc11c1f6f2e29a66c602b82d805c764a00517bf0` (`origin/main`)
- **Baseline production count:** 22,610 physical lines under `src/**/*.ts`

## Context

The worker and sandbox Dockerfiles remain Stage 0 scaffolds, there is no production entrypoint, and the complete trusted composition exists only in the development launcher. Promoting that launcher would also promote fixture-owned OpenBao, OTLP, deterministic model, Docker, local profile, and process-supervisor behavior that is explicitly development-only.

The first safe productionization step is narrower. A later entrypoint needs one strict non-secret runtime document, trusted callback-scoped reads of mounted capabilities, and a production `OpenBaoIdentityPort` that exchanges a rotating projected Kubernetes workload JWT for a short-lived OpenBao token. Those foundations can be built and tested without starting a worker, proxy, image, sandbox, daemon, controller, provider, cloud client, Kubernetes client, or model.

The pre-implementation measured estimate was:

| Production surface | Low | High |
| --- | ---: | ---: |
| strict runtime schema, snapshot, canonical byte parser, and semantic HTTPS checks | 260 | 400 |
| no-follow bounded regular-file capture, held parent generations, callback-scoped zeroing, and cleanup | 250 | 400 |
| Kubernetes-workload OpenBao login identity, bounded response parser, rotation, timeout, abort, and redaction | 300 | 500 |
| review correction margin | 0 | 90 |
| **Aggregate addition** | **810** | **1,390** |

The aggregate high yields an absolute production cap of `22,610 + 1,390 = 24,000` lines. Tests and schema are measured separately because moving security behavior out of production code creates no credit.

## Decision

Authorize exactly these two productionization slices:

1. **Runtime contract and trusted file capture**
   - Add one strict `cogs.runtime/v1alpha1` schema and production validator.
   - Fix the release profile to API-key-only and fix all credential, launch, Envoy, WAL, state, and skill paths.
   - Permit only canonical HTTPS OpenBao and exact OTLP/HTTP JSON signal endpoints.
   - Reject coercion, defaults, unknown fields, accessors, Proxies, noncanonical JSON, UTF-8 BOM, malformed UTF-8, duplicate/noncanonical bytes, control characters, and bounded-input violations.
   - Capture trusted files through `O_NOFOLLOW`, held no-follow parent directory descriptors, before/open/after generation equality, exact owner/group/mode/link/size policy, bounded descriptor reads, post-read revalidation, mandatory descriptor closure, callback scope, and byte zeroing.

2. **Production OpenBao Kubernetes-workload identity**
   - Implement the existing narrow `OpenBaoIdentityPort`; do not change model-auth or egress callers.
   - Reread the projected JWT from its trusted file for every login so rotation is observed.
   - Accept only a canonical HTTPS origin and bounded mount/role names.
   - Perform exactly one `POST /v1/auth/<mount>/login` with redirects disabled and a bounded timeout and response.
   - Strictly validate the OpenBao envelope, token type, printable client token, and configured maximum token TTL.
   - Expose the client token once, only through the awaited callback; clear local references afterward.
   - Abort and every file, transport, status, header, body, JSON, token, TTL, or callback failure return one generic redacted error with no fallback.

No new dependency is authorized. Use Node 22 standard APIs plus the existing Ajv dependency.

## Numeric bounds

Gross physical additions from the baseline are binding. Deletion, rename, movement, generated code, tests, or compression gives no credit.

| Surface | High |
| --- | ---: |
| `src/runtime/config.ts` | 400 |
| `src/runtime/trusted-files.ts` | 400 |
| `src/auth/openbao-workload-identity.ts` | 500 |
| aggregate production addition | 1,390 |
| aggregate focused tests | 1,000 |
| runtime schema | 180 |
| absolute `src/**/*.ts` count | 24,000 |

The implemented slice measures 226, 296, and 498 production lines respectively: **1,020 added production lines** and **23,630 total production lines**. Focused tests measure 806 lines and the schema measures 135 lines. All are below their non-transferable highs. The remaining 370 production lines are review-correction margin only; they do not authorize composition or another surface.

Stop for a new ADR before crossing any per-file or aggregate high, adding a dependency or file, weakening canonical/trusted-file/OpenBao behavior, or implementing a later productionization slice.

## Explicit non-authority

This decision grants no authority to implement or execute:

- `src/main.ts`, worker composition, proxy-capability correction, private API binding, graceful-shutdown wiring, or image construction;
- a production daemon, scheduler, controller, launcher, admission service, lease service, OAuth broker, or identity issuer;
- Envoy process changes, sidecar control, xDS, SDS, admin endpoints, direct egress, or fallback credentials;
- Kubernetes API discovery, Kubernetes SDK/client code, manifests, apply/install, RuntimeClass discovery, service-account creation, token issuance, RBAC, CNI, CSI, or cluster observation;
- AWS, another cloud, provider APIs, OpenTofu, Terraform, object storage, or infrastructure mutation;
- Docker, container, Kata, QEMU, KVM, image build/pull/push/signing, release publication, or runtime qualification;
- external model calls, OAuth/subscription authentication, refresh tokens, ambient Pi auth, or development credential fallback;
- production-readiness, release-eligibility, deployment, isolation, compliance, campaign, or Stage 4 exit claims.

The Kubernetes-auth name describes only the fixed OpenBao HTTPS login protocol and projected JWT input. It introduces no Kubernetes API or SDK access. The projected JWT is supplied by an external trusted materializer; this repository neither creates nor discovers it.

## Required evidence

Acceptance requires focused hostile tests plus the complete existing repository checks. Tests must cover canonical valid input, every fixed field and bound, getters and zero-trap Proxies, symlink/hard-link/mode/owner/group/size failures, callback byte zeroing, exact login request shape, projected-JWT rotation, pre-abort, in-flight abort, timeout, redirects, statuses, content types and lengths, streaming bounds, malformed/unknown OpenBao fields, token and TTL rejection, callback failure, and absence of sensitive values from errors.

## Consequences

Later work may consume these foundations but cannot infer authority for composition or deployment. The next productionization ADR must remeasure the exact branch, address proxy capability transport and worker-owned Envoy topology, and preserve the API-key-only and fail-closed boundaries established here.
