# Stage 4 static workload-identity and policy-contract evidence

## Scope

- Issue: #356.
- Authority: `static-only-stage4-policy`.
- Qualification: `pending-exact-eks-cni-runtime`.
- Cloud/provider/Kubernetes execution: none.
- Release eligible: false.

This report records local contract and fixture coverage only. It is not EKS, CNI, Kata, OpenBao, proxy, OTLP, teardown, deployment, or release evidence. No AWS/provider/OpenTofu/SSM operation, Kubernetes API call, `kubectl`, Helm install/apply, external model call, or network discovery was used.

## Contracts

`schemas/stage4-policy-contract-v1.json` and the pure validator in `scripts/stage4-policy-contract.ts` define:

1. one trusted-worker service account with an audience-bound, short-lived projected token used only for OpenBao login;
2. exact OpenBao namespace, service-account, audience, KV-handle, metadata-handle, and PKI-role bounds, with no list/write/delete or broad path grant;
3. an inert sandbox service-account binding with no RBAC, projected token, Kubernetes workload/API credential, OpenBao identity/handle, or cloud identity;
4. a trusted-worker-generated proxy capability bound to one session and the exact sandbox selector, immutable route-policy digest, old-capability invalidation, and `deny-new → drain-connections → request-replacement` revocation;
5. no direct-egress fallback;
6. dual-stack default-deny intent, UDP/QUIC denial, disabled guest DNS, exact selector requirements, and explicit protected-surface inventory;
7. metadata-only bounded OTLP where outage drops metadata with counters and does not authorize credential use; and
8. a 1 MiB / 10,000-record / 4 KiB-record trusted audit WAL whose append and sync precede credential use and whose unavailable, unwritable, full, append, sync, or correlation failure denies credentialed egress and requires recycle.

The Helm NOTES-only source shapes expose these contract labels and use the same 1 MiB WAL maximum. Helm still submits zero Kubernetes manifests.

## Readable security transitions

```text
trusted identity:
  admission → projected OpenBao token → scoped login → exact handle use
  any identity/auth failure → unready

sandbox identity:
  admission → inert no-RBAC service-account binding → no Kubernetes/OpenBao/cloud credential

proxy capability:
  absent → trusted-worker generated → immutable session/source bound → active
  revocation/change/unavailability → deny new → drain → request replacement
  replacement → old capability invalid; never direct-egress fallback

credentialed request:
  route/session authorize → WAL append → WAL sync → credential use
  authorization/WAL failure → deny → recycle; never anonymous/direct fallback

ordinary OTLP:
  metadata enqueue → bounded export or counted drop
  collector failure → ordinary work continues; no credential authorization effect
```

## Hostile fixtures

`test/fixtures/stage4-policy/hostile-probes-v1.json` contains static expected-policy probes for:

- empty, wrong-role, and proxy/sandbox selector confusion;
- IPv4 and IPv6 assigned-proxy policy plus direct-IP denial on both families;
- UDP, QUIC/HTTP/3, arbitrary DNS, and DNS-over-HTTPS denial;
- cloud metadata, Kubernetes API, worker API, proxy admin, and OpenBao denial;
- missing, revoked, and other-session proxy capabilities;
- other-session proxy/workload denial; and
- broad-policy and alternate-port denial.

The pure evaluator permits only TCP to the assigned proxy listener with the exact sandbox selector and active same-session capability. Its `allow` is a static expected-policy result, not an observation that CNI or runtime enforcement occurred.

## Remaining mandatory qualification

Every result fixes `cloud_execution_observed`, `cni_runtime_qualified`, `stage4_exit_satisfied`, and `release_eligible` to false. Exact EKS/Kata/CNI/runtime campaigns must still establish selector enforcement, dual-stack and UDP behavior, service-account token absence, metadata/API/admin isolation, OpenBao role behavior, proxy source binding, revocation timing/drain, WAL failures, OTLP outages, and cross-session denial. Issue #42 and a separate exact campaign approval remain mandatory before any such execution.
