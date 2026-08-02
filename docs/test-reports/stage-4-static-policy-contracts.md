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
2. exact current-user-only OpenBao namespace, service-account, audience, KV-handle, metadata-handle, and PKI-role bounds, with `organizations/*`, list/write/delete, and broad path grants forbidden;
3. exact sandbox account `cogs-sandbox-inert`, proven distinct from the trusted worker, with no RBAC, projected token, workload/cloud identity field, Kubernetes API credential, or OpenBao identity/handle;
4. a trusted-worker-generated proxy capability bound to one session, instance, worker pod, sandbox pod, exact sandbox selector, immutable route-policy digest, capability ID/generation/issued-at/expiry, and explicit previous→replacement identity; revocation is `deny-new → drain-connections → request-replacement` and the old capability is invalid;
5. no direct-egress fallback;
6. dual-stack default-deny intent, UDP/QUIC denial, disabled guest DNS, exact selector requirements, and explicit protected-surface inventory;
7. metadata-only bounded OTLP with a closed 11-field attribute vocabulary, fixed name/enum cardinality, and field-specific value limits; outage drops metadata with counters and does not authorize credential use; and
8. a 1 MiB / 10,000-record / 4 KiB-record trusted audit WAL with one closed nine-field record containing only fixed enums, bounded integers/booleans, and domain-separated SHA-256 session, intent, policy, and capability references. The session reference is recomputed exactly from the contract session binding, and every other reference is likewise recomputed rather than accepted as an opaque identifier. Append and sync precede credential use; unavailable, unwritable, full, append, sync, or correlation failure denies credentialed egress and requires recycle.

Both payload contracts explicitly forbid query, body, credential, placeholder, secret handle, source, prompt, model/tool output, command, arbitrary path, raw user/session identity, cloud identity, Kubernetes identity, and OpenBao identity fields. `validateStage4PolicyPayload()` safely snapshots and validates records without I/O or sensitive diagnostics.

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
- IPv4 and IPv6 assigned-proxy policy plus direct-host and direct-IP denial on both families;
- UDP, QUIC/HTTP/3, arbitrary DNS/resolver, and DNS-over-HTTPS denial, including explicit IPv6 QUIC, DNS, and DoH cases;
- cloud metadata plus explicit IPv4 and IPv6 Kubernetes API, worker API, proxy admin, and OpenBao denial;
- missing, revoked, replaced, not-yet-issued, expired, wrong-ID, wrong-generation, and other-session proxy capabilities;
- instance, source-pod, service, other-session proxy, and other-session workload confusion; and
- broad-policy and alternate-port denial.

The probe schema fixes every required ID in exact order. `validateStage4PolicyProbeSuite()` additionally requires the exact contract digest, complete unique inventory, exact semantic field combinations, and recomputes every supplied expected decision through the pure evaluator; omissions, duplicates, reordering, substitution, vacuous suites, and dishonest expected results fail. Alternate strings are bounded input-derived non-colliding values, and the alternate listener is 65534 at a 65535 boundary and 65535 otherwise. The evaluator permits only TCP to the assigned proxy listener with the exact instance/pod/sandbox selector and active current same-session capability. Its `allow` is a static expected-policy result, not an observation that CNI or runtime enforcement occurred.

## Remaining mandatory qualification

Every result fixes `cloud_execution_observed`, `cni_runtime_qualified`, `stage4_exit_satisfied`, and `release_eligible` to false. Exact EKS/Kata/CNI/runtime campaigns must still establish selector enforcement, dual-stack and UDP behavior, service-account token absence, metadata/API/admin isolation, OpenBao role behavior, proxy source binding, revocation timing/drain, WAL failures, OTLP outages, and cross-session denial. Issue #42 and a separate exact campaign approval remain mandatory before any such execution.
