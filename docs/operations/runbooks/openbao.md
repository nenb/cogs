# Draft OpenBao policy and revocation runbook

This guide contains no OpenBao command, token, endpoint credential, or secret value. It defines fail-closed review and future operational behavior. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future cluster may provide session-scoped worker identity and exact launch-authorized OpenBao policy. | [Authority: IMPLEMENTATION identity and secrets tasks](../../../IMPLEMENTATION.md#325-identity-and-secrets) |
| A future daemon/integration service may signal revocation and replace affected immutable worker/proxy resources. | [Authority: DESIGN MVP proxy construction](../../../DESIGN.md#112-mvp-proxy-construction) |
| OpenBao HA, backup, unseal, disaster recovery, and cluster ownership remain external and unimplemented here. | [Authority: DESIGN trust domains](../../../DESIGN.md#42-trust-domains) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Trusted code resolves API-key handles; values stay in memory/trusted tmpfs and are forbidden from launch, logs, telemetry, durable reports, and sandbox. | [Authority: DESIGN MVP proxy construction](../../../DESIGN.md#112-mvp-proxy-construction) |
| OpenBao PKI retains the CA private key; sandbox receives only public egress CA. | [Authority: DESIGN secret-injected egress placement](../../../DESIGN.md#111-placement) |
| Missing identity/policy/secret, stale metadata, startup outage, or WAL failure fails closed. | [Authority: DESIGN failure behavior](../../../DESIGN.md#21-failure-behavior) |
| Revocation denies new requests, drains connections, invalidates old capability, and requests replacement; metadata polling is at most 60 seconds and not instant for existing streams. | [Authority: DESIGN MVP proxy construction](../../../DESIGN.md#112-mvp-proxy-construction) |
| Subscription OAuth is disabled/unadvertised; issue #13 is future post-MVP only; workers have no refresh-token policy. | [Authority: provisional matrix OAuth blocker](../stage-5-api-key-release-acceptance-matrix.md#subscription-oauth-blocker) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| OpenBao `2.6.1` remains retired after fixed HIGH Go standard-library findings; its historical evidence authorizes nothing. | [Authority: OpenBao retirement record](../../security-evidence/openbao-2.6.1-retirement.md) |
| OpenBao `2.7.0` is admitted only as the exact upstream-signed index and Linux/amd64 member recorded by the repository; Cogs does not republish it or claim a direct child signature. | [Authority: OpenBao successor record](../../security-evidence/openbao-2.6.1-retirement.md#admitted-upstream-successor-openbao-270) |
| Independent review and current CI require zero HIGH/CRITICAL, `ignore-unfixed=false`, no suppression, exact SBOM identity, and functional paths against the same compiled-in pin. | [Authority: Stage 3 model-auth status](../stage-3-model-auth.md) |
| Admission and functional evidence do not establish EKS/Kata runtime observation, production readiness, cloud execution, Stage 4 exit, or release eligibility. | [Authority: Stage 4 readiness](../stage-4-offline-readiness.md) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Authenticate workload identity and exact user/session/handle boundaries. | [Planned DESIGN-24.4 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove no sandbox-usable token/handle, CA key, or real secret in specs/durable stores. | [Planned DESIGN-24.4, .12–.14 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe PKI issuance, SAN/lifetime, rotation, expiry, and failures. | [Planned DESIGN-24.4, .11 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Detect direct metadata version/delete within bound and immediate signal handling. | [Planned DESIGN-24.11 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Deny new traffic, reset established streams, invalidate old capability, and replace immutably. | [Planned DESIGN-24.11–.12 / `future-eks-conformance-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Observe audit-before-use, WAL-full denial, redacted completion, and OTLP outage behavior. | [Planned DESIGN-24.10, .22 / `future-eks-conformance-reference-v1`, `future-load-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Bind external backup/recovery and post-campaign revocation/cleanup. | [Planned STAGE5-45.09, .11 / `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Policy review checklist

**Section authority:** [Authority: DESIGN model authentication](../../../DESIGN.md#12-model-authentication).

For each API-key handle, record only opaque digest references and verify conceptually:

1. trusted principal, user, session, provider/integration, path, operations, lease/lifetime, and revocation owner are exact;
2. wildcard paths, list capability, cross-user/session access, sandbox identity, and refresh-token access are absent;
3. error, audit, proxy, and telemetry outputs cannot include the key, placeholder, query/body, or arbitrary path;
4. policy denial has no alternate source, ambient credential, cached open route, or anonymous forwarding path;
5. deletion/rotation preserves required incident evidence without preserving a usable credential.

Any ambiguous or wider policy is rejected, not narrowed by operator convention.

## Revocation decision flow

1. Mark the affected session/integration unready and deny new credentialed requests.
2. Revoke the exact secret/lease or version under the owning OpenBao authority; do not revoke unrelated paths.
3. Drain/reset established proxy connections and invalidate the exact proxy capability.
4. Replace the affected immutable worker/proxy only after exact ownership and launch-document binding are proven.
5. Preserve metadata-only WAL/telemetry and record whether each step is observed, failed, or unknown.
6. On any uncertainty, continue denial and escalate through [credential incident response](incident-response.md). Never restore access merely because the polling interval elapsed.
