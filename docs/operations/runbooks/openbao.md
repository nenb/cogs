# Draft OpenBao policy and revocation runbook

This guide contains no OpenBao command, token, endpoint credential, or secret value. It defines fail-closed review and future operational behavior. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future cluster will provide authenticated, session-scoped worker identity and an OpenBao policy that can resolve only launch-authorized handles.
- A future daemon/integration service will deliver immediate revocation signals and replace affected immutable worker/proxy resources.
- OpenBao HA, backup, unseal, disaster recovery, and cluster ownership are external platform responsibilities and are not implemented here.

## Static contract facts

- Model and integration API keys are resolved by trusted code from handles; values remain in memory or trusted tmpfs and are forbidden from launch documents, logs, telemetry, durable reports, and the sandbox.
- OpenBao PKI owns the CA private key. The sandbox receives only the public egress CA.
- Missing identity, policy denial, missing/revoked secret, stale metadata, OpenBao outage at startup, or audit-WAL failure fails closed.
- Revocation denies new requests, drains established connections, invalidates old proxy capability, and requests immutable replacement. Metadata polling is bounded to no more than 60 seconds as a backstop; it is not described as instant revocation for existing streams.
- Subscription OAuth is disabled and unadvertised. Issue #13 is future post-MVP work only; no worker refresh-token policy exists or may be added through this runbook.

## Authoritative-local facts

- The local functional smoke uses OpenBao `2.6.1` at digest `sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`, a fresh file-backed loopback fixture, an exact KV-v2 read policy, and a short-lived orphan read token.
- It verifies exact-path read, cross-path denial, revocation, generic errors, and cleanup. It is functional-only and proves neither Kubernetes auth nor multi-tenant production policy.
- The current OpenBao-specific vulnerability dispositions are described in [Stage 3 model-auth notes](../stage-3-model-auth.md) and must be handled by the [CVE runbook](cve-response.md).

## Future cloud evidence

A future exact-run authority must establish:

- authenticated workload identity and exact user/session/handle policy boundaries;
- no token, handle usable by the sandbox, CA key, or real secret in workload specs or durable stores;
- PKI issuance, SAN/lifetime bounds, rotation, expiry, and failure behavior;
- direct metadata version/delete detection within the declared bound and immediate signal handling;
- denial of new traffic, reset/drain of HTTP/2 and other established streams, old-capability invalidation, and immutable replacement;
- audit intent before credential use, WAL-full denial, redacted completion records, and OTLP-outage behavior;
- backup/recovery behavior owned by the external platform and evidence of post-campaign revocation/cleanup.

## Policy review checklist

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
