# Draft credential incident-response runbook

Use this decision plan when a model or integration API key, proxy capability, SSH identity, OpenBao token, CA key, placeholder mapping, or credential-bearing trusted component may be exposed. It grants no access or mutation authority. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future platform will have authenticated incident commander, credential owner, evidence custodian, and affected-user notification roles.
- It may be possible to deny admissions, revoke exact credentials, drain exact sessions, and rotate keys without affecting unrelated tenants.
- Those control surfaces and response times are not established for a cloud profile.

## Static contract facts

- The narrow guarantee is that a sandbox cannot read the real credential value; it does not prevent confused-deputy misuse of an allowed capability or exfiltration to an approved write-capable destination.
- Credential-use authorization and audit-WAL append fail closed. OpenBao startup failure or secret revocation leaves egress unavailable.
- Existing HTTP/2, gRPC, SSE, or WebSocket-like streams do not become safe merely because new requests are denied; supported connections must be drained/reset. WebSockets and general gRPC are outside the MVP support boundary.
- Central telemetry excludes prompts, model output, source, complete commands, arbitrary paths, query strings, bodies, tool output, credentials, and placeholders.
- Unknown prompt outcomes are never silently replayed.

## Authoritative-local facts

- Local Stage 3 evidence exercises API-key resolution, redaction, fail-closed proxy/WAL paths, revocation handling, and guest-root boundary in Linux/KVM within its exact applicability.
- It is not evidence of cloud identity, organization notification, provider-side key revocation, EKS containment, or multi-session blast radius.

## Future cloud evidence

The future response evidence plan must measure exact detection-to-denial, detection-to-connection-reset, rotation, replacement, recovery, and independent closure times with real dependencies. It must prove tenant/session scoping, no secret in collected artifacts, no unrelated deletion, and continued denial under OpenBao, proxy, OTLP, node, or storage failure. These remain requirements in the [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md).

## Classification

| Severity | Trigger | Initial disposition |
|---|---|---|
| `SEV-1` | confirmed real credential/CA-key disclosure, cross-session use, or uncontrolled credentialed traffic | exact-scope containment immediately; all facts not observed remain unknown |
| `SEV-2` | suspected disclosure, wrong-path access, stale credential use, audit gap, or proxy-admin exposure | deny affected scope; investigate from metadata-only evidence |
| `SEV-3` | placeholder/proxy-capability exposure with source binding intact, or redaction near miss without real value | invalidate exact capability; verify no escalation; keep scope bounded |

Severity never expands deletion authority.

## Exact response sequence

1. **Declare and bind.** Assign incident ID, authenticated incident commander, UTC start, exact source/artifact revision, affected opaque session/integration handles, and current confidence. Do not put raw secrets, prompts, source, or exports in the record.
2. **Contain exact scope.** Close admission and readiness for affected sessions, deny new credentialed egress, and preserve unknown outcomes. If scope is unknown, deny at the smallest safely enclosing policy boundary; do not delete or mutate discovered resources.
3. **Revoke exact material.** Credential owner revokes/rotates only the identified key, lease, token, certificate, SSH identity, or proxy capability. Subscription refresh tokens are not part of Cogs because subscription OAuth is disabled under future issue #13.
4. **Drain.** Reset established connections and replace only resources whose immutable session/launch ownership is proven. Do not infer ownership from names or tags.
5. **Preserve bounded evidence.** Retain metadata-only audit intent/completion, opaque IDs, timestamps, categorical outcomes, exact digests, and redacted diagnostics under controlled custody. Suspend ordinary deletion if evidence preservation or legal hold applies.
6. **Determine exposure.** Distinguish key value exposure, capability misuse, confused-deputy action, data returned by an API, source sent to an allowed destination, and false-positive logging. Do not overstate what logs can prove.
7. **Recover.** Restore only after policy, key/cert, proxy capability, image/runtime, WAL, and ownership checks are exact and independently reviewed. Start a new immutable session where outcome is unknown; never replay the prompt automatically.
8. **Close or escalate.** Close only with known scope, completed exact revocation, reviewed recovery, and required notifications. Ownership or cleanup uncertainty follows the exact [orphan escalation](teardown.md#exact-orphan-escalation).

## Communications and follow-up

Use private security reporting per [`SECURITY.md`](../../../SECURITY.md). Notify credential owners and affected users through approved private channels. Record residual uncertainty explicitly. Feed root cause into [OpenBao](openbao.md), [CVE](cve-response.md), [upgrade](upgrade.md), [retention/deletion](retention-deletion.md), and [limitations](limitations.md) reviews without copying sensitive artifacts.
