# Draft credential incident-response runbook

Use this decision plan when a model or integration API key, proxy capability, SSH identity, OpenBao token, CA key, placeholder mapping, or credential-bearing trusted component may be exposed. It grants no access or mutation authority. Read the [runbook authority rules](README.md) first.

## Assumptions

| Assumption | Specific planning authority |
|---|---|
| A future platform may bind incident commander, credential owner, evidence custodian, and notification roles. | [Authority: IMPLEMENTATION independent review and operations roles](../../../IMPLEMENTATION.md#392-independent-review) |
| Future controls may deny admissions, revoke exact credentials, drain exact sessions, and rotate without unrelated tenant impact. | [Authority: DESIGN failure behavior](../../../DESIGN.md#21-failure-behavior) |
| Cloud control surfaces and response times are not established. | [Authority: provisional matrix non-authority](../stage-5-api-key-release-acceptance-matrix.md#purpose-and-non-authority) |

## Static contract facts

| Static fact | Specific authority |
|---|---|
| Sandbox cannot read real credential value; this does not prevent confused-deputy misuse or source transfer to an approved write endpoint. | [Authority: DESIGN narrow credential guarantee](../../../DESIGN.md#41-narrow-credential-guarantee) |
| Credential authorization/WAL append fails closed; OpenBao startup failure or revocation leaves egress unavailable. | [Authority: DESIGN audit fail-closed behavior](../../../DESIGN.md#114-audit-fail-closed-behavior) |
| Existing streams require drain/reset; WebSockets and general gRPC are outside MVP boundary. | [Authority: DESIGN supported compatibility classes](../../../DESIGN.md#115-supported-compatibility-classes) |
| Central telemetry excludes prompts/output/source/complete commands/arbitrary paths/query/body/tool output/credentials/placeholders. | [Authority: DESIGN privacy defaults](../../../DESIGN.md#162-privacy-defaults) |
| Unknown prompt outcomes are never silently replayed. | [Authority: DESIGN failure behavior](../../../DESIGN.md#21-failure-behavior) |

## Authoritative-local facts

| Local fact | Exact authority and applicability |
|---|---|
| Stage 3 locally exercises API-key resolution, redaction, proxy/WAL denial, revocation handling, and Linux/KVM guest-root boundary. | [Authority: Stage 3 exit evidence](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#automatic-acceptance) |
| It proves no cloud identity, organization notification, provider-side revocation, EKS containment, or multi-session blast radius. | [Authority: Stage 3 exit scope](../../test-reports/stage-3-s3-09-linux-kvm-exit.md#accepted-scope) |

## Future cloud evidence

| Required future observation | Planned criterion, evidence contract, and location |
|---|---|
| Measure detection-to-denial/reset, rotation, replacement, recovery, and independent closure with real dependencies. | [Planned STAGE5-45.07, .10 / `future-eks-conformance-reference-v1`, `future-operations-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove tenant/session scoping and absence of secrets in collected artifacts. | [Planned DESIGN-24.12, .22 and STAGE5-45.08 / `future-eks-conformance-reference-v1`, `future-independent-review-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |
| Prove no unrelated deletion and continued denial through OpenBao/proxy/OTLP/node/storage failures. | [Planned STAGE5-45.07, .09, .11 / `future-eks-conformance-reference-v1`, `future-privacy-deletion-reference-v1`, `future-zero-inventory-reference-v1`](../stage-5-api-key-release-acceptance-matrix.md#criterion-level-traceability) |

## Classification

**Section authority:** [Authority: DESIGN failure behavior](../../../DESIGN.md#21-failure-behavior).

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
