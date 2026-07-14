# ADR 0011: Select Envoy for the initial HTTP egress proxy

- Status: Proposed — approval required at the Stage 1 gate
- Date: 2026-07-14
- Reviewer: Nick Byrne
- Decision owner: Nick Byrne

## Context

ADR 0003 places credential injection and default-deny enforcement outside the guest VM but intentionally deferred the concrete proxy. Stage 1 evaluated pinned Envoy and mitmproxy candidates against one immutable conformance manifest in both a functional root container and an authoritative root Linux/KVM guest.

The initial release is API-key-oriented HTTP/HTTPS egress. It does not require a generic TCP tunnel, database proxy, SSH egress, WebSockets, HTTP/3, mTLS, SigV4/HMAC signing, or subscription OAuth. Unsupported surfaces must fail closed rather than inherit accidental proxy behavior.

The complete comparison is [`stage-1-proxy-comparison.md`](../test-reports/stage-1-proxy-comparison.md). Client details are in [`stage-1-client-compatibility.md`](../test-reports/stage-1-client-compatibility.md).

## Decision

If this ADR is accepted, Cogs will use **Envoy 1.38.3**, pinned to OCI digest:

`sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb`

for the initial HTTP/HTTPS egress proxy.

Cogs will retain these boundaries from the Stage 1 candidate:

1. Generate deterministic static configuration for each immutable session/integration set.
2. Expose no Envoy admin endpoint and enable no xDS/SDS, Lua, original-destination, dynamic-forward-proxy, cluster-header, or direct-fallback path.
3. Use explicit CONNECT decapsulation and terminate inner TLS with host-specific certificate/listener material.
4. Enforce exact host, port, method, canonical path, declared query, CONNECT authority, SNI, Host, and HTTP/2 `:authority` consistency.
5. Use native v3 gRPC `ext_authz` with `failure_mode_allow: false`; successful authorization must follow a durable intent record.
6. Remove guest authorization values and overwrite only with route-owned credentials after authorization.
7. Emit bounded completion metadata correlated to the authorization intent. Credential values, capabilities, request/response bodies, prompts, source, and environment values are forbidden from central telemetry.
8. Keep the real credential, proxy leaf private key, and CA private key outside the guest. The guest receives only a public CA and short-lived session capability.
9. Preserve host-enforced default deny. Envoy is not the network-isolation boundary and cannot authorize direct traffic.
10. Treat resource replacement, rather than mutable in-place route expansion, as the MVP configuration-change model.

This selects a component and integration shape. It does **not** accept Stage 1 stubs as production evidence, enable release eligibility, authorize AWS use, or begin Stage 2.

## Evidence

The selected candidate and alternate ran the same 79 cases at source revision [`f6c474968b9f388025b4ad29e2c2159ec1289e65`](https://github.com/nenb/cogs/tree/f6c474968b9f388025b4ad29e2c2159ec1289e65).

- [Functional insecure-container reports, run 29323227947](https://github.com/nenb/cogs/actions/runs/29323227947): Envoy and mitmproxy each produced 66 `stubbed` and 13 `not-applicable` results. The profile is non-authoritative.
- [Authoritative Linux/KVM reports, run 29323229469](https://github.com/nenb/cogs/actions/runs/29323229469): each candidate produced 13 `pass`, 56 `stubbed`, and 10 `not-applicable` results. All 13 passes are host-enforced bypass-resistance cases against a root Debian guest with active KVM and no TCG fallback.
- [SBOM/vulnerability run 29323183206](https://github.com/nenb/cogs/actions/runs/29323183206): the selected Envoy pin passed the HIGH/CRITICAL policy without an exception.
- Client measurements were equivalent across candidates: curl, Git smart HTTP, pip, requests, httpx, Java HTTPS, and curl HTTP/2 were compatible. Debian npm 9.2.0 and Node 20.19.2 native HTTPS/fetch were measured unsupported without an explicit launcher/agent.
- Credential tests retain only keyed/boolean comparisons. `credential.no-leak` and post-suite serialization checks reject persistence of real fixture credentials or capabilities in guest-visible output, reports, observations, audit records, telemetry, and retained adapter state.
- The selected candidate's Stage 1 leaf certificates are valid for 48 hours. The suite asserts a remaining lifetime greater than the eight-hour maximum session plus a one-hour Stage 1 startup/drain margin. Production issuance remains an OpenBao Stage 3 gate and must fail closed unless validity exceeds the session maximum plus the configured production margin.

The Stage 1 guest image is SHA-512 pinned as:

`78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667`

No AWS resources were used.

## Rejected alternative

### mitmproxy 12.2.3

Pinned digest:

`sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f`

mitmproxy passed the same applicable mechanism tests and is operationally convenient for dynamic forward MITM. It is not selected because:

- 197 lines of Cogs-specific Python execute inside the proxy process for capability checks, route authorization, credential overwrite, and audit completion, increasing the security-critical in-process footprint;
- HTTP parser/resource bounds rely more on proxy defaults and container ceilings;
- its pinned latest image has six fixed HIGH findings under the candidate-only exception tracked by #25;
- that exception expires on 2026-07-27 and is explicitly ineligible to support selection or release.

The rejected candidate remains useful comparison evidence. It is not an automatic runtime fallback. Switching to it requires a new ADR, a clean supported pin, and a complete rerun.

## Custom-code and operational cost

Envoy does not execute custom Cogs code in-process. Stage 1 nevertheless demonstrates substantial integration work:

- a 551-line deterministic configuration generator;
- a 257-line minimal native-v3 gRPC codec used by the fault-injectable authorization fixture;
- host-specific CONNECT/inner-TLS listener and cluster generation;
- a required production Cogs authorization/WAL service and trusted completion collector.

The hand-written Stage 1 protobuf codec is test infrastructure, not the prescribed production implementation. Stage 3 should use generated, pinned Envoy API bindings where practical and must preserve minimized request decoding.

Operationally, Envoy's static host-specific configuration is less flexible than mitmproxy's dynamic MITM. This is accepted for the immutable MVP because it makes destinations and fallback absence inspectable. Scale and configuration-size limits must be measured before advertising production capacity.

## Unsupported surface

Selection does not add support for application gRPC, SigV4/HMAC signing, upstream mTLS, database protocols, SSH egress, WebSockets, arbitrary TCP/TLS, nested CONNECT, UDP, QUIC/HTTP/3, guest DNS/DoH, subscription OAuth refresh flows, npm 9.2.0 through the measured capability path, or native Node HTTPS/fetch without an explicit proxy agent.

Any addition requires a reviewed protocol/credential contract and rerunning the applicable identity, route, parser, credential, audit, revocation, client, and authoritative bypass groups.

## Mandatory Stage 3 reruns

Every Stage 1 audit and revocation stub below is mandatory against the real Cogs authorization path, durable WAL, completion path, OpenBao integration, and production telemetry boundary:

### Audit and authorization

- `audit.intent-before-use`
- `audit.wal-unwritable`
- `audit.wal-full`
- `audit.authorization-outage`
- `audit.telemetry-outage-uncredentialed`
- `audit.completion-correlated`
- `audit.central-metadata-only`

### Revocation and rotation

- `revocation.signal-denies-new`
- `revocation.direct-store-change`
- `revocation.long-lived-drain`
- `revocation.replacement-capability`
- `revocation.old-capability-invalid`

Stage 3 must also rerun all identity, routing, parsing, credential, and client cases because their Stage 1 reports depend on fixture identity/authz/audit contracts. No `stubbed` result can become release evidence by reference to this ADR.

## Update process

Envoy updates are deliberate security changes, not automatic tag movement:

1. choose an upstream-supported exact version and resolve its multi-platform OCI digest;
2. review upstream security advisories, release notes, parser/ext-auth changes, and supported-platform metadata;
3. update the version and digest together and verify runtime identity;
4. regenerate an unsuppressed vulnerability inventory and SBOM; no owner/expiry ignore may support selection or release;
5. inspect the complete deterministic configuration diff and validate configuration before startup;
6. rerun unit/schema/secret/supply-chain checks, the full insecure-container suite, and authoritative Linux/KVM suite;
7. rerun client presets and certificate lifetime checks;
8. obtain security review for changes to trust boundaries, parser behavior, ext-auth metadata, credentials, certificates, admin/dynamic configuration, or fallback routing.

## Rollback and revisit triggers

On a suspected Envoy bypass, credential exposure, parser vulnerability, ext-auth fail-open behavior, or unpatched critical finding, disable affected integrations and deny new egress. Do not fall back to direct traffic or silently activate mitmproxy.

A previous Envoy digest may be restored only if it remains supported, is not implicated, and its exact configuration and full evidence are still valid. Otherwise egress remains disabled until a qualified replacement exists.

Revisit this decision with a new ADR if:

- Envoy cannot meet a required client/protocol contract without weakening the trust boundary;
- static configuration size, startup time, memory, drain behavior, or host-specific listener count misses measured production limits;
- a supported patched Envoy pin is unavailable within the security response window;
- generated configuration or production authz/completion integration becomes more security-critical or complex than a qualified alternative;
- upstream removes or materially changes required CONNECT, HTTP/2, TLS, or ext-auth behavior;
- a new established candidate demonstrates a smaller trusted/custom-code footprint with equivalent authoritative evidence.

## Consequences

- Stage 2 may begin only after Nick Byrne accepts this ADR and the Stage 1 gate is closed.
- Production integration remains blocked on real WAL/authz, OpenBao credential and PKI paths, completion durability, lifecycle cleanup, and all mandatory Stage 3 evidence.
- npm/native Node support requires a separate reviewed launcher or proxy-agent decision.
- Envoy configuration generation and update qualification become owned security surfaces.
- The external trust boundary from ADR 0003 remains unchanged.
