# Stage 1 proxy comparison and unsupported surface

Date: 2026-07-14

Status: comparison input for ADR 0011; **not a proxy-selection decision and not release evidence**.

## Evidence boundary

Both candidates ran the same 79-case manifest. Candidate parser, CONNECT, TLS, routing, injection, and lifecycle behavior is real, but identity, authorization, audit, telemetry, and revocation dependencies are Stage 1 fixtures. The report therefore marks affected successful cases `stubbed`. A `stubbed` result proves an integration mechanism, not production acceptance.

Only Linux/KVM bypass cases are authoritative. The insecure-container profile is functional-only and cannot support guest-root default-deny, isolation, selection, or release claims. Neither candidate is release eligible.

Exact comparison source:

- source revision: [`f6c474968b9f388025b4ad29e2c2159ec1289e65`](https://github.com/nenb/cogs/tree/f6c474968b9f388025b4ad29e2c2159ec1289e65)
- case manifest: `test/egress-conformance/cases/stage-1.ts`
- insecure-container machine reports: [workflow run 29323227947](https://github.com/nenb/cogs/actions/runs/29323227947)
- authoritative Linux/KVM machine reports: [workflow run 29323229469](https://github.com/nenb/cogs/actions/runs/29323229469)
- SBOM and vulnerability evidence: [workflow run 29323183206](https://github.com/nenb/cogs/actions/runs/29323183206)

The workflow artifacts contain each candidate's `report.json` and `report.md`. GitHub artifact retention applies; the immutable source, image digests, case manifest, and report-generation code remain in the repository.

## Exact components

| Component | Version | OCI digest |
|---|---|---|
| Envoy | 1.38.3 | `sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb` |
| mitmproxy | 12.2.3 | `sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f` |
| Debian 13 KVM guest | root guest, kernel 6.12.95+deb13-amd64 | image SHA-512 `78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667` |

The KVM workflow additionally fails closed unless `/dev/kvm`, `-accel kvm`, and QMP `query-kvm` all prove hardware acceleration. There is no TCG fallback.

## Conformance outcomes

The two candidates have identical status counts. Identical counts do not imply identical implementation risk.

### Functional-only insecure-container

| Group | Envoy | mitmproxy | Interpretation |
|---|---:|---:|---|
| Identity and route | 17 stubbed | 17 stubbed | Real proxy enforcement with fixture identity/authz |
| HTTP parsing | 19 stubbed | 19 stubbed | Real HTTP/1.1, HTTP/2, CONNECT, TLS, and rejection behavior with fixture authz/audit |
| Credential handling | 8 stubbed | 8 stubbed | Real overwrite/non-reflection behavior; fixture credential source and audit |
| Client compatibility | 10 stubbed | 10 stubbed | Functional measurement only; includes explicit measured unsupported cases |
| Bypass resistance | 13 not-applicable | 13 not-applicable | Containers cannot establish guest-root default deny |
| Audit failure | 7 stubbed | 7 stubbed | Intent/completion contracts use the fault injector and OTLP fixture |
| Revocation | 5 stubbed | 5 stubbed | Deny-new, rotation, replacement certificate, and drain use fixture control |
| **Total** | **66 stubbed; 13 not-applicable** | **66 stubbed; 13 not-applicable** | No release-eligible result |

### Authoritative Linux/KVM

| Group | Envoy | mitmproxy | Interpretation |
|---|---:|---:|---|
| Identity and route | 17 stubbed | 17 stubbed | Candidate behavior is real; dependencies remain fixtures |
| HTTP parsing | 19 stubbed | 19 stubbed | Candidate behavior is real; dependencies remain fixtures |
| Credential handling | 8 stubbed | 8 stubbed | Candidate behavior is real; dependencies remain fixtures |
| Client compatibility | 10 not-applicable | 10 not-applicable | Client matrix is deliberately functional-only in Stage 1 |
| Bypass resistance | 13 pass | 13 pass | Authoritative host-enforced TAP policy, no NAT/default route, root guest |
| Audit failure | 7 stubbed | 7 stubbed | Mandatory Stage 3 rerun against real WAL/authz |
| Revocation | 5 stubbed | 5 stubbed | Mandatory Stage 3 rerun against real OpenBao/control path |
| **Total** | **13 pass; 56 stubbed; 10 not-applicable** | **13 pass; 56 stubbed; 10 not-applicable** | Only bypass results are release-semantics passes |

There were no `fail`, approved-skip, or candidate-specific omitted results in these runs.

## Engineering comparison

| Criterion | Envoy | mitmproxy |
|---|---|---|
| HTTP/1.1 and HTTP/2 | Envoy is the sole wire parser; explicit H1/H2 listeners and parser limits passed the shared ambiguity matrix. | mitmproxy is the sole wire parser; parsed-flow hooks passed the same matrix. |
| CONNECT and inner TLS | Explicit forward CONNECT decapsulation and host-specific inner TLS listeners. CONNECT/Host/SNI/`:authority` consistency is enforced by static routing and ext-auth metadata. | Native explicit-proxy MITM flow. The addon checks CONNECT target, Host, SNI, port, method, canonical path, and declared query before authorization. |
| Immutable configuration | Deterministic static bootstrap; no admin endpoint, xDS/SDS, Lua, original-destination, dynamic-forward, cluster-header routing, or direct fallback. | Deterministic read-only JSON policy and per-case CA state; no web/admin UI. The Python addon remains executable runtime policy code. |
| Fail-closed authorization | Native v3 gRPC `ext_authz`, `failure_mode_allow: false`, one-second bound, capability challenge, and intent metadata. Failure/outage denies before upstream use. | Addon performs a bounded external authorization call and denies on malformed response, timeout, or error before upstream use. This behavior depends on custom Python hook execution. |
| Credential injection | Static route-owned bearer, Basic, or API-key overwrite after authorization; guest values are removed. | Addon removes guest authorization/proxy authorization and writes route-owned credential after authorization. |
| Audit completion | Envoy emits bounded structured completion access records correlated by ext-auth metadata. Production requires a trusted collector/WAL completion path. | Addon directly correlates flow completion and posts bounded completion metadata. Production durability still requires the real Cogs WAL. |
| Revocation and draining | Deny-new fixture plus bounded process drain and replacement certificate/capability cases pass. Static host/certificate changes require config/process replacement in this Stage 1 design. | Deny-new fixture plus bounded process drain and replacement certificate/capability cases pass. Per-case CA/process state is operationally simpler for dynamic MITM but remains custom lifecycle code. |
| Limits | Explicit 32 KiB request-header and 100-header bounds, connection/upstream/authz timeouts, no unbounded admin surface; container is read-only with dropped capabilities, 256 PID, 256 MiB, and one-CPU limits. | Container has the same read-only, capability, PID, memory, and CPU bounds, and addon calls are bounded. HTTP parser/resource limits rely more heavily on mitmproxy defaults and container ceilings. |
| Operational complexity | More generated static configuration: CONNECT listener plus host-specific inner TLS/listener/cluster material. Mature native ext-auth and observability primitives, but config generation and completion collection must be maintained. | Less proxy configuration and natural dynamic MITM behavior, but requires Python runtime, per-session CA state, and a security-critical in-process addon. |
| Cogs-specific code | No custom code executes inside Envoy. Stage 1 has a 551-line deterministic config generator and 257-line minimal native-v3 gRPC codec in the fixture; production still needs the Cogs authz/WAL service and config materializer. | A measured 197-line Python addon executes inside the proxy for capability validation, routing checks, credential overwrite, and audit completion, plus a 110-line policy generator. |
| Patch maturity | The pinned image passed the HIGH/CRITICAL CI policy without an exception in the cited run. | The pinned latest image has six fixed HIGH findings under the temporary #25 exception. The exception expires 2026-07-27 and cannot support selection or release. |

### mitmproxy fixed HIGH inventory

- `CVE-2026-4878`
- `CVE-2026-45447`
- `GHSA-537c-gmf6-5ccf`
- `GHSA-6v7p-g79w-8964`
- `CVE-2026-49853`
- `CVE-2026-49855`

The unsuppressed Trivy JSON is retained as a CI artifact. Ignoring these findings for candidate testing is not an assertion that they are unexploitable.

## Client compatibility

Both candidates produced the same functional matrix:

- compatible: curl HTTPS, Git smart HTTP, pip wheel download, Python requests, Python httpx, Java `HttpClient` HTTPS, and curl HTTP/2;
- unsupported without an explicit launcher/agent decision: Debian npm 9.2.0 proxy authentication, Node 20.19.2 native HTTPS, and Node 20.19.2 native fetch.

Unsupported client cases are measured denials linked to `client.curl` as a positive control. Details and preset boundaries are in [`stage-1-client-compatibility.md`](stage-1-client-compatibility.md).

## Unsupported protocols and credential schemes

The following are outside the selected Stage 1 HTTP egress contract and must not be advertised as supported:

| Surface | Status and reason |
|---|---|
| Application gRPC | Unsupported. HTTP/2 transport parsing passed, but gRPC application semantics, streaming, metadata credentials, and trailers were not qualified. Envoy's authz gRPC control call is not evidence for guest gRPC egress. |
| SigV4 or generic HMAC signing | Unsupported. Neither adapter canonicalizes and signs method/path/query/headers/body under a production key contract. Static header injection is insufficient. |
| Upstream mTLS | Unsupported. Per-destination client certificate/key selection, key custody, rotation, and non-disclosure were not tested. |
| Databases | Unsupported. PostgreSQL, MySQL, Redis, MongoDB, and other non-HTTP protocols have no parser, policy, credential, or audit contract. |
| SSH egress | Unsupported and denied by the alternate-TCP bypass group. SFTP is only the trusted host-to-guest control plane, not guest egress. |
| WebSockets | Unsupported and explicitly denied by `bypass.websocket`; HTTP Upgrade is not an allowed credential-bearing route. |
| Arbitrary TCP/TLS | Unsupported. CONNECT is restricted to declared HTTPS routes and cannot be used as a generic tunnel. Nested CONNECT is denied. |
| UDP and QUIC/HTTP/3 | Unsupported and denied by authoritative silent UDP sensors. |
| Guest DNS and DoH | Unsupported by the egress contract. Presets use proxy CONNECT authority with `guest_resolution: false`; direct DNS and DoH bypasses pass as denials in Linux/KVM. |
| Subscription OAuth/refresh tokens | Unsupported for the initial release. Cogs remains API-key-only and must never handle refresh tokens. |
| Native npm/Node behavior listed above | Unsupported unless a separately reviewed explicit proxy agent or launcher is added and the full unchanged suite is rerun. |

Adding any resolver allowance, generic tunnel, protocol parser, signer, client-key path, or launcher changes the threat boundary and requires the complete applicable bypass, parser, credential, audit, and revocation groups to be rerun.

## Comparison conclusion for ADR input

Both candidates demonstrate the required Stage 1 HTTP mechanism and the same authoritative network-denial result. The differentiators are therefore implementation and supply-chain risk, not pass counts:

- Envoy requires more deterministic generated configuration and an external production authz/completion integration, but keeps policy code out of the proxy process, uses native fail-closed ext-auth, exposes no admin/dynamic-routing surface, and has the stronger current vulnerability result.
- mitmproxy is operationally convenient for dynamic MITM and required less listener configuration, but places 197 lines of Cogs-specific security logic inside the proxy runtime and currently carries six fixed HIGH findings under an expiring candidate-only exception.

On the present evidence, Envoy has the stronger security and patch-maturity profile. ADR 0011 must make or reject that selection explicitly, record the unsupported client cost, and preserve mandatory Stage 3 reruns. This report alone does not cross the proxy-selection gate.
