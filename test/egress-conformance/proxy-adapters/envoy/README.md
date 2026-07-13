# Pinned Envoy candidate

This directory contains the Stage 1 Envoy feasibility adapter. It is test infrastructure, not the selected or production proxy. Reports remain `insecure-container` / `functional-only`, and authorization, audit, identity, and revocation fixtures remain `stubbed` until their mandatory Stage 3 reruns.

## Candidate identity

- Envoy `1.38.3`
- OCI index `envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb`

The adapter records both values, validates the image-reported version, and runs the image by digest. CI scans and inventories the same digest.

## Immutable data path

`config.ts` validates trusted session input and emits deterministic static JSON accepted by Envoy's bootstrap API. It has no `admin`, xDS, ADS, SDS, original-destination, dynamic-forward-proxy, cluster-header, or direct fallback configuration. The only socket listener is the explicit forward-proxy data listener; CONNECT payloads are decapsulated into host-specific internal listeners.

For HTTPS, each allowed CONNECT authority selects a dedicated internal listener. That listener terminates inner TLS with the pre-provisioned SAN certificate, requires the corresponding SNI, parses HTTP/1.1 or HTTP/2, and exposes only routes with exact host/port, method, and canonical path-prefix policy. Upstreams are trusted-controller endpoints with normal TLS CA and DNS-SAN verification. Plain HTTP routes use the same static policy without CONNECT.

Guest `Authorization`, `Proxy-Authorization`, and configured API-key headers are removed at the route and the configured bearer, Basic, or API-key value is overwritten. Capability validation and per-request intent authorization use Envoy's native v3 gRPC `ext_authz` contract with `failure_mode_allow: false`; authorization and audit outages therefore deny. Route-specific context extensions carry only opaque trusted case/session/route metadata, while the request carries the proxy capability for keyed comparison. No Lua or custom HTTP request parser is used; Envoy remains the sole HTTP/1.1, HTTP/2, CONNECT, and TLS parser. The inner structured completion log consumes the returned opaque intent ID as dynamic metadata and contains only intent ID, route ID, status, and bounded latency. It contains no path, query, body, header value, capability, or credential.

The adapter validates config before readiness, runs Envoy read-only with no Linux capabilities, no privilege escalation, bounded CPU/memory/PIDs, and no admin port, then performs bounded TERM-to-KILL draining and positive container/config-state teardown checks.

## Parsing and normalization

Trusted policy input is rejected unless:

- hosts are exact lowercase DNS names, never wildcard/direct IP policy keys;
- methods are canonical tokens and never nested `CONNECT`;
- path prefixes contain no percent escapes, backslashes, repeated slashes, dot segments, query, fragment, or control bytes;
- route policy tuples and IDs are unique;
- API-key headers cannot target framing, routing, or authorization headers.

At runtime Envoy applies one normalization before route matching and forwarding: path normalization is enabled, slash merging is disabled, escaped slashes are rejected, underscore headers are rejected, malformed messages close/reset, and request headers are bounded. Issue #22 supplies the complete smuggling and protocol matrix; candidate-specific tests must not weaken these settings.

## Current evidence and limitations

`ci-smoke.ts` runs the shared conformance controller with a wrong-capability denial and a real CONNECT → inner TLS interception → bearer overwrite request. It correlates the stub intent, redacted Envoy completion, and non-reflecting upstream observation before atomically publishing the report.

Still outstanding by design:

- full route/parser/HTTP/2/redirect/Basic/API-key/drain/client probes are issue #22;
- guest-root default-deny is authoritative only in issue #23's Linux/KVM driver;
- direct OpenBao metadata polling and durable WAL behavior are Stage 3 reruns;
- Envoy cannot mint per-SNI leaves, so immutable certificates enumerate registered hosts;
- this result does not select Envoy; the alternate candidate and comparison remain required.
