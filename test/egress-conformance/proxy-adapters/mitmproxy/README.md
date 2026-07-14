# Pinned mitmproxy candidate

This time-boxed Stage 1 alternate uses `mitmproxy/mitmproxy:12.2.3` at OCI index digest `sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f`. It is a comparison candidate, not a proxy selection or production component.

The adapter writes a validated, immutable policy and mounts it read-only. `mitmdump` has one explicit proxy listener and no web/admin UI. Its generated CA private key remains in a trusted per-case state mount, while only `mitmproxy-ca-cert.pem` enters the insecure guest. Cleanup positively removes the container and all CA/configuration state.

Unlike Envoy, the candidate needs the measured 202-line `addon.py` integration to:

- validate a keyed session capability before CONNECT;
- enforce exact host, port, method, and canonical path-prefix policy;
- call fail-closed authorization/audit hooks before overwriting bearer, Basic, or API-key headers;
- record correlated, redacted completion metadata; and
- revalidate capabilities on every credentialed request so deny-new/revocation takes effect.

mitmproxy remains the HTTP/TLS parser; the addon consumes parsed flow fields and does not parse wire HTTP. Standard flow logging is disabled because it includes URLs. Upstream-certificate sniffing is disabled so no undeclared upstream connection precedes inner route authorization, and candidate configuration uses normal upstream TLS validation against an explicit CA.

The latest upstream image currently has six fixed HIGH findings. `.trivyignore-mitmproxy` records their narrow test-only scope, evidence, owner, issue #25 tracking, and automatic expiry on 2026-07-27. The findings remain visible in the unsuppressed CI inventory artifact and are a candidate-comparison disadvantage; the exception cannot support selection or release.

`ci-smoke.ts` runs the candidate smoke, while `suite-smoke.ts` executes the same immutable 56-case route, HTTP/1, HTTP/2, credential, audit, OTLP-confidentiality, failure, revocation, drain, capability-rotation, and certificate-replacement matrix as Envoy. Requests originate from root over SSH in the `insecure-container` guest. Evidence is `functional-only` and dependency-stub-aware; it cannot support isolation, proxy selection, or release claims. The separate Linux/KVM run provides authoritative guest-root and bypass evidence while preserving all stub labels.
