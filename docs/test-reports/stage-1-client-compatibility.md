# Stage 1 client compatibility

Date: 2026-07-14

This is functional, fixture-backed Stage 1 evidence. It does not establish guest isolation, production readiness, or release eligibility. The unchanged client cases run against both pinned candidates through the non-authoritative root guest. The complete DNS-bypass group remains authoritative Linux/KVM evidence; every preset keeps guest DNS disabled.

## Results

| Client path | Envoy | mitmproxy | Configuration measured |
|---|---:|---:|---|
| curl HTTPS | Compatible | Compatible | Explicit HTTP proxy, public CA, proxy Basic capability |
| Git smart HTTP | Compatible | Compatible | `http.proxy`, Basic proxy authentication, public CA; exact `info/refs?service=git-upload-pack` |
| pip wheel download | Compatible | Compatible | Explicit proxy and public CA; deterministic wheel fixture |
| npm tarball (`npm` 9.2.0) | Unsupported | Unsupported | Embedded Basic proxy credentials produced HTTP 407 on CONNECT |
| Python requests | Compatible | Compatible | Explicit HTTPS proxy and public CA |
| Python httpx | Compatible | Compatible | Explicit HTTPS proxy and public CA |
| Java HTTPS | Compatible | Compatible | `HttpClient` proxy selector/authenticator and isolated fixture trust store |
| curl HTTP/2 TLS | Compatible | Compatible | Explicit HTTP proxy, public CA, negotiated HTTP/2 |
| Node HTTPS (`node` 20.19.2) | Unsupported | Unsupported | Native API ignored standard proxy variables without an explicit proxy agent |
| Node fetch (`node` 20.19.2) | Unsupported | Unsupported | Native API ignored standard proxy variables without an explicit proxy agent |

Unsupported cases are represented as measured denials with `client.curl` as their positive control. They are not silently omitted or treated as release-compatible behavior. npm and native Node require an explicit proxy-agent/launcher decision before production integration.

## Presets

The following immutable presets validate against `schemas/integration-v1alpha1.json` and carry canonical SHA-256 revisions:

- `integrations/presets/github-smart-http-v1.json`
- `integrations/presets/pypi-v1.json`
- `integrations/presets/npm-v1.json`

Each preset declares exact lowercase hosts, port 443, methods, canonical path patterns, bounded redirect destinations, credential binding, and `proxy-connect-authority` DNS behavior with `guest_resolution: false`.

GitHub artifact redirects and PyPI package-file fan-out are explicitly uncredentialed at destination hosts. npm credentials remain bound only to `registry.npmjs.org`. Validator and unit tests reject undeclared redirect hosts, credentialed cross-host redirects, path traversal/encoding ambiguity, mutable filenames, and revision drift.

## Evidence locations

The `insecure-container` workflow publishes both candidate JSON and Markdown reports. Linux/KVM reports retain the client cases as profile-mismatched because client compatibility is functional evidence; authoritative KVM protocol and bypass evidence is unchanged.
