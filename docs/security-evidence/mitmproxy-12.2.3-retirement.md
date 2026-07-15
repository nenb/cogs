# Retired mitmproxy 12.2.3 candidate exception

Status: rejected as an active Stage 3 path. Historical Stage 1 comparison evidence and adapter code remain for review only; Envoy remains the sole Stage 3 implementation path under ADR 0011.

## Scan provenance

- Image: `mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f`
- Tooling: repository CI vulnerability job using `aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25` (`v0.36.0`), `ignore-unfixed: true`, severity `HIGH,CRITICAL`
- Evidence source: latest pre-retirement main CI artifact `mitmproxy-vulnerabilities.json` from workflow run `29381729559`
- Scan date: 2026-07-15

## Current findings

The exact pinned digest still has six unique HIGH finding identifiers, represented as eight package records because one OpenSSL finding affects three installed packages. All are reported with fixed versions available.

| Finding | Package record(s) | Status |
|---|---|---|
| `CVE-2026-4878` | `libcap2` | fixed |
| `CVE-2026-45447` | `libssl3t64`, `openssl`, `openssl-provider-legacy` | fixed |
| `GHSA-537c-gmf6-5ccf` | `cryptography` | fixed |
| `GHSA-6v7p-g79w-8964` | `msgpack` | fixed |
| `CVE-2026-49853` | `tornado` | fixed |
| `CVE-2026-49855` | `tornado` | fixed |

## Decision

The expiring candidate-only ignore is removed rather than renewed. mitmproxy is not scanned or allowed as an active selected CI image, receives no active selected-image SBOM job, and is not a release fallback. Switching to mitmproxy would require a new ADR, a clean supported pin with no owner/expiry ignore supporting selection, and a complete conformance rerun with real Stage 3 dependencies.

No proprietary advisory text, exploit detail, credentials, account identifiers, or raw scanner tokens are included here.
