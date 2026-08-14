# Retired OpenBao 2.6.1 candidate and fixture

Status: rejected as an active Stage 3 model-auth fixture and Stage 4 candidate on 2026-08-14. Historical code, reports, and exact identity records remain for review only. They establish no current runtime, production, Stage 4 exit, or release authority.

## Scan provenance

- Image: `quay.io/openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`
- Tooling: repository CI vulnerability job using `aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25` (`v0.36.0`), `ignore-unfixed: true`, severity `HIGH,CRITICAL`
- Evidence source: PR #392 workflow run `31836113876`, job `94882674339`
- Scan time: `2026-08-14T20:14:04Z`
- Detected runtime: Go standard library `v1.26.5`

## Retirement-triggering findings

The fresh scan reported two fixed HIGH findings in the exact pinned binary:

| Finding | Installed component | Fixed boundary reported by Trivy |
|---|---|---|
| `CVE-2026-39821` | Go standard library `v1.26.5` | Go `1.25.13`, `1.26.6`, or `1.27.0-rc.3` |
| `CVE-2026-46600` | Go standard library `v1.26.5` | Go `1.26.6` or `1.27.0-rc.3` |

The previously accepted exact-boundary `GHSA-hrxh-6v49-42gf` finding and pseudo-module scanner dispositions were due to expire at `2026-08-15T23:59:59Z`. They are not renewed. The scoped `.trivyignore-openbao` file is removed rather than expanded.

At review time, upstream OpenBao `v2.6.1` remained the latest stable release and exact published image. No upstream image built with the fixed Go standard library was available. A local rebuild was rejected because it would not preserve the upstream release signature and immutable published image identity.

## Decision

OpenBao is removed from active CI scanning, active selected-image SBOM generation, security-labelled model-auth/runtime/launcher smoke, and current campaign readiness. This is rejection, not a clean scan or remediation claim. Historical source and evidence remain readable but must not be executed or promoted as current authority.

Readmission requires all of the following in one separately reviewed change:

1. a stable upstream OpenBao release image at an exact immutable digest;
2. verified publisher identity and platform manifest closure;
3. a fresh zero-HIGH/zero-CRITICAL scan without an ignore or VEX;
4. restored functional model-auth, Stage 3 runtime, and launcher smoke against that same exact image;
5. regenerated static/runtime readiness evidence; and
6. no promotion of local evidence into cloud, Stage 4 exit, production, or release authority.

No proprietary advisory text, exploit detail, credentials, account identifiers, or raw scanner tokens are included here.
