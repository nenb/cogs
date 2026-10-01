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

## Admitted upstream successor: OpenBao 2.7.0

The 2.6.1 retirement above remains historical and unchanged. The protected-repository successor selects the signed upstream image directly rather than republishing changed or redundant first-party bytes:

- exact image: `quay.io/openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315`;
- Linux/amd64 manifest: `sha256:6d575d906d70d40b9d789149c8dc09897291c5a1707d4d0ba8a459eaaa94c8c4`;
- source commit: `ca305a02daa68b203325daa1b25c18d7a252d4b3`;
- `/usr/bin/bao` SHA-256: `9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e`;
- publisher identity: `https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.7.0`, issuer `https://token.actions.githubusercontent.com`;
- four verified index-signature records with transparency-log inclusion; the amd64 manifest is accepted as a member of that signed index, not as a directly signed child;
- embedded BuildKit SLSA provenance readback SHA-256 `1153e37ee798e3432f0a1e23078873272fdcc403511939bb0097e1627b1d7a88`;
- independent SPDX inventory: 321 packages, SHA-256 `14a79d1da7b1c26852c2c62e683ec3c9fb88ee0e87c8f6ba28a444f1b45f24b5`;
- pinned-database Trivy scan with `ignore-unfixed=false`, no suppressions: total 1 UNKNOWN/unfixed, HIGH 0, CRITICAL 0, report SHA-256 `c2286a589fa923d5791f5aebc9a4568c7b4dc03bf0539b83bfdf8e8f4a8424bb`; and
- independent upstream review SHA-256 `d9acfcbb2d9d4a44ab4893f4621a5b6db5bbd99969d59d03b414cc455a2cee88`.

The signed release archive and release SBOM were also verified, and the release binary equals the image binary. Local PebbleDB initialize/unseal, KV v2, AppRole restart recovery, PKI issue/revoke/reissue, graceful restart, and cleanup evidence is functional-only. The repository pin, runtime-artifact schema, CI scan/SBOM, launcher input preparation, model-auth smoke, and insecure-container Stage 3 runtime path admit this exact upstream dependency. They do not claim direct child signing, first-party publication, EKS/Kata observation, production readiness, cloud execution, Stage 4 exit, or release eligibility. Those claims remain fail-closed.
