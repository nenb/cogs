# Stage 3 S3-03 model authentication draft evidence

Issue: #65 model authentication.

## Claim boundary

This evidence is functional-only for local OpenBao model-auth integration. It does not support isolation, release, Kubernetes-auth, AWS, or production-readiness claims.

## Local OpenBao functional smoke

- Maintenance review date: 2026-07-29
- Image: `quay.io/openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`
- Entry point: `dev/openbao-model-auth/ci-smoke.sh`
- Runtime version check: `bao version` must report OpenBao v2.6.1 before evidence is written.
- Vulnerability scan note: `.trivyignore-openbao` remains scoped only to the OpenBao scan for five documented Trivy 0.70 pseudo-module false positives and one exact-boundary grpc-go exception. `CVE-2026-56852` is fixed by v2.6.1's `golang.org/x/text` v0.39.0 and is not ignored; the unchanged grpc-go exception retains its 2026-07-29 hard expiry.
- Result: static pin and validator checks passed; the v2.6.1 runtime smoke was not rerun locally because no Docker daemon was available
- Evidence artifact: `docs/security-evidence/generated/openbao-model-auth-local/report.json` (ignored generated output, `cogs.security-report/v1alpha1`)
- Evidence validation: `npm run schemas -- docs/security-evidence/generated/openbao-model-auth-local/report.json` passed
- Source revision binding: local report currently defaults to Git `HEAD`; regenerate after the final commit for exact commit binding.
- Post-exit independent cleanup check: `containers=0`, `volumes=0`, temp state count `0`

Expected functional behavior retained by the fixture (not rerun locally for v2.6.1):

- loopback-only OpenBao server with no persistent volume
- fresh KV-v2 mount at `model/`
- one model API key stored at `model/data/users/alice/anthropic`
- short-lived orphan read token scoped to the exact read path
- production `OpenBaoModelApiKeyStore` + `ModelCredentialResolver` retrieved the expected key without printing it
- another user/path was denied by the exact-path OpenBao ACL policy
- read token was revoked
- post-revoke retrieval failed generically
- bootstrap root token was revoked before successful report completion
- report limitations state that shell EXIT-trap cleanup verification occurs after report generation
- labeled containers, labeled volumes, and temp state were independently absent after process exit

## Maintenance checks

- `npm run images:check` — passed
- `npm run licenses` — passed
- focused launcher/image/report tests — passed, 33/33
- `bash -n dev/openbao-model-auth/ci-smoke.sh` — passed
- `bash -n test/egress-conformance/stage3-real-runtime/ci-smoke.sh` — passed
- `npm run typecheck` — passed
- `npm run format:check` — passed
- `git diff --check` — passed
- OpenBao runtime and Trivy image scans — not run locally because no Docker daemon or Trivy executable was available

## Line budget

Production TypeScript line count after Phase 3 fixture wiring: `5,694 / 6,050`.
