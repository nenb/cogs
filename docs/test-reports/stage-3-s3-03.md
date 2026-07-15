# Stage 3 S3-03 model authentication draft evidence

Issue: #65 model authentication.

## Claim boundary

This evidence is functional-only for local OpenBao model-auth integration. It does not support isolation, release, Kubernetes-auth, AWS, or production-readiness claims.

## Local OpenBao functional smoke

- Date: 2026-07-15
- Image: `quay.io/openbao/openbao:2.6.0@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653`
- Entry point: `dev/openbao-model-auth/ci-smoke.sh`
- Runtime version check: `bao version` must report OpenBao v2.6.0 before evidence is written.
- Vulnerability scan note: `.trivyignore-openbao` is scoped only to the OpenBao scan for five documented Trivy 0.70 pseudo-module false positives; no Go stdlib finding is ignored and review deadline is 2026-08-15.
- Result: passed locally
- Evidence artifact: `docs/security-evidence/generated/openbao-model-auth-local/report.json` (ignored generated output, `cogs.security-report/v1alpha1`)
- Evidence validation: `npm run schemas -- docs/security-evidence/generated/openbao-model-auth-local/report.json` passed
- Source revision binding: local report currently defaults to Git `HEAD`; regenerate after the final commit for exact commit binding.
- Post-exit independent cleanup check: `containers=0`, `volumes=0`, temp state count `0`

Validated behavior:

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

## Local checks

- `bash -n dev/openbao-model-auth/ci-smoke.sh` — passed
- `npm run images:check` — passed
- corrected real OpenBao smoke — passed
- `npm run schemas -- docs/security-evidence/generated/openbao-model-auth-local/report.json` — passed
- `npm run lint` — passed
- `npm run format:check` — passed with ignored AWS `.state` moved aside/restored
- `npm run typecheck` — passed
- `npx tsx --test test/model-auth.test.ts test/pi-session.test.ts` — passed, 27/27
- `npm run test` — passed, 169/169
- `git diff --check` — passed

## Line budget

Production TypeScript line count after Phase 3 fixture wiring: `5,694 / 6,050`.
