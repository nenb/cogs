# Stage 3 model authentication draft notes

Scope: issue #65 draft implementation notes.

Current draft architecture:

- Model API keys resolve through a narrow `ModelApiKeySource` callback port.
- OpenBao tokens resolve through a narrow `OpenBaoIdentityPort` callback port and are not accepted from launch documents.
- Pi-facing construction uses `createAuthenticatedCogsPiSession(...)`, which validates the launch document and derives `user_id`, `session_id`, provider, model, and credential handle from that document before resolving the runtime key.
- The lower-level raw-key Pi constructor remains only as an internal/test seam for now.
- OAuth broker production access remains disabled; no refresh-token path is implemented.

Boundaries:

- No ambient Pi/global auth discovery.
- Runtime keys are held in memory only and redacted from events, history, JSONL, and errors.
- OpenBao/dev-source failures fail closed and do not fall back to another source.
- Local OpenBao fixture evidence is functional-only. It does not make isolation, release, Kubernetes-auth, or AWS claims.

Retired local OpenBao functional smoke:

- The exact v2.6.1 fixture was retired on 2026-08-14 after a fresh scan reported fixed HIGH findings in its Go v1.26.5 standard library. The expiring scoped dispositions were removed rather than renewed or expanded.
- `dev/openbao-model-auth/ci-smoke.sh`, its fixed file-storage configuration, and historical reports remain review material only. Active CI, security-labelled smoke, selected-image SBOM generation, and campaign readiness must not execute or promote them.
- Current readiness carries `OPENBAO_FIXED_RELEASE_IMAGE_ABSENT`. This is a blocker, not a clean-scan, runtime, production, or release claim.
- Readmission requires one exact stable upstream image with verified publisher identity, a fresh zero-HIGH/zero-CRITICAL scan without ignores or VEX, restored functional smoke against that same identity, and regenerated readiness evidence.
- The complete scan facts, decision, and non-authorizing historical boundary are recorded in [`openbao-2.6.1-retirement.md`](../security-evidence/openbao-2.6.1-retirement.md).
