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

Local OpenBao functional smoke:

- Entry point: `dev/openbao-model-auth/ci-smoke.sh`.
- Image: `quay.io/openbao/openbao:2.6.0@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653`.
- The server is published on loopback only with no persistent volume.
- Bootstrap initializes a fresh server, enables KV-v2 at `model/`, writes exactly one model API key, and creates a short-lived orphan read token scoped to `model/data/users/alice/anthropic`.
- The TypeScript smoke uses production `OpenBaoModelApiKeyStore` plus `ModelCredentialResolver`, checks the expected key in-memory without printing it, verifies another user/path is denied by the exact-path OpenBao ACL policy, revokes the read token, verifies subsequent reads fail generically, revokes the bootstrap root token, and writes a strict `cogs.security-report/v1alpha1` `report.json`.
- The report binds `source_revision` from `COGS_SOURCE_REVISION`; local runs default to current Git `HEAD`, so the local report must be regenerated after the final commit for exact binding.
- The smoke verifies the runtime `bao version` reports OpenBao v2.6.0 before writing evidence.
- The CI OpenBao Trivy ignore is scoped to `.trivyignore-openbao` for the OpenBao scan only. Five separate CVE entries document a Trivy 0.70 detector limitation where OpenBao's pseudo Go module version `v0.0.0-20260714163401-03e3a243b6f0` is parsed even though the pinned runtime is v2.6.0; those ignored HIGH findings all have fixed versions no newer than 2.5.4 and are due for review by 2026-08-15.
- `GHSA-hrxh-6v49-42gf` is different: it is a real grpc-go v1.81.1 finding accepted only for exact OpenBao digest `sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653` and this fixed file-storage fixture with no HA, xDS, cluster forwarding, or external plugins and host-loopback-only REST publication. Boundary or image drift invalidates the exception. It expires at `2026-07-29T23:59:59Z`; expiry or a fixed upstream image requires removal or a new explicit security decision.
- The report records functional-only test results and states that shell EXIT-trap cleanup verification happens after report generation.
- The shell wrapper traps exits/signals and verifies labeled containers, labeled volumes, and temporary state are removed after process exit.
