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

OpenBao image status and functional smoke:

- The exact v2.6.1 fixture remains retired after fixed HIGH Go standard-library findings. Its dispositions remain removed and are not renewed or expanded.
- The selected successor is the upstream-signed OpenBao 2.7.0 index `sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315`, with exact Linux/amd64 child and binary closure recorded in the retirement/successor evidence record. Cogs consumes that upstream image directly; it does not claim first-party republication or a direct signature on the child manifest.
- Independent review reproduced four index signatures and transparency inclusion, embedded provenance, release-asset equality, a 321-package SPDX inventory, and a no-suppression scan with zero HIGH and zero CRITICAL. `dev/openbao-model-auth/ci-smoke.sh`, launcher image preparation, and the insecure-container Stage 3 real-runtime path are restored only for that compiled-in pin; caller image overrides remain unavailable.
- The local PebbleDB qualification and CI paths are functional/static evidence. They do not establish EKS/Kata observation, production credentials, cloud execution, Stage 4 exit, or release eligibility. The historical `linux-kvm` acquisition denial remains in force.
- The complete 2.6.1 retirement and 2.7.0 successor facts are recorded in [`openbao-2.6.1-retirement.md`](../security-evidence/openbao-2.6.1-retirement.md).
