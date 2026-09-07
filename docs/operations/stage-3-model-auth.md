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
- `dev/openbao-model-auth/ci-smoke.sh` and the Stage3 real-runtime smoke now unconditionally exit before setup, pulls/runs, or report writes, including the `linux-kvm` profile. Their historical recipes, fixed file-storage configuration, and reports remain review material only. Ordinary launcher image preparation excludes OpenBao; preparing Envoy alone cannot enable the launcher. No argument or environment override admits a replacement.
- Current readiness carries `OPENBAO_FIXED_RELEASE_IMAGE_ABSENT`: **no qualified fixed image**, not no newer upstream release. Researched signed 2.6.2 images remain scan-failing; no derivative is admitted. This is a blocker, not a clean-scan, runtime, production, or release claim.
- The upstream readmission route requires one exact stable image with verified publisher identity, a fresh zero-HIGH/zero-CRITICAL scan without ignores or VEX, functional smoke against that same identity, and regenerated readiness evidence. ADR 0309/0310 additionally permit bounded first-party local-functional derivative feasibility, not signing, publication, readmission or production eligibility; its compiler/tool gates remain blocked. Historical evidence cannot qualify changed bytes.
- ADR 0313 separates only the forthcoming Stage2 rootfs/Kata/custody graph from this OpenBao-dependent Stage3 launcher. Real OpenBao ACL/KV/PKI/storage/root-retirement, S3/Envoy/KVM and production-credential qualification remain unresolved. Synthetic tests are `synthetic-contract-only`; all production, cloud, Stage3/Stage4 exit and release authority remains absent.
- The complete scan facts, decision, and non-authorizing historical boundary are recorded in [`openbao-2.6.1-retirement.md`](../security-evidence/openbao-2.6.1-retirement.md).
