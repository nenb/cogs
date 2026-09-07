# ADR 0309: Retire post-review H and authorize bounded corrections

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through explicit acceptance of the bounded post-H correction plan in the implementation conversation, before implementation
- Scope: `/tmp/cogs42-posth-governance.md`, assessed at H `6bd12dcd25d877ffac03752fa0f71beeeb86a99e`; this slice implements only governance, mechanical retirement, accounting and offline guards/tests

## Decision and operational hold

Permanently retire exact H `6bd12dcd25d877ffac03752fa0f71beeeb86a99e` from selection. Supersede any unused H-specific selection permission. No producer, publisher, run or artifact identity is asserted for this H. Preserve ADR 0308's retired H `8907eba3191d07573cd84573cb0b2adddff17bd6`, G `242bbefeae5444118d9e97b46597130b509ca253`, diagnostic `34023790672`, producer `34028384783` and artifact `9988125363` as non-authorizing tombstones. ADR 0308 and earlier evidence remain historical, not rewritten or rebound.

Retirement applies to exact selected executable source/H/G/Q and authenticated artifact provenance, never merely to ancestor presence. A corrected descendant may contain retired commits in history. Missing or malformed retirement policy denies selection. Protected workflows carry literal pre-checkout mirrors of the exact policy tombstones, tested for equality; a guard loaded from the retired checkout cannot protect its own acquisition. Repeat selection checks before build/publication/grant effects. Preserve archival decoding, custody interpretation and cleanup-only settlement.

Not retired is not authorization. Keep protected-main, actor, exact reviewed constants, sole-first-created/attempt-one, authenticated custody and directional H→G→Q requirements. Unfilled authority fields remain blocked. No rollback/tag dispatch is permitted. New guards cannot retroactively patch old workflow versions or stop intentional execution of old source; protected-main and this operational hold remain necessary.

This decision grants no dispatch, producer, publisher, preflight, qualification, AWS credential/API, provider/OpenTofu, SSM, inventory generation, deployment, campaign, release, Stage 4 authority or Issue #42 closure permission. No replacement H/G/Q is assigned. No GitHub variable is changed. Fresh independent security/lifecycle/evidence review and corrected endpoint evidence are required before a later accepted freeze.

## Seven bounded closures (not claims of implementation)

Retain ADR 0308's shared contracts and default-deny boundaries. Authorize only:

1. Positive-only S3-09: expected positive fixture delta, authenticated relay observations, durable correlated intent and successful completion. Deliver only the generation public CA through existing trusted transport, verify chain/name, remove insecure curl, forward the existing session capability. Zero/missing traffic never passes.
2. Explicit aggregate Envoy envelope for outer/internal connections, H1/H2 buffers/streams, deadlines, upstream/authz circuit breakers and finite generation lifetime; review a multiplicative bound and prove pinned-runtime enforcement and client compatibility.
3. Revoke bootstrap OpenBao root and verify denial before ready; failure is terminal with exact cleanup/custody. A separate narrow short-lived orphan harness-mutation token may preserve fixture mutation, never root or broader runtime privilege during traffic.
4. Preserve the full eight-hour session plus certificate margin and rounding. Raise only fixed fixture PKI role ceiling to 9h within the existing 24h mount/CA; never clamp a requested leaf to 8h or weaken validation.
5. Fresh bounded close observers per caller, with one actual retirement owner, inherited absolute deadlines, sticky failure/uncertainty and dependency-safe release. No repeated effects or timeout-as-retirement.
6. Reject the x32 syscall bit before native seccomp dispatch, preserving exact native exceptions; update only active digest consumers and portable hostile tests. Historical accepted digests remain historical. Host ENOSYS is not filter-denial evidence.
7. Use `-serial null` after checking consumers: no guest-controlled host serial retention; retain SSH/QMP readiness and exact teardown. If serial evidence is required, stop for a reviewed byte-bounded design.

No new proxy, capability lifecycle, database, scheduler, secrets framework or cloud authority is authorized. Preserve hostile tests. Any newly discovered path requires reviewed exact allocation before editing.

## Exact allocation and measurement

`config/external-review-remediation-budget-v1.json` is the whole-file exact ownership map, including future closure files (x32 and serial included), all nine retirement workflows, seven Python guards and the preflight shell, their existing tests, and the retirement policy/helper. Existing assignments remain unchanged. No wildcard, deletion credit, transferable hunk credits or binary/ignored-input exceptions are allowed. Charge additions, replacements, moves and formatting from unchanged baseline `242bbefeae5444118d9e97b46597130b509ca253`, with rename/copy detection disabled.

| Owner | Measured H gross | New ceiling | Forecast additional reserve | Forecast endpoint |
|---|---:|---:|---:|---:|
| route | 664 | 2,200 | 450 | 1,114 |
| revocation | 737 | 1,700 | 600 | 1,337 |
| relay | 527 | 2,300 | 330 | 857 |
| lifecycle | 2,896 | 4,300 | 1,050 | 3,946 |
| completion | 1,754 | 2,600 | 0 | 1,754 |
| integration | 909 | 2,900 | 1,450 | 2,359 |
| **Total** | **7,487** | **16,000** | **3,880** | **11,367** |

Integration forecast: 350 seccomp + 1,100 retirement/governance/accounting/tests. These are forecast subceilings, not measured future closure. Byte forecasts and new-file highs remain unchanged (40 total, integration 24). The three immediate new files are this ADR, retirement data and helper. Planned integration baseline-absent paths rise from 18 to 21. Replace absent old reservations with this ADR and future `0310-freeze-remediated-H-and-authorize-control.md` / `0311-establish-remediated-Q-and-authorize-qualification.md`; do not create those future records now.

Measured at H: Stage2 physical 90,536, conservative 94,195; deploy/retained/workflow correction 21,948 / 12,055 / 4,838, global 38,841; mutable owners 1,126. Reserve at most 150 / 500 / 350 additional counted lines respectively (≤1,000 combined); forecast conservative ≤95,195 and global ≤39,841. Explicitly retain and charge the new helper/data; do not remove retained members for capacity. Keep accounting anchor `FINAL_H_REVISION` unchanged.

Retain Stage2 highs 22,300 / 13,100 / 5,500, global 40,500, strict hard `<95,900`, advisory 90,000 and strict mutable-owner `<2,000`. Retain source limits: 1,460 tracked files, 22,020,096 aggregate included bytes, 262,144 serialized inventory bytes and 4 MiB/file. H measured 1,431 tracked files, 1,428 included entries, 19,045,737 included bytes and 221,408 serialized bytes. All thirteen future v5 members remain reserved and exactly absent until Q; partial, extra or ignored v5 is rejected. Actual endpoint measurements replace forecasts in the implementation handoff; any overrun stops for reviewed adjustment.

## Same-day accepted integration extension: local OpenBao derivative feasibility

The user explicitly approved the bounded first-party path in the implementation conversation on 2026-09-07, before recipe implementation, and requested this governance extension. Inputs are the fully read `/tmp/cogs42-posth-supply.md` and `/tmp/cogs42-openbao-path.md`. Their temporary research receipts are not admission evidence. Upstream v2.6.2 exists and its exact standard image is signed, but both researched amd64/arm64 scans fail with **9 HIGH rows and 1 CRITICAL row**; the separately signed distroless amd64 variant fails with 7 HIGH and 1 CRITICAL. The current npm lock's dated zero-finding audit is a separate fact; no npm exception is restored.

Supersede **only** the upstream-image-only/no-local-rebuild restriction in `openbao-2.6.1-retirement.md` for a new **first-party local-functional derivative class**. Preserve that historical record and all existing production restrictions. Neither upstream 2.6.1 nor the researched 2.6.2 images become selectable. No final derivative digest, producer, publisher, run or successful build is asserted.

Authorize narrow recipe/validator/test implementation and a time-boxed local feasibility phase under the integration lead, with an accountable build/security owner and a distinct independent admission reviewer recorded before feasibility starts. The first **0.5–1 engineer-day** must establish build compatibility and honest scanner recognition of the OpenBao application; without both, stop. Local feasibility builds and later synthetic-secret functional tests are the only execution class contemplated by this extension, after their input/admission gates. **This governance slice executes none of them.** Signing, publication, operational workflow dispatch, inventory/readiness generation, authoritative KVM qualification, production/cloud/Stage 4 exit and release remain separately blocked. The dedicated build/publisher workflows below are reservations, not dispatch permission; worker/sandbox `release-images.yml` remains outside this change.

### Artifact trust and bounded construction

- Authenticate source distribution `openbao-dist-v2.6.2.tar.xz` (39,943,844 bytes, SHA-256 `a7784550a9db16f24e99d65a18c9b12a433707c79ef4c1f34262d3f48171c7a9`) against signed checksums SHA-256 `3d4a19fdc54a86fd94ce59ea91316dbf4304180bb27ae818e78e85c7f2164645`. Verify the exact release-file Sigstore identity `https://github.com/openbao/openbao/.github/workflows/release.yml@refs/heads/release/2.6.x`, issuer `https://token.actions.githubusercontent.com`, and the separately pinned published GPG key/signature in empty keyrings. The image tag signer and release-file branch signer are different trust identities; no wildcard substitution. Bind source commit `dd9c19c37a878cf4a81b18efb8d6f0599c7da923` and tree `308de7e6da19d8b994c5710ffd715ce4cedde448`; compare all upstream tracked source, explicitly allow only reviewed generated distribution additions, and reject unsafe archive entries or unknown executable changes.
- Initial security patch set: Go 1.26.8, x/crypto 0.55.0, grpc 1.83.2 and go-archive 0.3.0. Freeze and review the complete checksum-verified MVS/module/vendor delta, including the exact coupled requirements in the path report (x/net 0.58.0, x/sys 0.47.0, x/term 0.45.0, x/text 0.41.0, x/sync 0.22.0, patternmatcher 0.6.1, sequential 0.7.0, user 0.4.1, cel.dev/expr 0.25.2, genproto api/rpc `v0.0.0-20260526163538-3dc84a4a5aaa` and justified graph dependencies). Do not downgrade already higher selections. Unexpected graph changes stop for review. No blanket update, root-module rename, wholesale main merge, application/auth/PKI rewrite, test deletion or source hooks.
- Use the supported no-UI, CGO-disabled API server, retaining upstream KV-v2/token/ACL/PKI/auth implementation and existing local file-storage configuration. Independently authenticate and scan exact compiler/builder/tool/base inputs before freezing the build lock; the report's immutable candidates are proposals, not admitted tools. Preserve OS/package metadata, CA trust, license notices and honest derivative version/source/patch identity. No tracked upstream/vendor dump or binary archive: external bounded acquisition and hash manifests retain the existing repository byte/cardinality limits.
- Two clean isolated builders, no shared writable cache, credentials, cloud metadata, source-visible host socket, or network during compilation/export. Freeze toolchain, module/vendor closure, architecture, flags, locale, UID/GID, ordering, timestamps and `SOURCE_DATE_EPOCH=1787067785`. Require per-platform binary **and complete runtime layer/config/manifest/index byte equality**, initially linux/amd64 and linux/arm64 only. Keep time-varying attestations separate from runtime equality. Cross-compilation is not native/KVM qualification. Every admitted platform needs actual local functional tests; a single-platform milestone must reject every other platform.
- Require per-platform SPDX SBOM, source/patch/module/compiler/base provenance, exact image/platform/config/binary subject binding, and raw whole-image scans recognizing nonempty OS packages, `/usr/bin/bao` Go dependencies **and the real OpenBao derivative application identity**. Cross-check source/application SBOM and `go version -m`. Both builder and runtime inputs remain gated. DB age at admission must be ≤24 hours and not past NextUpdate; pin tool/DB identity and retain report hashes. Require zero HIGH/CRITICAL including unfixed findings, no ignore/VEX/skip/analyzer-disable/severity rewrite. Unknown application identity, missing language coverage, likely false-positive raw HIGH rows or stale/acquisition-failed scans still fail.
- Feasibility must retain controls that detect genuinely vulnerable old OpenBao versions and a deliberately vulnerable module. No `(devel)`/stripped/fictitious metadata, disabling VCS stamping to hide findings, fabricated SBOM identity or bespoke advisory exception. If recognition requires a broad scanner fork, main's `/v2`/internal-package migration, or incompatible build/application changes, **stop the bounded path** and use explicitly `synthetic-contract-only` fixtures while awaiting a qualified upstream artifact.
- A later separately authorized isolated first-party publisher must not execute candidate code and must authenticate exact reviewed producer artifacts, A/B equality, scans/SBOM/tests and cleanup before signing immutable subjects. Freeze exact first-party workflow/ref/source identity, provenance and signature bundles; independently verify publication/readback before an exact local-only pin. Never reuse upstream signatures for changed bytes or allow consumer-time build/tag fallback. Production eligibility stays false. Rescan admitted digests daily; blocking findings disable new local starts, not roll back to retired images. Require reviewed renewal within 30 days and prefer a clean authenticated upstream replacement; continued fork maintenance requires a new decision.

### Adjacent fixture closures and exact reservation

Add whole-response OpenBao request deadlines through body consumption/parsing (including headers-then-stalled-body), acquisition intent recorded **before** Docker create/start effects and retained across timeout/cancellation/late completion, and explicit bounded uid-owned tmpfs for `/openbao/file` with read-only rootfs and no anonymous/persistent volume fallback. Preserve nonroot numeric identity, loopback-only random port, existing config bytes, cap-drop/no-new-privileges, root revocation before ready, fresh close observers and sticky cleanup uncertainty. Tests must distinguish timeout from actual retirement and must retain exact container/storage custody. These edits belong to existing `dev/launcher/openbao.ts` / `test/dev-launcher-trusted-fixtures.test.ts`, with smoke/harness changes charged to their existing owners. No root startup, host networking, external plugins, new storage architecture or credential fallback is authorized.

The adjacent KVM driver's PID-only kill/identity and best-effort network-removal behavior remain **review-stop uncertainties**, not closed by `-serial null`. Reserve `dev/linux-kvm/driver.sh`, `dev/linux-kvm/README.md` and `test/linux-kvm-git-tools.test.ts` for bounded observation/regression and separately reviewed exact-owner corrections; do not silently expand to a process/network framework or claim cleanup from PID absence.

New exact baseline-absent reservations (create none in this governance slice):

| Owner | Exact path |
|---|---|
| revocation | `config/openbao-local-build-v1.json` |
| revocation | `images/openbao-local/Dockerfile` |
| revocation | `images/openbao-local/dependencies.patch` |
| revocation | `scripts/openbao-local-artifact.py` |
| revocation | `test/openbao-local-artifact.test.ts` |
| integration | `.github/workflows/build-openbao-local.yml` |
| integration | `.github/workflows/release-openbao-local.yml` |
| integration | `docs/security-evidence/openbao-local-artifact-candidate.md` |
| integration | `docs/operations/openbao-local-artifact.md` |

The updated exact allocation also reserves the existing pin/smoke/harness/sidecar/launcher-image/image-gate consumers and their existing evidence tests/docs named in the reports; original file ownership is preserved. Old versioned readiness schemas/receipts remain immutable. A successor readiness/admission schema or another newly discovered seam requires a reviewed exact-path update after feasibility, **before editing**; allocation of existing consumers does not permit relabeling old evidence or bypassing regeneration approval. No future v5 control member is created.

### Superseding forecast and ceiling vector

The original table above records the initially accepted plan. This same-day extension supersedes its **owner ceiling/new-file-high vector only**, retaining baseline, global 16,000, whole-file/no-deletion accounting and all Stage2/source hard limits. The new forecast adds 1,700 revocation-owned recipe/validator/consumer/test lines, 300 OpenBao fixture-bound lines, 200 relay-owned pin/harness lines, 150 driver review/regression lines and 1,000 integration-owned workflow/gate/docs/tests lines: **3,350**, producing a conditional total forecast **14,717**, not measured implementation or guaranteed admission.

| Owner | Measured H gross | Extended forecast endpoint | Superseding gross ceiling | New-file high (previous → new) |
|---|---:|---:|---:|---:|
| route | 664 | 1,114 | 1,500 | 2 → 1 |
| revocation | 737 | 3,337 | 3,500 | 1 → 5 |
| relay | 527 | 1,207 | 1,400 | 3 → 0 |
| lifecycle | 2,896 | 3,946 | 4,100 | 5 → 4 |
| completion | 1,754 | 1,754 | 1,900 | 5 → 5 |
| integration | 909 | 3,359 | 3,600 | 24 → 25 |
| **Total** | **7,487** | **14,717** | **16,000** | **40 → 40** |

This reallocates unused reservations explicitly, not silently; planned exact baseline-absent paths are **40** (integration 25), exactly the unchanged 40-file allowance. This preserves both currently absent completion reservations as well as all thirteen v5 members. There is no unallocated file contingency: any additional successor schema/seam must stop for a reviewed reservation/capacity decision, never an implicit 1,461st tracked file. Keep gross-byte forecasts totaling 2,570,000 unchanged by keeping recipes/patches/manifests bounded rather than vendoring upstream source. All new or modified build/gate workflows combined must fit **≤219 further workflow lines**, inside the original post-H ≤350 workflow reserve (retirement guards use 131), including any conditional CI restoration. Exceeding this small workflow allowance stops before expansion. The original ≤150 deploy / ≤500 retained / ≤350 workflow / ≤1,000 combined post-H counted-line reserves remain binding; the new recipe helper is separately charged under whole-file remediation/source accounting, not an uncounted Stage2 retirement member. Forecasts are conditional on these small implementations; infeasibility requires measured review, not automatic cap growth. Future ADR freeze/Q reservations remain 0310/0311.

## Historical snapshot and next decision

The assessment observed no tracked full-H literal or repository variable equal to new H. Preserve the observed repository-variable snapshot (not a fresh remote audit): implementation `229ea62bce964086726181974a6fec1c6dfd1f86`, control `821149ba4c3dbccef48694efcdb1eb29fa9fd2b9`, qualification `06188f67a9a699924d645ce8aa0e91950b6341c7`, package `7ee5d6c324363116080b528d1b912d2c123f45d7`, rootfs `de027e33312be49e5b825c0abc7e864688ae2aaa`; local/native/release authorized actors each `nenb`. Environment/organization variables and remote artifacts were not enumerated. Before any separately authorized mutation, recheck and report drift rather than overwriting unrelated bindings.

Retained source inventory Merkle `8a1f2931a6d1a131df9b5a2de0e72b198c1bfb81fe9d53f16ea8536f681800ad` binds H's bytes, not a commit or clean index. Preserve it as historical evidence; do not relabel or regenerate in this slice. Passing offline tests or ordinary CI cannot make old H selectable. Stop after local implementation, measurement and handoff; later ADR 0310/0311 require genuinely new reviewed source and observed custody, never renamed old artifacts.
