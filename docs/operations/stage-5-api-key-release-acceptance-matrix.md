# Issue #363 draft — API-key-only Stage 5 release acceptance matrix

**Status:** draft and provisional; local/static requirements inventory only

**Current decision:** `matrix_finalized=false`, `release_eligible=false`, `go_no_go=not-available`

**Machine-readable draft:** [`stage5-api-key-release-matrix.draft.json`](../security-evidence/stage5-api-key-release-matrix.draft.json)

**Schema:** [`stage5-api-key-release-matrix-draft-v1.json`](../../schemas/stage5-api-key-release-matrix-draft-v1.json)

## Purpose and non-authority

This draft defines the API-key-only Stage 5 gate without supplying evidence or authority. S4-11 is a hard predecessor and remains `required-not-observed-by-this-draft`; `stage4_exit_satisfied=false` and `evidence_accepted=false`. Stage 4 static preparation and teardown-order outputs remain disjoint local authorities and cannot satisfy S4-11.

Every authority-bearing field is false. The release-candidate source revision, artifact root, immutable binding, principal identities, identity bindings, criterion evidence bindings, and provider evidence bindings are null and explicitly blocking; no evidence-reference instance or schema surface exists in this draft. Schema validity proves only bounded inventory consistency. It authenticates no person or artifact, grants no approval, observes no cloud or provider execution, and establishes no release, production, GA, or compliance result.

Finalization requires a new authority/schema after accepted S4-11 and later evidence bound to one frozen release candidate. This draft cannot be edited into a release verdict.

## Criterion-level traceability

The matrix contains **35 immutable criterion mappings**: all 22 numbered criteria in `DESIGN.md` section 24 and all 13 checkboxes in `IMPLEMENTATION.md` section 45. Each row has a source locator and full source-text SHA-256 in the JSON, accountable role, exact profile, evidence lane and future evidence-contract category, dependencies, current blocker, and applicability. All rows remain `unexecuted-by-this-draft`, have null principal/evidence bindings, and are not release eligible.

The expected inventory in `test/stage5-api-key-release-matrix.test.ts` is independent of the JSON and schema. It derives source-text digests from the two authoritative documents while separately fixing IDs and mappings; missing, duplicate, reordered, remapped, or stale-source criteria fail.

| Criterion | Immutable source | Accountable role | Exact profile | Evidence lane / contract | Dependencies | Current blocker | Applicability |
|---|---|---|---|---|---|---|---|
| `DESIGN-24.01` | `DESIGN.md#24.1` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.02` | `DESIGN.md#24.2` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.03` | `DESIGN.md#24.3` | `release-engineer` | `linux-kvm` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.04` | `DESIGN.md#24.4` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.05` | `DESIGN.md#24.5` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.06` | `DESIGN.md#24.6` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.07` | `DESIGN.md#24.7` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.08` | `DESIGN.md#24.8` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.09` | `DESIGN.md#24.9` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.10` | `DESIGN.md#24.10` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.11` | `DESIGN.md#24.11` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.12` | `DESIGN.md#24.12` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.13` | `DESIGN.md#24.13` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.14` | `DESIGN.md#24.14` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`oauth-disabled-branch` | `release-candidate-binding-not-present` | `mandatory-api-key-disabled-oauth-branch` |
| `DESIGN-24.15` | `DESIGN.md#24.15` | `release-engineer` | `linux-kvm` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.16` | `DESIGN.md#24.16` | `release-engineer` | `linux-kvm` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.17` | `DESIGN.md#24.17` | `release-engineer` | `linux-kvm` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.18` | `DESIGN.md#24.18` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.19` | `DESIGN.md#24.19` | `release-engineer` | `linux-kvm` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `DESIGN-24.20` | `DESIGN.md#24.20` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.21` | `DESIGN.md#24.21` | `campaign-operator` | `eks-kata-release-load` | `separately-approved-campaign` / `future-load-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `DESIGN-24.22` | `DESIGN.md#24.22` | `campaign-operator` | `eks-kata-release-load` | `separately-approved-campaign` / `future-load-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`stage5-load-50` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `STAGE5-45.01` | `IMPLEMENTATION.md#45.1` | `independent-security-reviewer` | `independent-review-exact-release-candidate` | `independent-review` / `future-acceptance-index-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`stage5-design-criteria`<br>`real-dependencies` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.02` | `IMPLEMENTATION.md#45.2` | `independent-security-reviewer` | `independent-review-exact-release-candidate` | `independent-review` / `future-independent-review-reference-v1` | `release-candidate-binding`<br>`independent-principal-bindings` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.03` | `IMPLEMENTATION.md#45.3` | `independent-security-reviewer` | `independent-review-exact-release-candidate` | `independent-review` / `future-independent-review-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`proxy-runtime-evidence` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.04` | `IMPLEMENTATION.md#45.4` | `release-engineer` | `local-static` | `local-test` / `future-local-test-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`provider-support-claims` | `release-candidate-binding-not-present` | `mandatory-api-key-disabled-oauth-branch` |
| `STAGE5-45.05` | `IMPLEMENTATION.md#45.5` | `campaign-operator` | `eks-kata-release-load` | `separately-approved-campaign` / `future-load-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`stage5-load-50` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `STAGE5-45.06` | `IMPLEMENTATION.md#45.6` | `staff-release-decider` | `staff-release-decision` | `staff-decision` / `future-release-decision-reference-v1` | `stage5-load-50`<br>`advertised-concurrency-claim` | `staff-decision-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.07` | `IMPLEMENTATION.md#45.7` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-eks-conformance-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `STAGE5-45.08` | `IMPLEMENTATION.md#45.8` | `independent-security-reviewer` | `independent-review-exact-release-candidate` | `independent-review` / `future-independent-review-reference-v1` | `release-candidate-binding`<br>`stage5-privacy-evidence`<br>`independent-principal-bindings` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.09` | `IMPLEMENTATION.md#45.9` | `campaign-operator` | `eks-kata-release-candidate` | `separately-approved-campaign` / `future-privacy-deletion-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`real-dependencies` | `s4-11-not-accepted` | `mandatory-api-key-release` |
| `STAGE5-45.10` | `IMPLEMENTATION.md#45.10` | `release-engineer` | `local-static` | `local-test` / `future-operations-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`operations-runbook-inventory` | `release-candidate-binding-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.11` | `IMPLEMENTATION.md#45.11` | `zero-inventory-observer` | `independent-zero-inventory` | `independent-review` / `future-zero-inventory-reference-v1` | `S4-11`<br>`release-candidate-binding`<br>`campaign-approval`<br>`campaign-teardown-complete` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.12` | `IMPLEMENTATION.md#45.12` | `independent-security-reviewer` | `independent-review-exact-release-candidate` | `independent-review` / `future-independent-review-reference-v1` | `release-candidate-binding`<br>`residual-risk-register`<br>`independent-principal-bindings` | `independent-identities-not-present` | `mandatory-api-key-release` |
| `STAGE5-45.13` | `IMPLEMENTATION.md#45.13` | `staff-release-decider` | `staff-release-decision` | `staff-decision` / `future-release-decision-reference-v1` | `stage5-design-criteria`<br>`stage5-independent-review`<br>`stage5-campaign-evidence`<br>`stage5-zero-inventory` | `staff-decision-not-present` | `mandatory-api-key-release` |

## Evidence lanes remain separate

- `local-test` evidence is repeatable release-candidate evidence only. It is neither independent review nor campaign approval.
- `independent-review` requires a stable authenticated reviewer principal bound to exact source/artifacts and distinct from the roles listed below.
- `separately-approved-campaign` requires fresh exact-revision approval, operator, approver, account/region, spend/resource/time bounds, destroy path, and evidence plan. Approval is not execution evidence.
- `staff-decision` occurs only after all mandatory evidence and cannot be produced by this draft.

No mandatory criterion may be satisfied by a stub, `not-applicable`, unapproved skip, extrapolation, stale revision, self-asserted identity, or unauthenticated digest. Failure and uncertainty stay explicit.

<!-- BEGIN MACHINE-GENERATED SUPPORT CLAIMS -->
## Machine-generated support and unsupported claims

> Generated deterministically from `support_claims` and `subscription_oauth` in the machine JSON. The machine JSON is authoritative for support claims. The exact-render test covers this marked block; it does not claim to detect arbitrary natural-language paraphrases elsewhere.

### Release posture

| Claim | Value |
|---|---:|
| `production_ready` | `false` |
| `general_availability` | `false` |
| `compliance_certified` | `false` |
| `advertised_release` | `false` |

### Provisional API-key provider candidates

| Provider | Auth class | Implementation state | Decision | Advertised | Real-provider evidence required | Evidence binding | Blocker |
|---|---|---|---|---:|---:|---|---|
| `anthropic` | `api-key` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `true` | `null` | `provider-real-evidence-not-present` |
| `openai` | `api-key` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `true` | `null` | `provider-real-evidence-not-present` |
| `openrouter` | `api-key` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `true` | `null` | `provider-real-evidence-not-present` |

### Platform profiles

| Profile | Status | Advertised |
|---|---|---:|
| `aws-eks-kata` | `pending-s4-s5-evidence-unadvertised` | `false` |
| `linux-kvm` | `authoritative-local-only-unadvertised` | `false` |
| `insecure-container` | `development-only-unadvertised` | `false` |
| `macos-vm-dev` | `development-only-unadvertised` | `false` |

### Unsupported capabilities and claims

| Capability | Status | Advertised | Evidence binding | Reason |
|---|---|---:|---|---|
| `subscription-oauth` | `unsupported-unadvertised` | `false` | `null` | `deferred-issue-13` |
| `production-daemon` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `user-ingress` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `session-sanitizer` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `apps` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `indexing-vector-search` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `gcp-production` | `unsupported-unadvertised` | `false` | `null` | `other-cloud-not-validated` |
| `azure-production` | `unsupported-unadvertised` | `false` | `null` | `other-cloud-not-validated` |
| `hetzner-production` | `unsupported-unadvertised` | `false` | `null` | `other-cloud-not-validated` |
| `other-cloud-production` | `unsupported-unadvertised` | `false` | `null` | `other-cloud-not-validated` |
| `general-availability` | `unsupported-unadvertised` | `false` | `null` | `release-not-established` |
| `compliance-certification` | `unsupported-unadvertised` | `false` | `null` | `compliance-not-claimed` |
| `grpc-credential-injection` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |
| `non-http-egress` | `unsupported-unadvertised` | `false` | `null` | `outside-mvp-scope` |

### Subscription OAuth blocker

| Status | Advertised | Release gate | Deferred issue | Worker refresh tokens |
|---|---:|---:|---:|---|
| `disabled-unadvertised` | `false` | `false` | `13` | `forbidden` |
<!-- END MACHINE-GENERATED SUPPORT CLAIMS -->

## Future authenticated principals and separation

The schema reserves nine stable roles. In this draft all principal identifiers and identity bindings are null, every `principal_id` and `identity_binding_sha256` field is null, and every state is `not-present-blocking`. Role labels are not identities, and the current ownership register does not satisfy independence.

- `independent-security-reviewer` must differ from `matrix-author`; current state: `blocked-identities-not-present`.
- `independent-security-reviewer` must differ from `evidence-producer`; current state: `blocked-identities-not-present`.
- `independent-security-reviewer` must differ from `campaign-operator`; current state: `blocked-identities-not-present`.
- `independent-security-reviewer` must differ from `campaign-approver`; current state: `blocked-identities-not-present`.
- `independent-security-reviewer` must differ from `zero-inventory-observer`; current state: `blocked-identities-not-present`.
- `campaign-operator` must differ from `campaign-approver`; current state: `blocked-identities-not-present`.
- `zero-inventory-observer` must differ from `campaign-operator`; current state: `blocked-identities-not-present`.
- `zero-inventory-observer` must differ from `campaign-approver`; current state: `blocked-identities-not-present`.

A future principal identifier must be authenticated and immutably bound. No separation is currently claimed. In particular, independent review and independently observed zero inventory remain blocked rather than inferred from role names.

## No evidence-reference surface in this draft

This provisional schema accepts no evidence-reference object, array, report, log, diagnostic, producer identity, approval, or run record. It does not extend or promote `security-report-v1alpha1` into Stage 5 release evidence.

A separate future authority must define a new schema **and reusable semantic validator** before any evidence can be attached. Every consumer must invoke that validator. At minimum it must:

- bind each criterion ID to the exact immutable source hash, profile, lane, evidence-contract category, accountable role, producer role, release-candidate binding, and authenticated principal/identity bindings;
- bind campaign criteria to a distinct authenticated approver, exact approved revision/scope, and exact campaign run;
- enforce reviewer/operator/approver/zero-inventory separation constraints;
- require exact criterion prefix/order and unique criterion IDs;
- reject duplicate evidence, conflicting results, stale source/artifact bindings, missing mandatory criteria, cross-profile substitution, and authority-domain promotion;
- define aggregate byte/item/property/string bounds and categorical diagnostics without inline reports, logs, prompts, source, or secrets.

Until that separate schema and semantic validator exist and are reviewed, all evidence remains absent and every criterion remains blocked.

## Finalization rule for a future authority

A future API-key-only decision remains blocked until:

1. S4-11 is accepted under its own future authority.
2. A clean source revision and immutable artifact root are bound.
3. All 35 mandatory/applicable criterion mappings have accepted evidence using their exact profile and future contract.
4. Anthropic, OpenAI, and OpenRouter each have separately bound real-provider evidence before any corresponding advertisement.
5. Stable authenticated principals exist and every separation constraint is proven.
6. Mandatory local, independent-review, approved-campaign, privacy/deletion, load, operations, cost, and independent zero-inventory evidence is accepted.
7. Subscription OAuth remains disabled/unadvertised and #13 remains deferred.
8. A distinct staff release decision publishes bounded support claims and residual risks.

Any missing, duplicate, stale, conflicting, failed, skipped, stubbed, uncertain, unbounded, or unauthenticated mandatory item keeps finalization and release eligibility false.

## Draft issue acceptance checklist

- [ ] Accept S4-11 under its future authority.
- [ ] Freeze and bind the exact release candidate.
- [ ] Bind authenticated principals and satisfy every separation constraint.
- [ ] Execute and independently review all 35 criterion mappings.
- [ ] Define the separate future evidence schema/semantic validator, then record separately approved campaign evidence.
- [ ] Obtain per-provider real evidence before advertising an API-key provider.
- [ ] Publish the future API-key-only staff decision and residual risks.

All checklist items remain open in this provisional draft.
