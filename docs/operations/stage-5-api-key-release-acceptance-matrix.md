# Issue #363 draft — API-key-only Stage 5 release acceptance matrix

**Status:** draft and provisional; local/static requirements inventory only

**Current decision:** `matrix_finalized=false`, `release_eligible=false`, `go_no_go=not-available`

**Machine-readable draft:** [`stage5-api-key-release-matrix.draft.json`](../security-evidence/stage5-api-key-release-matrix.draft.json)

**Schema:** [`stage5-api-key-release-matrix-draft-v1.json`](../../schemas/stage5-api-key-release-matrix-draft-v1.json)

## Purpose and non-authority

This draft defines the API-key-only Stage 5 gate without supplying evidence or authority. S4-11 is a hard predecessor and remains `required-not-observed-by-this-draft`; `stage4_exit_satisfied=false` and `evidence_accepted=false`. Stage 4 static preparation and teardown-order outputs remain disjoint local authorities and cannot satisfy S4-11.

Every authority-bearing field is false. The release-candidate source revision, artifact root, immutable binding, principal identities, identity bindings, criterion evidence bindings, provider evidence bindings, and evidence references are null or empty and explicitly blocking. Schema validity proves only bounded inventory consistency. It authenticates no person or artifact, grants no approval, observes no cloud or provider execution, and establishes no release, production, GA, or compliance result.

Finalization requires a new authority/schema after accepted S4-11 and later evidence bound to one frozen release candidate. This draft cannot be edited into a release verdict.

## Criterion-level traceability

The matrix contains **35 immutable criterion mappings**: all 22 numbered criteria in `DESIGN.md` section 24 and all 13 checkboxes in `IMPLEMENTATION.md` section 45. Each row has a source locator and full source-text SHA-256 in the JSON, accountable role, exact profile, evidence lane and future digest-reference contract, dependencies, current blocker, and applicability. All rows remain `unexecuted-by-this-draft`, have null principal/evidence bindings, and are not release eligible.

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

## API-key provider claim matrix

The explicit conservative provider set follows the implemented generic Pi runtime API-key path and the design's continuously tested target set. These are **provisional candidates**, not current release advertisements. Each provider needs its own future real-provider sample and immutable evidence binding before it may appear in an advertised support decision; one representative sample cannot cover the set.

| Provider | Implemented path state | Decision now | Advertised now | Future gate |
|---|---|---|---:|---|
| `anthropic` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `provider-real-evidence-not-present`; one future real-provider evidence binding is required before any advertisement |
| `openai` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `provider-real-evidence-not-present`; one future real-provider evidence binding is required before any advertisement |
| `openrouter` | `generic-runtime-key-path-present-provider-not-release-validated` | `provisional-candidate` | `false` | `provider-real-evidence-not-present`; one future real-provider evidence binding is required before any advertisement |

Subscription OAuth is separately fixed to `disabled-unadvertised`, workers are forbidden from receiving refresh tokens, and #13 remains deferred outside this API-key release gate.

## Platform and unsupported claim matrix

`aws-eks-kata` is pending S4/S5 evidence and unadvertised. `linux-kvm` remains authoritative-local only. `insecure-container` and `macos-vm-dev` remain development-only. None is a current release claim.

The following capabilities and claims are explicitly unsupported and unadvertised in this draft:

| Capability or claim | Status | Advertised | Reason |
|---|---|---:|---|
| `subscription-oauth` | `unsupported-unadvertised` | `false` | `deferred-issue-13` |
| `production-daemon` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `user-ingress` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `session-sanitizer` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `apps` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `indexing-vector-search` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `gcp-production` | `unsupported-unadvertised` | `false` | `other-cloud-not-validated` |
| `azure-production` | `unsupported-unadvertised` | `false` | `other-cloud-not-validated` |
| `hetzner-production` | `unsupported-unadvertised` | `false` | `other-cloud-not-validated` |
| `other-cloud-production` | `unsupported-unadvertised` | `false` | `other-cloud-not-validated` |
| `general-availability` | `unsupported-unadvertised` | `false` | `release-not-established` |
| `compliance-certification` | `unsupported-unadvertised` | `false` | `compliance-not-claimed` |
| `grpc-credential-injection` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |
| `non-http-egress` | `unsupported-unadvertised` | `false` | `outside-mvp-scope` |

This excludes a production daemon, user ingress, session sanitizer, apps, indexing/vector search, GCP/Azure/Hetzner or other-cloud production support, general availability, compliance certification, subscription OAuth, gRPC credential injection, and non-HTTP egress. Contradictory affirmative wording is a contract-test failure.

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

## Bounded digest-only evidence references

This draft contains zero evidence references and cannot accept one. Its schema defines the future reference shape separately so later evidence work starts fail-closed without changing the old `security-report-v1alpha1` contract or treating that older report as release evidence.

The Stage 5 reference is digest-only and permits no inline report, log, prompt, source, secret, arbitrary diagnostic, URL, or path. It requires criterion ID, artifact SHA-256, declared bytes, bounded media type, future evidence-contract category, exact profile, source revision, release-candidate binding digest, authenticated producer role/principal/binding, result, and categorical diagnostic code.

Bounds are:

- matrix JSON: at most 262,144 bytes;
- future references: at most 64;
- declared aggregate: at most 16,777,216 bytes;
- each referenced artifact: at most 262,144 bytes;
- each reference: exactly 13 required properties and no unknown property;
- bounded principal string: at most 128 characters;
- diagnostics: categorical only.

The `64 × 262,144` per-item envelope equals the aggregate maximum. Artifact bytes remain external; a digest does not establish truth, provenance, identity, or acceptance.

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
- [ ] Record separate campaign approvals and bounded digest-only evidence.
- [ ] Obtain per-provider real evidence before advertising an API-key provider.
- [ ] Publish the future API-key-only staff decision and residual risks.

All checklist items remain open in this provisional draft.
