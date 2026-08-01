# Issue #363 draft — API-key-only Stage 5 release acceptance matrix

**Status:** draft and provisional; local/static requirements inventory only

**Current decision:** `matrix_finalized=false`, `release_eligible=false`, `go_no_go=not-available`

**Machine-readable draft:** [`stage5-api-key-release-matrix.draft.json`](../security-evidence/stage5-api-key-release-matrix.draft.json)

**Schema:** [`stage5-api-key-release-matrix-draft-v1.json`](../../schemas/stage5-api-key-release-matrix-draft-v1.json)

## Purpose and non-authority

Define the API-key-only Stage 5 release gate before a release candidate or Stage 5 campaign exists. This issue is specification work, not acceptance evidence. Its local tests establish only that the draft has the intended strict shape and fail-closed constants.

This draft does **not**:

- complete, accept, or infer S4-11 or any Stage 4 exit criterion;
- convert Stage 4 static preparation or teardown-order output into EKS evidence;
- authorize a campaign, provider/model request, deployment, cluster, or inventory operation;
- establish that any listed release requirement passed;
- authenticate a reviewer, campaign operator, evidence producer, artifact, or observation;
- finalize the matrix, make a go/no-go recommendation, or make Cogs release eligible.

S4-11 is a hard predecessor. This draft records it as `required-not-observed-by-this-draft`, with `stage4_exit_satisfied=false` and `evidence_accepted=false`. The merged Stage 4 static report and local teardown classifier remain disjoint, non-release authorities: their static assertions and digest bindings cannot satisfy S4-11. Only the future S4-11 authority may establish its result.

After S4-11 is accepted, Stage 5 still requires evidence bound to one frozen release candidate. S4-11 closure or acceptance alone cannot finalize this matrix or establish release eligibility.

## Fixed release boundary

The release scope is **API keys only**:

- organization/user API keys are resolved through the scoped trusted path and supplied as runtime auth;
- API-key values remain memory-only and absent from durable state, reports, and telemetry;
- subscription OAuth is disabled and absent from the advertised support matrix;
- Cogs workers cannot receive, persist, or refresh subscription refresh tokens;
- subscription OAuth remains deferred to #13 and is not a release blocker.

Enabling or advertising subscription OAuth invalidates this matrix. It requires the separate post-MVP broker, provider-terms decision, concurrency/revocation tests, review, and a new support declaration.

## Evidence separation rules

The three sections below are separate gates.

1. **Local tests** are repeatable release-candidate checks. A test run is not an independent review and cannot authorize a campaign.
2. **Independent review** examines exact source, artifacts, and evidence. A local assertion, digest, self-review, or schema-valid document does not prove review independence or acceptance.
3. **Separately approved campaigns** require fresh manual approval bound to the exact release-candidate revision, scope, spend, resource ceiling, expiry, operator, destroy path, and evidence plan. An approval is not execution evidence; execution evidence is not review acceptance; cleanup claims are not independent zero-inventory evidence.

No mandatory row may be satisfied by `stubbed`, `not-applicable`, an unapproved skip, extrapolation, or evidence from a different source revision. Failures and unknown outcomes remain failures or uncertainty until rerun under newly recorded authority. Evidence must retain redacted diagnostics and known limitations rather than converting uncertainty to pass.

## A. Local release-candidate tests

All rows are mandatory and currently `unexecuted-by-this-draft` / `not-observed-by-this-draft`.

| ID | Requirement | Minimum evidence required after S4-11 |
|---|---|---|
| `S5-L01.exact-release-candidate-binding` | Freeze one clean source revision; pin worker, sandbox, proxy, Kata/QEMU/kernel/OpenBao versions, image digests, and lockfiles. Prevent drift across evidence. | Exact source SHA, immutable image/artifact digests, version inventory, clean-tree assertion, and deterministic build/render records. |
| `S5-L02.unit-schema-api-pi-jsonl` | Run formatting, typecheck, unit, strict schema, API, policy, Pi embedding, hostile discovery, native JSONL, history, export, and Helm static checks. | Complete local test manifest and machine report bound to L01, with failures/skips retained. |
| `S5-L03.api-key-runtime-auth-and-redaction` | Prove API-key-only runtime auth for supported API-key providers, scoped retrieval, memory-only handling, and redacted errors/telemetry. | Positive fake/local auth flow plus negative missing/revoked/wrong-scope and durable/log/telemetry leakage checks. No external model call is part of this local row. |
| `S5-L04.oauth-disabled-unadvertised-refresh-token-denial` | Prove every release configuration and support document keeps subscription OAuth disabled/unadvertised and rejects worker refresh-token material. | Config/schema/launch/API negative tests, support-matrix scan, and durable-state/log scan; #13 remains deferred. |
| `S5-L05.trusted-worker-discovery-and-secret-confinement` | Re-run closed Pi loader canaries and trusted/untrusted boundary tests. | Evidence that no built-in host tool, extension, package, project code, guest path, session JSONL, model credential, integration credential, OpenBao identity, or CA private key crosses into the sandbox/trusted loader incorrectly. |
| `S5-L06.local-security-failure-and-privacy-regression` | Re-run applicable local Linux/KVM egress, audit/WAL, revocation, SSH/SFTP, resource-limit, failure, and telemetry privacy regressions. | Authoritative-local reports with real local dependencies where applicable; local authority remains non-EKS and cannot satisfy C01. |
| `S5-L07.supply-chain-sbom-vulnerability-license` | Build release artifacts reproducibly; generate SBOMs; run dependency, license, vulnerability, image-pin, lock-integrity, and secret scans. | Bound SBOM/scan reports, exception records with owner/expiry, image signatures or digest verification, and proof project dependencies cannot modify trusted packages. |
| `S5-L08.runbook-support-matrix-and-contract-drift` | Verify required operations documents, supported/unsupported matrix, API-key-only claims, residual risks, and automated-test links are complete and mutually consistent. | Documentation inventory and contract-drift test report; absent runbooks or overstated claims fail this row. |

Passing the draft-schema tests added by #363 satisfies none of L01–L08; those tests validate only this provisional inventory.

## B. Independently reviewed evidence

All rows require a reviewer authority bound to the exact L01 release candidate. They are currently `unperformed-by-this-draft` / `not-observed-by-this-draft`.

| ID | Review requirement | Required reviewed output |
|---|---|---|
| `S5-R01.exact-source-artifact-and-evidence-binding` | Verify source/artifact/evidence identity and reject stale, mixed-revision, unauthenticated, or promoted Stage 4 static artifacts. | Review record naming exact source and artifact digests, evidence inventory, reviewer identity/provenance mechanism, findings, and disposition. |
| `S5-R02.pi-loader-ssh-sftp-and-path-boundaries` | Review Pi resource loading/extension disabling, host-key verification, SSH channel handling, cancellation, path/symlink handling, and SFTP atomicity. | Findings report and verified resolutions bound to exact changed bytes. |
| `S5-R03.proxy-openbao-policy-audit-and-revocation` | Review CONNECT/TLS/HTTP normalization, header stripping, redirects, route presets, proxy capability scope, OpenBao policy/PKI, audit fail-closed behavior, and connection draining. | Findings report, parser/credential threat analysis, and verified resolutions. |
| `S5-R04.kata-kubernetes-identity-network-and-storage` | Review guest image/Kata configuration, no-fallback behavior, service-account mounts, workload identity, NetworkPolicies/CNI expectations, node separation, PVC isolation, and lifecycle limits. | Findings report cross-referenced to authoritative S4-11 and Stage 5 campaign evidence, without promoting static shapes. |
| `S5-R05.privacy-deletion-oauth-and-support-claims` | Review telemetry/log/report fields, deletion/retention/export behavior, API-key-only support text, disabled OAuth, #13 deferral, and residual-risk wording. | Privacy/support review with exact inspected sinks and explicit unknowns. |
| `S5-R06.findings-resolution-no-critical-or-high` | Triage all independent security and supply-chain findings. | No unresolved critical/high finding; lower findings have explicit owner, decision, expiry/review date, and public-risk impact. A risk acceptance cannot relabel an unexecuted security test as pass. |
| `S5-R07.residual-risk-and-go-no-go-review` | Review the final evidence inventory, supported AWS matrix, tested concurrency, cost, teardown, known risks, and proposed staff recommendation. | Signed/otherwise authenticated review decision. The future staff go/no-go remains separate; this draft supplies neither. |

## C. Separately approved Stage 5 campaigns

Each row requires its own `separate-exact-revision-manual-approval`. This draft contains no approval and observes no execution. Campaigns may start only after accepted S4-11 evidence and a frozen L01 candidate. They must use synthetic repositories/credentials, bounded spend/resources/time, stop on failure or cleanup uncertainty, and destroy resources afterward.

| ID | Campaign requirement | Acceptance evidence required |
|---|---|---|
| `S5-C01.eks-release-candidate-full-conformance` | Run every mandatory `DESIGN.md` acceptance test on the frozen EKS/Kata release candidate with real applicable CNI, identity, OpenBao, authz/WAL, proxy, OTLP, storage, and runtime dependencies. | Authoritative production-profile reports with no mandatory stub/skip/not-applicable; exact component/image digests; full known-limitations record. |
| `S5-C02.api-key-real-model-sample` | Run only a small, separately budgeted representative real-model sample using authorized runtime API keys. No subscription OAuth. | Redacted provider/model compatibility, auth-failure, latency, usage, and leakage evidence. Infrastructure saturation uses mocked models instead. |
| `S5-C03.performance-cold-start-and-resource-classes` | Measure scheduled-to-SSH-ready and first-tool p50/p95/p99, Git/build/proxy/storage overhead, all three resource classes, limits, idle shutdown, and recycle. | Raw bounded measurements and methodology; under-30-second agreed percentile or reviewed exception/plan. |
| `S5-C04.scale-10` | Run 10 active real sandboxes and verify stability, telemetry, cleanup, and cost. | Per-step resource/startup/error/backlog/cost report and zero-residue result. |
| `S5-C05.scale-25` | Run only after C04 acceptance and a fresh approval. | Same evidence set as C04, preserving all degraded or unknown outcomes. |
| `S5-C06.scale-50` | Run only after C05 acceptance and a fresh approval. Fifty passing real sandboxes are the minimum release gate. | Same evidence set as C04 plus the maximum support claim capped at the highest accepted real load. |
| `S5-C07.scale-100-if-advertised` | Conditional: required only to advertise support above 50 and through 100; run after C06 under separate approval. | Accepted 100-real-sandbox evidence. Extrapolation is not evidence. |
| `S5-C08.scale-250-if-advertised` | Conditional: required only to advertise support above 100 and through 250; run after C07 under separate approval. | Accepted 250-real-sandbox evidence. Extrapolation is not evidence. |
| `S5-C09.multi-user-isolation-and-writer-leases` | Validate four-session defaults, distinct-project concurrency, same-project exclusive writer lease, resource classes, and cross-user storage/skill/proxy/history/telemetry denial. | Positive and negative multi-session records at real EKS/Kata boundaries. |
| `S5-C10.destructive-reliability-and-recovery` | Inject worker/sandbox/proxy/node/storage/OpenBao/OTLP/WAL/disk/SSE/JSONL/Git/skill failures and revocation during long-lived traffic. | Outcomes matched to `DESIGN.md`; unknown prompt outcomes are not replayed or converted to success. |
| `S5-C11.privacy-deletion-retention-backup-and-export` | Inspect all central sinks and test deletion, object versions, legal hold separation, 30-day default retention, backup, authenticated raw export, and attachment exclusion. | Sink inventory and redacted inspection results; complete deletion/export records and explicit backend assumptions. |
| `S5-C12.install-upgrade-incident-teardown-and-cost` | Exercise install, upgrade, incident, drain/recycle, destroy, orphan detection, and cost accounting. | Runbook execution records, cost report, campaign-owned cleanup record, and separately produced read-only zero-resource inventory. The local Stage 4 teardown classifier cannot supply this inventory. |

## Finalization rule for a future authority

This draft is intentionally incapable of becoming final or release eligible. A future, separately reviewed contract/evidence authority may issue a decision only when all of the following are established for one exact release candidate:

1. S4-11 is accepted by its proper future authority and all Stage 4 dependencies are closed without promoting static/local classifier output.
2. L01–L08 have passing accepted evidence.
3. R01–R07 have independently authenticated review evidence and no unresolved critical/high finding.
4. Mandatory C01–C06 and C09–C12 have separately approved, passing, real-dependency evidence and complete teardown/cost evidence.
5. C07/C08 are accepted only when needed for the advertised concurrency; the advertised maximum does not exceed the highest accepted real load.
6. Subscription OAuth remains disabled/unadvertised, refresh tokens remain forbidden in workers, and #13 remains deferred.
7. The staff engineer issues a documented API-key-only go/no-go recommendation with residual risks and evidence links.

Any missing, failed, stale, conflicting, skipped, stubbed, uncertain, or unauthenticated mandatory evidence keeps finalization and release eligibility false. A future decision must use a new authority/schema; editing this draft's fixed `false` fields is invalid.

## Draft issue acceptance checklist

- [ ] Confirm the requirement IDs and wording after S4-11 is accepted.
- [ ] Bind the matrix to the frozen Stage 5 release candidate and evidence formats.
- [ ] Obtain independent review of the finalized matrix.
- [ ] Record separate campaign approvals; do not infer them from this issue or S4-11.
- [ ] Execute and review mandatory local and campaign evidence.
- [ ] Publish the API-key-only final report and explicit residual risks.

All checklist items remain open in this provisional draft.
