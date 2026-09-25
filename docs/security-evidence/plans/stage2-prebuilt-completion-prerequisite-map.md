# Stage 2 prebuilt completion prerequisite map

Status: binding non-AWS implementation map for Issue #42

This map supersedes the readiness conclusion, but not the historical facts or no-AWS boundary, of ADR 0266. ADR 0357 retires the failed timeout-corrected H/G/Q generation; ADR 0360 additionally retires the host-scoped generation; ADR 0364 retires stale-binding H `6d2eff8ffa8fe525b5566a0ddded7d79e868ba16`, G `c075458cf2d853200df57584c1b16cf38bd6e38c`, Q `f75d3f09990de4635cc3890efe0f5f6e783312bd`, their supply-chain observations, and failed preflight `35946454149`. ADR 0365 additionally retires premature-producer H `56fdd694c1a0c6967bf09156d44260f18a28888d`, producer run `35957236430`, and artifact `10791707159`; it authorizes only a replacement H followed by a producer after all exact-main checks complete. No old H, G, Q, run, or artifact may be mutated or retroactively blessed. The seven subordinate cycle artifacts from failed qualification `35685410662` remain diagnostic only. A passing local or diagnostic result cannot authorize AWS activity or close Issue #42.

## Global observation rules

Every authoritative observation is first-created, attempt 1, exact-head, non-retried, and pass-only. Failure, cancellation, diagnostics, stale inputs, missing artifacts, uncertain cleanup, and replacement runs grant no claim. Recovery is cleanup-only. H precedes independently produced G. Host boot, operation, rootfs, key, state, instance, resource, grant, receipt, status, and artifact identities retain their global freshness rules. PID/device/inode-derived QEMU runtime, live-mapping, and process-fact observations are unique within their host-boot scope; equal raw values on distinct boots are not replay. Before source effects, every GitHub-hosted static, preflight, and qualification host authenticates its assigned `ubuntu24` image against the exact official `actions/runner-images` release and tag ref. Different authenticated rollout versions may coexist; missing, malformed, draft, mismatched, or unofficial records fail closed. The old dual-build report remains immutable historical evidence and is not evidence of prebuilt consumption.

## Acceptance map

| Requirement | Producer/effect owner | Independent observer | Canonical evidence | Validator / rejection rule |
|---|---|---|---|---|
| One production rootfs is built twice and published once | Qualification-only rootfs producer; isolated trusted publisher | Equality/pin checker and immutable-object GET readback | Producer receipt, publication receipt, descriptor, canonical ustar/manifest/metadata identities | Reject unequal builds, wrong V2 pins, mutable coordinate, publisher authority in H job, uncertain create, missing exact readback, expiry-only storage |
| Every lifecycle consumes the prebuilt rootfs without rebuilding | Fixed descriptor issuer in G; transport-neutral verifier; one importer | Static no-build call-graph control, import postwalk, lease observer | Descriptor digest, acquisition/import receipt, rootfs ledger/reference, local/cycle receipt | Reject caller selection, alternate URL, original-16-input consumer authority, build/fallback/retry, host tar/extractall, unsupported format, package drift |
| Artifact custody survives interruption and leaves no residue | Acquisition/import/lease owners | Fresh descriptor/generation checks and final residue observer | Durable intents/settlements, recovery receipt, artifact/import residue domains | Preserve foreign/replaced/uncertain state; reject path-only ownership, unsafe cleanup, in-memory-only recovery authority |
| Seven independent campaigns execute in order across one fixed two-job generation | Phase-one controller: ordinals 1–3; authenticated phase-two controller: ordinals 4–7 | Signed current-run continuation admission, batch reducer, and typed provider/remote receipts | v6 approval, phase-one continuation and Cosign bundle, root-owned admission, controller journal, seven ordered cycle receipts | Reject overlap, retry, replacement, ordinal/mode drift, direct in-memory handoff, replay/stitching, shared state lineage, forward recovery, or common-binding drift |
| Repeated cold boot and authenticated SSH-ready p50/p95 | Per-cycle instance and fixed full/readiness owner | Provider running observer and authenticated remote owner | Seven launch samples, seven SSH-ready samples, summary projection | Require seven independent create/measure/destroy cycles; reject warm samples or unauthenticated readiness |
| Git, package build, and representative workload measurements | Full-cycle guest owner | Authenticated SSH/workload receipt issuer | Seven Git, seven package, seven representative workload measurements | Exactly 21 measurements in the full cycle; no within-observation retry |
| CPU/filesystem overhead, idle memory, bounded density | Historical accepted measurement producer unless semantics change | Existing validators and retained campaign-8 evidence | Historical campaign-8 report cited by final report | Do not rerun merely for duplication; reject reinterpretation beyond accepted scope |
| Destroy and prove zero after every cycle | State-bound destroy owner | Independent read-only account/region inventory observer | Seven destroy receipts and seven detailed zero-inventory receipts | Require complete pagination, baseline reconciliation, fresh observer/session, no next plan before zero |
| Prove one distinct final zero observation | Final inventory owner after cycle 7 | Fresh independent read-only observer | Typed eighth final inventory receipt, not only a commitment | Reject observer/session/run reuse, pre-cycle-7 ordering, incomplete pagination, or missing categories |
| Inventory covers all Issue #42 resource classes | Inventory adapter | Schema/category reconciliation | EC2, EBS, ENI public addresses, Elastic IPs, security groups, IAM campaign resources, schedules, and related-resource rows | Reject tag-only or partial account inventory, omitted categories, extras, unstable reads |
| Bind one AMI and artifact set across the batch | Read-only discovery plus exact approval and plan owners | Per-plan and post-launch identity observers | Resolved AMI, H/G, source, runtime, rootfs descriptor, fixture, schema/workflow commitments | Reject moving SSM parameter authority during the batch or any per-cycle drift |
| Record actual campaign duration and bounded cost | Controller clock observations and typed provider receipts | Evidence validator recomputation | First-apply through final-zero elapsed duration; separate per-cycle/billable sums and price lock | Reject summed cycle duration presented as wall time, missing gaps/final inventory, ungrounded rate or cost |
| Export redacted machine and human reports | Pass-only v4 evidence issuer after authenticated phase two; deterministic v4 renderer | Schema validator, handoff/custody verifier, upload/readback observer | Canonical v4 machine report, deterministic v4 human report, v2 publication receipt, v3 upload receipt | No manual assembly; reject diagnostic/failure/uncertainty publication, unbound handoff claims, non-deterministic projection, or missing continuation custody |
| Evidence contains no credentials, source, prompts, or secrets | Bounded typed receipt projection | Independent redaction/secret scan | Redaction verdict bound into final package | Reject raw command output, locals/arguments, secret material, source bytes, prompts, forbidden identifiers |
| Issue closure reflects truth | Final acceptance reviewer | Live GitHub state check | Evidence-to-acceptance index and Issue #42 attachments | Keep OPEN until all AWS acceptance rows pass; closure grants no Stage 4 authority |

## Required production call graph

```text
qualification producer: 16 fixed inputs -> build A + build B -> equality/pins
  -> one canonical ustar -> isolated immutable publication -> exact readback -> descriptor

consumer: authenticated G descriptor -> external acquisition -> fixed private custody
  -> transport-neutral verification/preflight -> one fd-relative materialization/postwalk
  -> existing RetainedRootfsLease -> unchanged Kata/QMP/network/SSH/workload/teardown

campaign: exact v6 approval -> fixed phase one [full, readiness, readiness]
  -> destroy/independent zero after each -> retire job-1 credentials
  -> canonical signed credential-free continuation + exact artifact readback
  -> same-run root-authenticated admission -> private sealed phase-two capability
  -> fixed phase two [readiness x4] with fresh executor/observer sessions
  -> destroy/independent zero after each -> distinct final zero
  -> same-process full candidate -> pass-only v4 machine/human publication
```

Production consumer reachability to the 16-input builder, mutable tags, alternate mirrors, fallback, or retry is forbidden. Network credentials and downloads remain outside the privileged rootfs/Kata lifecycle. A staged blob becomes authority only through authenticated descriptor custody and exact verifier/importer receipt.

## Pre-H gates

1. Close the descriptor, durable-store, provenance, publication-isolation, no-fallback, and evidence-version contracts.
2. Implement the entire non-AWS production-shaped graph, including real cycle capabilities, controller ports, final inventory receipt, duration, AMI/artifact binding, and evidence issuer, without cloud effects.
3. Pass portable hostile descriptor/blob/tar/call-graph/controller tests.
4. Pass native Linux acquisition/import/recovery and exact residue tests.
5. Preserve the already completed no-mint KVM rehearsal facts for the real full and readiness owner routes; the bounded host-boundary correction does not turn the later AWS diagnostic into formal evidence or require another seven-cycle AWS rehearsal.
6. Obtain protected exact-head validation and a clean whole-graph readiness review of the corrected source. Any later implementation change invalidates that review.

The first H from those gates is terminal because its producer began before fresh exact-main checks completed. Replacement H `ba085947eaee321dfb724d94169d42bc36d397b0` passed protected review and fresh exact-main checks before sole producer `35990583990` / artifact `10804234912` began. Only after independent producer acceptance did ADR 0366 establish sole-child G `c37baf5c1fbb8f1e335945ad7ac93452d4537c9d`, followed by sole publisher `36006546962` / artifact `10810159633` and sole static observation `36008194540` / artifact `10811168115`. That static observation passed and was independently accepted before protected Q `2d4b61a63cdb08a92d5fbde9095532fad2383e90`, whose sole parent is G. Q binds all three run/artifact custody generations, their archive digests, the accepted 13-member static package and control digest `28ea28ef436623f202f056638ad712ed885ed1d121ecf1eb314f7c41b1a76555`, source manifest `cf15e437888f7c1c2808e113576d3592bef40e39c9a88db199f0ca6a38986bb9`, descriptor `88b33740b2782240c894a8b1abf0988f5e65e0343cfda3cb1811affe1e8ca615`, and reviewed source/workflow hashes.

Sole mixed preflight `36035076262` and sole seven-host qualification `36036544983` passed attempt one and were independently accepted. Qualification artifact `10829051963`, archive `sha256:372c0a9ba454d1789eb2299495a58426190127548f4437c0be9f4746321a4fc2`, contains only the accepted V6 package and V2 custody member. The static envelope remains additive V4, each cycle status remains additive V3, and historical V3/V2/V5 contracts remain immutable. No failed generation can be retried into authority.

## AWS boundary

ADR 0368 accepted the replacement qualification and established protected planning-control revision R `727636d61207903744aba52cb6a2325e92f13f8b`. R's sole planning run `36096732289`, attempt one, failed deterministically while producing its first plan because the required ten-hour campaign expiry was rejected by stale strict eight-hour OpenTofu and canonical-plan validators. It published zero artifacts; no downstream workflow or resource effect occurred; exact inventory remained zero; and the temporary planning role and variable were removed. The run is terminal and cannot be retried, stitched, resumed, salvaged, or reused.

ADR 0369 permits only a protected direct-child source correction aligning those two validators to the existing strict ten-hour planner and campaign contract. It preserves exact H, G, Q, qualification `36036544983`, artifact `10829051963`, the accepted static package, and every effect, cleanup, cost, identity, evidence, and authorization bound. The correction source grants no AWS authority. Any future bounded IAM/OIDC bootstrap and planning require separate explicit authorization, a fresh zero-resource baseline, and exactly one first-created attempt-one planning run under the new protected revision; no byte or authority from `36096732289` may be consumed.

Independent acceptance of all seven fresh plans is required before one plan-bound signed V6 approval and exactly one attempt-one, two-job seven-cycle execution batch with at least 32,400 actual seconds remaining before production credentials. Each executor and observer assumption uses one bounded root-staged OIDC/STS helper that samples every applicable deadline immediately before its single STS request, retains at least 900 seconds of expiry margin, and rejects a returned expiration outside the campaign runway; the entire helper must complete within 10 minutes. Before the authorized run, both role definitions must have `MaxSessionDuration >= 30600`; reducing that prerequisite cannot be compensated by workflow timeouts. The diagnostic route emits only a non-authoritative diagnostic receipt and cannot satisfy any acceptance row. Failure, retry, mismatch, uncertain cleanup, or unexpected inventory is terminal and permits cleanup only; Stage 4 remains separate and non-authorized.
