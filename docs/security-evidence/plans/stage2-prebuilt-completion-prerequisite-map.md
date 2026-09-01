# Stage 2 prebuilt completion prerequisite map

Status: binding non-AWS implementation map for Issue #42

This map supersedes the readiness conclusion, but not the historical facts or no-AWS boundary, of ADR 0266. It must be satisfied before implementation H is frozen. A passing local result cannot authorize AWS activity or close Issue #42.

## Global observation rules

Every authoritative observation is first-created, attempt 1, exact-head, non-retried, and pass-only. Failure, cancellation, diagnostics, stale inputs, missing artifacts, uncertain cleanup, and replacement runs grant no claim. Recovery is cleanup-only. H precedes independently produced G. The old dual-build report remains immutable historical evidence and is not evidence of prebuilt consumption.

## Acceptance map

| Requirement | Producer/effect owner | Independent observer | Canonical evidence | Validator / rejection rule |
|---|---|---|---|---|
| One production rootfs is built twice and published once | Qualification-only rootfs producer; isolated trusted publisher | Equality/pin checker and immutable-object GET readback | Producer receipt, publication receipt, descriptor, canonical ustar/manifest/metadata identities | Reject unequal builds, wrong V2 pins, mutable coordinate, publisher authority in H job, uncertain create, missing exact readback, expiry-only storage |
| Every lifecycle consumes the prebuilt rootfs without rebuilding | Fixed descriptor issuer in G; transport-neutral verifier; one importer | Static no-build call-graph control, import postwalk, lease observer | Descriptor digest, acquisition/import receipt, rootfs ledger/reference, local/cycle receipt | Reject caller selection, alternate URL, original-16-input consumer authority, build/fallback/retry, host tar/extractall, unsupported format, package drift |
| Artifact custody survives interruption and leaves no residue | Acquisition/import/lease owners | Fresh descriptor/generation checks and final residue observer | Durable intents/settlements, recovery receipt, artifact/import residue domains | Preserve foreign/replaced/uncertain state; reject path-only ownership, unsafe cleanup, in-memory-only recovery authority |
| Seven independent campaigns execute in order | Production controller: full ordinal 1, readiness ordinals 2–7 | Batch reducer and typed provider/remote receipts | Approval, controller journal, seven ordered cycle receipts | Reject overlap, retry, replacement, ordinal/mode drift, shared state lineage, forward recovery, common-binding drift |
| Repeated cold boot and authenticated SSH-ready p50/p95 | Per-cycle instance and fixed full/readiness owner | Provider running observer and authenticated remote owner | Seven launch samples, seven SSH-ready samples, summary projection | Require seven independent create/measure/destroy cycles; reject warm samples or unauthenticated readiness |
| Git, package build, and representative workload measurements | Full-cycle guest owner | Authenticated SSH/workload receipt issuer | Seven Git, seven package, seven representative workload measurements | Exactly 21 measurements in the full cycle; no within-observation retry |
| CPU/filesystem overhead, idle memory, bounded density | Historical accepted measurement producer unless semantics change | Existing validators and retained campaign-8 evidence | Historical campaign-8 report cited by final report | Do not rerun merely for duplication; reject reinterpretation beyond accepted scope |
| Destroy and prove zero after every cycle | State-bound destroy owner | Independent read-only account/region inventory observer | Seven destroy receipts and seven detailed zero-inventory receipts | Require complete pagination, baseline reconciliation, fresh observer/session, no next plan before zero |
| Prove one distinct final zero observation | Final inventory owner after cycle 7 | Fresh independent read-only observer | Typed eighth final inventory receipt, not only a commitment | Reject observer/session/run reuse, pre-cycle-7 ordering, incomplete pagination, or missing categories |
| Inventory covers all Issue #42 resource classes | Inventory adapter | Schema/category reconciliation | EC2, EBS, ENI public addresses, Elastic IPs, security groups, IAM campaign resources, schedules, and related-resource rows | Reject tag-only or partial account inventory, omitted categories, extras, unstable reads |
| Bind one AMI and artifact set across the batch | Read-only discovery plus exact approval and plan owners | Per-plan and post-launch identity observers | Resolved AMI, H/G, source, runtime, rootfs descriptor, fixture, schema/workflow commitments | Reject moving SSM parameter authority during the batch or any per-cycle drift |
| Record actual campaign duration and bounded cost | Controller clock observations and typed provider receipts | Evidence validator recomputation | First-apply through final-zero elapsed duration; separate per-cycle/billable sums and price lock | Reject summed cycle duration presented as wall time, missing gaps/final inventory, ungrounded rate or cost |
| Export redacted machine and human reports | Pass-only evidence issuer; deterministic human renderer | Schema validator, custody verifier, upload/readback observer | Canonical machine report, deterministic human report, upload receipt | No manual assembly; reject failure/uncertainty publication, unbound claims, non-deterministic projection |
| Evidence contains no credentials, source, prompts, or secrets | Bounded typed receipt projection | Independent redaction/secret scan | Redaction verdict bound into final package | Reject raw command output, locals/arguments, secret material, source bytes, prompts, forbidden identifiers |
| Issue closure reflects truth | Final acceptance reviewer | Live GitHub state check | Evidence-to-acceptance index and Issue #42 attachments | Keep OPEN until all AWS acceptance rows pass; closure grants no Stage 4 authority |

## Required production call graph

```text
qualification producer: 16 fixed inputs -> build A + build B -> equality/pins
  -> one canonical ustar -> isolated immutable publication -> exact readback -> descriptor

consumer: authenticated G descriptor -> external acquisition -> fixed private custody
  -> transport-neutral verification/preflight -> one fd-relative materialization/postwalk
  -> existing RetainedRootfsLease -> unchanged Kata/QMP/network/SSH/workload/teardown

campaign: exact approval -> controller -> [full, readiness x6]
  -> fresh state/instance -> fixed consumer -> typed remote receipt
  -> destroy -> independent zero -> next cycle -> distinct final zero
  -> pass-only machine/human publication
```

Production consumer reachability to the 16-input builder, mutable tags, alternate mirrors, fallback, or retry is forbidden. Network credentials and downloads remain outside the privileged rootfs/Kata lifecycle. A staged blob becomes authority only through authenticated descriptor custody and exact verifier/importer receipt.

## Pre-H gates

1. Close the descriptor, durable-store, provenance, publication-isolation, no-fallback, and evidence-version contracts.
2. Implement the entire non-AWS production-shaped graph, including real cycle capabilities, controller ports, final inventory receipt, duration, AMI/artifact binding, and evidence issuer, without cloud effects.
3. Pass portable hostile descriptor/blob/tar/call-graph/controller tests.
4. Pass native Linux acquisition/import/recovery and exact residue tests.
5. Publish and read back a non-authoritative candidate artifact, then pass one no-mint KVM rehearsal through both real full and readiness owner routes.
6. Obtain a clean whole-graph readiness review. Any implementation change invalidates that review and rehearsal.

Only then may one implementation H be designated. Exact H produces the twice-built artifact; an isolated publisher reads it back; independently produced G binds H and the artifact descriptor. One mixed preflight/static observation and one seven-sample formal qualification may then run. A failed formal run requires a new generation after private diagnosis; it cannot be retried into authority.

## AWS boundary

After the corrected package is frozen, stop. Separate authorization is required first for bounded read-only AWS discovery/planning and later for exactly one seven-cycle execution batch. No credential use, provider/OpenTofu effect, SSM command, deployment, inventory query, campaign, or AWS cleanup is authorized by this map.
