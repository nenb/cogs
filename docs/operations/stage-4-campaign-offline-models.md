# Stage 4 campaign and exit-review offline models

This document describes the preserved **historical Stage 4 campaign-model v1** schemas and fixtures. Their deliberately absent fields and blocked semantics are immutable snapshots; current successor-readiness facts do not mutate or promote them. Issues #358 through #362 remain **open and blocked**. Neither a valid draft nor a terminal local model result can close an issue or become campaign evidence or an exit decision.

No AWS/provider operation, OpenTofu init/plan/apply, SSM operation, EKS or Kubernetes API access, `kubectl`, Helm install/apply, deployment, external-model call, network discovery, current price/quota discovery, or inventory operation is exposed or performed. Upstream NIC is unchanged. Every verdict fixes execution authority, provider/Kubernetes truth, retry authority, Stage 4 exit, and release eligibility to false.

## #358: historical v1 absent/unapproved approval-envelope draft

The strict draft and verdict schemas are:

- [`stage4-campaign-approval-draft-v1.json`](../../schemas/stage4-campaign-approval-draft-v1.json);
- [`stage4-campaign-approval-verdict-v1.json`](../../schemas/stage4-campaign-approval-verdict-v1.json); and
- pure classifier [`stage4-campaign-approval.ts`](../../scripts/stage4-campaign-approval.ts).

The deterministic fixture is [`approval-draft-blocked-v1.json`](../../test/fixtures/stage4-campaign/approval-draft-blocked-v1.json). The following are historical v1 semantics, not statements of current successor-readiness state; this is deliberately the only state representable by that v1 draft authority:

- #42 repeated-measurement, destruction-report, and final-zero-inventory evidence is absent;
- S4-06 acceptance evidence is absent;
- the downstream campaign issue and attempt identifier are unnamed/absent;
- approval and approval evidence are absent/unapproved;
- campaign operator, campaign approver, budget approver, security/evidence reviewer, and independent zero-inventory observer bindings are absent;
- exact source, source inventory, plan, render, and runtime artifact bindings are absent;
- account, region, and instance-type bindings are absent;
- resource graph/caps, budget/current-price/current-quota evidence, expiry/duration/TTL, destroy path/state binding, and independent inventory procedure/scope/observer are absent or unapproved; and
- `attempt_number=1`, `maximum_attempts=1`, `retry=prohibited`, and `execution_authorized=false` are immutable.

Supplying a digest, identity, account, budget, expiry, destroy path, inventory claim, second attempt, approval, or execution authority is rejected. Issue #42 later closed under a separate exact historical closure record; that fact does not mutate this blocked v1 draft into an approval.

## #359–#361: campaign plan and claimed-evidence state models

The common strict schemas and pure driver are:

- [`stage4-campaign-plan-v1.json`](../../schemas/stage4-campaign-plan-v1.json);
- [`stage4-campaign-evidence-v1.json`](../../schemas/stage4-campaign-evidence-v1.json);
- [`stage4-campaign-model-verdict-v1.json`](../../schemas/stage4-campaign-model-verdict-v1.json); and
- [`stage4-campaign-model.ts`](../../scripts/stage4-campaign-model.ts).

Each plan is one-attempt-only, unapproved, and non-executable. It binds exact digest references for source revision, bounded source inventory, offline-readiness package, #358 blocked draft, campaign profile, and artifact manifest. A domain-separated artifact-set root covers those references. Domain-separated campaign and attempt identities then bind the exact issue, artifact root, approval draft, and immutable attempt number. Each evidence model must reproduce both identities before its exact plan digest and artifact-set root are considered. The plan fixtures use deterministic synthetic offline digest references (apart from their real binding to the checked #358 fixture); they do not claim an authenticated campaign revision or artifact provenance and must be replaced under a future reviewed source-selection authority. Mixed plans, stale roots, digest replay, unknown fields, authority promotion, retry counters, and executor/provider surfaces fail closed without returning semantic digests for the rejected document.

The issue-specific qualification orders are fixed:

- **#359 / S4-08:** source/render/object binding; launch-template nested KVM; active Kata/KVM with distinct guest and no runc/TCG fallback; EBS workspace/session lifecycle; exclusive-writer and forced-loss behavior; runtime/object cleanup behavior.
- **#360 / S4-09:** admitted real dependencies; guest-root IPv4/IPv6/UDP/QUIC/DNS denial; API/metadata/admin/cross-session/storage denial; no Kubernetes/cloud/OpenBao/integration/model/CA-key material; Stage 3 scenario on Kata/EBS/OpenBao/OTLP; separately authorized API-key samples.
- **#361 / S4-10:** startup p50/p95/p99; first-tool; storage attach; cold pulls/scale; idle; Git/build; proxy; recycle; under-30-second agreed percentile or reviewed exception; worker/sandbox/proxy/node/OpenBao/OTLP/storage/WAL/policy/recycle failure cases with no prompt replay; bounded cost/capacity observations with no support extrapolation.

Every path then requires exactly:

```text
stop -> destroy -> independent-inventory
```

A qualification failure skips only the remaining qualification claims and moves to `stop`; it never skips stop/destroy/inventory and never authorizes correction or retry. Each terminal phase occurs exactly once; terminal completion is closed and cannot be reopened by another stop/destroy/inventory suffix, even when the suffix remains below the byte/event ceiling. Uncertainty is sticky and remains preserved, but it does not terminate array validation. After the first uncertain row, the only representable continuation is the exact remaining best-effort `stop -> destroy -> independent-inventory` suffix; each suffix phase is consumed once even when its claim is failed or uncertain, so independently safe later cleanup remains representable. Uncertainty in a terminal phase advances to the next terminal phase rather than requesting a replay of the uncertain phase. Every row, including the complete trailing suffix, must still have exact order, producer class, and a unique non-replayed digest. A skipped, duplicate, qualification, completion, retry, out-of-order, or replayed trailing row rejects the whole evidence document without returning its digest. Terminal-step failure or uncertainty cannot be promoted to cleanup or zero inventory. The independent-inventory phase requires its distinct claimed observer category. A fully supplied best-effort suffix remains `preserve-uncertain` with no next phase; it never becomes `model-order-complete-blocked`. Even `model-order-complete-blocked` means only that caller-supplied metadata followed the local ordering model; `campaign_execution_observed`, `cleanup_observed`, and `zero_inventory_claimed` remain false.

Evidence rows are bounded categorical metadata plus SHA-256 references only. Phase values are closed issue-specific enums; arbitrary execution/provider-like phase tokens are not representable. They contain no resource IDs, account IDs, commands, targets, URLs, logs, prompts, source, credentials, provider payloads, callbacks, or arbitrary diagnostics. Producer categories and digests are claims, not provenance, independence, custody, execution, or provider truth. Safe snapshots reject Proxies before traps, accessors without invoking them, inherited properties, oversized strings/keys/property sets before descriptor-value traversal, and non-exact artifact-root fields.

### #359 provider-free lifecycle preparation

The same pure driver also exports a separately namespaced `cogs.stage4-s408-*` lifecycle model. It is local-only preparation for Issue #359 and does not alter the historical Stage 4 v1 schemas, fixtures, or semantic digests. Its default policy stops after source and discovery fixtures because provider-created counts remain unresolved and uncapped. A separate explicit hand-built frozen fixture can exercise ordering only; it is not a provider plan and remains `MODEL_ORDER_COMPLETE_BLOCKED` even after every row.

Both policies bind blockers stating that S4-07 acceptance, fresh Issue #359 approval, an authorized saved plan, and provider discovery are absent. They also bind an exact qualification-requirements digest covering:

- exact approved source, render, and artifact identities plus live-object readback;
- Kata with KVM acceleration, nested virtualization, a distinct guest kernel, and no `runc`, QEMU TCG, or trusted-sidecar fallback;
- EBS workspace and session create/attach/use/detach/delete lifecycle, exclusive-writer behavior, and forced-loss behavior; and
- mandatory `stop -> destroy -> custody-inventory -> retained-state-retirement -> final-inventory` after pass, failure, timeout, or uncertainty.

The fixture apply row carries only a digest of synthetic fixture observations and must state `provider_observation_claimed=false`. It cannot stand in for AWS, EKS, Kata, EBS, or live-object evidence. Stop and destroy rows bind cleanup for every outcome. The custody inventory binds all retained S3 versions, delete markers, multipart uploads, and locks before retirement. Final inventory is complete, deletion-blind, non-tag-only, identity-separated, and spans account/region EC2 including EBS and ENI, EKS, load balancers, Auto Scaling, IAM, KMS, logs, S3, budgets, schedules, and Lambda. The classifier nevertheless fixes provider truth, custody, retirement, zero inventory, retry authority, and execution authority to false. OpenBao is excluded only from #359 and remains required for later stages.

## #362: strict blocked exit-review templates

The matrix/report templates and classifier are:

- [`stage4-exit-review-matrix-template-v1.json`](../../schemas/stage4-exit-review-matrix-template-v1.json);
- [`stage4-exit-review-report-template-v1.json`](../../schemas/stage4-exit-review-report-template-v1.json);
- [`stage4-exit-review-verdict-v1.json`](../../schemas/stage4-exit-review-verdict-v1.json); and
- [`stage4-exit-review.ts`](../../scripts/stage4-exit-review.ts).

The matrix has exact rows for one source/artifact/image revision, real dependencies, complete evidence, guest-root network denial, absent sandbox credentials, unchanged conformance, EBS/exclusive writer, real Pi functionality, startup gate/exception, recovery/no replay, repeatable lifecycle, no fallback, privacy, and destroyed resources with independent zero inventory. Every row is `unreviewed-reject`, every evidence/exception binding is null, and the review revision and accepted #359–#361/final-inventory bindings are absent.

The report binds the exact matrix digest and has mandatory fail-closed checks for:

1. mandatory stubs or non-real dependencies;
2. skips or missing evidence;
3. runtime/policy fallback;
4. sensitive-data leaks;
5. mixed source/artifact/image revisions;
6. unreviewed exceptions; and
7. cleanup or inventory uncertainty.

All seven remain `unreviewed-reject` in the template. Region/type/runtime scope, residual risks, local check receipts, and artifact scans remain unreviewed/unexecuted. The template states that the temporary launcher is not a daemon and Stage 4 is not GA, compliance, release, or production approval. Its decision is always `stage4_exit_satisfied=false` and `release_eligible=false`. A future actual exit review needs accepted #359–#361 evidence, final independent zero inventories, one exact evidence revision, rerun local checks/scans, and a different reviewed decision authority.

## Fixtures, tests, and registry

Deterministic fixtures live in [`test/fixtures/stage4-campaign/`](../../test/fixtures/stage4-campaign/). Tests cover isolated field mutations, source/artifact mixing, digest replay, retries, skipped terminal phases, wrong producer categories, authority promotion, strict rejection rows, getters, and Proxy traps. All new schemas are included in the bounded Stage 4 registry test and the repository-wide schema compiler.
