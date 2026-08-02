# Stage 4 campaign and exit-review offline models

Issues #358 through #362 remain **open and blocked**. This package prepares only local/static schemas, deterministic fixtures, and pure classifiers. Neither a valid draft nor a terminal local model result can close #358, #359, #360, #361, or #362. The templates cannot be promoted into campaign evidence or an exit decision.

No AWS/provider operation, OpenTofu init/plan/apply, SSM operation, EKS or Kubernetes API access, `kubectl`, Helm install/apply, deployment, external-model call, network discovery, current price/quota discovery, or inventory operation is exposed or performed. Upstream NIC is unchanged. Every verdict fixes execution authority, provider/Kubernetes truth, retry authority, Stage 4 exit, and release eligibility to false.

## #358: absent/unapproved approval-envelope draft

The strict draft and verdict schemas are:

- [`stage4-campaign-approval-draft-v1.json`](../../schemas/stage4-campaign-approval-draft-v1.json);
- [`stage4-campaign-approval-verdict-v1.json`](../../schemas/stage4-campaign-approval-verdict-v1.json); and
- pure classifier [`stage4-campaign-approval.ts`](../../scripts/stage4-campaign-approval.ts).

The deterministic fixture is [`approval-draft-blocked-v1.json`](../../test/fixtures/stage4-campaign/approval-draft-blocked-v1.json). It is deliberately the only state representable by this v1 draft authority:

- #42 repeated-measurement, destruction-report, and final-zero-inventory evidence is absent;
- S4-06 acceptance evidence is absent;
- the downstream campaign issue and attempt identifier are unnamed/absent;
- approval and approval evidence are absent/unapproved;
- campaign operator, campaign approver, budget approver, security/evidence reviewer, and independent zero-inventory observer bindings are absent;
- exact source, source inventory, plan, render, and runtime artifact bindings are absent;
- account, region, and instance-type bindings are absent;
- resource graph/caps, budget/current-price/current-quota evidence, expiry/duration/TTL, destroy path/state binding, and independent inventory procedure/scope/observer are absent or unapproved; and
- `attempt_number=1`, `maximum_attempts=1`, `retry=prohibited`, and `execution_authorized=false` are immutable.

Supplying a digest, identity, account, budget, expiry, destroy path, inventory claim, second attempt, approval, or execution authority is rejected. Closure of #42 will require a new evidence-bound authority; this blocked draft is not designed to become an approval by mutation.

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

A qualification failure skips only the remaining qualification claims and moves to `stop`; it never skips stop/destroy/inventory and never authorizes correction or retry. Each terminal phase occurs exactly once; terminal completion is closed and cannot be reopened by another stop/destroy/inventory suffix, even when the suffix remains below the byte/event ceiling. Uncertainty is sticky and remains preserved. Terminal-step failure or uncertainty cannot be promoted to cleanup or zero inventory. The independent-inventory phase requires its distinct claimed observer category. Even `model-order-complete-blocked` means only that caller-supplied metadata followed the local ordering model; `campaign_execution_observed`, `cleanup_observed`, and `zero_inventory_claimed` remain false.

Evidence rows are bounded categorical metadata plus SHA-256 references only. Phase values are closed issue-specific enums; arbitrary execution/provider-like phase tokens are not representable. They contain no resource IDs, account IDs, commands, targets, URLs, logs, prompts, source, credentials, provider payloads, callbacks, or arbitrary diagnostics. Producer categories and digests are claims, not provenance, independence, custody, execution, or provider truth. Safe snapshots reject Proxies before traps, accessors without invoking them, inherited properties, oversized strings/keys/property sets before descriptor-value traversal, and non-exact artifact-root fields.

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
