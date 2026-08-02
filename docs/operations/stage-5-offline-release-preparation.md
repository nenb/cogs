# Stage 5 offline release preparation for issues #367–#373

**Status:** provisional, local/static, false authority; every issue remains open or blocked

This package prepares only contracts, templates, deterministic generators, and metadata aggregators. It did not freeze a release candidate, perform an independent review, run a campaign or load test, choose a capacity, or make a release decision. It contains no AWS/provider/cluster/deployment/OpenTofu/external-model invocation and no scheduler or provider route.

The pure implementation is [`scripts/stage5-offline-release-preparation.ts`](../../scripts/stage5-offline-release-preparation.ts). It accepts or emits bounded categorical metadata only. Canonical JSON means code-point-key-sorted JSON with exactly one terminal LF. Schema validity and local aggregation authenticate no artifact, identity, approval, execution, result, inventory, or decision.

## Provisional artifacts

| Issue | Offline artifact | Schema | Current fixed state |
|---|---|---|---|
| #367 / S5-04 | [`rc-freeze-manifest.provisional.json`](../security-evidence/stage5-offline-preparation/rc-freeze-manifest.provisional.json) | [`stage5-rc-freeze-manifest-v1.json`](../../schemas/stage5-rc-freeze-manifest-v1.json) | source, locks, chart, skills, schemas, runtime, images, SBOM, signatures, vulnerability, license, and AWS-matrix bindings are absent/blocking; `rc_frozen=false` |
| #368 / S5-05 | [`independent-review.template.json`](../security-evidence/stage5-offline-preparation/independent-review.template.json) | [`stage5-independent-review-template-v1.json`](../../schemas/stage5-independent-review-template-v1.json) | reviewer/evidence-producer identities absent; 13 review areas unexecuted; finding count is not asserted as zero; decision unavailable |
| #369 / S5-06 | [`campaign-plan.unexecuted.json`](../security-evidence/stage5-offline-preparation/campaign-plan.unexecuted.json) | [`stage5-campaign-plan-v1.json`](../../schemas/stage5-campaign-plan-v1.json) | ordered conformance, recovery, privacy/deletion, destroy, and independent-inventory phases all unexecuted |
| #370–#371 / S5-07–S5-08 | [`load-plan.mocked.unexecuted.json`](../security-evidence/stage5-offline-preparation/load-plan.mocked.unexecuted.json) | [`stage5-load-plan-v1.json`](../../schemas/stage5-load-plan-v1.json) | deterministic mocked-model 10/25/50 steps unexecuted; claimed capacity null |
| #372 / S5-09 | [`capacity-decision.unavailable.json`](../security-evidence/stage5-offline-preparation/capacity-decision.unavailable.json) | [`stage5-capacity-decision-template-v1.json`](../../schemas/stage5-capacity-decision-template-v1.json) | real 50-session binding absent; decision and advertised maximum unavailable |
| #373 / S5-12 | [`release-readiness.unavailable.json`](../security-evidence/stage5-offline-preparation/release-readiness.unavailable.json) | [`stage5-release-readiness-template-v1.json`](../../schemas/stage5-release-readiness-template-v1.json) | recommendation unavailable; highest passing real concurrency null; every release evidence category absent/blocking |

## #367 freeze and drift contract

The provisional manifest inventories every required freeze category but binds none because there is no authentic release candidate. OAuth is disabled/unadvertised and a worker refresh-token path is forbidden. A future freeze must be based on one authentic source and complete artifact evidence under a new authority.

The snapshot comparator requires all 12 categories and exact digest equality. It accepts only a plain exact own-property object with bounded lowercase SHA-256 values. It rejects Proxies before reflection and rejects inherited values, accessors, symbols, non-enumerable fields, missing/extra fields, and malformed or oversized values without invoking getters. Hash input is copied into fixed component order. Any missing category or changed source, lock, chart, skill, schema, runtime, image, SBOM, signature, vulnerability, license, or supported-AWS-matrix binding invalidates the snapshot, requires refreeze, and invalidates dependent review/campaign results. A metadata match is explicitly not a freeze decision.

## #368 independent review gate

The checklist covers Pi discovery, SSH/SFTP, paths, proxy parsing/routing, proxy capabilities, OpenBao, the audit WAL, policy, guest/Kata, privacy, integrity, production artifact pinning, and project-dependency isolation. Findings have bounded severity, owner, disposition, retest, and evidence-binding fields.

Critical/high findings cannot be resolved by risk acceptance. They count as unresolved unless fixed or false-positive, owned, retested `pass`, and evidence-bound. Open findings must remain unresolved and unexecuted without an evidence binding; failed retests remain unresolved and evidence-bound; resolved fixes/false positives require an owner, passing retest, evidence, and `resolved-evidence-bound` state. Critical/high findings can use only that fixed/false-positive resolution path: they cannot use risk acceptance or `resolved-metadata-only`. Only medium/low findings may use evidence-bound, owned `resolved-metadata-only` risk acceptance with no retest required. Finding IDs and release-report residual-risk IDs are semantically unique, including when duplicate-ID rows otherwise differ. Even a metadata-level clear gate cannot establish independent acceptance while authenticated independent identities and an exact RC binding are absent.

## #369 campaign state machine

The offline aggregator permits only ordered phase metadata. Failure or uncertainty stops later phases; skipped-ahead results are invalid. Completion-shaped metadata still cannot claim campaign completion or zero resources. Future execution requires S5-05, a fresh exact campaign approval, real dependencies, API-key-only auth, synthetic sessions for privacy/deletion, destruction, and independently produced zero-inventory evidence.

## #370–#371 load planning

The generator fixes steps at 10, 25, and 50 active sessions using deterministic mocked model responses. Every step requires:

- a four-simultaneous-session user probe with per-user limit 4;
- exclusive same-project writer enforcement;
- cross-user storage, skill, proxy, history, and telemetry isolation;
- startup, scheduling, resource, proxy, OpenBao, SSH, storage, WAL, OTLP, cost, and cleanup metrics; and
- stop-before-next on failure or uncertainty.

The 25 step requires a passing 10 step and the 50 step requires a passing 25 step. Aggregation may report only a mocked planning step; `claimed_capacity` remains null even when synthetic metadata says all steps passed. The harness contains no scheduler, provider, deployment, cluster, or external-model route.

## #372 and #373 unavailable decisions

The #372 template forbids extrapolation as a basis for capacity. It cannot select 50 or propose a separately budgeted 100 step until authentic real 50-session evidence exists under a future decision authority. A 250 proposal additionally requires a real passing 100 step and another approval.

The #373 template fixes go/no-go to `not-available`, highest passing real concurrency to null, and the API-key provider set to provisional/unadvertised. Subscription OAuth remains disabled/unadvertised. Source/artifacts, acceptance, independent review, security campaign, performance/load, privacy/deletion, zero inventory, cost/capacity, and operations evidence are all absent/blocking. Any future decision is scoped only to the Cogs agent layer, not a daemon, user service, GA, compliance, or other cloud.

## Open and blocked issue register

| Issue | State after this offline preparation | Unmet dependency or authority |
|---|---|---|
| #367 | **open / blocked; not frozen** | S4-11 and S5-00 through S5-03; authentic RC artifact/evidence bindings; separate campaign approval |
| #368 | **open / blocked; not reviewed** | accepted #367 freeze; authenticated independent identities; executed checklist and resolved findings |
| #369 | **open / blocked; not executed** | accepted #368 review and fresh exact campaign approval |
| #370 | **open / blocked; not executed** | accepted #369 campaign and step-specific spend/node approval |
| #371 | **open / blocked; not executed** | passing real #370 steps and separate 50-session approval |
| #372 | **open / unavailable; no decision** | authentic passing real #371 50-session result |
| #373 | **open / unavailable; no go/no-go** | #367–#372 mandatory evidence, privacy/deletion, independent zero inventory, and staff decision |

Closing a dependency, merging this package, matching a digest, or passing local tests supplies no campaign or release authority. All acceptance checkboxes in #367–#373 remain incomplete.
