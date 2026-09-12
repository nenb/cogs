# ADR 0338: Correct the pre-H plan and preserve all effect denials

## Status

Accepted **planning and budget governance only**. This commit authorizes only this
ADR, its index entry, the closed allocation, its checker, and focused governance
validation. It grants no product, KVM, workflow dispatch, Docker, OpenTofu,
OIDC/STS, provider, AWS, SSM, network, inventory, remote-command, readiness,
full-suite, image, release, H/G/Q, or no-mint effect.

`eda2dc499153f3053772790c02ea6d332403742e` / tree
`9ad48a2be811745f0d8032a0a9f52a33c4b2edec` remains a protected product
checkpoint, not H, G, or Q. Every successor is a direct linear child. Added
lines and UTF-8 added-line bytes remain cumulative from that checkpoint: no
delete, rename, copy, compression, net-size, or prior-checkpoint credit.

## Closed accounting and path custody

The historical product allocation is 18,000 lines / 8,000,000 bytes and the
historical remediation allocation is 48,000 / 11,000,000. The separately
allocated prospective matrix is exactly **15,127 / 15,000,000**, so cumulative
product ceilings are **33,127 / 23,000,000** and remediation ceilings are
**63,127 / 26,000,000**. The source ceiling is
`18,763,891 + 26,000,000 = 44,763,891 <= 45,000,000`; tracked files are
`1,420 + 200 = 1,620 <= 1,620`. The measured current 99,872 leaves 15,128 before the strict 115,000 hard
limit; the 15,127 forward ceiling remains below it (114,999 maximum), never
deletion credit. Integration's new-file cap is 180
(total 200); it specifically funds the custody schema, fake end-to-end adapter
test, and thirteen fresh v8 control members. Each owner and task ceiling is
independent and non-transferable.

The ledger at the review baseline charged 402 lines / 319,440 bytes after the
checkpoint (264 / 27,093 governance, 110 / 8,593 protected-product runtime,
and 28 / 283,754 explicitly identified prior checkpoint work). Those charges
remain charged. The checker now assigns every admitted path to one **named**
task; it has no complement task. It preserves historical owners, including the
integration-owned KVM workflow, and rejects every path not in the exact matrix.
It reports each task's gross consumed and remaining lines/bytes. Every task has
an explicit pre-H maximum; the final task's pre-H maximum is 1,127 / 1,000,000,
which mechanically withholds at least 2,500 / 3,000,000 for H/G/Q. This is a
capacity guarantee, not a claim that its paths are isolated: pre-H edits to a
final-task path consume that task and its pre-H maximum. Current checker accounting
(lines/bytes consumed → remaining) is governance 1,110/79,092 → 290/920,908;
AWS 5/264 → 4,295/4,799,736; product 49/6,423 → 3,951/3,193,577; readiness
6/281,045 → 1,794/1,718,955; final 392/58,478 → 3,235/3,941,522.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 1,400 / 1,000,000 pre-H maximum | ADR/index/allocation plus exact-head CI workflow/topology tests |
| AWS principal denial and cycle custody | 4,300 / 4,800,000 pre-H maximum | actual adapter, planner, production model/provider/controller/state/receipts, versioned backend config, every legacy shell denial, custody schema, and fake adapter → provider → recovery/effect-sentinel tests |
| protected product and KVM contract | 4,000 / 3,200,000 pre-H maximum | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 1,800 / 2,000,000 pre-H maximum | readiness generators/artifacts/tests and separately reviewed no-mint grant |
| final H/G/Q control reserve | 3,627 / 4,000,000 total; **≤1,127 / 1,000,000 pre-H**, leaving **≥2,500 / 3,000,000** | all equality-test workflow mirrors, fresh v8 controls, H/G/Q guard/staging/qualification schemas and tests |

The final H/G/Q task is separately charged but shares its listed paths with the
pre-H plan; it is not an isolated-path reserve. Its enforced pre-H maximum and
final minimum above protect final-chain capacity. Its exact list includes all
twelve mirrors exercised by the equality test: rootfs producer and diagnostic producer; rootfs publisher
and diagnostic publisher; static-control candidate; mixed-H/G preflight;
local-Kata qualification; KVM rehearsal and integration diagnostic; and
production plan, approval, and campaign. It also separately funds retirement,
`stage2-prebuilt-local-qualification-guard.py`,
`stage2-stage-prebuilt-control.py`, the formal qualifier/preflight, all three
formal v2 schemas, the pre-AWS package schema, their focused tests, the budget
checker/equality test and formatter configuration, and the complete
thirteen-member fresh v8 control package. The pre-H governance task also owns
`.github/workflows/ci.yml` and `test/ci-infrastructure-boundary.test.ts`; the
AWS task owns `deploy/aws-feasibility/versions.tf`, the provider tests, and the
following complete legacy shell-entrypoint denial set:
`apply.sh`, `destroy.sh`, `inventory.sh`, `plan.sh`,
`recover-production-campaign-entry.sh`, `recover-production-campaign.sh`,
`run-measurement-campaign.sh`, `run-measurement-validation.sh`,
`run-production-campaign.sh`, `run-production-effect.sh`,
`run-production-inventory.sh`, `run-production-remote.sh`, `run-runtime-validation.sh`,
`validate.sh`, `remote/measure-runtime.sh`, `remote/recover-stage2-completion-remote.sh`,
`remote/run-stage2-completion-full-rehearsal.sh`, `remote/run-stage2-completion-full.sh`,
`remote/run-stage2-completion-readiness-rehearsal.sh`,
`remote/run-stage2-completion-readiness.sh`,
`remote/run-stage2-completion-remote.sh`, and `remote/validate-runtime.sh`.
It further enumerates the H-owned
consumer closure that the guard seals: fixed-source preparation, hosted mode,
local/native settlement, diagnostic lock, producer, publisher and static-control
boundary scripts; Kata preparation and all three formal-cycle adapters; and the
static-control runtime-boundary test. The AWS task includes the actual
production owner `completion_campaign_aws_adapter.py`, not a substitute
fake-only controller, plus the new Python fake end-to-end
adapter → provider → recovery test and existing adapter/provider tests. Alongside
the existing ADR documents, the only new non-control files are the immutable
`schemas/aws-stage2-production-{principal-contract,custody}-v1.json` and that
fake end-to-end test; no unlisted new file is allowed.

## Blocking AWS authority contract

Principal separation and external custody are **unimplemented and blocking**.
Until they exist under later source and AWS-planning authority, the campaign is
unconditionally denied. Every listed legacy shell entrypoint and every Python
production/recovery entrypoint must make the same literal, mechanical denial
before `source`/`exec`, command substitution, file/package/credential reads,
install/resolve work, OIDC, STS, provider construction, OpenTofu, SSM, network,
inventory, or remote-command code. The future direct-entry tests invoke every
listed shell route with credential/install/network/tofu/AWS/SSM effect sentinels
and prove the denial occurs first; a wrapper's historic “measurement” label is
not an exception. Thus an old package cannot become executable merely because
an old workflow or a domain-separated hash still parses.

The future immutable authority contract must bind authenticated, individually
verifiable identities for operator, approver/budget/security reviewer, executor,
and zero-inventory observer; their role, expiry, candidate/tree, package, and
contract version are immutable inputs. Missing, equal, expired, stale,
unauthenticated, or representation-only identities deny. A role cannot attest
itself or another role. Tests use fake executables and effect sentinels to prove
that each of those cases, and each stale package identity (H, G, Q, run,
artifact, control, qualification), stops before OIDC/STS/provider/tofu/SSM or
network. Documentation, hashes, and the allocation do not lift this denial.

The future Python route, not a legacy shell route, must use the actual
`completion_campaign_aws_adapter.py` as the sole production custody owner.
Runner-local `/var/lib/cogs/...` files and flock are only cache. Before any
future AWS effect, a **pre-existing versioned S3 backend/object custody** and a
DynamoDB conditional journal/lease must exist in a separately administered
control account. That account, bucket, table, region, and namespace seed are
provisioned only under later AWS-planning authority. The immutable, non-AWS
preauthorization supplies those values plus expected workload account/region,
package/candidate/tree, custody and principal-contract versions, and a distinct
planning principal before workload credentials exist.

The planner first authenticates only that planning principal, checks the
preauthorization, and uses conditional DynamoDB writes to bind STS and AMI
*discoveries* into the approval batch. It transitions the namespace **seed** to
the discovered approval-batch namespace by CAS; discovered values never change
the seed/key. The normal executor then uses the distinct executor principal and
short bounded STS session. S3 versioned backend state, saved-plan bytes and
immutable objects, plus DynamoDB generation-numbered `campaign`, `intent`,
`receipt`, hash-chained `journal`, lease, and current-generation pointer,
survive runner loss. Each pointer/lease/journal transition is conditional on
prior generation and monotonically increasing epoch. Missing/replaced/foreign
state or plan bytes, failed condition, local-cache disagreement, or unreadable
custody is sticky uncertainty and denies effects.

Lease expiry alone never permits takeover. Recovery records the old session's
bounded STS `NotAfter`, waits through `NotAfter + configured skew`, then
verifies that no old process or session can still effect before it CAS-advances
the epoch. Until that proof, it reports uncertainty and opens no new cycle;
there is no merely-expired-lease takeover. Every admitted operation carries its
epoch and deterministic `(campaign, cycle, verb, prior-state)` intent ID.
Recovery reads external custody, never runner disk, and reconciles persisted
intent only by exact campaign tags/IDs and bounded observations. A lost response,
cancellation, runner destruction, missing receipt, or ambiguous normal **or
cleanup** intent is never resent: it stays sticky uncertain until exact
post-session reconciliation proves its outcome. Cleanup has the same
intent-before-send rule and ends only with fresh authenticated account/region
zero-inventory receipt, immutable final settlement, and credential retirement.

Planner, adapter, and provider/controller share the custody handle and explicit
per-cycle `TF_DATA_DIR`, S3 backend metadata, versioned state/plan-object IDs,
saved-plan bytes, and identity; they initialize/reopen that backend
cross-process before plan/apply compatibility and reject stale, fenced,
replaced, foreign, or cross-cycle metadata. Fake end-to-end tests traverse
planner → staging → **actual adapter** → provider → fresh recovery owner and
model runner loss, CAS conflicts, lost normal/cleanup responses, reconciliation,
and final zero inventory. In particular they pause an old operation **after
admission**, expire the lease, attempt takeover, wait through session expiry,
advance only after the old-session proof, then resume the old operation and
reject it. This ADR neither provisions that external service/principals nor
invokes tofu/AWS.

For remote validation the provider first observes exact-instance SSM `Online`
within one monotonic deadline, records durable send intent, invokes AWS CLI SSM
send with authenticated AWS CLI `max_attempts=1` (`AWS_MAX_ATTEMPTS=1`)/equivalent CLI max-attempts one,
and binds the returned command/instance receipt before polling only that pair.
Orchestration never reissues. There is one OpenTofu process per durable intent;
where the provider supports them it supplies deterministic idempotency tokens.
Terraform cannot promise one underlying HTTP request: provider-internal retry or
lost response is sticky uncertainty until post-session reconciliation, never
success proof or a second invocation. `versions.tf`, provider configuration and
the provider/adapter tests must pin and verify this policy. Observational
reads may retry only within the deadline and never create/settle an effect
intent. The same no-second-invocation rule covers ambiguous cleanup. Terminal,
mismatched, incomplete, or late `Success` is fatal; tests cover propagation,
foreign IDs, response/output completeness, timeout, internal-retry/lost-response
uncertainty, and no reissue.

## Product and KVM contract to be implemented later

The later implementation has two separate protected fresh runners and
generations: one authenticated `skills=empty` case and one canonical nonempty
shared/user case. Image/build/pass/**failure** receipts authenticate the exact
profile, generation, candidate/tree, role-indexed image identity, runner,
limits and settlement. They cannot share runner, generation, image tag,
publication, state, or pass authority. Role-indexed convergence means distinct
profile tags/generations and custody for empty, nonempty, and each probe while
equivalent approved **worker** roles have the same approved content digest and
provenance (and equivalent sandbox roles likewise). It never means one tag or
one image for all roles: the Debian QCOW2 guest and KVM runner identity are
separate authenticated role records and must not converge with OCI worker or
sandbox identities.

The contract enumerates every admitted input capability and every measured
SSH/SFTP capability. For each it creates a fresh full-minus-one probe with its
own generation, input/mount identity, expected allowed operation and expected
denied operation. SSH and SFTP probes must prove their intended boundary with
successful control and denied-operation oracles, not merely a startup failure.
Missing, substituted, widened, retained, late-failed, or foreign capability
fails before candidate work. Probe receipts aggregate coverage but are never a
candidate pass or dispatch authority.

Both product and KVM produce a bounded, secret-safe failure/uncertainty receipt
independent of a pass receipt: identity, deadline class, cleanup intent,
settlement observations, redacted diagnostics, and quarantine disposition. It
never uploads credentials, raw disks, or workspace images. Hosted runners are
ephemeral: artifact upload is an authenticated handoff of that bounded record,
not proof that local custody survives runner disposal. If handoff or quarantine
cannot complete before disposal, the result is uncertain/failed and cannot pass.

## Later authorization and required order

Merging this plan **never authorizes dispatch**. Before implementation PR
publication, a separately authorized deterministic, non-AWS readiness
regeneration must refresh and pass its freshness assertions for the candidate
bytes; it is repeated after feedback/final validation and never relaxed. The
future `.github/workflows/ci.yml` change must check out and verify the exact PR
head SHA in **Quality**, **Secret scan**, **Images**, and every applicable root
PR job. Required protected-PR evidence is exactly those successful exact-head
jobs—not a synthetic merge ref and not a skipped native job. Native remains a
later separately authorized gate; product and KVM remain later gates. Main-push
CI may observe merged bytes, but grants no authority and is not PR-head
substitute evidence. `workflow_dispatch`, product workflow, KVM workflow, and
every Stage2/AWS workflow remain forbidden by this plan; no AWS workflow is
created or enabled.

Those CI results are evidence only, not product/KVM execution authority.
Product/KVM runs may be considered only in a later exact protected-main
implementation gate after focused validation, independent exact-tree reviews,
changed-since-review checks, and the required exact-head PR checks. That gate
must mechanically admit the complete profile/probe matrix, sealed execution
closure, limits, image provenance, failure handoff, and shared `git-tools.sh`
gate. It may authorize only first-created attempt-one product/KVM runs for that
exact commit, never cancellation replacement, concurrency cancellation, rerun,
retry, or redispatch.

The required pre-H order is exact:

1. corrected source;
2. focused tests;
3. separately authorized deterministic readiness regeneration and freshness check;
4. PR publication and required exact-head Quality, secret, images, and applicable root checks;
5. separately authorized protected product/KVM feedback runs;
6. candidate publication and durable readback;
7. separately reviewed no-mint full validation plus regenerated readiness;
8. recovery/residue validation and two independent audits;
9. final full validation and deterministic regeneration;
10. exact-tree reviews and changed-since-review checks;
11. retirement/freeze decision; then
12. H.

The no-mint pre-H rehearsal binds its exact candidate publication/readback and
may not mint credentials/resources or claim production. It does **not** require
a fresh Q. A later rehearsal after Q, if desired, is a different separately
reviewed authorization.

The intermediate audits are: source/path/budget ownership; production principal
and pre-credential denial; externally durable adapter/provider custody,
fencing, lost-response reconciliation and no-effect sentinels; SSM one-send
transport/crash recovery; product input/SSH/SFTP probe matrix; KVM shared-gate
and custody; failure-artifact/quarantine; candidate publication/readback;
recovery/residue; generated readiness; and two independent final implementation
audits. Hosted image convergence is role-indexed: equivalent approved OCI roles
must match content/provenance while profile tags/generations remain distinct;
QCOW2 guest and KVM runner identities are separately authenticated. Any
mismatch stops.

OpenBao is deferred and nonblocking **only** for narrowed Stage2 synthetic
measurement. The future fixtures must prove no OpenBao availability, identity,
PKI, revocation, Kubernetes, cloud, ordinary admission, or production
qualification; the unresolved fixed OpenBao image remains a Stage3/Stage4 and
production blocker.

After H, only the separately decided direct-child G and fresh Q sequence may
proceed under their own gates. A retirement/freeze decision must enumerate the
superseded H/G/Q/run/artifact identities and preserve their denial. This plan
creates neither effects nor AWS authority.

## Validation for this commit

Run only the central checker, `test/stage2-remediation-budget.test.ts`,
formatting, and diff/path inspection. No product behavior, full/readiness
result, Docker/KVM, OpenTofu/provider/SSM/AWS result, dispatch, or production
claim is made.
