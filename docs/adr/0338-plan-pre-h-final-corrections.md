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
allocated prospective matrix is exactly **19,127 / 19,000,000**, so cumulative
product ceilings are **37,127 / 27,000,000** and remediation ceilings are
**67,127 / 30,000,000**. The source ceiling is
`18,763,891 + 30,000,000 = 48,763,891 <= 49,000,000`; tracked files are
`1,420 + 200 = 1,620 <= 1,620`. The measured current 99,908 leaves 20,092 before
the strict 120,000 hard limit; the 19,127 forward ceiling remains below it
(119,035 maximum), never deletion credit. Integration's new-file cap is 180
(total 200); it specifically funds the custody schema, fake end-to-end adapter
and direct-ingress tests, and thirteen fresh v8 control members. Each owner and task ceiling is
independent and non-transferable.

The ledger at the review baseline charged 402 lines / 319,440 bytes after the
checkpoint (264 / 27,093 governance, 110 / 8,593 protected-product runtime,
and 28 / 283,754 explicitly identified prior checkpoint work). Those charges
remain charged. The checker now assigns every admitted path to one **named**
task; it has no complement task. It preserves historical owners, including the
integration-owned KVM workflow, and rejects every path not in the exact matrix.
The AWS task remains independently capped at 7,000 / 8,000,000, but its
three non-transferable forecasts deliberately consume only 6,800 / 7,800,000:
deployment/custody/direct ingress 5,200 / 6,000,000; pinned OpenTofu
backend/workflow compatibility 1,100 / 1,300,000; and approval/staging/focused
authority tests 500 / 500,000. The remaining 200 / 200,000 is withheld, not a
fourth slice. The exact config maps these forecasts to the actual integration
owner: `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`,
`.terraform.lock.hcl`, actual `completion_campaign_aws_adapter.py` and
`completion_campaign_remote_adapter.py`, bootstrap/provider, state, receipt,
and identity owners plus controller/provider/remote-adapter/state/receipt/
cycle-authority ingress tests. A slice or task overrun stops for a reviewed replan; no owner, forecast,
or withheld room transfers.
It reports each task's gross consumed and remaining lines/bytes. Every task has
an explicit pre-H maximum; the final task's pre-H maximum is 1,227 / 1,300,000,
which mechanically withholds at least 3,500 / 3,500,000 for H/G/Q. This is a
capacity guarantee, not a claim that its paths are isolated: pre-H edits to a
final-task path consume that task and its pre-H maximum. The checker reports each measured consumed/remaining task total and separately
enforces the final pre-H maximum; it does not treat lower current consumption as
release. The separate 3,500/3,500,000 H/G/Q reserve remains withheld.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 1,600 / 1,000,000 pre-H maximum | ADR/index/allocation plus exact-head CI workflow/topology tests |
| AWS principal denial and cycle custody | 7,000 / 8,000,000 pre-H maximum | 5,200 / 6,000,000 deployment/custody/direct-ingress + 1,100 / 1,300,000 OpenTofu/backend/workflow + 500 / 500,000 approval/staging/test forecasts; 200 / 200,000 withheld; actual adapter, planner, provider/controller/state/receipts, schemas, all direct denials, and fake adapter → provider → recovery/effect-sentinel tests |
| protected product and KVM contract | 4,000 / 3,200,000 pre-H maximum | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 1,800 / 2,000,000 pre-H maximum | readiness generators/artifacts/tests and separately reviewed no-mint grant |
| final H/G/Q control reserve | 4,727 / 4,800,000 total; **≤1,227 / 1,300,000 pre-H**, leaving **≥3,500 / 3,500,000** | all equality-test workflow mirrors, fresh v8 controls, H/G/Q guard/staging/qualification schemas and tests |

The final H/G/Q task is separately charged but shares its listed paths with the
pre-H plan; it is not an isolated-path reserve. Its enforced pre-H maximum and
final minimum above protect final-chain capacity. Release of that separately
withheld H/G/Q reserve requires a later independent review of measured task
consumption, the exact changed-since-review diff, and the H/G/Q gate; it is
never released by a passing pre-H checker or a lower endpoint. Its exact list includes all
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
adapter → provider → recovery test and existing adapter/provider tests. Alongside the existing ADR documents, the only new non-control files are the
immutable `schemas/aws-stage2-production-{principal-contract,custody}-v1.json`,
the fake end-to-end test, and
`test/aws-stage2-completion-campaign-ingress.py`; no unlisted new file is
allowed.

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
itself or another role. The closed ingress inventory distinguishes planner CLI
`stage2-production-planner.py`; approval/staging front doors
`stage2-production-approval.py` and `stage2-stage-production-approval.py`; AWS
entry/recovery (`check-plan.py`, AWS entry/recovery, actual AWS/remote adapters
and provider); direct-cycle Python (`completion_cycle_{full,readiness}.py` and
`completion_formal_cycle_{full,readiness}.py`); and every listed legacy shell
effect route. Codec, contract, and receipt **decode-only** modes are a separate
read-only class: they may decode a supplied historical byte fixture but cannot
construct a principal, grant, client, backend, inventory, or effect intent.
The config/checker require this exact inventory, no overlap, and named-task
ownership; focused ingress, controller, provider, remote-adapter, state,
receipt, and cycle-authority tests invoke each effect-capable member directly
with credential/install/network/tofu/AWS/SSM sentinels and prove denial first.

Pre-H, v7 is only a pinned historical artifact-decoding fixture: its decoding
tests cannot execute it, and the current route set transitions to denial. The
sole future exception is a separately reviewed, candidate/tree/package-bound,
expiry-bounded non-AWS no-mint grant that names exactly logical
`run-stage2-completion-full`, `run-stage2-completion-readiness`, and
`recover-stage2-completion-remote` (or an explicitly reviewed replacement with
the same bindings). It admits only full/readiness observation or cleanup of the
grant's own persisted non-AWS intent; direct, stale, substituted, or ungranted
invocation denies before any effect. It cannot mint credentials/resources,
become AWS authority, or authorize an AWS entry/recovery or legacy wrapper:
those remain unconditional denial. Fresh Q is still required for every other
current source route. Tests must cover valid v7 decode-only fixture versus the
current-denial transition, every grant binding/expiry mutation, and direct
ungranted full/readiness/recovery invocation. Documentation, hashes, and the
allocation do not lift a denial.

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

Lease expiry alone never permits takeover. **Old-effect quiescence is an
observation protocol, not a Boolean.** Each executor STS session is at most 900
seconds; external custody persists its authenticated `NotAfter` before any
intent. Recovery may not CAS an epoch before `NotAfter + 120 seconds`, and then
must reconcile every accepted asynchronous intent by its deterministic
`(campaign, cycle, epoch, verb, prior-state)` ID and exact campaign/intent tags.
For each recorded SSM `(command-id, instance-id)` it observes that exact pair
terminal, or sends one recorded cancel intent and observes the same pair's
terminal cancellation; a different command, instance, status, absent output,
or absent observation is uncertainty. It submits and observes termination of
the exact tagged instance, revokes the instance role's older sessions, removes
the exact scheduler, role policy/attachment, role, and instance profile, and
waits through every delegated credential `NotAfter` where one was issued. Only
then does the independent observer perform two complete, bounded,
account-and-region inventory passes separated by the configured poll interval.
Every observation is authenticated, tagged, persisted, and read back; any
missing, foreign, incomplete, late, or contradictory observation is sticky
uncertainty. A paused old process may resume only with expired credentials; its
request must be rejected. It never gets a new epoch or usable credential.

Recovery has no successor NORMAL authority. Conditional on the external fence
above, exactly one separately authenticated cleanup-only recovery owner may
hold a bounded recovery lease, and exactly one independently authenticated,
read-only observer may hold an observation lease; both differ from executor,
planner, approver, and each other. The cleanup owner may act only on
externally persisted intents in its fenced epoch: reconcile, cancel, terminate,
revoke, and request the observer's inventory. It may never do normal work,
issue a new normal intent, or reissue an ambiguous normal **or cleanup** intent.
The observer can only read and persist the two fenced inventory passes. Their
leases and credentials end no later than cleanup; loss/expiry leaves sticky
uncertainty. Recovery-of-recovery is another separately authenticated
cleanup-only owner after the old lease and credential `NotAfter` plus fence
proof; it inherits only the same persisted-intent set and cannot promote to
NORMAL. Final-byte durable/readback/hash-bound settlement is required before
any later recovery owner, invocation, epoch, or credential is admitted.

The simultaneous limits are: normal effect time at most 180 minutes; all
cleanup/reconciliation, including delegated-credential quiescence, at most 60
minutes; each executor, cleanup, and observer STS credential at most 15
minutes; and the campaign workflow wall time at most 240 minutes. Its exact
cleanup inequality is `cleanup_reserve_ns = 3,600,000,000,000 > 900 STS + 120
fence skew + 4×60 request + 4×300 terminal/poll + 2×300 inventory =
3,060,000,000,000`; tests must require `cleanup_reserve_ns >
3,060,000,000,000`, and 540 seconds remains withheld inside cleanup. At the
conservative `$0.118/hour`, 240 minutes costs `4 × 0.118 × 1,000,000 =
472,000` microUSD, strictly below the 500,000 microUSD limit. Later
`stage2-production-plan` and `stage2-production-approval` drafts each timeout
at 30 minutes and are non-effecting; their immutable approval expires before
campaign admission. Only a read-back draft approved before the 240-minute
campaign starts may bind that run; no plan/approval refresh, effect, or grant
is allowed after its 180-minute normal-effect boundary. These are future
contract/schema/workflow timeouts, not authority now.

Recovery reads external custody, never runner disk. A lost response,
cancellation, runner destruction, missing receipt, or ambiguous normal **or
cleanup** intent is never resent: it stays uncertain until the protocol above
proves its outcome. Cleanup ends only after final inventory, immutable
settlement, and credential retirement.

Planner, adapter, and provider/controller share the custody handle and explicit
per-cycle `TF_DATA_DIR`, S3 backend metadata, versioned state/plan-object IDs,
saved-plan bytes, and identity; they initialize/reopen that backend
cross-process before plan/apply compatibility and reject stale, fenced,
replaced, foreign, or cross-cycle metadata. Before any source implementation,
a separately authorized **pinned OpenTofu non-AWS backend/saved-plan
compatibility gate** must authenticate the actual `versions.tf` OpenTofu
`= 1.12.4`, AWS-provider `= 6.54.0`, lockfile hashes, and exact binary/provider
bytes, then use only a non-AWS test backend with no credentials, provider calls,
plan apply, or network effects. A second, later separately authorized real-control-backend gate
must prove S3/DynamoDB state and saved-plan compatibility before any workload
credential or apply. Neither gate is authorized here: do not run OpenTofu now. Fake end-to-end tests traverse
planner → staging → **actual adapter** → provider → fresh recovery owner and
model runner loss, CAS conflicts, lost normal/cleanup responses, reconciliation,
and final zero inventory. They also prove final-byte restart ordering: no new
process, invocation, epoch, or credential is admitted until the old epoch's
terminal reconciliation/settlement record has had its final byte durably
written, versioned read back, and hash-bound; crash at any earlier byte is
uncertainty. In particular they pause an old operation **after admission**,
expire the lease, attempt takeover, wait through session expiry and every
quiescence observation, advance only after the proof, then resume the old
operation and reject it for expired credentials. This ADR neither provisions
that external service/principals nor invokes tofu/AWS.

For remote validation the provider first observes exact-instance SSM `Online`
within one monotonic deadline, records durable send intent, invokes AWS CLI SSM
send with authenticated AWS CLI `max_attempts=1` (`AWS_MAX_ATTEMPTS=1`)/equivalent CLI max-attempts one,
and binds the returned command/instance receipt before polling only that pair.
Orchestration guarantees only one orchestration process and one invocation per
durable intent, plus authenticated idempotency where supported and the
reconciliation above. Its only retry guarantee is that it sets the **client**
AWS CLI/equivalent request maximum to one; it makes **no** claim about provider
internal retries, transport delivery, or invisible duplicate effects. A lost
response or unknown internal retry is uncertainty, not success proof and not
permission for a second invocation. Observational reads may retry only within
the deadline and never create/settle an effect intent. The same no-second-
invocation rule covers ambiguous cleanup. Terminal, mismatched, incomplete, or
late `Success` is fatal; tests cover propagation, foreign IDs, response/output
completeness, timeout, unknown-retry/lost-response uncertainty, and no reissue.

## Host bootstrap contract to be implemented later

A later separately reviewed gate must choose exactly one authenticated host
bootstrap authority before the one-shot remote command: either (1) a prepared,
immutable image whose authenticated descriptor binds `git`, `python`, `tar`,
`zstd`, and cloud-init identities/versions/digests, or (2) bounded deterministic
cloud-init preparation that installs only that exact tool set, verifies each
identity/digest, persists a receipt, and finishes before the one-shot command.
The command may not use ambient PATH, package resolution, bootstrap retries, or
unverified tools. Missing image provenance, preparation receipt, deadline, or
any tool identity denies. This is future source and AWS-gate work; no image,
cloud-init, install, command, or effect occurs now.

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
