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
allocated prospective matrix is exactly **19,927 / 19,000,000**, so cumulative
product ceilings are **37,927 / 27,000,000** and remediation ceilings are
**67,927 / 30,000,000**. The pre-H governance task rises honestly from its
already consumed 1,799 lines to 2,600 lines; it is not presented as one-line
headroom or funded from the AWS holdback. The source ceiling is
`18,763,891 + 30,000,000 = 48,763,891 <= 49,000,000`; tracked files are
`1,420 + 200 = 1,620 <= 1,620`. The measured current 99,955 leaves 20,045 before
the strict 120,000 hard limit; the 19,927 forward ceiling remains below it
(119,882 maximum), never deletion credit. Integration's new-file cap is 180
(total 200); it specifically funds the custody schema, fake end-to-end adapter
and direct-ingress tests, and thirteen fresh v8 control members. Each owner and task ceiling is
independent and non-transferable.

The ledger at the review baseline charged 402 lines / 319,440 bytes after the
checkpoint (264 / 27,093 governance, 110 / 8,593 protected-product runtime,
and 28 / 283,754 explicitly identified prior checkpoint work). Those charges
remain charged. The checker now assigns every admitted path to one **named**
task; it has no complement task. It preserves historical owners, including the
integration-owned KVM workflow, and rejects every path not in the exact matrix.
The AWS task is independently capped at **7,357 / 8,400,000**. Its exact,
non-transferable forecast categories are deployment/custody/direct ingress
**5,457 / 6,200,000**; pinned OpenTofu backend/workflow compatibility **1,200 /
1,500,000**; and approval/staging/focused authority tests **500 / 500,000**.
The remaining **200 / 200,000** is an **enforceable unallocated holdback**, not
a fourth forecast: config and checker require it exactly, report it separately
from category consumption, and permit its use only by a reviewed replan. The
checker rejects AWS-task consumption above the 7,157 / 8,200,000 category
forecast until that replan; the 7,358 / 8,400,000 task ceiling cannot silently
absorb holdback. The added 357 / 400,000 is funded by reducing only pre-H
headroom in the final-control task, while retaining its exact 3,500 / 3,500,000
H/G/Q reserve. The exact config maps these forecasts to the actual integration
owner: `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`,
`.terraform.lock.hcl`, actual `completion_campaign_aws_adapter.py` and
`completion_campaign_remote_adapter.py`, bootstrap/provider, state, receipt,
and identity owners plus controller/provider/remote-adapter/state/receipt/
cycle-authority ingress tests. It also assigns the concrete cost-budget
consumers—OpenTofu budget/scheduler declarations, controller/provider,
production/receipt/state, approval/staging, the no-mint rehearsal grant
consumer (`scripts/stage2-prebuilt-rehearsal-grant.py`) and its Python/TypeScript
focused grant tests, and their focused tests—to their named task and category. The three exact forecast categories and the 200/200,000 holdback are literal checker inputs: category totals remain exactly 7,157/8,200,000 and holdback exactly 200/200,000; no category may absorb it. A slice, task, or holdback overrun stops for a reviewed
replan; no owner, forecast, category, or withheld room transfers.
It reports each task's gross consumed and remaining lines/bytes. Every task has
an explicit pre-H maximum; the final task's pre-H maximum is 670 / 900,000,
which mechanically withholds at least 3,500 / 3,500,000 for H/G/Q. This is a
capacity guarantee, not a claim that its paths are isolated: pre-H edits to a
final-task path consume that task and its pre-H maximum. The checker reports each measured consumed/remaining task total and separately
enforces the final pre-H maximum; it does not treat lower current consumption as
release. The separate 3,500/3,500,000 H/G/Q reserve remains withheld.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 2,600 / 1,000,000 pre-H maximum | ADR/index/allocation plus required readiness-before-PR order and exact-head CI workflow/topology tests |
| AWS principal denial and cycle custody | 7,357 / 8,400,000 pre-H maximum | 5,457 / 6,200,000 deployment/custody/direct-ingress + 1,200 / 1,500,000 OpenTofu/backend/workflow + 500 / 500,000 approval/staging/test forecasts; 200 / 200,000 withheld and separately reported; actual adapter, planner, provider/controller/state/receipts, schemas, all direct denials, and fake adapter → provider → recovery/effect-sentinel tests |
| protected product and KVM contract | 4,000 / 3,200,000 pre-H maximum | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 1,800 / 2,000,000 pre-H maximum | readiness generators/artifacts/tests and separately reviewed no-mint grant |
| final H/G/Q control reserve | 4,170 / 4,400,000 total; **≤670 / 900,000 pre-H**, leaving **≥3,500 / 3,500,000** | all equality-test workflow mirrors, fresh v8 controls, H/G/Q guard/staging/qualification schemas and tests |

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
It further enumerates the H-owned consumer closure that the guard seals:
fixed-source preparation, hosted mode, local/native settlement, diagnostic lock,
producer, publisher and static-control boundary scripts; and the
static-control runtime-boundary test. The AWS custody task, rather than the
H/G/Q reserve, owns Kata preparation, `completion_cycle_authority.py`, the
coordinator grant consumer, all formal-cycle adapters, rehearsal/recovery
entrypoints, and their direct-denial tests. AWS ingress is derived independently
from the capabilities that can obtain AWS credentials, touch the control account
or native backend, construct a provider, issue SSM, inventory, or cause a
resource effect—not from every executable in the allocated integration task.
The root-only `provision-stage2-nft-owner.py` and unrelated local/package/Kata
front doors remain separately governed non-AWS routes. In particular,
`scripts/run-stage2-package-native-candidate.py` and
`scripts/run-stage2-phase-a-candidate.py` are explicitly classified as non-AWS
diagnostic routes: they are neither AWS ingress targets nor part of the AWS
completeness claim. The config/checker reject overlap with AWS targets. The
existing v3 completion-evidence schema, validator, renderer, and focused test
are AWS budget consumers for the later separate-deadline/historical-decode
change, not authority to change or execute them now. The AWS task includes the actual
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
itself or another role. The closed **AWS** ingress inventory names the planner
CLI `stage2-production-planner.py`; approval/staging front doors
`stage2-production-approval.py` and `stage2-stage-production-approval.py`; and
only credential/control-account/backend/provider, SSM/inventory/resource-effect,
and legacy shell front doors. It is an independently enumerated,
capability-scoped set, not an assertion that every Python or shell executable
in the broad AWS task is AWS-capable. Codec, contract, receipt, and artifact-
verifier **decode-only** modes are a separate read-only class: they may decode a
supplied historical byte fixture but cannot construct a principal, grant,
client, backend, inventory, or effect intent. The two named native-candidate
diagnostics and other non-AWS diagnostics are governed by their separate route
contracts, not this AWS target set. The config/checker require the exact AWS
inventory, no overlap, named-task ownership, diagnostic exclusion, and exact
budget-consumer list; focused AWS ingress/controller/provider/remote-adapter/
state/receipt/coordinator/recovery tests invoke each AWS target directly with
credential/install/network/tofu/AWS/SSM sentinels and prove denial first.

Pre-H, v7 is only a pinned historical artifact-decoding fixture: its decoding
tests cannot execute it, and the current route set transitions to denial. The
sole future exception is a separately reviewed,
candidate/tree/package/expiry-bound non-AWS no-mint grant that names exactly logical
`run-stage2-completion-full`, `run-stage2-completion-readiness`, and
`recover-stage2-completion-remote` (or an explicitly reviewed replacement with
the same bindings). It admits only full/readiness observation or cleanup of the grant's own
persisted non-AWS intent; direct, stale, substituted, or ungranted invocation
denies before any effect. “No-mint” may create only bounded **local synthetic**
rootfs, input, network, runtime, and Kata resources beneath existing local
custody. It confers neither qualification nor evidence authority and absolutely
no cloud credential or AWS resource authority. It cannot mint credentials or
AWS resources, become AWS authority, or authorize an AWS entry/recovery or
legacy wrapper: those remain unconditional denial. Fresh Q is still required for every other
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

The planner first authenticates a **distinct preapproval planning principal and
session**, not a workload or broker session. Its allow-list is only
`sts:GetCallerIdentity`; exact approved-account/region `ec2:DescribeImages` for
the pinned AMI; native backend state/lock reads and lock operations on the
exact planning state and `.tflock` keys; immutable if-absent plan-object writes
and readback in the exact approval-plan prefix; and DynamoDB Get/Put/Update/
TransactWrite CAS in the planning namespace. It has no workload CRUD,
`iam:PassRole`, scheduler/budget mutation, SSM, normal-role assumption, or
cleanup permission. It CAS-binds caller identity, AMI, account, and region into
the approval batch, transitions only the namespace **seed** to its discovered
approval-batch namespace, and never lets discovery alter the seed/key.

The later design separates that planning role from normal workload, native
backend, cleanup workload, recovery/fence, session broker, observer, and
adapter-journal custody roles. The broker may only call `sts:AssumeRole` for
the exact normal role; it has no workload API, S3, or DynamoDB permission.
Cleanup is distinct in trust, permissions, tags, and credential material and
can never assume or refresh normal authority.

OpenTofu uses its native S3 backend, not an adapter post-copy. Before a cycle,
a separately administered control account provides a pre-existing versioned,
encrypted bucket and an exact per-cycle backend key/workspace. The normal
backend role is assumed only for that native backend and can use the exact
bucket/prefix and native conditional `.tflock` lockfile/CAS protocol; it cannot
call workload APIs. The workload role cannot read or write S3 backend objects
or DynamoDB custody. S3 state and saved-plan bytes stay in that backend through
plan/apply/reopen; copying state after an apply is not a substitute. The
adapter journal is separate from the backend: its tightly scoped custody
helper/role accepts a signed request containing campaign, cycle, epoch,
operation ID, expected generation, and application key, then independently
checks exact object prefix/DynamoDB leading key, hash, prior state, and the
DynamoDB conditional-write/CAS condition. A cleanup request may append only its
persisted unresolved-cleanup intent or terminal observation. Missing,
replaced, foreign, or unreadable state/plan/journal, a failed condition, or
local-cache disagreement is sticky uncertainty and denies effects.

**Old-effect quiescence is an observation protocol, not a Boolean.** At normal
window close, recovery fences every outstanding normal workload **and** native-
backend session without attempting an issuance-inventory race. It attaches an
unconditional explicit `Deny: *` session-policy/role-permission-boundary to each
dedicated normal role, disables further `sts:AssumeRole` trust for those roles,
and durably records the exact policy/boundary and trust versions through
custody. The recovery/fence role has only those exact role-fencing and custody
request permissions, no workload APIs; the broker remains assume-role-only.
After bounded IAM propagation, recovery probes representative previously
permitted workload and backend calls with recorded normal sessions and requires
explicit denial. Missing or late propagation, an accepted probe, mismatched
role/policy/session/scope, or absent proof is sticky uncertainty. Only then may
cleanup reconcile every accepted asynchronous normal intent; cleanup itself is
a distinct role and never receives normal or backend authority.

The future IAM matrix is action-by-action and deny-by-default:

| Principal | Permitted AWS actions | Exact scope and application checks |
| --- | --- | --- |
| session broker | `sts:AssumeRole` | Exact normal-workload and normal-backend role ARNs only; no workload API. |
| normal backend | `s3:GetObject`, `GetObjectVersion`, `PutObject`, `DeleteObject`, `ListBucket` | One encrypted/versioned bucket, exact campaign/cycle prefix and workspace/key; `PutObject`/`DeleteObject` are only native conditional `.tflock` lockfile/CAS operations. No workload APIs or DynamoDB custody. |
| normal workload | `ec2:CreateVpc`, `CreateInternetGateway`, `AttachInternetGateway`, `CreateSubnet`, `CreateRouteTable`, `CreateRoute`, `AssociateRouteTable`, `CreateSecurityGroup`, `CreateLaunchTemplate`, `RunInstances`, `CreateTags`, `ssm:SendCommand`, `scheduler:CreateSchedule`, `budgets:CreateBudget`, `iam:CreateRole`, `PutRolePolicy`, `AttachRolePolicy`, `CreateInstanceProfile`, `AddRoleToInstanceProfile` | Destructive actions use exact tagged ARNs/IDs where AWS supports them; unavoidable create scope is application-validated against exact account, region, campaign tags, and recorded IDs. No S3/DynamoDB custody. |
| cleanup workload | `ssm:CancelCommand`, `ListCommandInvocations`, `ec2:DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `TerminateInstances`, `DetachVolume`, `DeleteVolume`, `DetachNetworkInterface`, `DeleteNetworkInterface`, `ReleaseAddress`, `DeleteLaunchTemplate`, `DeleteSecurityGroup`, `DeleteRoute`, `DisassociateRouteTable`, `DeleteRouteTable`, `DetachInternetGateway`, `DeleteInternetGateway`, `DeleteSubnet`, `DeleteVpc`, `scheduler:GetSchedule`, `DeleteSchedule`, `budgets:DescribeBudget`, `DeleteBudget`, `iam:GetRole`, `GetPolicy`, `DetachRolePolicy`, `DeleteRolePolicy`, `DeletePolicyVersion`, `DeletePolicy`, `RemoveRoleFromInstanceProfile`, `DeleteInstanceProfile`, `DeleteRole` | Only persisted unresolved intent IDs and exact campaign tags; broad describe/list is granted only for named AWS read actions lacking resource scoping, then application validates exact account/region/tag/ID. No create, normal effect, or direct custody write. |
| observer | `ec2:DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `ssm:ListCommandInvocations`, `scheduler:GetSchedule`, `budgets:DescribeBudget`, `iam:GetRole`, `GetPolicy` | Read-only; broad describe/list only where AWS lacks resource-level scope; application verifies exact account, region, tags, and IDs. |
| recovery/fence | `iam:PutRolePermissionsBoundary`, `iam:UpdateAssumeRolePolicy`, exact custody-request action | Exact dedicated normal-role ARNs; unconditional deny-all and disabled trust only; no assume or workload API. |
| adapter custody helper | `s3:GetObject`, `PutObject`, `ListBucket`, `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `TransactWriteItems` | Exact journal S3 prefix and DynamoDB table/leading key only; application CAS/conditional expressions are mandatory for every journal/pointer/lease write. |

No table row gets a wildcard resource effect. Where an AWS action cannot be
resource-scoped, its broad permission is explicit and the application validates
exact account, region, tags, and IDs before accepting the result; where AWS
supports destructive resource scope, the policy uses it.

Only after that proof does recovery admit one separately authenticated cleanup-only owner. It reconciles every accepted asynchronous normal intent by its deterministic `(campaign, cycle, epoch, verb, prior-state)` ID and exact campaign/intent tags. For each recorded SSM `(command-id, instance-id)` it observes that exact pair terminal, or sends one recorded cancel intent and observes the same pair's terminal cancellation; a different command, instance, status, absent output, or absent observation is uncertainty. Cleanup authority covers the complete exact tagged/ID graph, in dependency order: (1) SSM command; (2) instance, attached EBS volumes, ENIs, and EIPs; (3) scheduler and budget; (4) launch template; (5) IAM attachments, customer policies, instance profile, and role; (6) security group, routes, route-table association, internet gateway, subnet, and VPC; then (7) final cleanup of the declared external backend objects where applicable. Every delete/cancel/terminate/revoke has a durable deterministic intent `(campaign, cycle, epoch, verb, exact-ID, prior-state)`, exact tag and ID scope, bounded observe/reconcile loop, and lost-response rule: no ambiguous intent is reissued. Dependency failure, foreign tag/ID, missing readback, or unresolved response is sticky uncertainty. The future least-privilege cleanup policy must enumerate exactly the corresponding SSM cancel/list, EC2 terminate/describe/delete/detach/release, Scheduler delete/get, Budgets delete/describe, IAM detach/delete/remove/revoke/ get, and custody-service request actions, each restricted to the recorded campaign tags and IDs; no wildcard create, normal-effect action, or direct custody-store mutation is granted to cleanup. It waits through every delegated credential `NotAfter` where one was issued. Only then does the independently authenticated, read-only observer perform two complete, bounded, account-and-region inventory passes separated by the configured poll interval. Every observation is authenticated, tagged, persisted, and read back; any missing, foreign, incomplete, late, or contradictory observation is sticky uncertainty. A paused old process may resume only with its fenced credential; its request must be rejected.

Recovery has no successor NORMAL authority. The cleanup admission record is not terminal settlement. Exactly one independently authenticated, read-only observer may hold the matching observation lease; both differ from executor, planner, approver, and each other. A cleanup owner acts only on externally persisted unresolved intents in its fenced epoch: reconcile, cancel, terminate, revoke, delete in the declared graph order, and request the observer's inventory. It may never do normal work, issue a new normal intent, or reissue an ambiguous normal **or cleanup** intent. The observer can only read and persist the two fenced inventory passes. Their leases and credentials end no later than cleanup; loss/expiry leaves sticky uncertainty.

The former 1,800-second cleanup-epoch description is superseded by the P1
correction below; it is not a future implementation contract. Only final-byte
durable, versioned readback, hash-bound **terminal settlement** (complete graph, credentials, and inventory) gates any future normal authority, normal epoch, normal credential, or normal invocation. A cleanup recovery process is not a normal process: it may be admitted only under the preceding two-epoch fenced rule and only to finish persisted unresolved cleanup. No normal process, invocation, epoch, or credential is admitted until the old epoch's terminal settlement record has had its final byte durably written, versioned read back, and hash-bound.

The former 240-minute/220-minute/500,000-microUSD timing and evidence wording
is superseded by the P1 correction below. The historical v1/v2 decoding as decode-only input
remains: historical bytes may render their historical form but cannot
satisfy v3 authority, settlement, or issuance. This ADR does not alter the
existing schema, validator, renderer, fixtures, or tests.

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
plan apply, or network effects. Offline fake/static tests cannot prove native
live S3 backend compatibility or custody. A second, later separately authorized
authenticated real-control-account compatibility gate must prove the native
S3-lockfile/CAS and DynamoDB-journal state/saved-plan compatibility before any
workload credential or apply; no post-copy result substitutes for that gate. Neither gate is authorized here: do not run OpenTofu now. Fake end-to-end tests traverse
planner → staging → **actual adapter** → provider → fresh recovery owner and
model runner loss, CAS conflicts, lost normal/cleanup responses, reconciliation,
and final zero inventory. They also prove final-byte restart ordering: no new **normal** process, invocation, epoch, or credential is admitted until the old epoch's terminal reconciliation/settlement record has had its final byte durably written, versioned read back, and hash-bound; a cleanup process may enter only through the separately proven two-epoch fence rule. Crash at any earlier byte is uncertainty.

In particular they pause an old operation **after admission**,
expire the lease, attempt takeover, wait through bounded IAM propagation and
every quiescence observation, advance only after the proof, then resume the old
operation and reject it through the explicit deny-all fence. This ADR neither provisions
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

## P1 campaign-model correction (authoritative and still plan-only)

This section supersedes every earlier ADR 0338 sentence about campaign roles,
credential lifetime, recovery, backend custody, IAM actions, timing, cost, and
adapter testing. It is an implementable future contract, **not** implementation,
AWS configuration, an OIDC exchange, an OpenTofu run, or evidence that any
adapter has run.

### Cycle and normal authority

A campaign has exactly seven sequential normal cycles. Every STS
`SourceIdentity` is the fixed ASCII encoding
`cogs-${campaignDigest}-${cycle}-${epoch}-${purpose}`: `campaignDigest` is a
fixed 26-character lowercase base32 digest, `cycle`/`epoch` are decimal, and `purpose` is one of
`planner`, `apply`, `show`, `destroy`, `cleanup`, or `observe`. It contains only
`[A-Za-z0-9+=,.@_-]`, contains no slash, and is at most 64 characters. Session
names and required `Campaign`, `Cycle`, `Epoch`, `Purpose`, and immutable
`AuthorityId` tags are independently fixed by the same custody record.

For each `(campaign, cycle, epoch)`, the broker has exactly one permission:
`sts:AssumeRole` to the exact normal-cycle role ARN. Its trust permits
`sts:AssumeRole`, `sts:SetSourceIdentity`, and `sts:TagSession` only from that
broker with the exact source identity and tag values. The normal-cycle role is
issued once per cycle with `DurationSeconds=1800`; it has no refresh,
replacement, concurrent session, successor session, or cross-cycle credential.
It owns routine native apply and dependency-ordered routine destroy, and must
settle every intent plus independent zero inventory before `NotAfter` and the
next-cycle admission.

A backend credential is **not** a fictional once-per-cycle issuance. The
normal-cycle role may make one separately intent-recorded, CAS-read-back
`sts:AssumeRole` request for each exact process `planner`, `apply`, `show`, and
`destroy`; each request names its process, session name, source identity, tags,
parent normal-session ARN, state key, lock key, plan VersionId, and expected
journal generation. The backend trust permits `sts:AssumeRole`,
`sts:SetSourceIdentity`, and `sts:TagSession` only from the matching normal
session and matching `Purpose`; its session ends no later than the parent.
Duplicate, missing, cross-purpose, stale, or unrecorded issuance denies. Thus
broker itself can assume only the normal-cycle role, and workload never gets S3
or DynamoDB custody APIs. Seven cycles still fit in the 120-minute normal
window; a 30-minute session is not a seven-times-30-minute extension. A future
actual-adapter test must execute seven fake-controlled cycles, all four backend
process issuances where reached, routine destroy, and settled zero inventory
before every next-cycle admission.

### Native backend, immutable plan, and journal custody

The native encrypted/versioned S3 **state** backend, immutable saved-plan
object, and DynamoDB journal are three different lifecycles. The backend role
uses the exact state key only for backend state reads/writes/version readback;
it uses the distinct exact `.tflock` key only for OpenTofu's native conditional
lock acquire, refresh, release, and readback. State deletion is forbidden during
plan/apply/show and occurs only as native destroy's state lifecycle requires;
no plan bytes ever occupy either state or lock key and no adapter post-copy is a
backend substitute.

Before approval, the planning custody path writes plan bytes once to its exact
immutable `plans/${approvalDigest}/...` prefix with if-absent semantics, then
persists and version-reads back its SHA-256, VersionId, key, and encryption
metadata. Approval binds all of them; `apply` and `show` reopen precisely that
VersionId and rehash it; `destroy` records its separately approved state/plan
lineage rather than overwriting the plan. The custody helper has an exact
DynamoDB journal/lease role: all planning namespace, issuance, intent, lease,
pointer, and settlement writes carry expected generation and conditional/CAS
expression. Workload and cleanup call it only by signed request and have no
direct S3/DynamoDB permission. Missing, ambiguous, replaced, unreadable, or
wrong-prefix state, lock, plan version, journal, readback, or CAS result is
sticky uncertainty.

### Uncertainty fence and cleanup issuance

On any uncertainty, the recovery/fence principal first CAS-persists the normal
session ARN, role, `NotAfter`, all accepted intent IDs, and the fence request.
It then disables normal-role trust and attaches a role-level unconditional
explicit deny-all policy to the exact normal-cycle role. This is a future IAM
change evaluated against existing sessions; there is no fictional
`iam:RevokeSession` action or claim that STS credentials can be revoked. After
those changes are version-read back, recovery waits through the **recorded
normal-session `NotAfter + 120 seconds`** before cleanup can touch the graph.
Representative old-session probes are supplemental diagnostic evidence only:
they can reveal a failed fence earlier, but never shorten the required wait.
The normal role remains disabled and deny-all attached throughout cleanup.

The cleanup issuer is a distinct GitHub Actions OIDC principal, not broker,
normal, recovery/fence, or workload. **Before any OIDC request**, custody
CAS-persists an epoch-specific immutable issuance record containing GitHub
issuer/audience/repository/ref/workflow/commit subject, cleanup executor role
ARN, campaign/cycle/epoch, valid encoded source identity, immutable external
ID, exact tags, requested `DurationSeconds=3600`, clock-skew allowance, and an
absolute `issuance_cutoff`. It then CAS-persists the issuance intent referring
to that record. The cutoff precedes the intent; a paused or delayed issuer may
never create a credential after it.

OIDC first receives only a no-workload cleanup-issuer session. That session
assumes the cleanup executor role with the persisted external ID, source
identity, and tags. The executor trust policy allows `sts:AssumeRole`,
`sts:SetSourceIdentity`, and `sts:TagSession` only from that issuer and has all
of: `DateLessThan: {"aws:CurrentTime": issuance_cutoff}`, exact
`sts:ExternalId`, exact `sts:SourceIdentity`, and exact request/principal epoch
and authority tags. The record's external ID and epoch are immutable CAS
fields, never caller input. This is deliberately an `AssumeRole` hop because
`AssumeRoleWithWebIdentity` cannot carry an STS ExternalId; the OIDC trust is
separately exact on the recorded GitHub claims. Thus the cutoff is enforced by
AWS trust evaluation rather than only a client clock. The executor records
returned session ARN and actual `NotAfter` before action. A lost response is not
retried: state becomes `issuance-unknown` and conservative expiry is exactly
`issuance_cutoff + 3600 seconds + recorded skew`; uncertainty remains through
that expiry plus 120 seconds.

There are at most two epochs; both are cleanup epochs. Epoch two has a new persisted cutoff and
issuance record, and is admitted only after epoch one's recorded (or
conservative) expiry plus 120 seconds. It continues deterministic unresolved
intents and cannot reissue ambiguity. A post-cutoff attempt, loss after epoch
two, or failed persistence/readback is sticky uncertainty/manual intervention.
There is no third epoch, normal re-admission, credential refresh, or other
cleanup-role assumption.

The normal role performs routine teardown. The cleanup role has the full exact
tagged/recorded-ID graph deletion and reconciliation authority only after the
fence wait: SSM command cancellation/terminal observation; instance, volume,
ENI, and EIP reconciliation; scheduler and budget; launch template; IAM
attachments, inline policy, instance profile, and role; then security group,
routes/association, route table, gateway, subnet, and VPC. It persists every
intent and result through the custody helper, observes bounded completion, and
leaves final two-pass observer zero inventory. It has no normal apply/create
authority and no direct custody API.

### Complete future IAM matrix

The later policy generator must derive and test this matrix against
`deploy/aws-feasibility/main.tf`, its AWS provider operations, and
`INVENTORY_QUERIES`; an unlisted provider action denies. All creation that AWS
cannot resource-scope is explicitly narrowly allowed only after application
validation of the approved account, region, campaign tags, and recorded IDs.
Every resource-scopable destructive action is restricted to exact recorded
campaign resources/tags; `iam:PassRole` is restricted to the exact host and
terminator roles with `iam:PassedToService` respectively `ec2.amazonaws.com`
and `scheduler.amazonaws.com`.

| Principal | Complete future allowed actions | Boundary |
| --- | --- | --- |
| preapproval planner | `sts:GetCallerIdentity`; EC2 `DescribeImages`; exact planning S3 `GetObject`, `GetObjectVersion`, `PutObject`, `DeleteObject`, `ListBucket`; DynamoDB `GetItem`, `PutItem`, `UpdateItem`, `TransactWriteItems` | Exact approved account/region/AMI; planning state/`.tflock` keys, immutable plan prefix, and planning namespace CAS only. No workload CRUD, `PassRole`, SSM, scheduler/budget, cleanup, or normal assumption. |
| broker | `sts:AssumeRole`, `sts:SetSourceIdentity`, `sts:TagSession` | Exact normal-cycle role only and exact encoded identity/tags; no backend, cleanup, workload, S3, DDB, or other API. |
| normal cycle | `sts:AssumeRole`, `sts:SetSourceIdentity`, `sts:TagSession` (exact backend process); `sts:GetCallerIdentity`; EC2 `DescribeImages`, `DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeKeyPairs`, `CreateVpc`, `ModifyVpcAttribute`, `DeleteVpc`, `CreateInternetGateway`, `AttachInternetGateway`, `DetachInternetGateway`, `DeleteInternetGateway`, `CreateSubnet`, `ModifySubnetAttribute`, `DeleteSubnet`, `CreateRouteTable`, `DeleteRouteTable`, `CreateRoute`, `ReplaceRoute`, `DeleteRoute`, `AssociateRouteTable`, `ReplaceRouteTableAssociation`, `DisassociateRouteTable`, `CreateSecurityGroup`, `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupEgress`, `DeleteSecurityGroup`, `CreateLaunchTemplate`, `ModifyLaunchTemplate`, `DeleteLaunchTemplate`, `RunInstances`, `TerminateInstances`, `CreateTags`, `DeleteTags`; IAM `CreateRole`, `GetRole`, `ListRoles`, `DeleteRole`, `UpdateAssumeRolePolicy`, `PutRolePolicy`, `GetRolePolicy`, `ListRolePolicies`, `DeleteRolePolicy`, `AttachRolePolicy`, `ListAttachedRolePolicies`, `DetachRolePolicy`, `CreateInstanceProfile`, `GetInstanceProfile`, `ListInstanceProfiles`, `DeleteInstanceProfile`, `AddRoleToInstanceProfile`, `RemoveRoleFromInstanceProfile`, scoped `PassRole`; Scheduler `CreateSchedule`, `GetSchedule`, `ListSchedules`, `UpdateSchedule`, `DeleteSchedule`; Budgets `CreateBudget`, `DescribeBudget`, `DescribeBudgets`, `ModifyBudget`, `DeleteBudget`; SSM `DescribeInstanceInformation`, `SendCommand`, `GetCommandInvocation`, `ListCommandInvocations`, `CancelCommand` | Exact account/region, tags, IDs, deterministic intent, and process-bound backend issuance; routine apply/destroy only; no direct custody. `PassRole` is exact host/terminator role with `iam:PassedToService` respectively EC2/Scheduler. |
| backend | exact state/lock S3 `GetObject`, `GetObjectVersion`, `PutObject`, `DeleteObject`, `ListBucket` | Exact per-process state and `.tflock` key only, native conditional lock lifecycle/version readback; no plan prefix, workload, or DDB API. |
| GitHub cleanup issuer | `sts:AssumeRole`, `sts:SetSourceIdentity`, `sts:TagSession` | Exact cleanup executor only, immutable external ID/epoch/tags and trust-policy cutoff; no graph, S3, or DDB action. |
| cleanup executor | EC2 `DescribeImages`, `DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeKeyPairs`, `TerminateInstances`, `DetachVolume`, `DeleteVolume`, `DetachNetworkInterface`, `DeleteNetworkInterface`, `ReleaseAddress`, `DeleteLaunchTemplate`, `RevokeSecurityGroupEgress`, `DeleteSecurityGroup`, `DeleteRoute`, `DisassociateRouteTable`, `DeleteRouteTable`, `DetachInternetGateway`, `DeleteInternetGateway`, `DeleteSubnet`, `DeleteVpc`, `DeleteTags`; IAM `GetRole`, `ListRoles`, `GetRolePolicy`, `ListRolePolicies`, `ListAttachedRolePolicies`, `DetachRolePolicy`, `DeleteRolePolicy`, `RemoveRoleFromInstanceProfile`, `GetInstanceProfile`, `ListInstanceProfiles`, `DeleteInstanceProfile`, `DeleteRole`; Scheduler `GetSchedule`, `ListSchedules`, `DeleteSchedule`; Budgets `DescribeBudget`, `DescribeBudgets`, `DeleteBudget`; SSM `DescribeInstanceInformation`, `GetCommandInvocation`, `ListCommandInvocations`, `CancelCommand`; signed custody requests | This independent list is not inherited from normal. No create/apply/`PassRole`/normal assumption/direct custody; only persisted unresolved IDs/tags. |
| recovery/fence | IAM `GetRole`, `GetRolePolicy`, `ListRolePolicies`, `UpdateAssumeRolePolicy`, `PutRolePolicy`, `DeleteRolePolicy`; signed custody requests | Exact normal role and named deny-all only; required trust/policy readbacks before fence wait and after removal; no assume/workload API. |
| observer | `sts:GetCallerIdentity`; EC2 `DescribeImages`, `DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeKeyPairs`; IAM `ListRoles`, `GetRole`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `ListInstanceProfiles`, `GetInstanceProfile`; Scheduler `ListSchedules`, `GetSchedule`; Budgets `DescribeBudget`, `DescribeBudgets`; SSM `DescribeInstanceInformation`, `GetCommandInvocation`, `ListCommandInvocations` | Read-only broad reads only where AWS cannot scope them; validate account, region, campaign tag/prefix, and recorded ID. |
| custody helper / journal role | plan/journal S3 `GetObject`, `GetObjectVersion`, `PutObject`, `ListBucket`; DynamoDB `GetItem`, `PutItem`, `UpdateItem`, `TransactWriteItems` | Exact plan/journal prefixes and table leading key, hash/VersionId and CAS required; no workload graph action. |

The normal and cleanup rows intentionally enumerate CRUD, tags, reads, waits,
and termination rather than use an incomplete create-only family. A generated,
static **permission-closure test** is mandatory before any future authorization:
it extracts required actions from `deploy/aws-feasibility/main.tf`, the pinned
provider inventory, SSM Online/send/get/list/cancel paths, STS/trust actions,
and every observer/fence readback; it compares that inventory to generated IAM
for each principal and fails both an omission and an unapproved extra action.
The test is source/static only until later authority and must be a required
focused governance check. Tests also enumerate every graph operation, session
lifetime, seven-cycle transition, cutoff/late-paused issuance/lost-issuance
branch, fence wait, and exact `+1` bound. Unsupported resource scopes receive
only the explicit read-only broad permission above, never broad mutation.

### Absolute windows, budget, and later-only compatibility

One normal-admission exposure forecast is 302 resource minutes: 120 normal,
32 fence (including recorded `NotAfter + 120`), and 150 cleanup/reconciliation.
At 118,000 microUSD/hour, `ceil(302 / 60 × 118,000) = **594,000 microUSD**` is
an **admission exposure forecast, not an enforced campaign cap and not a claim
that cleanup is cost-bounded**. Setup/final publication has no resource
authority. The 330-minute workflow deadline is only an ordinary workflow
boundary; sticky cleanup/manual intervention can exceed it and can exceed
594,000, with **no normal authority**. It requires a separately approved incident budget before any continued
cleanup, plus a failure-independent budget alarm and terminator that persist
and act even if executor reporting, success receipts, or cleanup logic fail.
No completion or success claim is permitted merely because an alarm/terminator
fires or a budget is exhausted. Evidence separately reports normal admission
forecast, actual spend, incident-budget approval, alarm/terminator state, and
sticky outcome; no `+1` forecast is silently admitted.

The only compatibility work is a later, separately authorized gate: first the
pinned OpenTofu `= 1.12.4` / AWS provider `= 6.54.0` non-AWS backend/saved-plan
compatibility gate, then separately authorized real-control-account native
backend compatibility. Neither is authorized, run, or claimed here because the
current authorization permits **no OpenTofu**. No plan in this ADR claims a
tofu, provider, OIDC, STS, S3, DynamoDB, SSM, inventory, or AWS effect.

## Host bootstrap contract to be implemented later

A later separately reviewed gate must choose exactly one authenticated host
bootstrap authority before the one-shot remote command: either (1) a prepared,
immutable image whose authenticated descriptor binds the complete absolute
bootstrap executable closure—launcher, script/artifact bytes, interpreter,
loader, transitive shared libraries, `git`, `python`, `tar`, `zstd`, cloud-init,
CA bundle, TLS hostname and trust-anchor/SPKI policy—or (2) bounded
deterministic cloud-init preparation that installs only that exact closure,
verifies every identity/digest and TLS trust input, persists a receipt, and
finishes before the one-shot command. Equivalently, the authenticated descriptor
may name one absolute launcher that verifies the entire closure before exec.
The command may not use ambient PATH, package resolution, bootstrap retries,
ambient TLS trust, or unverified tools. Missing image provenance, preparation
receipt, deadline, launcher closure, TLS trust closure, or any tool identity
denies. This is future source and AWS-gate work; no image,
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

Merging this plan **never authorizes dispatch**. Before implementation PR publication, a separately authorized deterministic, non-AWS readiness regeneration must refresh and pass its freshness assertions for the candidate bytes; it is repeated after feedback/final validation and never relaxed. The future `.github/workflows/ci.yml` change must check out
and verify the exact PR head SHA in **Quality**, **Secret scan**, **Images**, and every applicable root PR job. Required protected-PR evidence is exactly those successful exact-head jobs—not a synthetic merge ref and not a skipped native job. Native remains a later separately authorized
gate; product and KVM remain later gates. Main-push CI may observe merged bytes, but grants no authority and is not PR-head substitute evidence. `workflow_dispatch`, product workflow, KVM workflow, and every Stage2/AWS workflow remain forbidden by this plan; no AWS workflow is created or enabled.

Those CI results are evidence only, not product/KVM execution authority. An
offline plan draft is only a non-AWS artifact and cannot discover, authenticate,
or assert a control account, bucket, role, backend, or live compatibility. It is
distinct from later, separately authorized **authenticated control-account
planning**, which may authenticate the named planning principal and inspect the
pre-existing backend but still grants no workload credential, plan apply, or
resource effect. Product/KVM runs may be considered only in a later exact
protected-main implementation gate after focused validation,
independent exact-tree reviews, changed-since-review checks, and the required exact-head PR checks. That gate must mechanically admit the complete profile/probe matrix, sealed execution closure, limits, image provenance, failure
handoff, and shared `git-tools.sh` gate. It may authorize only first-created attempt-one product/KVM runs for that exact commit, never cancellation replacement, concurrency cancellation, rerun, retry, or redispatch.

The required pre-H order is exact:

1. separately reviewed offline pre-source compatibility design (including the
   pinned non-AWS compatibility gate and the role/fence/evidence contract), with
   no source, credential, backend, provider, or dispatch effect; authenticated
   control-account planning remains a later separately authorized gate;
2. corrected source;
3. focused tests;
4. separately authorized deterministic readiness regeneration and freshness check;
5. PR publication and required exact-head Quality, secret, images, and applicable root checks;
6. separately authorized protected product/KVM feedback runs;
7. candidate publication and durable readback;
8. separately reviewed no-mint full validation plus regenerated readiness;
9. recovery/residue validation and two independent audits;
10. final full validation and deterministic regeneration;
11. exact-tree reviews and changed-since-review checks;
12. separately authorized authenticated control-account planning and native
    backend compatibility gate, with no workload credential or resource effect;
13. separately reviewed pre-dispatch review of the exact candidate, external
    custody, normal/backend/cleanup role split, fence proof, v3 evidence
    boundaries, and unchanged denial inventory;
14. retirement/freeze decision; then
15. H.

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
