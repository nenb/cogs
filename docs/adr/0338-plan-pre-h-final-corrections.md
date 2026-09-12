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
allocated prospective matrix is exactly **19,527 / 19,000,000**, so cumulative
product ceilings are **37,527 / 27,000,000** and remediation ceilings are
**67,527 / 30,000,000**. The pre-H governance task rises honestly from its
already consumed 1,799 lines to 2,200 lines; it is not presented as one-line
headroom or funded from the AWS holdback. The source ceiling is
`18,763,891 + 30,000,000 = 48,763,891 <= 49,000,000`; tracked files are
`1,420 + 200 = 1,620 <= 1,620`. The measured current 99,908 leaves 20,092 before
the strict 120,000 hard limit; the 19,527 forward ceiling remains below it
(119,435 maximum), never deletion credit. Integration's new-file cap is 180
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
three non-transferable forecast categories deliberately consume only 6,800 /
7,800,000: deployment/custody/direct ingress 5,200 / 6,000,000; pinned
OpenTofu backend/workflow compatibility 1,100 / 1,300,000; and
approval/staging/focused authority tests 500 / 500,000. The remaining 200 /
200,000 is an **enforceable unallocated holdback**, not a fourth forecast:
config and checker require it exactly, and it can be used only by a reviewed
replan. Category forecasts are planning estimates, not measured sub-limits; the
named-task ceiling is the measured enforcement boundary. The exact config maps these forecasts to the actual integration
owner: `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`,
`.terraform.lock.hcl`, actual `completion_campaign_aws_adapter.py` and
`completion_campaign_remote_adapter.py`, bootstrap/provider, state, receipt,
and identity owners plus controller/provider/remote-adapter/state/receipt/
cycle-authority ingress tests. It also assigns the concrete cost-budget
consumers—OpenTofu budget/scheduler declarations, controller/provider,
production/receipt/state, approval/staging, and their focused tests—to that
same task and category. The three exact forecast categories and the 200/200,000 holdback are literal checker inputs: totals remain exactly 6,800/7,800,000 and 200/200,000; no category may absorb it. A slice, task, or holdback overrun stops for a reviewed
replan; no owner, forecast, category, or withheld room transfers.
It reports each task's gross consumed and remaining lines/bytes. Every task has
an explicit pre-H maximum; the final task's pre-H maximum is 1,027 / 1,300,000,
which mechanically withholds at least 3,500 / 3,500,000 for H/G/Q. This is a
capacity guarantee, not a claim that its paths are isolated: pre-H edits to a
final-task path consume that task and its pre-H maximum. The checker reports each measured consumed/remaining task total and separately
enforces the final pre-H maximum; it does not treat lower current consumption as
release. The separate 3,500/3,500,000 H/G/Q reserve remains withheld.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 2,200 / 1,000,000 pre-H maximum | ADR/index/allocation plus required readiness-before-PR order and exact-head CI workflow/topology tests |
| AWS principal denial and cycle custody | 7,000 / 8,000,000 pre-H maximum | 5,200 / 6,000,000 deployment/custody/direct-ingress + 1,100 / 1,300,000 OpenTofu/backend/workflow + 500 / 500,000 approval/staging/test forecasts; 200 / 200,000 withheld; actual adapter, planner, provider/controller/state/receipts, schemas, all direct denials, and fake adapter → provider → recovery/effect-sentinel tests |
| protected product and KVM contract | 4,000 / 3,200,000 pre-H maximum | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 1,800 / 2,000,000 pre-H maximum | readiness generators/artifacts/tests and separately reviewed no-mint grant |
| final H/G/Q control reserve | 4,527 / 4,800,000 total; **≤1,027 / 1,300,000 pre-H**, leaving **≥3,500 / 3,500,000** | all equality-test workflow mirrors, fresh v8 controls, H/G/Q guard/staging/qualification schemas and tests |

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

The planner first authenticates only that planning principal, checks the
preauthorization, and uses conditional DynamoDB writes to bind STS and AMI
*discoveries* into the approval batch. It transitions the namespace **seed** to
the discovered approval-batch namespace by CAS; discoveries never change the
seed/key. The later design separates a normal workload role, a normal native-
backend role, a cleanup-only workload role, a recovery/fence role, a session
broker, and an adapter-journal custody helper/role. The broker may only call
`sts:AssumeRole` for the two dedicated normal roles; it has no workload API,
S3, or DynamoDB permission. Cleanup is distinct in trust, permissions, tags,
and credential material and can never assume or refresh normal authority.

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
| cleanup workload | `ssm:CancelCommand`, `ListCommandInvocations`, `ec2:DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `TerminateInstances`, `DetachVolume`, `DeleteVolume`, `DetachNetworkInterface`, `DeleteNetworkInterface`, `ReleaseAddress`, `DeleteLaunchTemplate`, `DeleteSecurityGroup`, `DeleteRoute`, `DisassociateRouteTable`, `DeleteRouteTable`, `DetachInternetGateway`, `DeleteInternetGateway`, `DeleteSubnet`, `DeleteVpc`, `scheduler:GetSchedule`, `DeleteSchedule`, `budgets:DescribeBudget`, `DeleteBudget`, `iam:GetRole`, `GetPolicy`, `DetachRolePolicy`, `DeleteRolePolicy`, `DeletePolicyVersion`, `DeletePolicy`, `RemoveRoleFromInstanceProfile`, `DeleteInstanceProfile`, `DeleteRole`, `RevokeSession` | Only persisted unresolved intent IDs and exact campaign tags; broad describe/list is granted only for named AWS read actions lacking resource scoping, then application validates exact account/region/tag/ID. No create, normal effect, or direct custody write. |
| observer | `ec2:DescribeInstances`, `DescribeVolumes`, `DescribeNetworkInterfaces`, `DescribeAddresses`, `DescribeLaunchTemplates`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`, `DescribeRouteTables`, `DescribeInternetGateways`, `ssm:ListCommandInvocations`, `scheduler:GetSchedule`, `budgets:DescribeBudget`, `iam:GetRole`, `GetPolicy` | Read-only; broad describe/list only where AWS lacks resource-level scope; application verifies exact account, region, tags, and IDs. |
| recovery/fence | `iam:PutRolePermissionsBoundary`, `iam:UpdateAssumeRolePolicy`, exact custody-request action | Exact dedicated normal-role ARNs; unconditional deny-all and disabled trust only; no assume or workload API. |
| adapter custody helper | `s3:GetObject`, `PutObject`, `ListBucket`, `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `TransactWriteItems` | Exact journal S3 prefix and DynamoDB table/leading key only; application CAS/conditional expressions are mandatory for every journal/pointer/lease write. |

No table row gets a wildcard resource effect. Where an AWS action cannot be
resource-scoped, its broad permission is explicit and the application validates
exact account, region, tags, and IDs before accepting the result; where AWS
supports destructive resource scope, the policy uses it.

Only after that proof does recovery admit one separately authenticated cleanup-only owner. It reconciles every accepted asynchronous normal intent by its deterministic `(campaign, cycle, epoch, verb, prior-state)` ID and exact campaign/intent tags. For each recorded SSM `(command-id, instance-id)` it observes that exact pair terminal, or sends one recorded cancel intent and observes the same pair's terminal cancellation; a different command, instance, status, absent output, or absent observation is uncertainty. Cleanup authority covers the complete exact tagged/ID graph, in dependency order: (1) SSM command; (2) instance, attached EBS volumes, ENIs, and EIPs; (3) scheduler and budget; (4) launch template; (5) IAM attachments, customer policies, instance profile, and role; (6) security group, routes, route-table association, internet gateway, subnet, and VPC; then (7) final cleanup of the declared external backend objects where applicable. Every delete/cancel/terminate/revoke has a durable deterministic intent `(campaign, cycle, epoch, verb, exact-ID, prior-state)`, exact tag and ID scope, bounded observe/reconcile loop, and lost-response rule: no ambiguous intent is reissued. Dependency failure, foreign tag/ID, missing readback, or unresolved response is sticky uncertainty. The future least-privilege cleanup policy must enumerate exactly the corresponding SSM cancel/list, EC2 terminate/describe/delete/detach/release, Scheduler delete/get, Budgets delete/describe, IAM detach/delete/remove/revoke/ get, and custody-service request actions, each restricted to the recorded campaign tags and IDs; no wildcard create, normal-effect action, or direct custody-store mutation is granted to cleanup. It waits through every delegated credential `NotAfter` where one was issued. Only then does the independently authenticated, read-only observer perform two complete, bounded, account-and-region inventory passes separated by the configured poll interval. Every observation is authenticated, tagged, persisted, and read back; any missing, foreign, incomplete, late, or contradictory observation is sticky uncertainty. A paused old process may resume only with its fenced credential; its request must be rejected.

Recovery has no successor NORMAL authority. The cleanup admission record is not terminal settlement. Exactly one independently authenticated, read-only observer may hold the matching observation lease; both differ from executor, planner, approver, and each other. A cleanup owner acts only on externally persisted unresolved intents in its fenced epoch: reconcile, cancel, terminate, revoke, delete in the declared graph order, and request the observer's inventory. It may never do normal work, issue a new normal intent, or reissue an ambiguous normal **or cleanup** intent. The observer can only read and persist the two fenced inventory passes. Their leases and credentials end no later than cleanup; loss/expiry leaves sticky uncertainty.

Each cleanup epoch requests an actual `DurationSeconds=1800` credential, above
AWS's 900-second minimum. There are at most two epochs: epoch one is bounded to
1,800 seconds, then a 120-second NotAfter/skew fence, then epoch two is bounded
to 1,800 seconds, leaving 1,680 seconds of the 90-minute cleanup phase for
separately bounded reconcile/inventory/terminal operations. A second owner can
be admitted only after the first NotAfter + 120 seconds, fence proof, and a
CAS-persisted unresolved-cleanup intent set. It continues deterministic IDs and
never replaces an ambiguous operation. If it cannot settle, the result is sticky
uncertainty/manual intervention with **no normal authority**. No third epoch,
credential refresh, or promotion exists.

Only final-byte durable, versioned readback, hash-bound **terminal settlement** (complete graph, credentials, and inventory) gates any future normal authority, normal epoch, normal credential, or normal invocation. A cleanup recovery process is not a normal process: it may be admitted only under the preceding two-epoch fenced rule and only to finish persisted unresolved cleanup. No normal process, invocation, epoch, or credential is admitted until the old epoch's terminal settlement record has had its final byte durably written, versioned read back, and hash-bound.

One absolute workflow budget is fixed: setup `10` minutes + normal resource
window `120` minutes + revoke/fence propagation and old-call proof `10` minutes
+ cleanup/reconciliation `90` minutes + final publication `10` minutes = `240`
minutes. Resource exposure includes the control/fence phase: `120 + 10 + 90 =
220` minutes. At 118,000 microUSD/hour its ceiling is
`ceil(220 / 60 × 118,000) = 432,667` microUSD, strictly below 500,000. Setup and
final publication have no priced resource authority. The two actual 1,800-second
cleanup sessions, their 120-second fence, and the separately bounded remaining
operations fit inside cleanup and never borrow from final publication. Tests
must enumerate every graph operation, IAM action, bounded level, credential
lifetime, both cleanup epochs, propagation proof, and this exact phase/resource
sum; a new action, serial level, lifetime, or `+1` minute/microUSD overrun
denies. Later `stage2-production-plan` and `stage2-production-approval` drafts each timeout at 30 minutes and are non-effecting. First the plan draft is read back; then approval consumes that exact draft; then the immutable approval is read back and must be unexpired at campaign admission. Its admission validity spans only normal authority and ends no later than the 120-minute normal resource boundary; cleanup/recovery derives only its previously persisted cleanup credential, never an approval refresh. No plan/approval refresh, normal effect, or grant is allowed after that boundary. These are future contract/schema/workflow timeouts, not authority now.

The future v3 evidence schema/validator/renderer/tests must expose separate absolute `normal_deadline` and `cleanup_deadline` fields, the 10/120/10/90/10 phase commitment, 432,667-microUSD resource-exposure ceiling, normal workload/backend fence proof, cleanup epoch count/NotAfter/skew, and terminal publication deadline. They must retain historical v1/v2 decoding as decode-only input: historical bytes may render their historical form but cannot satisfy v3 authority, settlement, or issuance. Boundary tests cover each phase exact limit and `+1`, old-token rejection before cleanup, accepted async SSM reconciliation, first and second cleanup admission, failed second settlement, and final-byte normal re-admission ordering. This ADR does not alter the existing schema, validator, renderer, fixtures, or tests.

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
