# ADR 0338: Temporary AWS test-campaign plan

## Status

Accepted as **Row 1 only**. This is a temporary, source-only plan. It authorizes
source implementation, focused validation, and PR CI. It authorizes no product
or KVM dispatch, no AWS, OpenTofu, or SSM effect, and no H/G/Q action.

## Accounting and hard cap

`eda2dc499153f3053772790c02ea6d332403742e` / tree
`9ad48a2be811745f0d8032a0a9f52a33c4b2edec` remains the protected product
checkpoint. Every successor must be a direct linear child. Accounting is
cumulative from that checkpoint: every added line and UTF-8 added-line byte
from every local plan commit remains charged. Deletion, rewrite, rename,
compression, and net-tree comparisons provide no credit.

The already-consumed product allocation is 18,000 lines / 8,000,000 bytes.
The temporary plan allocates at most 21,557 / 20,200,000 more, for cumulative
forecasts of 39,557 / 28,200,000. The independently retained remediation
allocation remains 48,000 / 11,000,000, with its existing 78,000 / 35,000,000
ceiling unchanged. The strict hard cap is **132,000 lines**. It is a hard stop,
not headroom. The final-HGQ reserve leaves 3,500 lines / 3,500,000 bytes
unavailable before a later review.

| Exact named task | Gross cap (lines / bytes) | Exact paths / purpose |
| --- | ---: | --- |
| governance | 6,000 / 1,100,000 | ADR0338/ADR0339/ADR0340, index, budget, central checker, focused budget test |
| product | 4,000 / 3,200,000 | protected product workflow and ancestry record; `.github/workflows/kvm-qualification.yml`, `dev/linux-kvm/driver.sh`, `dev/linux-kvm/bounded-command.py`, `test/linux-kvm-git-tools.test.ts`, `test/dev-launcher-profiles.test.ts`, and current separate empty/nonempty runners and existing capability probes with profile-bound receipts/tests |
| local-tofu-ssm | 4,457 / 8,400,000 | Production plan/approval/campaign workflows; Python planner, approval stager, adapter, provider/controller, normal cleanup shell entry; and their fake planner/provider/adapter/workflow tests |
| readiness-ci | 1,800 / 2,000,000 | `.gitleaksignore`, protected-main CI, and source-inventory/readiness files and tests |
| final-HGQ | 5,300 / 5,500,000 | no Row 1 implementation paths; exact hosted full-check wrappers are `test/aws-stage2-completion-kata-mutable-bridges.test.ts`, `test/aws-stage2-completion-kata-runtime.py`, `test/aws-stage2-completion-kata-runtime.test.ts`, `test/aws-stage2-completion-local-result.test.ts`, and `test/stage2-prebuilt-local-kata-workflow.test.ts`; at most 1,800 / 2,000,000 pre-H, retaining the unavailable 3,500 / 3,500,000 reserve |

The checker has no catch-all task: a changed or untracked path outside these
literal lists fails. The source inventory remains at protected-main caps of
1,530 tracked files and 34,000,000 bytes; historical envelope arithmetic does
not enlarge that runtime guard.

## Permitted future source scope

Only the following temporary campaign work may be implemented under this row:

1. Protected product empty and nonempty cases use separate runners. Existing
   capability probes remain in place and their receipts/tests stay bound to
   the selected profile.
2. The actual Python production planner initializes a **local** backend and
   gives each cycle separate local `TF_DATA_DIR`, state, and plan paths. It
   rejects stale or cross-cycle inputs. Tests use fakes only; they must not
   invoke OpenTofu.
3. The provider waits, within a bounded deadline, for the exact instance to be
   SSM `Online`, sends exactly one command, and polls that same
   command-and-instance pair. Orchestration never resends. Tests use fakes.
4. Planner bootstrap preserves a bounded complete OpenTofu AWS provider package
   (ordinary files including `LICENSE` and the executable) by exact relative
   names, modes, byte counts, and SHA-256 digests. Its mode-bearing tar archive,
   archive digest, and manifest pass unchanged through approval; campaign safely
   extracts and verifies that exact closure before staging only it in the
   filesystem mirror used by `init -lockfile=readonly`. No package acquisition
   or execution is authorized.
5. The existing normal cleanup path remains intact. On its normal path it
   destroys and confirms zero before the next cycle.

No other product behavior, provider control-plane design, credential design,
or launch mechanism is planned by this ADR.

## Accepted temporary risk

The user accepts that loss of a GitHub runner can leave temporary AWS resources.
Such a run is failed or uncertain: it has no automatic retry, success claim, or
reuse. Cleanup may be performed manually later. This risk does not relax the
normal path: it still destroys and confirms zero before the next cycle.

## Validation boundary

Row 1 validation is limited to the central checker, focused fake tests, format
and diff checks, and PR CI. No check or merge authorizes product/KVM dispatch,
AWS/OpenTofu/SSM activity, or a later H/G/Q transition.

## Post-Q documentation revision allocation

After replacement Q `4e16c314b220c59330a1b4fb898c532f9ca6460e` completed the
non-AWS qualification, the owner requested one documentation/governance-only
protected planning revision. The new `BUGS-TO-FIX.md` records explicitly
accepted deferred review findings without changing campaign implementation or
workflow bytes. Admit that file only to the existing governance and integration
inventories.

A deterministic readiness refresh replaces one already large generated
validation line. Without deletion credit, reallocate 100,000 prospective bytes
from the otherwise unused `local-tofu-ssm` task to `readiness-ci`: their active
highs become 7,300,000 and 4,400,000 bytes. Their line highs, every other task
high, the 21,500,000-byte remaining-tranche total, the 29,500,000-byte forecast,
and all global/source byte hard stops remain unchanged. Raise only the complete
tracked-file maximum from 1,540 to 1,541 for the one new documentation file.
This one-time reallocation and cardinality increment fund only the post-Q
documentation, synchronized governance assertions, and required deterministic
readiness refresh. It grants no AWS identity, API,
provider, OpenTofu, SSM, inventory, deployment, or campaign authority.

The first protected planning generation later completed successfully but expired
unused before destructive approval. Recording that disposition in the same
tracked governance document requires a second deterministic readiness refresh,
whose one-line generated inventories receive no deletion credit. Reallocate a
further 600,000 prospective bytes from the unused `local-tofu-ssm` task to
`readiness-ci`; their active highs become 6,700,000 and 5,000,000 bytes. Keep
all line highs, the total remaining-tranche bytes, forecasts, global limits,
tracked-file maximum, campaign implementation, and workflow bytes unchanged.
This R2 accounting permits only the expired-generation record and synchronized
local readiness evidence; fresh planning and every AWS effect still require
their separate authorization gates.

Protected R2 `89b0a5b5843373ab92710ce92008fe1b4e6ca658` planning run
`35114827724` and artifact `10454702483`
(`sha256:1159450680d732f03f398a04e19b442cf022436e05714defab66575a7683d379`)
passed independent readback and semantic review, but its sole attempt-one
approval run `35118929555` failed before signing or artifact publication: the
pinned non-root Cosign container could not traverse the runner-owned
mode-`0700` approval directory. It produced no approval artifact, no campaign
was dispatched, and all temporary IAM roles and ARN variables were removed.
Treat the complete R2 planning and approval generation as terminal and
non-authorizing. Authorize one narrow R3 correction that runs both
pinned Cosign invocations under the exact positive numeric UID/GID owning that
private directory, asserts that binding in synchronized tests, records the
failed run and absent artifact additively, and refreshes deterministic readiness
evidence. The correction must preserve the private directory, pinned image,
keyless identity, offline verification, H/G/Q, all campaign implementation, and
all non-approval workflow bytes. Admit the existing synchronized production-
approval test path to the `local-tofu-ssm` task without changing any task high,
forecast, global limit, or tracked-file maximum. The correction remains inside
those existing task and source highs and grants no retry, planning, approval,
provider, or AWS-effect authority.

Protected R3 `cb30f534ce8801f605a5c021656d7569ff35306c` planning run
`35148506458` and artifact `10468186158`
(`sha256:f84383926493be9e7f98592c38b9479a18c1a1676891ab11f5c682e6fe44c80b`)
also passed exact archive readback and semantic review. Its sole attempt-one
approval run `35150577796` failed before signing or publication because the
exact runner UID had no writable container home and pinned Cosign attempted
`mkdir /.sigstore` during TUF initialization. It produced no approval artifact,
no campaign was dispatched, and all temporary IAM roles and ARN variables were
removed. Treat the complete R3 planning and approval generation as terminal and
non-authorizing.

Authorize one narrow R4 correction that centralizes the exact pinned signer,
uses separate mode-`0700` runner-owned signing and verification homes, and adds
one singleton protected diagnostic exercising the complete keyless path before
any IAM setup or fresh planning: live TUF initialization, GitHub OIDC,
Fulcio/Rekor signing, bounded bundle creation, fresh-home network-disabled
verification against the committed trusted root and exact identity/issuer,
pinned binary extraction/hash, and diagnostic artifact upload. Preserve H/G/Q,
all campaign execution implementation, the private approval directory, and
every non-approval production workflow byte. Add only the signer and diagnostic workflow
to the existing `local-tofu-ssm` task, and raise the tracked-file source limit
from 1,541 to 1,543 for those two files. The deterministic readiness refresh
needs no deletion credit; reallocate 300,000 prospective bytes from the unused
`local-tofu-ssm` task to `readiness-ci`, making their active byte highs 6,400,000
and 5,300,000. Keep every line high, the 21,500,000-byte tranche total,
forecasts, global limits, and all other source limits unchanged. Neither R4 nor
its diagnostic grants a retry, planning, approval, provider, campaign, or AWS-
effect authority.

Protected R4 `1116692df81f40c9f3f60c0a7448bcb46167cc61` first passed
singleton non-authorizing signing diagnostic run `35168491742` and artifact
`10475417794`
(`sha256:c43103ce7b93c62f3345bb93fe7ce8945ad6ae1f21a6889d123aba46a39a0b08`).
Its exact pinned signer completed live TUF initialization, GitHub OIDC,
Fulcio/Rekor signing, bundle publication, fresh-home network-disabled
verification, binary custody, and artifact readback. That diagnostic remains
valid and grants no campaign authority.

R4 then produced sole attempt-one planning run `35170392903` and artifact
`10476681104`
(`sha256:a99eb16c3766a6021e177753d3be9d49279f30d598491c862e6df303d6f52182`).
Exact archive readback and expanded review accepted all seven distinct
create-only plans under batch
`447f6e4a73aab1911bb66f07e4b86f92501592dd58e9e341c4ddb1cbb337e4a8`.
Sole attempt-one approval run `35172329037` and artifact `10476784540`
(`sha256:60680ae214d4ea43e4bf0c4214800a915ebe1f7d7a8e9cac9c3fbfe12ed24ffc`)
also passed. Independent readback proved exact inherited plan bytes, canonical
approval bindings, pinned binary and provider custody, one Rekor inclusion
proof, one RFC3161 timestamp, and offline verification of the exact protected
approval-workflow identity and GitHub issuer.

No destructive authorization was issued before the approval expired at
`2026-09-17T08:24:18Z`; no campaign run or campaign resource was created. The
three temporary IAM roles and ARN variables were removed, and independent
inventory found zero campaign instances, volumes, networks, IAM resources,
schedules, or budgets. Treat the complete R4 planning and approval generation
as expired unused, terminal, and permanently non-authorizing. Neither workflow
may be retried at R4, and neither artifact may authorize a later campaign.

Authorize one direct-child protected R5 governance-only successor to record
that disposition, add synchronized assertions, and refresh deterministic
readiness evidence. R5 must preserve H/G/Q, the successful R4 signing
diagnostic, all signer, approval, planning, campaign, provider, and executable
bytes, and the immutable historical artifacts. Its deterministic readiness
refresh receives no deletion credit; reallocate another 300,000 prospective
bytes from the unused `local-tofu-ssm` task to `readiness-ci`, making their
active byte highs 6,100,000 and 5,600,000. Keep every line high, tracked-file
limit, tranche total, forecast, and global/source limit unchanged. R5 grants no
IAM setup, planning, approval, retry, AWS API, OpenTofu, SSM, resource, or
campaign authority. Only after R5 is protected may fresh temporary roles be
separately established; fresh planning still requires the exact read-only
authorization phrase and a new complete supervised window.

Protected R5 `87be0712de3889721b7c4ed3194c32646f823356`
produced sole successful attempt-one planning run `35225324388` and artifact
`10498263515`
(`sha256:1df0a4f015d225464929b1dece0b4a2d24fe75bf3cddf5ecb8ea9c0360101350`).
Independent exact archive readback accepted all seven distinct create-only plans
under batch
`5a29a9601d008640d7789adef3b0a7914b1bff5e71b520d5ea07a0eb0db4f931`.
The draft began at `2026-09-17T13:09:43Z` and stated expiry at
`2026-09-17T20:09:43Z`. The campaign's unchanged 20,000-second minimum
credential duration and 60-second margin nevertheless closed admission at
`2026-09-17T14:35:23Z`, only 5,140 seconds after planning began. Independent
review was not complete before that hidden cutoff. The pre-dispatch guard
therefore rejected later approval authorization before any approval or campaign
workflow dispatch.

No approval or campaign run exists at R5. No campaign resource was created and
campaign spend was zero. All three temporary IAM roles and ARN variables are
absent, independent inventory reports zero campaign resources, and the inert
GitHub OIDC provider remains. Treat R5 planning as terminal and permanently
non-authorizing; it cannot be retried or used by a successor.

The owner expressly supersedes the earlier no-production-control-plane-redesign
constraint only for one narrow direct-child protected R6 correction. Change the
campaign's minimum derived credential duration from 20,000 to 16,500 seconds.
The existing seven-hour approval lifetime and 60-second margin then provide a
visible 8,640-second (`2h24m`) planning-to-admission interval. The new minimum
still contains the complete 14,700-second effect-and-cleanup envelope plus 1,800
seconds for post-credential staging. The strict eight-hour maximum remains
unchanged. Add focused exact-guard assertions and record this disposition in
the existing governance surfaces.

R6 must preserve exact H/G/Q, the qualified runtime, planner, approval signer,
campaign controller, provider, Terraform graph, effect deadline, cleanup
reserve, cost bound, evidence formats, terminators, and every destructive
authorization gate. It may refresh deterministic readiness evidence for its
exact source without deletion credit. Reallocate 200,000 prospective bytes from
the unused `local-tofu-ssm` task to `readiness-ci`, making their active byte
highs 5,900,000 and 5,800,000; keep every task line high, tracked-file limit,
tranche total, forecast, and global/source limit unchanged. After protected CI,
fresh IAM setup and read-only planning still require their separate
authorization; authenticated approval and
`authorize-seven-stage2-production-cycles` remain later human gates.

PR #557 passed every required protected check and merged as R6
`2975deffaf20f518d6611f5757fc2778f7e53d50`, sole child of R5, with reviewed
tree `48c379d2027df7016f7aca5a1eca09b45cdb9cd3`. Exact-R6 Linux foundations run
`35259074785`, attempt 1, passed. Exact-R6 CI run `35259074947`, attempt 1,
failed only while downloading pinned packages for the unchanged insecure-
container image: Debian Snapshot returned `TooManyRequests 503 No healthy
backends` for seven package archives. Quality, secret scanning, worker and
sandbox image builds, and all completed jobs passed. This external snapshot-
availability failure is not evidence against the campaign-admission change, but
a failed exact-head generation grants no production planning authority and
cannot be retried into authority.

No R6 IAM setup, planning, approval, campaign, provider, OpenTofu, SSM, or
resource operation occurred. Treat R6 as terminal for production planning.
Authorize one direct-child protected R7 governance-only successor that records
this failure and preserves the complete R6 tree except synchronized governance,
accounting assertions, and deterministic readiness evidence. Reallocate another
300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making their
active byte highs 5,600,000 and 6,100,000, while keeping every task line high,
tranche total, forecast, and global/source limit unchanged.

R7 must not change H/G/Q, the 16,500-second campaign guard, or any planner,
signer, campaign controller, provider, Terraform, cost, cleanup, terminator, or
evidence behavior. Only a clean first-created attempt-one protected R7 and
successful exact-R7 post-merge CI/foundations may proceed to temporary IAM
setup. Fresh read-only planning, authenticated approval, and destructive
campaign authorization remain separate later gates.

Protected R7 `6a28492a70ee3b0eaffa57e8355070ee865492b9`, tree
`e52a42a82456182d5a0e5cb618b2430d3550d74f`, passed exact-head attempt-one CI
`35269083825` and Linux foundations `35269083795`. Sole read-only planning run
`35275965649` produced artifact `10519889589`
(`sha256:22948dfcc672cd9ec2c15457d205fde5f8a79e6784d9e295d2f63e3f50a9acb5`)
and seven independently accepted plans under batch
`1e6f37299df6bd92ced863afca4b5298b61311f1a43cd5a4da1f5a0905f31151`.
Sole authenticated approval run `35278527916` produced independently verified
artifact `10521084322`
(`sha256:43e775acd96f7994612c6db70370d97e921fe42e2039586731647ad911ef9fe7`).

Sole attempt-one campaign run `35281016121` authenticated and staged those
exact bytes, acquired the independently committed executor and observer
identities, and created the first cycle graph. It then failed during OpenTofu
apply before a provider apply receipt, SSM command, workload, or measurement.
Its cleanup-only recovery also failed before any delete call. CloudTrail
independently recorded `budgets:ListTagsForResource` `AccessDenied` during the
Budget create readback at `2026-09-17T22:17:56Z`, apply refresh at
`2026-09-17T22:18:25Z`, and recovery refresh at
`2026-09-17T22:18:38Z`. The temporary executor policy allowed Budget
modification, tagging, untagging, and viewing but omitted that distinct
provider-required tag-read action. Pinned provider v6.54.0 calls
`ListTagsForResource` while reading a Budget and propagates the error, so apply
could not settle and recovery could not reach destroy. The provider's observed
`GetInstanceUefiData` call with an AMI ID is explicitly ignored on error by its
pinned AMI reader and is not the causal failure.

The operator authenticated the exact batch tags and graph identities, deleted
the termination schedule, terminated the sole instance, waited for its
DeleteOnTermination volume and network interface, and then removed the exact
launch template, route association and table, gateway, security group, subnet,
VPC, two campaign roles, instance profile, and budget. Repeated independent
inventory returned total zero by `2026-09-17T22:23:06Z`. The three temporary
GitHub OIDC roles and ARN variables were then removed; the inert OIDC provider
remains. Campaign run `35281016121` published no artifact. No cycle succeeded,
no SSM command or workload ran, and R7 planning, approval, and campaign bytes
are terminal and permanently non-authorizing.

Authorize one direct-child protected R8 correction. After approval verification
and acquiring the executor identity but before sealing credentials or any
resource effect, call `budgets:ListTagsForResource` on an exact nonexistent
`cogs-s2-permission-probe-<run>` budget ARN. Require the authorized
`NotFoundException`, reject `AccessDenied`, retain no probe output, and perform
no write. Fresh IAM bootstrap must add and independently simulate
`budgets:ListTagsForResource` before planning. Add synchronized workflow and
governance assertions and refresh deterministic readiness evidence without
deletion credit. Reallocate 300,000 prospective bytes from `local-tofu-ssm` to
`readiness-ci`, making their active byte highs 5,300,000 and 6,400,000, while
keeping every task line high, tranche total, forecast, and global/source limit
unchanged.

R8 must preserve exact H/G/Q, the 16,500-second campaign guard, planner,
approval issuer, controller, provider, Terraform graph, effect and cleanup
deadlines, cost bound, terminators, and evidence formats. It grants no same-byte
retry or inherited planning, approval, or destructive authority. Only a clean
protected R8 and successful exact-head post-merge checks may proceed to fresh
IAM setup. Fresh read-only planning authorization, authenticated approval
authorization, and `authorize-seven-stage2-production-cycles` remain separate
later gates.

Protected R8 `fff2b20f89b1aae26158376104ada8425f8a0d19`, tree
`7213123761ef06efbae50a653a3a17604d96cb3d`, passed exact-head attempt-one CI
`35289516189` and Linux foundations `35289516201`. Sole planning run
`35293994076` produced independently accepted artifact `10526314592`
(`sha256:6d4c5deb521734dcde4ecbca203fdf1b94f7d945fe586a7e110ee9214c29130d`)
under batch `596afdde2cb6c6ae20c6e6e7b385c1829c87bfcf34b61dd58be68d5fc7b1b187`.
Sole authenticated approval run `35295519831` produced independently verified
artifact `10527701595`
(`sha256:7b1ecc45c2818c884ae112d8ca28b7431585612bc909100d05a90f87ba163b5f`).

Sole attempt-one campaign `35297082154` passed approval verification, acquired
both OIDC identities, and proved the corrected pre-effect Budget tag-read
permission through the required `NotFoundException`. Cycle 1 then applied its
resource graph, launched `i-00d50d862530755a0`, and sent sole SSM command
`06a3f62c-20b4-4bfa-9f75-b45e2196bacc`. That command failed after nine seconds
with response code 2 and exact diagnostic `immutable Stage 2 preparation failed
at entry`. No Kata launch, workload, measurement, successful cycle, or evidence
artifact occurred.

The fixed immutable preparer rejects all ambient `AWS_*` and acquisition-
authority variables before changing its diagnostic stage from `entry`.
`completion_campaign_aws_provider.py` generated the SSM shell with a direct
`python3 -I -B .../completion_kata_immutable_preparation.py` invocation instead
of the fixed clean environment used by every reviewed local owner entry. Root,
zero-argument, Linux x86_64, and exact source-path conditions were established;
the AWS SSM ambient environment was the remaining entry mismatch. The provider
must invoke immutable preparation through exact `/usr/bin/env -i` values before
`/usr/bin/python3 -I -B`. This is an H-owned provider correction, not a
same-byte R8 retry.

CloudTrail recorded immediate destruction of the cycle-1 graph. Independent
inventory returned exact zero at `2026-09-18T02:06:33Z`, `02:07:15Z`, and
`02:07:58Z`, and again after temporary IAM cleanup. The terminated instance has
no attached volume or network interface; its volume returns
`InvalidVolume.NotFound`. All three temporary roles and ARN variables were
removed, no static credential exists, and the inert OIDC provider remains.
R8 planning, approval, campaign, and destructive authorization are terminal.

Before another formal H/G/Q chain, authorize one protected non-authoritative R
diagnostic candidate. It may change only the H-owned provider's immutable-
preparation invocation to the exact clean environment, add executable hostile-
environment regression coverage, add distinct diagnostic-only planning,
signing, seven-cycle campaign, readback and cleanup workflows, synchronized
governance assertions, and deterministic readiness refresh. The diagnostic
workflows must use distinct phrases and artifact names, set production and Issue
42 eligibility false, publish no accepted production evidence, and refuse every
formal production workflow run at the candidate revision. They retain the same
OIDC roles, pinned tools, plans, cost controls, deadlines, independent observer,
seven sequential cycles, recovery and zero-inventory requirements.

The preparation authorization grants source changes, local validation,
protected CI, merge, and later read-only diagnostic planning only. It grants no
AWS resource effect. A real diagnostic campaign still requires the distinct
phrase `authorize-seven-stage2-non-authoritative-diagnostic-cycles`. A failed or
uncertain diagnostic grants no evidence credit and cannot be rerun without new
destructive authorization. Only an end-to-end seven-cycle diagnostic pass may
make its exact unchanged candidate bytes eligible to enter a fresh formal
H -> G -> Q process; the diagnostic itself grants no H, G, Q, R, production,
release, or Issue 42 closure authority. Raise only the tracked-file high from
1,543 to 1,545 for the two literal diagnostic workflow files. Reallocate
300,000 prospective bytes from `local-tofu-ssm` to `readiness-ci`, making their
active byte highs 5,000,000 and 6,700,000. Keep every line high, tranche total,
forecast, serialized-inventory bound, and global source-byte limit unchanged.

Protected diagnostic candidate `8f1bf3032668c6f986fa31145911a42c0ece7925`,
tree `a9d3635aa67be3d047f97dc57a9e2c7242d1b140`, passed exact-head
attempt-one CI `35354704622` and Linux foundations `35354704494`. Fresh
account-wide inventory found zero active resources in all 17 enabled regions,
exact Stage 2 inventory was zero, and the temporary OIDC roles passed
independent allow/deny simulation. Sole attempt-one diagnostic preparation run
`35369019149` authenticated the exact historical fixture, assumed only the
read-only planning role, generated seven fresh plans, retired credentials, and
published explicitly non-authoritative planning artifact `10557980075`
(`sha256:3cd400242d442cbb741d50a3e737c4e1cce87cbcf61dcf41612755c91c5fc862`).

The run failed at its first exact artifact readback comparison because the
planner output retained local scratch directory `plans/.provider-tf-data`, while
`actions/upload-artifact` correctly omitted that hidden, explicitly unstaged
bootstrap cache. No approval was issued or signed, no diagnostic campaign was
dispatched, and no EC2, OpenTofu apply, SSM, Kata, workload, or campaign effect
occurred. Exact inventory remained zero; all three temporary roles and ARN
variables were removed. The run, artifact, plans, window authorization, and
candidate are terminal and permanently non-authorizing.

Authorize a direct-child diagnostic preparation correction that verifies and
removes only the disposable `.provider-tf-data` tree after the production
planner returns, rejects every remaining hidden planning path, and performs the
existing exact readback over the published planning bytes. This preserves the
planner, provider, adapter, qualified fixture, seven plans, signer, campaign,
AWS graph, deadlines, costs, recovery, and evidence behavior. The correction
may receive local validation, protected CI, and merge, but no workflow retry,
IAM setup, planning, signing, approval, or AWS effect. A fresh
`start-stage2-r-diagnostic-window` remains mandatory for the replacement
candidate; destructive diagnostic authority remains separately absent. The
regenerated one-line source inventory exhausts the prior `readiness-ci` byte
margin, so reallocate 300,000 prospective bytes from `local-tofu-ssm` to
`readiness-ci`, making their active byte highs 4,700,000 and 7,000,000. Keep all
line highs, tranche totals, forecasts, source limits, and the global high
unchanged.

Protected replacement diagnostic candidate
`ce4b5895e16e882067cd01bc258394e25bc42048`, tree
`bb324ac7763caca746e734353d7b60257f2c5ec7`, passed exact-head attempt-one CI
`35377483991` and Linux foundations `35377483993`. Under the single complete
non-authoritative diagnostic authorization, fresh account-wide and exact Stage
2 inventories were zero and temporary OIDC roles passed independent policy
verification. Sole attempt-one preparation `35390352878` again generated seven
plans, removed the disposable bootstrap cache, passed exact artifact readback,
and published non-authoritative planning artifact `10566006682`
(`sha256:65ed5766f877e3302a2d3f0c96c685269827305bf54d1586b96971c94526ea18`).
It then failed at approval issuance because the diagnostic workflow exported
`CONTROL_HEAD` but omitted the issuer's closed environment name
`COGS_STAGE2_CONTROL_REVISION`.

No approval or signature was produced, no campaign was dispatched, and no AWS
resource effect occurred. Exact inventory remained zero and all temporary roles
and ARN variables were removed. The candidate, run, artifact, plans, and
complete-run authorization are terminal and permanently non-authorizing.
Authorize only a direct-child preparation correction that maps the existing
exact control input to the issuer's required environment name and asserts that
mapping. Preserve every planner, provider, adapter, immutable-preparation,
signer, campaign, graph, deadline, cost, recovery, and evidence byte. The
replacement receives validation and protected merge authority only; one new
upfront complete diagnostic authorization remains required before any workflow
or IAM operation. Reallocate another 300,000 prospective bytes from
`local-tofu-ssm` to `readiness-ci`, making their active byte highs 4,400,000 and
7,300,000 while preserving all line highs, totals, forecasts, source limits,
and the global high.

Protected main `3be83879c87b552f7cdb07480ceda5e843add905`, tree
`570b8f4c527d8156ca14d4db389a999f060be70a`, contains that exact environment
mapping. PR checks CI `35392818607` and Linux foundations `35392818603` passed
at its identical reviewed tree. At the owner's request to stop spending CI
before a complete diagnostic audit, post-merge CI `35397053515` and Linux
foundations `35397053474` were explicitly cancelled. They grant no exact-head
candidate authority and must not be retried or combined with the PR checks.

The subsequent no-cloud audit downloaded exact failed-run artifact `10566006682`
and matched its GitHub digest. All seven plan binaries matched the draft, all
seven JSON plans passed the production plan checker, and every staged-plan
binding matched. The exact failed draft and prerequisite package then passed
the real approval issuer and authenticator with the corrected environment.
Forty-one focused workflow, approval, adapter, provider, controller, receipt,
state, remote, cycle-authority, Linux-integration, and V3-evidence tests passed.
Diagnostic normal and recovery entries also executed with a fake adapter under
the exact clean selector environment. Every preparation and campaign input,
environment, artifact member, identity selector, overlay, execution, recovery,
and evidence handoff was reviewed; no additional diagnostic defect was found.
No workflow or AWS operation occurred, exact inventory remained zero, and the
temporary roles and variables remained absent.

Authorize one replacement candidate that adds only durable versions of those
diagnostic entry/recovery and handoff assertions plus this cancellation/audit
disposition. It must preserve every R-path implementation byte, perform complete
local validation before publication, and receive one protected PR and exact-main
check sequence. No IAM or AWS workflow is authorized. After a clean candidate,
one later upfront `authorize-complete-stage2-r-non-authoritative-diagnostic`
may cover preparation, signing, all seven real cycles, evidence validation,
zero inventory, and IAM cleanup without intermediate human gates. Reallocate
300,000 further prospective bytes from `local-tofu-ssm` to `readiness-ci`,
making active byte highs 4,100,000 and 7,600,000 while preserving all line
highs, totals, forecasts, source limits, and the global high.
