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
