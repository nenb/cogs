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
| governance | 6,000 / 1,100,000 | ADR0338/ADR0339, index, budget, central checker, focused budget test |
| product | 4,000 / 3,200,000 | protected product workflow and ancestry record; `dev/linux-kvm/driver.sh`, `test/linux-kvm-git-tools.test.ts`, and current separate empty/nonempty runners and existing capability probes with profile-bound receipts/tests |
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
