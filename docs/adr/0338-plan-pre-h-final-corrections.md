# ADR 0338: Plan pre-H final corrections and preserve AWS denial

## Status
Accepted planning/governance gate only. This decision supersedes neither a historical H/G/Q identity nor ADR0337's protected-squash accounting. It authorizes this ADR, the ADR index, the closed budget configuration/checker, and their focused governance tests only. It does **not** authorize product, workflow, OpenTofu, provider, SSM, AWS, Docker, KVM, readiness, full-suite, image, release, or dispatch work.

## Baseline and accounting
The protected product checkpoint remains `eda2dc499153f3053772790c02ea6d332403742e`, tree `9ad48a2be811745f0d8032a0a9f52a33c4b2edec`; it is not H, G, or Q. Every successor must remain a direct linear child for the checker, and every added line and UTF-8 added-line byte is cumulatively charged from that checkpoint without deletion, rename, copy, net-size, compression, or prior-checkpoint credit.

This plan consumes a separately closed governance task of at most **600 gross lines / 600,000 raw added-line bytes** in these exact paths:

- `docs/adr/0338-plan-pre-h-final-corrections.md`
- `docs/adr/README.md`
- `config/external-review-remediation-budget-v1.json`
- `scripts/check-stage2-retained-lines.py`
- `test/stage2-remediation-budget.test.ts`

The remaining final-H/G/Q control-and-evidence task is **1,400 / 1,400,000**. Runtime correction/tests retain **1,000 / 1,000,000**. Thus the final tranche remains exactly **3,000 / 3,000,000**, product remains `18,000 + consumed <= 21,000` lines and `8,000,000 + consumed <= 11,000,000` bytes, and remediation remains `48,000 + consumed <= 52,000` lines and `11,000,000 + consumed <= 14,000,000` bytes. The hard limit remains strictly below 115,000 lines. The remediation new-file high rises only from 99 to 100: `1,420 + 100 = 1,520 <= 1,530`; source aggregate remains `18,763,891 + 14,000,000 = 32,763,891 <= 34,000,000`, leaving 1,236,109 bytes. The serialized inventory stays 262,144 bytes. These are independent ceilings, not transferable balances.

## Ten completed whole-tree review outcomes and adjudication

1. **OpenBao:** defer it. It is nonblocking only for the narrowed Stage2 synthetic measurement. A synthetic port or fixture is not OpenBao availability, identity, PKI, revocation, Kubernetes, cloud, or production evidence and grants no production claim.
2. **Historical H/G/Q guards:** retain them. Their hardcoded identities are expected until a fresh Q exists. They must reject stale selection, not be relabeled as current authorization.
3. **Old AWS packages:** deny their AWS admission. A package bound to an old H/G/Q, old run, old artifact, or old control/qualification identity is a vetoed input even if an old local guard would otherwise pass.
4. **OpenTofu local state:** correct source only. `deploy/aws-feasibility/plan.sh`, `apply.sh`, `destroy.sh`, and `run-measurement-validation.sh` must later initialize an explicit local backend and use fresh, per-cycle state/plan paths; no stale state may be read across cycles.
5. **SSM readiness:** correct source only. `deploy/aws-feasibility/apply.sh` must later bound `Online` polling and bind the observed instance ID, command ID, deadline, and timing receipt.
6. **Same-command propagation:** correct source only. `deploy/aws-feasibility/run-measurement-validation.sh` must later poll and retrieve only the command it created for the already authenticated instance; `Online`, timeout, terminal status, and output must be causally tied to that one command.
7. **Empty skills product case:** require one fresh protected non-AWS runner for `skills=empty`, with a separately created generation, sealed inputs, exact inventory, and exact settlement.
8. **Nonempty skills product case:** require a different fresh protected non-AWS runner for a canonical nonempty shared/user pair; it must not reuse the empty runner, generation, publication, image tag, receipt, or state.
9. **Input capability probes:** require full-minus-one probes for every admitted input capability on fresh probe generations. A probe missing, substituting, widening, or retaining a capability must fail before candidate work and settle only its own exact resources.
10. **SSH capability probes:** require a separate full-minus-one probe for each measured SSH/SFTP capability, with exact allowed/denied operation evidence. Guest mutation results are supplemental and cannot replace the authenticated capability/mount proof.

Outcomes 4–6 are source corrections only; no `tofu`, provider, AWS CLI, SSM, inventory, or remote command may be invoked under this ADR. Outcomes 7–10 are product requirements, not evidence that either runner exists or has run.

## Future implementation matrix and invariants

The future source-only correction is limited to the already allocated paths below; an unlisted path, new file, workflow, or schema stops for a reviewed scope/budget decision.

| Task | Exact future paths | Required invariant |
| --- | --- | --- |
| stale-package AWS denial and fresh H/G/Q admission | `scripts/stage2-production-planner.py`, `scripts/stage2-production-approval.py`, `scripts/stage2-stage-production-approval.py`, `.github/workflows/stage2-production-plan.yml`, `.github/workflows/stage2-production-approval.yml`, `.github/workflows/stage2-production-campaign.yml`, `test/stage2-production-planner.py`, `test/stage2-production-approval.py`, `test/stage2-production-workflows.test.ts` | Old package/revision/run/artifact identities deny before any AWS-facing effect; existing hardcoded H/G/Q guards remain until a separately frozen fresh Q. |
| local-state and SSM source repair | `deploy/aws-feasibility/plan.sh`, `deploy/aws-feasibility/apply.sh`, `deploy/aws-feasibility/destroy.sh`, `deploy/aws-feasibility/run-measurement-validation.sh`, `test/stage2-production-planner.py`, `test/aws-stage2-completion-campaign-aws-provider.py` | Explicit per-cycle local backend/state, bounded `Online`, and instance/command/receipt sameness; no execution in this tranche. |
| separate product profiles and probes | `dev/product-test/host-custody.py`, `dev/product-test/runner.ts`, `dev/product-test/snapshot-owner.ts`, `test/production-compose.test.ts`, `test/ci-infrastructure-boundary.test.ts`, `.github/workflows/insecure-container.yml` | Empty and nonempty use distinct fresh protected runners and exact generations; each input and SSH capability is full-minus-one faulted before work. |
| KVM capability-probe parity | `dev/linux-kvm/driver.sh`, `dev/linux-kvm/ci-smoke.sh`, `dev/linux-kvm/qualify.sh`, `dev/linux-kvm/bounded-command.py`, `test/linux-kvm-git-tools.test.ts`, `test/egress-conformance/stage3-real-runtime/harness.ts`, `.github/workflows/kvm-qualification.yml` | A probe is non-authorizing, has no candidate pass/evidence authority, cannot reuse state, and preserves uncertain custody. |
| final H/G/Q controls | existing allocated Stage2 control/evidence paths only | Fresh H then direct-child G then fresh Q; no old package admission and no AWS step. |

Every admission checks exact candidate/tree, protected ref, root-owned custody, distinct run/attempt and generation, fixed limits, and no foreign inventory before effect. Failure, timeout, missing receipt, nonempty pre-inventory, stale capability, or uncertain cleanup fails closed and preserves custody. No timeout, empty inventory assertion, local test, package parse, or historical Q is authorization.

## Hostile and no-effect validation

Focused future tests must mutate an old package identity one field at a time (H, G, Q, run, artifact, control, qualification), stale/replaced local state, missing/late/foreign `Online`, mismatched SSM command output, duplicate or foreign instance ID, reused runner/generation, empty/nonempty cross-use, each missing/widened input/SSH capability, late probe failure, and cleanup uncertainty. Each negative must prove it stops before the relevant effect sentinel. The source-only AWS tests use fake executables and temporary files only: zero `tofu`, AWS CLI, provider, SSM, network, inventory, or remote command calls. Product and KVM probe models use no Docker, KVM, SSH server, workflow dispatch, or privileged host operation.

For this planning commit, validation is limited to the central budget checker, `test/stage2-remediation-budget.test.ts`, formatter, and diff/path inspection. It claims no product behavior, no readiness/full suite, no Docker/KVM, no OpenTofu/provider/SSM/AWS result, and no workflow dispatch.

## Authority and later gates

After this commit is merged to protected main, protected **non-AWS** product/KVM dispatch is authorized only under the existing protected workflow admission plus the fresh-runner/profile/probe invariants above. This is not authorization for AWS, and it does not permit a workflow edit or dispatch in this branch.

There is no single-operator exception now. Future AWS remains mechanically denied until a separate AWS authorization binds distinct authenticated operator, approver/budget/security reviewer, executor, and zero-inventory observer, or a later reviewed decision explicitly supersedes this rule. No role may self-attest another role; missing, equal, expired, or unauthenticated identities deny before credentials, OpenTofu, provider, AWS, SSM, inventory, or remote effects.

A later no-mint full/readiness rehearsal requires its own reviewed authorization. It must bind the fresh Q and exact no-mint inputs, state that it cannot create credentials/resources or claim production, and separately authorize its validation scope. This ADR grants neither that rehearsal nor a production claim.
