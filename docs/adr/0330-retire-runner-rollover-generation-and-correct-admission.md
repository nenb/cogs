# ADR 0330: Retire runner-rollover generation and correct admission

- Status: Accepted
- Date: 2026-09-09
- Deciders: Nick Byrne
- Scope: failed Stage2 mixed preflight, hosted-runner admission, cleanup correction, and one replacement non-AWS chain

## Context

ADR 0329 established Q `d0e29eb359f0c1678c18f676e312276eff3aa3f8`, sole parent G `15d99b55f4910df94decdd7edcc80bf95aee492d`, describing H `c30e0d69ec374cd812ff361e670e974d51b661c4`. Producer `34375934829`, publisher `34402409489`, and static observation `34403562378` were sole first-created successful attempt-one runs. Their artifacts were `10114901253`, `10123988189`, and `10124443866`.

Mixed preflight `34411847798`, attempt 1, admitted the exact chain and completed source/control acquisition and immutable installation without KVM. Both mandatory recovery attempts then failed closed with `executable closure source differs`; neither reached cleanup, residue, or pass. Hosted `/opt` restoration alone is not settlement evidence. The run produced no artifact and grants no preflight, qualification, production, or AWS authority.

The static observation ran on GitHub image `ubuntu24` version `20260831.293.1`; preflight ran 90 minutes later on `20260907.300.1` during a phased regional rollout of the rolling `ubuntu-24.04` label. GitHub's release evidence updates OpenSSH from `1:9.6p1-3ubuntu13.18` to `.19`. The static `/usr/bin/ssh` digest equals the `.18` package while `.19` has the same size and different bytes. This establishes an unbound rolling-image dependency; the destroyed runner log does not independently reveal the exact first differing object.

Review also found that Bash `errexit` does not stop after the first failing command in the existing `/opt/kata` absence `&&` lists. Permission restoration could therefore proceed without proved absence. This does not explain the executable mismatch, but it invalidates use of that step as residue evidence.

## Decision

Retire exactly:

- revisions H `c30e0d69ec374cd812ff361e670e974d51b661c4`, G `15d99b55f4910df94decdd7edcc80bf95aee492d`, Q `d0e29eb359f0c1678c18f676e312276eff3aa3f8`;
- runs `34375934829`, `34402409489`, `34403562378`, and `34411847798`;
- artifacts `10114901253`, `10123988189`, and `10124443866`.

The central policy, closed Python copy, and all 19 pre-effect workflow mirrors must agree on 27 revisions, 33 runs, and 23 artifacts. Preserve v6 and all prior bytes as history. Do not retry, relabel, delete for credit, blacklist shared content digests, or treat retired ancestry as a selection veto.

Freeze exact hosted image policy `ImageOS=ubuntu24` and `ImageVersion=20260907.300.1` in H-owned workflow literals. Check it independently before the first repository-controlled shell effect in the static, mixed-preflight, formal-admission, each of seven formal-cycle, and aggregate runners. Runner-managed prefetch of immutable pinned actions remains an explicit pre-admission limitation; it is not described as zero acquisition. The value is a fail-closed compatibility fuse, not a scheduler pin or executable attestation. Do not begin the successor static observation while GitHub marks this image rollout incomplete; ordinary non-authorizing runner observations must show convergence first.

After authenticated Q checkout and before `/opt`, fixed-root, immutable, network, or lifecycle mutation, compare every ambient host executable, loader, and library against the exact static package. Reuse the strict canonical contract and stable descriptor-relative byte/ELF checks. This read-only check issues no grant, custody, retry, cleanup, or mint authority. Keep all existing use-time checks.

Replace hosted `/opt` mode handling with one H-owned descriptor-relative helper that admits only root-owned `/opt`, exact modes 0755/0777, and proven `kata` absence before and after a held-fd mode transition. Before mutation it durably records the exact directory identity, original mode, run, and attempt under root-owned `/run`; restoration authenticates and consumes that record. It must roll back and fail on uncertainty. An untouched pre-acquisition refusal performs no cleanup mutation. Once acquisition begins, exact cleanup or explicit sticky red uncertainty remains mandatory: a partial or unauthenticated fixed source is preserved and never executed or broadly deleted, while a completed authenticated source enters recovery. Never suppress recovery failure or infer cleanup from runner disposal.

Use successor control directory v7. H and G require it absent; Q may add only the exact independently read-back 13 members and fill the reviewed binding adapters. Preserve v6 as mandatory historical custody.

## Bounded accounting

The failed endpoint consumed all 1,492 tracked-file and 64 integration-new-file slots and left 79 integration gross lines. Allocate the complete measured correction and later H/G/Q closure without deletion credit:

| Bound | ADR 0327 | ADR 0330 |
| --- | ---: | ---: |
| remediation global gross | 29,000 | 30,000 |
| integration owner gross | 11,000 | 12,500 |
| integration planned new files | 64 | 81 |
| total planned new files | 72 | 89 |
| tracked files | 1,492 | 1,509 |

All other owner, correction, post-H, serialized-inventory, source-byte, and conservative hard ceilings remain unchanged. The 17 added planned files are this decision, reserved ADRs 0331–0332, one `/opt` helper, and thirteen v7 members.

## Required gates and consequences

Before replacement H: complete retirement equality/rejection; real image-predicate behavior tests; early host-closure mutation and stable-read tests; `/opt` race/error/rollback tests; no-acquisition and acquired-state cleanup tests; workflow topology/order assertions for all eleven relevant runners; Linux/root diagnostics; schemas, syntax, accounting, full checks, deterministic readiness regeneration; broad reviews followed by two exact-tree reviews; protected tree equality.

Then require a wholly fresh H → producer → direct-child G → publisher → static observation → direct-child Q → attempt-one mixed preflight → two audits → attempt-one seven-runner qualification → two audits. Any failure retires that generation and grants no rerun.

This decision grants no AWS, provider, OpenTofu, SSM, inventory, deployment, campaign, production, release, Stage3, Stage4, or OpenBao-production operation. After the final non-AWS handoff, stop immediately before AWS.
