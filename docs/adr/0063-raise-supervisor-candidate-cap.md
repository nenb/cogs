# ADR 0063: Raise the supervisor candidate cap after measured implementation

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #234](https://github.com/nenb/cogs/pull/234).
- Amendment scope: This ADR amends only ADR 0062's absolute gross-addition maximum for `test/aws-stage2-completion-rootfs-candidate.py`, from 1,100 to 1,150, and the corresponding excluded three-file total from 1,250 to 1,300. The TypeScript maximum remains 30 and the workflow maximum remains 110. Every other ADR 0062 requirement remains binding.

## Context

The accepted ADR 0062 parent/child supervisor has now been implemented in honest, ordinary-readable form. Measured against the inherited exact baseline `8caab23bb4277121a77d80dc043b3c2c43b07ced`, its excluded-file gross additions are:

| Excluded file | Measured gross additions | ADR 0062 maximum |
| --- | ---: | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **1,121** | 1,100 |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** | 30 |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **108** | 110 |
| **Excluded three-file total** | **1,259** | **1,250** |

The candidate file exceeds its accepted maximum by exactly 21 lines, and the aggregate exceeds its accepted maximum by exactly nine lines. Deleting or compressing readable supervisor checks to fit those maxima would not be valid budget credit.

## Decision

If accepted, raise only the candidate-file maximum from 1,100 to 1,150 and the excluded three-file total from 1,250 to 1,300:

| Excluded file | Absolute maximum gross additions |
| --- | ---: |
| `test/aws-stage2-completion-rootfs-candidate.py` | **1,150** |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` | **30** |
| `.github/workflows/stage2-rootfs-full-build-qualification.yml` | **110** |
| **Excluded three-file total** | **1,300** |

The measured candidate has 29 lines of file headroom. The measured aggregate has 41 lines of total headroom. The maximum per-file sum is `1,150 + 30 + 110 = 1,290`, which is within the 1,300 aggregate maximum. The aggregate margin is not transferable, does not permit any file to exceed its own maximum, and does not authorize another file.

Gross additions remain measured from the exact baseline above. Deletions receive no credit, presentation compression receives no credit, and ordinary readable formatting remains required. Stop and replan before crossing any file maximum or the aggregate maximum.

## Exact implementation review and acceptance

Acceptance requires an independent exact-implementation review of the complete ADR 0062 supervisor implementation at one recorded full 40-hex head. The review must:

- cover the exact baseline-to-head range and report no unresolved P0–P3 finding;
- verify the exact measured additions of 1,121 candidate Python lines, 30 TypeScript lines, 108 workflow lines, and 1,259 aggregate lines, with no deletion credit;
- verify compliance with every per-file maximum and the aggregate maximum above; and
- confirm that the implementation retains ADR 0062 behavior and scope without moving or compressing logic to manufacture budget margin.

Any implementation change after that review invalidates its signoff and requires a new exact review; this ADR itself authorizes no such change.

## Retained boundaries and consequences

This is a cap-only amendment. It changes no behavior, implementation-file scope, production code, deadline, process model, fault boundary, test, event, run, recovery authority, workflow behavior, cloud boundary, or AWS authority. It grants no deletion or compression credit and no implementation, correction, refactor, companion, command, execution, candidate, report, retry, stage, campaign, release, or later-work authority.

Every non-conflicting ADR 0057–0062 requirement remains binding, including the exact supervisor design, existing files and commands, sole event/run/attempt, deadlines, faults, tests, recovery limits, mandatory stops, production boundaries, and cloud/AWS prohibitions.

The consequence is only enough numeric capacity to retain the measured accepted supervisor implementation in readable form and submit that exact implementation to the required review. This documentation-only proposal remains uncommitted and creates no implementation or operational action.
